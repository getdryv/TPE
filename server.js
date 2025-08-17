// server.js
require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser'); // RAW pour le webhook Stripe
const crypto = require('crypto');

const app = express();

// ----- Stripe -----
if (!process.env.STRIPE_SECRET_KEY) {
  console.error('❌ STRIPE_SECRET_KEY manquant');
  process.exit(1);
}
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// ----- Firebase Admin (Firestore) -----
const admin = require('firebase-admin');
if (!admin.apps.length) {
  if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !process.env.FIREBASE_PRIVATE_KEY) {
    console.error('❌ Variables Firebase manquantes');
    process.exit(1);
  }
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
}
const db = admin.firestore();
const paymentsCol = db.collection('tpe_payments');

// ----- Middlewares globaux -----
// (ne pas parser /webhook/stripe)
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook/stripe') return next();
  return express.json()(req, res, next);
});

// ----- Utils -----
function requireBasicAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const [type, raw] = auth.split(' ');
  if (type === 'Basic' && raw) {
    const [user, pass] = Buffer.from(raw, 'base64').toString().split(':');
    if (user === process.env.BASIC_AUTH_USER && pass === process.env.BASIC_AUTH_PASS) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="TPE Admin"');
  res.status(401).send('Authentication required.');
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ======================= Stripe Terminal =======================
// 1) Connection token
app.post('/connection-token', async (_req, res) => {
  try {
    const params = {};
    if (process.env.STRIPE_TERMINAL_LOCATION) {
      params.location = process.env.STRIPE_TERMINAL_LOCATION;
    }
    const token = await stripe.terminal.connectionTokens.create(params);
    res.json({ secret: token.secret });
  } catch (err) {
    console.error('connection-token error:', err);
    res.status(500).send({ error: err.message });
  }
});

// 2) Création PaymentIntent (montant en CENTIMES) + Customer + METADATA
app.post('/create-payment-intent', async (req, res) => {
  try {
    const { montant, email, firstName, lastName } = req.body;

    if (!Number.isInteger(montant) || montant <= 0) {
      return res.status(400).json({ error: 'montant doit être un entier > 0 (en centimes)' });
    }

    const fName = (firstName || '').toString().trim();
    const lName = (lastName  || '').toString().trim();
    const fullName = [fName, lName].filter(Boolean).join(' ').trim();
    const emailSafe = (email || '').toString().trim();

    const idempotencyKey = req.headers['idempotency-key'] || crypto.randomUUID();

    // Créer/associer un customer (utile pour reçus + fallback nom/email)
    const customer = await stripe.customers.create({
      name: fullName || undefined,
      email: emailSafe || undefined,
    });

    const pi = await stripe.paymentIntents.create(
      {
        amount: montant,
        currency: 'eur',
        payment_method_types: ['card_present'],
        capture_method: 'manual',
        customer: customer.id,
        receipt_email: emailSafe || undefined,
        // On place nos infos pour les retrouver au webhook même si billing_details est vide
        metadata: {
          source: 'terminal',
          firstName: fName,
          lastName: lName,
          fullName,
          email: emailSafe
        },
      },
      { idempotencyKey }
    );

    res.json({ client_secret: pi.client_secret, id: pi.id });
  } catch (err) {
    console.error('create-payment-intent error:', err);
    res.status(500).send({ error: err.message });
  }
});

// 3) Capture PaymentIntent (après autorisation sur le TPE)
app.post('/capture-payment', async (req, res) => {
  try {
    const { paymentIntentId } = req.body;
    if (!paymentIntentId) return res.status(400).json({ error: 'paymentIntentId requis' });

    const captured = await stripe.paymentIntents.capture(paymentIntentId);
    res.send({ success: true, captured });
  } catch (err) {
    console.error('capture-payment error:', err);
    res.status(500).send({ error: err.message });
  }
});

// ======================= Webhook Stripe =======================
// RAW body obligatoire pour la vérification de signature
app.post('/webhook/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET manquant');
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'payment_intent.succeeded': {
        const pi = event.data.object;

        // 1) On tente d’abord via METADATA (toujours présent car envoyé par nous)
        let customerName = pi.metadata?.fullName || '';
        let customerEmail = pi.metadata?.email || '';

        // 2) Sinon on regarde la charge/billing_details
        const charge = pi.charges?.data?.[0];
        if (!customerName) {
          customerName = charge?.billing_details?.name || '';
        }
        if (!customerEmail) {
          customerEmail = pi.receipt_email || charge?.billing_details?.email || '';
        }

        // 3) En dernier recours : we fetch le Customer
        if ((!customerName || !customerEmail) && pi.customer) {
          try {
            const cust = await stripe.customers.retrieve(pi.customer);
            customerName = customerName || cust?.name || '';
            customerEmail = customerEmail || cust?.email || '';
          } catch (e) {
            console.warn('⚠️ retrieve customer failed:', e?.message || e);
          }
        }

        const doc = {
          pi_id: pi.id,
          amount_cents: pi.amount || 0,
          currency: pi.currency || 'eur',
          customer_name: customerName || '',
          email: customerEmail || '',
          status: 'succeeded',
          created_at: admin.firestore.Timestamp.fromMillis((pi.created || Math.floor(Date.now()/1000)) * 1000),
          succeeded_at: admin.firestore.Timestamp.fromMillis(Date.now()),
        };

        await paymentsCol.doc(pi.id).set(doc, { merge: true });
        console.log(`🔥 Firestore: saved ${pi.id} — ${doc.amount_cents} ${doc.currency} — ${doc.customer_name} <${doc.email}>`);
        break;
      }

      case 'payment_intent.payment_failed':
      case 'payment_intent.canceled':
      case 'terminal.reader.action_failed':
      case 'terminal.reader.action_succeeded':
      case 'charge.captured':
      case 'charge.refunded':
        console.log(`ℹ️ ${event.type}`);
        break;

      default:
        console.log(`(ignored) ${event.type}`);
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
    // On renvoie quand même 200 pour éviter les retries infinis si souci métier
  }

  res.json({ received: true });
});

// ======================= Admin (Dashboard) =======================
// JSON data
app.get('/admin.json', requireBasicAuth, async (req, res) => {
  try {
    const range = (req.query.range || '30d').toLowerCase();

    let start = new Date();
    if (range === '7d') start.setDate(start.getDate() - 7);
    else if (range === '30d') start.setDate(start.getDate() - 30);
    else if (range === 'mo') { start = new Date(); start.setDate(1); start.setHours(0,0,0,0); }
    else start.setDate(start.getDate() - 30);

    const snap = await paymentsCol
      .where('status', '==', 'succeeded')
      .where('created_at', '>=', admin.firestore.Timestamp.fromDate(start))
      .orderBy('created_at', 'desc')
      .limit(1000)
      .get();

    const rows = [];
    const perDay = new Map(); // yyyy-mm-dd -> {total, count}

    snap.forEach(doc => {
      const d = doc.data();
      const date = d.created_at.toDate();
      const dayKey = date.toISOString().slice(0,10);
      const amount = d.amount_cents || 0;

      rows.push({
        pi_id: d.pi_id,
        amount_cents: amount,
        currency: d.currency || 'eur',
        customer_name: d.customer_name || '',
        email: d.email || '',
        created_at: date.toISOString(),
      });

      const agg = perDay.get(dayKey) || { total: 0, count: 0 };
      agg.total += amount;
      agg.count += 1;
      perDay.set(dayKey, agg);
    });

    const series = Array.from(perDay.entries())
      .sort((a,b) => a[0].localeCompare(b[0]))
      .map(([day, v]) => ({ day, total: v.total, count: v.count }));

    res.json({
      range,
      currency: 'EUR',
      days: series,
      items: rows
    });
  } catch (e) {
    console.error('admin.json error', e);
    res.status(500).json({ error: e.message });
  }
});

// CSV export
app.get('/admin.csv', requireBasicAuth, async (req, res) => {
  try {
    const r = await fetch(`${req.protocol}://${req.get('host')}/admin.json?range=${encodeURIComponent(req.query.range||'30d')}`, {
      headers: { authorization: req.headers.authorization || '' }
    });
    const data = await r.json();

    const rows = [
      ['Date', 'Montant(€)', 'Nom', 'Email', 'PaymentIntent'],
      ...data.items.map(x => [
        new Date(x.created_at).toLocaleString(),
        (x.amount_cents/100).toFixed(2).replace('.', ','),
        x.customer_name || '',
        x.email || '',
        x.pi_id
      ])
    ];

    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(';')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="paiements.csv"');
    res.send(csv);
  } catch (e) {
    console.error('admin.csv error', e);
    res.status(500).send('CSV error');
  }
});

// HTML dashboard
app.get('/admin', requireBasicAuth, async (req, res) => {
  res.send(`<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8" />
<title>Dashboard TPE</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f6f9fc;margin:0;padding:24px}
.card{background:#fff;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,.06);padding:20px;max-width:1100px;margin:0 auto}
h1{margin:0 0 16px}
.controls{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
table{width:100%;border-collapse:collapse;margin-top:14px}
th,td{padding:8px;border-bottom:1px solid #e5e7eb}
th{background:#fafafa;text-align:left}
.r{text-align:right}
.badge{display:inline-block;padding:4px 8px;border-radius:8px;background:#edf2ff;color:#334}
a.btn{display:inline-block;padding:8px 10px;border:1px solid #d7dbe7;border-radius:8px;text-decoration:none;color:#111;background:#fff}
a.btn:hover{background:#f5f7ff}
</style>
</head>
<body>
<div class="card">
  <h1>Dashboard TPE</h1>
  <div class="controls">
    <a class="btn" href="?range=7d">7 jours</a>
    <a class="btn" href="?range=30d">30 jours</a>
    <a class="btn" href="?range=mo">Mois courant</a>
    <a id="csv" class="btn" href="#">Export CSV</a>
  </div>
  <canvas id="chart" height="90"></canvas>
  <table id="tbl">
    <thead><tr>
      <th>Date</th><th class="r">Montant (€)</th><th>Nom</th><th>Email</th><th>PI</th>
    </tr></thead>
    <tbody></tbody>
  </table>
</div>
<script>
const qs = new URLSearchParams(location.search);
const range = qs.get('range') || '30d';
document.getElementById('csv').href = '/admin.csv?range=' + range;

async function load() {
  const r = await fetch('/admin.json?range=' + range, { credentials: 'include' });
  const data = await r.json();

  // Graph
  const labels = data.days.map(d => d.day);
  const totals = data.days.map(d => (d.total/100).toFixed(2));
  const ctx = document.getElementById('chart').getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Total (€)', data: totals }] },
    options: { plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}} }
  });

  // Tableau
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = data.items.map(x => {
    const euros = (x.amount_cents/100).toFixed(2).replace('.', ',');
    const date = new Date(x.created_at).toLocaleString();
    return \`<tr>
      <td>\${date}</td>
      <td class="r">\${euros}</td>
      <td>\${x.customer_name||''}</td>
      <td>\${x.email||''}</td>
      <td><span class="badge">\${x.pi_id}</span></td>
    </tr>\`;
  }).join('');
}
load();
</script>
</body></html>`);
});

// ----- Lancement -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
