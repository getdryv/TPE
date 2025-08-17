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

// ----- Firebase Admin (Firestore + vérif ID token) -----
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

// ----- Middleware Firebase Auth pour l'API admin -----
async function verifyFirebaseIdToken(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing Bearer token' });

    const decoded = await admin.auth().verifyIdToken(token);
    const email = (decoded.email || '').toLowerCase();

    const allowed = (process.env.ADMIN_EMAILS || '')
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean);

    if (!email || !allowed.includes(email)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    req.user = { email, uid: decoded.uid };
    next();
  } catch (e) {
    console.error('verifyFirebaseIdToken error:', e);
    res.status(401).json({ error: 'Invalid token' });
  }
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

    // Créer/associer un customer
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
        metadata: {
          source: 'terminal',
          firstName: fName,
          lastName: lName,
          fullName,
          email: emailSafe,
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

        // 1) via METADATA
        let customerName = pi.metadata?.fullName || '';
        let customerEmail = pi.metadata?.email || '';

        // 2) via charge/billing_details
        const charge = pi.charges?.data?.[0];
        if (!customerName) customerName = charge?.billing_details?.name || '';
        if (!customerEmail) customerEmail = pi.receipt_email || charge?.billing_details?.email || '';

        // 3) en dernier recours: retrieve customer
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
// JSON data (protégé par Firebase Auth + liste blanche emails)
// Support des filtres from/to + raccourcis + KPIs
app.get('/admin.json', verifyFirebaseIdToken, async (req, res) => {
  try {
    const { range = 'today', from, to } = req.query;

    // helpers
    const startOfDay = (d) => { d.setHours(0,0,0,0); return d; };
    const endOfDay   = (d) => { d.setHours(23,59,59,999); return d; };

    // Déterminer la fenêtre temporelle
    let start = null;
    let end = null;

    if (from || to) {
      if (from) start = new Date(from);
      if (to)   end   = new Date(to);
      if (start && isNaN(start)) start = null;
      if (end   && isNaN(end))   end   = null;
      if (start && !end) end = endOfDay(new Date()); // fallback
      if (!start && end) start = startOfDay(new Date(end)); // fallback
    } else {
      const now = new Date();
      if (range === '7d') {
        end = now;
        start = new Date(); start.setDate(now.getDate() - 6); start = startOfDay(start);
      } else if (range === '30d') {
        end = now;
        start = new Date(); start.setDate(now.getDate() - 29); start = startOfDay(start);
      } else if (range === 'mo') {
        start = new Date(now.getFullYear(), now.getMonth(), 1);
        end   = endOfDay(new Date());
      } else { // today par défaut
        start = startOfDay(new Date());
        end   = endOfDay(new Date());
      }
    }

    // Construire la requête Firestore
    let q = paymentsCol.where('status', '==', 'succeeded'); // on reste sur "réussis"
    if (start) q = q.where('created_at', '>=', admin.firestore.Timestamp.fromDate(start));
    if (end)   q = q.where('created_at', '<=', admin.firestore.Timestamp.fromDate(end));
    q = q.orderBy('created_at', 'desc').limit(2000);

    const snap = await q.get();

    const rows = [];
    const perDay = new Map(); // yyyy-mm-dd -> { total, count }
    let totalCents = 0;
    let count = 0;

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

      totalCents += amount;
      count += 1;

      const agg = perDay.get(dayKey) || { total: 0, count: 0 };
      agg.total += amount;
      agg.count += 1;
      perDay.set(dayKey, agg);
    });

    const series = Array.from(perDay.entries())
      .sort((a,b) => a[0].localeCompare(b[0]))
      .map(([day, v]) => ({ day, total: v.total, count: v.count }));

    res.json({
      filters: {
        range,
        from: start ? start.toISOString() : null,
        to:   end   ? end.toISOString()   : null,
        status: 'succeeded'
      },
      currency: 'EUR',
      kpis: {
        total_cents: totalCents,
        count,
        avg_cents: count ? Math.round(totalCents / count) : 0,
      },
      days: series,
      items: rows
    });
  } catch (e) {
    console.error('admin.json error', e);
    res.status(500).json({ error: e.message });
  }
});

// CSV export (protégé pareil) — on le garde simple pour l’instant
app.get('/admin.csv', verifyFirebaseIdToken, async (req, res) => {
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

// HTML dashboard (publique; le JS gère le login + Bearer)
app.get('/admin', async (req, res) => {
  // valeurs pour init Firebase côté client
  const WEB_API_KEY   = process.env.FIREBASE_WEB_API_KEY || '';
  const AUTH_DOMAIN   = process.env.FIREBASE_AUTH_DOMAIN || '';
  const PROJECT_ID    = process.env.FIREBASE_PROJECT_ID || '';

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
.controls{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse;margin-top:14px}
th,td{padding:8px;border-bottom:1px solid #e5e7eb}
th{background:#fafafa;text-align:left}
.r{text-align:right}
.badge{display:inline-block;padding:4px 8px;border-radius:8px;background:#edf2ff;color:#334}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.kpis .k{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:10px 12px;min-width:140px}
a.btn,button.btn{display:inline-block;padding:8px 10px;border:1px solid #d7dbe7;border-radius:8px;text-decoration:none;color:#111;background:#fff;cursor:pointer}
a.btn:hover,button.btn:hover{background:#f5f7ff}
input[type="date"]{padding:6px 8px;border:1px solid #d7dbe7;border-radius:8px;background:#fff}
</style>
</head>
<body>
<div class="card">
  <h1>Dashboard TPE</h1>

  <!-- Barre login -->
  <div id="authbar" class="controls" style="justify-content:flex-start">
    <button id="loginBtn" class="btn">Se connecter avec Google</button>
    <button id="logoutBtn" class="btn" style="display:none">Se déconnecter</button>
    <span id="who" style="margin-left:auto;color:#555"></span>
  </div>

  <!-- Filtres -->
  <div class="controls">
    <span id="badge" class="badge">Aujourd’hui • Réussis</span>
    <a class="btn" data-range="today">Aujourd’hui</a>
    <a class="btn" data-range="7d">7 jours</a>
    <a class="btn" data-range="30d">30 jours</a>
    <a class="btn" data-range="mo">Mois courant</a>
    <span style="margin-left:auto"></span>
    <label>Du <input id="from" type="date"></label>
    <label>au <input id="to" type="date"></label>
    <button id="apply" class="btn">Appliquer</button>
    <a id="csv" class="btn" href="#">Export CSV</a>
  </div>

  <div class="kpis">
    <div class="k"><div>Total €</div><div id="k_total" style="font-weight:700;font-size:20px">—</div></div>
    <div class="k"><div>Nb paiements</div><div id="k_count" style="font-weight:700;font-size:20px">—</div></div>
    <div class="k"><div>Ticket moyen €</div><div id="k_avg" style="font-weight:700;font-size:20px">—</div></div>
  </div>

  <canvas id="chart" height="90"></canvas>
  <table id="tbl">
    <thead><tr>
      <th>Date</th><th class="r">Montant (€)</th><th>Nom</th><th>Email</th><th>PI</th>
    </tr></thead>
    <tbody></tbody>
  </table>
</div>

<!-- Firebase Auth côté client -->
<script type="module">
  import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
  import { getAuth, GoogleAuthProvider, signInWithPopup, onAuthStateChanged, signOut } 
    from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

  const firebaseConfig = {
    apiKey: "${WEB_API_KEY}",
    authDomain: "${AUTH_DOMAIN}",
    projectId: "${PROJECT_ID}"
  };

  const app = initializeApp(firebaseConfig);
  const auth = getAuth(app);
  const provider = new GoogleAuthProvider();

  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const who = document.getElementById('who');

  loginBtn.onclick = () => signInWithPopup(auth, provider);
  logoutBtn.onclick = () => signOut(auth);

  let idToken = null;
  window.__getIdToken = async () => idToken || (await auth.currentUser?.getIdToken());

  onAuthStateChanged(auth, async (user) => {
    if (user) {
      idToken = await user.getIdToken(true);
      loginBtn.style.display = 'none';
      logoutBtn.style.display = 'inline-block';
      who.textContent = user.email || '';
      if (typeof load === 'function') load(); // recharge les données
    } else {
      idToken = null;
      loginBtn.style.display = 'inline-block';
      logoutBtn.style.display = 'none';
      who.textContent = '';
    }
  });
</script>

<script>
let state = { range: (new URLSearchParams(location.search).get('range')||'today'), from: null, to: null };
const badgeEl = document.getElementById('badge');
const fromEl = document.getElementById('from');
const toEl = document.getElementById('to');
const applyEl = document.getElementById('apply');

document.querySelectorAll('a.btn[data-range]').forEach(btn=>{
  btn.addEventListener('click', (e)=>{
    e.preventDefault();
    state.range = btn.dataset.range;
    state.from = state.to = null;
    fromEl.value = toEl.value = '';
    load();
  });
});

applyEl.addEventListener('click', ()=>{
  state.range = 'custom';
  state.from = fromEl.value || null;
  state.to   = toEl.value || null;
  load();
});

document.getElementById('csv').addEventListener('click', async (e) => {
  e.preventDefault();
  const token = await (window.__getIdToken ? window.__getIdToken() : null);
  if (!token) return alert('Connecte-toi avec Google');
  const qs = new URLSearchParams();
  qs.set('range', state.range === 'custom' ? '30d' : state.range); // on garde simple côté serveur pour le moment
  const resp = await fetch('/admin.csv?' + qs.toString(), { headers: { Authorization: 'Bearer ' + token } });
  if (!resp.ok) return alert('Accès refusé');
  const blob = await resp.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'paiements.csv';
  a.click();
});

let chart;

function formatEuros(cents){
  return (cents/100).toFixed(2).replace('.', ',');
}

async function load() {
  const token = await (window.__getIdToken ? window.__getIdToken() : null);
  if (!token) return;

  // Construire la query
  const qs = new URLSearchParams();
  if (state.range && state.range !== 'custom') qs.set('range', state.range);
  if (state.range === 'custom') {
    if (state.from) qs.set('from', state.from);
    if (state.to)   qs.set('to', state.to);
  }

  const r = await fetch('/admin.json?' + qs.toString(), { headers: { Authorization: 'Bearer ' + token } });
  if (!r.ok) { console.error('admin.json error', r.status); return; }
  const data = await r.json();

  // Badge période
  let label = 'Aujourd’hui';
  if (data.filters?.range === '7d') label = '7 jours';
  else if (data.filters?.range === '30d') label = '30 jours';
  else if (data.filters?.range === 'mo') label = 'Mois courant';
  if (data.filters?.from && data.filters?.to) {
    label = 'Du ' + data.filters.from.slice(0,10) + ' au ' + data.filters.to.slice(0,10);
  }
  badgeEl.textContent = label + ' • Réussis';

  // KPIs
  document.getElementById('k_total').textContent = formatEuros(data.kpis?.total_cents||0);
  document.getElementById('k_count').textContent = (data.kpis?.count||0);
  document.getElementById('k_avg').textContent   = formatEuros(data.kpis?.avg_cents||0);

  // Graph
  const labels = data.days.map(d => d.day);
  const totals = data.days.map(d => (d.total/100).toFixed(2));
  const ctx = document.getElementById('chart').getContext('2d');
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Total (€)', data: totals }] },
    options: { plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}} }
  });

  // Tableau
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = data.items.map(x => {
    const euros = formatEuros(x.amount_cents);
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
</script>
</body></html>`);
});

// ----- Lancement -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
