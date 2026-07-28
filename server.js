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

// ----- Middlewares globaux -----
// (ne pas parser /webhook/stripe)
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook/stripe') return next();
  return express.json()(req, res, next);
});

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
// Le journal des paiements (Firestore) a été retiré : Stripe reste la source de
// vérité de l'encaissement, et le tableau de bord qui le lisait ne servait pas.
//
// L'endpoint est conservé volontairement. Une destination webhook est déclarée
// dans le compte Stripe et pointe ici : supprimer la route ferait tomber Stripe
// sur des 404 et déclencherait ses relances en boucle. On accuse donc réception
// et on journalise, sans rien écrire nulle part.
//
// La vérification de signature est maintenue : sans elle, n'importe qui pourrait
// écrire dans nos logs en appelant cette URL publique.
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

  switch (event.type) {
    case 'payment_intent.succeeded': {
      const pi = event.data.object;
      const amount = ((pi.amount || 0) / 100).toFixed(2);
      const who = pi.metadata?.fullName || '';
      console.log(`✅ ${pi.id} — ${amount} ${(pi.currency || 'eur').toUpperCase()} — ${who}`);
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

  res.json({ received: true });
});

// ----- Lancement -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
