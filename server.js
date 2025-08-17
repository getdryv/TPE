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
  console.error('❌ STRIPE_SECRET_KEY manquant dans les variables d’environnement');
  process.exit(1);
}
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// ----- Middlewares globaux -----
// CORS + fichiers statiques
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// IMPORTANT : ne PAS parser /webhook/stripe avec express.json()
// On applique express.json() à toutes les autres routes uniquement.
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook/stripe') return next();
  return express.json()(req, res, next);
});

// ----- Routes de base -----
app.get('/health', (_req, res) => res.json({ ok: true }));

// Sert explicitement l'index pour la racine
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ----- Stripe Terminal -----
// 1) Connection token (scopé sur une Location si fournie)
app.post('/connection-token', async (_req, res) => {
  try {
    const params = {};
    if (process.env.STRIPE_TERMINAL_LOCATION) {
      // tml_xxx (ID de Location LIVE recommandé pour la prod)
      params.location = process.env.STRIPE_TERMINAL_LOCATION;
    }
    const token = await stripe.terminal.connectionTokens.create(params);
    res.json({ secret: token.secret });
  } catch (err) {
    console.error('connection-token error:', err);
    res.status(500).send({ error: err.message });
  }
});

// 2) Création PaymentIntent (montant en CENTIMES)
app.post('/create-payment-intent', async (req, res) => {
  try {
    const { montant, email, firstName, lastName } = req.body;

    if (!Number.isInteger(montant) || montant <= 0) {
      return res.status(400).json({ error: 'montant doit être un entier > 0 (en centimes)' });
    }

    // Idempotency pour éviter les doublons en cas de retry réseau
    const idempotencyKey = req.headers['idempotency-key'] || crypto.randomUUID();

    const customer = await stripe.customers.create({
      name: [firstName, lastName].filter(Boolean).join(' ').trim() || undefined,
      email: email || undefined,
    });

    const pi = await stripe.paymentIntents.create(
      {
        amount: montant,
        currency: 'eur',
        payment_method_types: ['card_present'],
        capture_method: 'manual', // autorisation puis capture séparée
        customer: customer.id,
        receipt_email: email || undefined,
        metadata: { source: 'terminal' },
      },
      { idempotencyKey }
    );

    res.json({ client_secret: pi.client_secret, id: pi.id });
  } catch (err) {
    console.error('create-payment-intent error:', err);
    res.status(500).send({ error: err.message });
  }
});

// 3) Capture (après autorisation sur le TPE)
app.post('/capture-payment', async (req, res) => {
  try {
    const { paymentIntentId } = req.body;
    if (!paymentIntentId) {
      return res.status(400).json({ error: 'paymentIntentId requis' });
    }

    const captured = await stripe.paymentIntents.capture(paymentIntentId);
    res.send({ success: true, captured });
  } catch (err) {
    console.error('capture-payment error:', err);
    res.status(500).send({ error: err.message });
  }
});

// ----- Webhook Stripe (RAW body obligatoire) -----
// ⚠️ Cette route doit AVANT TOUT recevoir le corps "brut" (buffer),
// d'où l'absence de express.json() pour /webhook/stripe (voir middleware plus haut).
app.post('/webhook/stripe', bodyParser.raw({ type: 'application/json' }), (req, res) => {
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
        console.log(`✅ payment_intent.succeeded: ${pi.id} — montant=${pi.amount} ${pi.currency}`);
        break;
      }
      case 'payment_intent.payment_failed': {
        const pi = event.data.object;
        console.log(`❌ payment_intent.payment_failed: ${pi.id}`);
        break;
      }
      case 'payment_intent.canceled': {
        const pi = event.data.object;
        console.log(`⚪ payment_intent.canceled: ${pi.id}`);
        break;
      }
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
  }

  res.json({ received: true });
});

// ----- Lancement -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
