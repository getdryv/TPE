// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser'); // pour le webhook (raw)
const crypto = require('crypto');

const app = express();

// ----- Config -----
if (!process.env.STRIPE_SECRET_KEY) {
  console.error('❌ STRIPE_SECRET_KEY manquant dans les variables d’environnement');
  process.exit(1);
}
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Middleware global (⚠️ pas pour /webhook/stripe qui utilise raw)
app.use(cors());
app.use(express.static('public'));
app.use(express.json());

// --- Healthcheck ---
app.get('/health', (_req, res) => res.json({ ok: true }));

// --- Connection token pour Stripe Terminal ---
app.post('/connection-token', async (_req, res) => {
  try {
    const connectionToken = await stripe.terminal.connectionTokens.create();
    res.json({ secret: connectionToken.secret });
  } catch (err) {
    console.error('connection-token error:', err);
    res.status(500).send({ error: err.message });
  }
});

// --- Création PaymentIntent (montant en centimes) ---
app.post('/create-payment-intent', async (req, res) => {
  try {
    const { montant, email, firstName, lastName } = req.body;

    // validations rapides
    if (!Number.isInteger(montant) || montant <= 0) {
      return res.status(400).json({ error: 'montant doit être un entier > 0 (en centimes)' });
    }

    // Idempotency (optionnel mais recommandé)
    const idempotencyKey =
      req.headers['idempotency-key'] ||
      crypto.randomUUID();

    // Créer/associer un customer (facultatif mais utile pour reçus)
    const customer = await stripe.customers.create({
      name: [firstName, lastName].filter(Boolean).join(' ').trim() || undefined,
      email: email || undefined,
    });

    const paymentIntent = await stripe.paymentIntents.create(
      {
        amount: montant,
        currency: 'eur',
        payment_method_types: ['card_present'],
        // manual = capture en 2 temps (authorize puis capture)
        capture_method: 'manual',
        customer: customer.id,
        receipt_email: email || undefined,
        // utile pour débogage/backoffice
        metadata: {
          source: 'terminal',
        },
      },
      { idempotencyKey }
    );

    res.json({ client_secret: paymentIntent.client_secret, id: paymentIntent.id });
  } catch (err) {
    console.error('create-payment-intent error:', err);
    res.status(500).send({ error: err.message });
  }
});

// --- Capture PaymentIntent (après autorisation sur le TPE) ---
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

// --- Webhook Stripe (⚠️ RAW body obligatoire) ---
app.post(
  '/webhook/stripe',
  bodyParser.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET; // à configurer dans Render

    let event;
    try {
      if (!webhookSecret) {
        throw new Error('STRIPE_WEBHOOK_SECRET manquant');
      }
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error('⚠️ Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Traiter les événements utiles
    try {
      switch (event.type) {
        case 'payment_intent.succeeded': {
          const pi = event.data.object;
          console.log(`✅ payment_intent.succeeded: ${pi.id} — montant=${pi.amount} ${pi.currency}`);
          // TODO: marquer la commande payée, envoyer reçu, etc.
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
      // on renvoie quand même 200 si l’event est bien reçu, pour éviter le retry infini
    }

    res.json({ received: true });
  }
);

// ----- Start -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
