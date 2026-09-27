// routes/webhook.js
//
// ======================= Webhook Stripe =======================
// Le journal des paiements (Firestore) a été retiré : Stripe reste la source de
// vérité de l'encaissement, et le tableau de bord qui le lisait ne servait pas.
//
// L'endpoint est conservé volontairement. Une destination webhook est déclarée
// dans le compte Stripe et pointe ici : supprimer la route ferait tomber Stripe
// sur des 404 et déclencherait ses relances en boucle. On accuse donc réception
// et on journalise.
//
// La vérification de signature est maintenue : sans elle, n'importe qui pourrait
// écrire dans nos logs en appelant cette URL publique — et, désormais, faire
// déclarer au CRM des paiements imaginaires.
//
// Monté AVANT l'analyse JSON : la signature porte sur le corps BRUT.

const express = require('express');
const bodyParser = require('body-parser'); // RAW pour le webhook Stripe
const { agenceParDefaut } = require('../lib/agences');
const { declarerDepuisPaiement } = require('../lib/declaration');

const router = express.Router();

router.post('/webhook/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET manquant');
    // La vérification de signature est purement cryptographique : elle n'appelle
    // pas Stripe et ne dépend donc d'aucune clé de compte. N'importe quelle
    // instance du client convient, ici celle de l'agence par défaut.
    event = agenceParDefaut().stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
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
      // Filet : rattrape le paiement déjà capturé quand la caisse l'interroge,
      // où l'appel de capture n'a pas lieu. Un paiement déjà déclaré par la
      // capture est simplement refusé en doublon par le CRM (« déjà »).
      // Paiement de caisse (devis dans les métadonnées) → déclaration de
      // caisse, montant = `amount_received` ; sinon → chemin historique.
      declarerDepuisPaiement(pi, null);
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

module.exports = router;
