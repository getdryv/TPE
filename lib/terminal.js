// lib/terminal.js
//
// ======================= Encaissement, piloté par le serveur =======================
//
// Le navigateur ne parle plus jamais au lecteur. Il demande à notre serveur, qui
// demande à Stripe, qui pousse l'ordre au lecteur par la liaison nuage que
// celui-ci maintient en permanence.
//
// ─── Pourquoi avoir abandonné le SDK navigateur ─────────────────────────────
// Le SDK JavaScript exige une connexion directe entre le navigateur et le
// lecteur, sur le réseau local. Éprouvé le 2026-07-28 sur le WisePOS E de
// Getdryv : nom résolu correctement, appareil présent sur le réseau (réponse
// ARP), mais aucune connexion acceptée — et la même chose depuis un terminal,
// donc ni le navigateur ni le système n'étaient en cause. Le pilotage par le
// serveur a fonctionné du premier coup sur ce même lecteur.
//
// Ce qu'on y gagne, au-delà du déblocage : plus aucune dépendance au réseau
// local, donc la caisse fonctionne depuis n'importe où — un autre bureau, un
// téléphone en 4G — tant que le lecteur, lui, a Internet.
//
// Ce qu'on y perd : le navigateur ne connaît plus l'état du lecteur en direct,
// il faut le demander régulièrement. D'où `etatDuPaiement`.
//
// Ce module est partagé par le mode secours (montant saisi) et le mode
// catalogue (montant du devis) : seule l'ORIGINE du montant diffère, jamais la
// façon de piloter le lecteur.

const crypto = require('crypto');

/** Lecteurs de l'agence, pour que la caisse sache lequel solliciter. */
async function listerLecteurs(agence) {
  // Sans emplacement on ne filtre pas : mieux vaut proposer trop de lecteurs
  // que zéro. Avec, on ne voit que ceux de cette agence — indispensable dès
  // que deux agences partagent un compte Stripe.
  const params = { limit: 20 };
  if (agence.terminalLocation) params.location = agence.terminalLocation;

  const liste = await agence.stripe.terminal.readers.list(params);
  return (liste.data || []).map((r) => ({
    id: r.id,
    label: r.label || r.serial_number || r.id,
    enLigne: r.status === 'online',
  }));
}

/**
 * Lance un encaissement : crée le paiement et l'affiche sur le lecteur.
 *
 * Montant en CENTIMES. Capture manuelle : la carte est autorisée à l'écran du
 * lecteur, mais rien n'est prélevé tant que la capture n'a pas été demandée.
 * C'est ce qui permet d'annuler sans frais si quelque chose cloche entre
 * l'autorisation et la fin.
 *
 * @param {object} agence
 * @param {object} p { montant, lecteur, nomComplet, email, metadata, idempotencyKey }
 */
async function lancerEncaissement(agence, { montant, lecteur, nomComplet, email, metadata, idempotencyKey }) {
  // Deux clics rapides sur « Envoyer au TPE » ne doivent pas créer deux
  // paiements : la même clé donne le même PaymentIntent.
  const cle = idempotencyKey || crypto.randomUUID();

  const customer = await agence.stripe.customers.create({
    name: nomComplet || undefined,
    email: email || undefined,
  });

  const pi = await agence.stripe.paymentIntents.create(
    {
      amount: montant,
      currency: 'eur',
      payment_method_types: ['card_present'],
      capture_method: 'manual',
      customer: customer.id,
      receipt_email: email || undefined,
      metadata,
    },
    { idempotencyKey: cle }
  );

  await agence.stripe.terminal.readers.processPaymentIntent(lecteur, {
    payment_intent: pi.id,
  });

  return pi;
}

/**
 * Où en est l'encaissement ?
 *
 * Renvoie un état unique plutôt que l'état brut de Stripe, pour que la page
 * n'ait pas à connaître son vocabulaire :
 *   attente   — le lecteur affiche le montant, la carte n'est pas passée
 *   autorise  — la carte a été acceptée, il reste à capturer
 *   echec     — refus, annulation, ou erreur du lecteur
 *   capture   — déjà encaissé
 */
async function etatDuPaiement(agence, piId, lecteur) {
  const intent = await agence.stripe.paymentIntents.retrieve(piId);

  if (intent.status === 'requires_capture') return { etat: 'autorise' };
  if (intent.status === 'succeeded') return { etat: 'capture' };
  if (intent.status === 'canceled') return { etat: 'echec', message: 'Paiement annulé.' };

  // Toujours en attente côté paiement : le lecteur peut néanmoins avoir
  // échoué (carte refusée, annulation sur l'écran). Son action porte alors le
  // motif, bien plus parlant que « en attente ».
  if (lecteur) {
    const r = await agence.stripe.terminal.readers.retrieve(lecteur);
    if (r.action && r.action.status === 'failed') {
      return { etat: 'echec', message: r.action.failure_message || 'Le lecteur a refusé le paiement.' };
    }
  }

  return { etat: 'attente' };
}

/** Capture : c'est ici, et seulement ici, que l'argent part. */
function capturer(agence, piId) {
  return agence.stripe.paymentIntents.capture(piId);
}

/**
 * Capture si besoin (mode catalogue) : la carte a pu être capturée entre-temps
 * (état « capture » vu par la page, ou double clic). Dans ce cas il n'y a rien
 * à capturer, mais le paiement doit quand même être déclaré.
 *
 * Prend le paiement DÉJÀ RELU : l'appelant vérifie son devis avant de
 * prendre l'argent.
 *
 * @returns {{ ok: true, pi } | { ok: false, message }}
 */
async function capturerSiBesoin(agence, pi) {
  if (pi.status === 'succeeded') return { ok: true, pi };
  if (pi.status !== 'requires_capture') {
    return { ok: false, message: "La carte n'a pas été acceptée : rien n'a été débité." };
  }
  return { ok: true, pi: await capturer(agence, pi.id) };
}

/**
 * Annule l'encaissement en cours : efface l'écran du lecteur et le paiement.
 *
 * Les deux annulations sont indépendantes et chacune peut échouer sans que
 * l'autre en pâtisse — un lecteur qui n'affiche déjà plus rien ne doit pas
 * empêcher d'annuler le paiement, sinon on laisserait une autorisation ouverte.
 */
async function annuler(agence, { paymentIntentId, lecteur }) {
  if (lecteur) {
    try {
      await agence.stripe.terminal.readers.cancelAction(lecteur);
    } catch (err) {
      console.warn('annulation de l\'affichage :', err.message);
    }
  }
  if (paymentIntentId) {
    try {
      await agence.stripe.paymentIntents.cancel(paymentIntentId);
    } catch (err) {
      console.warn('annulation du paiement :', err.message);
    }
  }
}

module.exports = { listerLecteurs, lancerEncaissement, etatDuPaiement, capturer, capturerSiBesoin, annuler };
