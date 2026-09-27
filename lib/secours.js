// lib/secours.js
//
// ======================= Qui a droit au montant saisi =======================
//
// `POST /api/paiement` est le SEUL chemin où un montant venu du navigateur
// atteint Stripe. Il existe pour une raison, et une seule : encaisser quand
// le CRM ne peut pas décider du prix (non configuré, muet, agence par défaut
// sans slug ou inconnue du CRM — ARCHITECTURE.md § 7).
//
// Cacher l'écran ne suffit pas : une requête tapée à la main (console, curl)
// passerait sinon le montant libre réservé aux administrateurs, sans motif ni
// auteur. C'est donc le SERVEUR qui refuse, avec la même décision que celle
// qui choisit l'écran (`sessionCaisse`) : si le CRM répond, le montant libre
// passe par le catalogue (onglet « Montant libre », admin, motif obligatoire).
//
// L'agence par défaut sans CRM configuré ou sans slug ne fait AUCUN appel
// réseau ici : `sessionCaisse` tranche sans sonder.

const { sessionCaisse } = require('./session');
const { lireJetonCaisse, jetonDeLaRequete } = require('./jeton');
const { slugEffectif } = require('./agences');

const MESSAGE_REFUS =
  "Le CRM répond : l'encaissement de secours est fermé. Rechargez la caisse et encaissez depuis le catalogue " +
  '(montant libre : un administrateur, avec un motif).';

/**
 * Le montant saisi est-il permis pour cette requête ?
 *
 * @returns {Promise<{ ok: true, auteurId: string } | { ok: false, status: number, corps: object }>}
 *   `auteurId` : le compte du jeton de caisse s'il est encore valable (vide
 *   sinon) — porté dans les métadonnées pour tracer qui a encaissé.
 */
async function autoriserSecours(req) {
  const session = await sessionCaisse(req);
  if (session.mode !== 'secours') {
    return { ok: false, status: 403, corps: { error: MESSAGE_REFUS, code: 'secours_indisponible' } };
  }
  const lecture = lireJetonCaisse(jetonDeLaRequete(req), slugEffectif(req));
  return { ok: true, auteurId: lecture.ok ? lecture.payload.u : '' };
}

module.exports = { autoriserSecours };
