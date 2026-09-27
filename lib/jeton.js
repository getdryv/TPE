// lib/jeton.js
//
// ======================= Le jeton de caisse : qui encaisse =======================
//
// Contrat : ARCHITECTURE.md § 3. Le CRM émet ce jeton pour l'utilisateur
// connecté quand il affiche `/paiements`, et le passe à la caisse dans le
// FRAGMENT de l'adresse du cadre. La page le garde en mémoire et nous l'envoie
// dans l'en-tête `x-caisse-jeton`.
//
// Ici, on ne fait qu'un REFUS RAPIDE, sans appeler le CRM : signature,
// expiration, agence. Le CRM reste l'autorité : il revérifie à chaque appel et
// relit le rôle et le statut du compte (un compte désactivé perd ses droits
// sans attendre l'expiration). Le jeton ne porte ni nom ni rôle.
//
// Un jeton ne se journalise JAMAIS en entier : c'est une identification valable
// douze heures.

const { CONTEXTE_JETON, lire, maintenantSecondes, secretInterne } = require('./signature');

function estPayload(p) {
  return (
    !!p &&
    typeof p === 'object' &&
    p.v === 1 &&
    typeof p.u === 'string' &&
    p.u.length > 0 &&
    typeof p.a === 'string' &&
    p.a.length > 0 &&
    Number.isFinite(p.iat) &&
    Number.isFinite(p.exp)
  );
}

/**
 * Relit le jeton de caisse.
 *
 * @returns {{ ok: true, payload } | { ok: false, motif: 'absent' | 'invalide' | 'expire' | 'autre_agence' }}
 */
function lireJetonCaisse(jeton, slug, { maintenant = maintenantSecondes(), secret = secretInterne() } = {}) {
  const brut = String(jeton ?? '').trim();
  if (!brut) return { ok: false, motif: 'absent' };
  const payload = lire(CONTEXTE_JETON, brut, secret);
  if (!estPayload(payload)) return { ok: false, motif: 'invalide' };
  if (payload.exp <= maintenant) return { ok: false, motif: 'expire' };
  if (payload.a !== String(slug ?? '').trim().toLowerCase()) return { ok: false, motif: 'autre_agence' };
  return { ok: true, payload };
}

const MESSAGES = {
  absent: 'Ouvrez la caisse depuis le CRM pour vous identifier.',
  invalide: 'Identification de la caisse invalide : rouvrez la caisse depuis le CRM.',
  expire: 'Identification de la caisse expirée : rouvrez la caisse depuis le CRM.',
  autre_agence: 'Cette identification vaut pour une autre agence : rouvrez la caisse depuis le CRM.',
};

/** Le jeton porté par une requête du navigateur. */
const jetonDeLaRequete = (req) => (req.headers['x-caisse-jeton'] || '').toString().trim();

/**
 * Exige un jeton valide pour l'agence de la requête, ou répond 401.
 *
 * `tolererExpiration` : pour la CAPTURE seulement. La carte est déjà autorisée
 * sur un devis vérifié à la création du paiement ; refuser de capturer parce
 * que la journée de comptoir vient de finir laisserait une autorisation
 * ouverte et un paiement perdu. La signature et l'agence restent exigées.
 */
function exigerJeton(req, res, slug, { tolererExpiration = false } = {}) {
  const jeton = jetonDeLaRequete(req);
  let lecture = lireJetonCaisse(jeton, slug);
  if (!lecture.ok && lecture.motif === 'expire' && tolererExpiration) {
    lecture = lireJetonCaisse(jeton, slug, { maintenant: 0 });
  }
  if (lecture.ok) return { jeton, payload: lecture.payload };
  res.status(401).json({ error: MESSAGES[lecture.motif], code: `jeton_${lecture.motif}` });
  return null;
}

module.exports = { lireJetonCaisse, jetonDeLaRequete, exigerJeton, MESSAGES_JETON: MESSAGES };
