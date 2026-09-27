// lib/signature.js
//
// ======================= Signature des jetons de caisse =======================
//
// Contrat : docs/caisse-tpe/ARCHITECTURE.md § 2 (dépôt du CRM).
//
//   corps     = base64url( UTF-8( JSON.stringify(payload) ) )
//   signature = base64url( HMAC-SHA256( secret, contexte + "." + corps ) )
//   jeton     = corps + "." + signature
//
// Le CONTEXTE cloisonne les jetons signés du même secret (`INTERNAL_API_SECRET`) :
// sans lui, un jeton de lien de paiement prépa examen pourrait passer pour un
// devis, ou un devis pour une identification.
//
// ⚠️ Deux implémentations doivent concorder : celle-ci et
// `features/caisse/domain/signature.ts` dans le CRM. Les vecteurs du § 2 sont
// le contrat ; chaque côté a un test qui les rejoue.

const crypto = require('crypto');

const CONTEXTE_JETON = 'caisse-jeton.v1';
const CONTEXTE_DEVIS = 'caisse-devis.v1';

const base64url = (valeur) =>
  Buffer.from(valeur).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const depuisBase64url = (valeur) => Buffer.from(valeur.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function calculerSignature(contexte, corps, secret) {
  return base64url(crypto.createHmac('sha256', secret).update(`${contexte}.${corps}`).digest());
}

/**
 * Signe un payload sous un contexte. L'ordre des clés du payload est celui du
 * jeton. La caisse ne signe rien en production (c'est le CRM qui émet) : cette
 * fonction sert aux tests, et à garder les deux implémentations symétriques.
 */
function signer(contexte, payload, secret) {
  // Sans secret, on ne signe pas « faiblement » : on refuse.
  if (!secret) throw new Error('Secret de signature absent.');
  const corps = base64url(JSON.stringify(payload));
  return `${corps}.${calculerSignature(contexte, corps, secret)}`;
}

/**
 * Relit un jeton : le payload si la signature est bonne SOUS CE CONTEXTE, sinon
 * `null`. Ne regarde ni l'expiration ni la forme : c'est l'affaire de
 * l'appelant. Le jeton se relit, il ne se re-sérialise jamais pour vérifier.
 */
function lire(contexte, jeton, secret) {
  if (!secret) return null;
  const morceaux = String(jeton ?? '').split('.');
  if (morceaux.length !== 2) return null;
  const [corps, sig] = morceaux;
  if (!corps || !sig) return null;

  // Comparaison à temps constant : `===` laisserait deviner la signature.
  const recue = Buffer.from(sig);
  const attendue = Buffer.from(calculerSignature(contexte, corps, secret));
  if (recue.length !== attendue.length || !crypto.timingSafeEqual(recue, attendue)) return null;

  try {
    return JSON.parse(depuisBase64url(corps).toString('utf8'));
  } catch {
    return null;
  }
}

/** Secondes depuis l'époque. */
const maintenantSecondes = () => Math.floor(Date.now() / 1000);

/** Le secret partagé avec le CRM (vide si non configuré). */
const secretInterne = () => (process.env.INTERNAL_API_SECRET || '').trim();

module.exports = { CONTEXTE_JETON, CONTEXTE_DEVIS, signer, lire, maintenantSecondes, secretInterne };
