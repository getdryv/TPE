// lib/devis.js
//
// ======================= Le devis signé =======================
//
// Contrat : ARCHITECTURE.md § 4.1 et § 4.2. Le CRM DÉCIDE le prix, la caisse
// EXÉCUTE : elle débite EXACTEMENT `cb`, relu dans un devis dont elle vérifie
// la signature (contexte `caisse-devis.v1`). Aucun montant venu du navigateur
// n'atteint Stripe hors du mode secours.
//
// Le devis voyage ensuite DANS le paiement Stripe (métadonnées) : c'est le seul
// état que partagent les deux chemins de déclaration, la capture et le webhook.
// Une valeur de métadonnée Stripe tient en 500 caractères ; le jeton (536 dans
// l'exemple du contrat) est donc découpé en morceaux de 450 au plus.
//
// Invariants (les mêmes que `devisCoherent` du CRM) : tot = cb + esp ;
// carte ⇒ esp = 0 et cb ≥ 50 ; espèces ⇒ cb = 0 ; mixte ⇒ esp > 0 et cb ≥ 50.

const { CONTEXTE_DEVIS, lire, maintenantSecondes, secretInterne } = require('./signature');

const CARTE_MIN_CENTS = 50;
const TAILLE_MORCEAU = 450;
const MORCEAUX_MAX = 4;

const entier = (n) => typeof n === 'number' && Number.isInteger(n);
const texte = (v) => typeof v === 'string' && v.length > 0;

function produitValide(p) {
  if (!p || typeof p !== 'object') return false;
  if (p.t === 'forfait') return texte(p.f) && p.sc === undefined;
  // Heures supp : `sc` = accompagnement à l'examen ajouté par le CRM (case cochée).
  if (p.t === 'heures_supp') return texte(p.f) && (p.sc === undefined || (entier(p.sc) && p.sc > 0));
  if (p.t === 'prepa') {
    return (
      entier(p.h) && p.h >= 0 && typeof p.acc === 'boolean' && typeof p.rf === 'boolean' &&
      (p.sc === undefined || (entier(p.sc) && p.sc >= 0))
    );
  }
  // Montant libre sans motif depuis le 27/09/2026 : `d` = note facultative ; `m` ancien, toléré.
  if (p.t === 'libre') return (p.m === undefined || typeof p.m === 'string') && (p.d === undefined || typeof p.d === 'string');
  return false;
}

/** Le devis a-t-il la forme et les invariants du contrat ? */
function devisCoherent(d) {
  if (!d || typeof d !== 'object' || d.v !== 1) return false;
  if (![d.id, d.a, d.s, d.u, d.l].every(texte)) return false;
  if (!produitValide(d.p)) return false;
  if (![d.tot, d.cb, d.esp, d.iat, d.exp].every(entier)) return false;
  if (d.tot <= 0 || d.cb < 0 || d.esp < 0 || d.tot !== d.cb + d.esp) return false;
  if (d.p.t === 'heures_supp' && d.p.sc !== undefined && d.p.sc >= d.tot) return false;
  if (d.mo === 'carte') return d.esp === 0 && d.cb >= CARTE_MIN_CENTS;
  if (d.mo === 'especes') return d.cb === 0;
  if (d.mo === 'mixte') return d.esp > 0 && d.cb >= CARTE_MIN_CENTS;
  return false;
}

/**
 * Relit un devis signé.
 *
 * `exigerExpiration` (création du paiement, espèces) : un devis périmé est
 * refusé avec le motif `expire`, que la page traduit en « redemander un devis
 * pour le même panier ». Sans (capture, webhook), un devis se relit même tard :
 * l'argent a pu être pris juste avant l'échéance.
 *
 * @returns {{ ok: true, devis } | { ok: false, motif: 'invalide' | 'expire' | 'autre_agence' }}
 */
function lireDevis(jeton, { slug, exigerExpiration = false, maintenant = maintenantSecondes(), secret = secretInterne() } = {}) {
  const devis = lire(CONTEXTE_DEVIS, String(jeton ?? ''), secret);
  if (!devisCoherent(devis)) return { ok: false, motif: 'invalide' };
  if (exigerExpiration && devis.exp <= maintenant) return { ok: false, motif: 'expire' };
  if (slug !== undefined && devis.a !== String(slug ?? '').trim().toLowerCase()) {
    return { ok: false, motif: 'autre_agence' };
  }
  return { ok: true, devis };
}

/**
 * Découpe le jeton de devis pour les métadonnées Stripe :
 * `{ devis_0, …, devis_{n-1}, devis_n: "<n>" }`, chaque morceau ≤ 450
 * caractères. `null` si le jeton ne tient pas en quatre morceaux (le CRM n'en
 * émet jamais d'aussi long : le libellé est borné à 60 caractères).
 */
function decouperPourMetadonnees(jeton) {
  const brut = String(jeton ?? '');
  if (!brut) return null;
  const n = Math.ceil(brut.length / TAILLE_MORCEAU);
  if (n > MORCEAUX_MAX) return null;
  const meta = {};
  for (let i = 0; i < n; i += 1) {
    meta[`devis_${i}`] = brut.slice(i * TAILLE_MORCEAU, (i + 1) * TAILLE_MORCEAU);
  }
  meta.devis_n = String(n);
  return meta;
}

/** Le paiement porte-t-il un devis de caisse ? (sinon : chemin historique) */
function porteUnDevis(meta) {
  return Boolean(meta && typeof meta === 'object' && meta.devis_n);
}

/** Recompose le jeton depuis les métadonnées d'un paiement, ou `null`. */
function recomposerDepuisMetadonnees(meta) {
  if (!porteUnDevis(meta)) return null;
  const n = Number(meta.devis_n);
  if (!Number.isInteger(n) || n < 1 || n > MORCEAUX_MAX) return null;
  let jeton = '';
  for (let i = 0; i < n; i += 1) {
    const morceau = meta[`devis_${i}`];
    if (typeof morceau !== 'string' || !morceau) return null;
    jeton += morceau;
  }
  return jeton;
}

module.exports = {
  CARTE_MIN_CENTS,
  TAILLE_MORCEAU,
  devisCoherent,
  lireDevis,
  decouperPourMetadonnees,
  recomposerDepuisMetadonnees,
  porteUnDevis,
};
