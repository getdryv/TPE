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
// Invariants (les mêmes que `devisCoherent` du CRM, contrat Encaisser § 3.1) :
// tot = cb + esp + (chq ?? 0) ; carte ⇒ esp = 0 et cb ≥ 50 ; espèces ⇒ cb = 0 ;
// mixte ⇒ esp > 0 et cb ≥ 50 ; chèques ⇒ cb = esp = 0, chq = tot, 1 à 3
// chèques ; espèces + chèques ⇒ cb = 0, esp > 0, chq = tot − esp, 1 ou 2
// chèques. `chq` et `ech` n'existent QUE pour les deux moyens chèques.
//
// La caisse ne recalcule aucune date ni aucun montant d'échéance : elle vérifie
// seulement que l'échéancier signé se tient (somme, ordre, avance, minimum).

const { CONTEXTE_DEVIS, lire, maintenantSecondes, secretInterne } = require('./signature');

const CARTE_MIN_CENTS = 50;
const CHEQUE_MIN_CENTS = 100;
const CHEQUES_MAX = { cheques: 3, especes_cheques: 2 };
const MOYENS_HISTORIQUES = ['carte', 'especes', 'mixte'];
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

const DATE_ISO = /^(\d{4})-(\d{2})-(\d{2})$/;

/** « 2026-10-19 » : une vraie date du calendrier (pas de 31 novembre). */
function dateIso(v) {
  const m = typeof v === 'string' ? DATE_ISO.exec(v) : null;
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
}

/**
 * L'échéancier signé `ech` : [[dueOn, montant, prevuLe], …], dates de remise
 * strictement croissantes, jamais après la date prévue (avance, jamais recul),
 * chaque chèque d'au moins 1 € et la somme égale à `chq`.
 */
function echeancierCoherent(ech, chq, max) {
  if (!Array.isArray(ech) || ech.length < 1 || ech.length > max) return false;
  let somme = 0;
  let precedente = '';
  for (const e of ech) {
    if (!Array.isArray(e) || e.length !== 3) return false;
    const [dueOn, montant, prevuLe] = e;
    if (!dateIso(dueOn) || !dateIso(prevuLe) || !entier(montant) || montant < CHEQUE_MIN_CENTS) return false;
    if (dueOn > prevuLe || dueOn <= precedente) return false;
    precedente = dueOn;
    somme += montant;
  }
  return somme === chq;
}

/** Les deux moyens chèques : répartition et échéancier. */
function partChequesCoherente(d) {
  if (!entier(d.chq) || d.cb !== 0) return false;
  if (d.mo === 'cheques' && (d.esp !== 0 || d.chq !== d.tot)) return false;
  if (d.mo === 'especes_cheques' && (d.esp <= 0 || d.chq !== d.tot - d.esp)) return false;
  return echeancierCoherent(d.ech, d.chq, CHEQUES_MAX[d.mo]);
}

/** Le devis a-t-il la forme et les invariants du contrat ? */
function devisCoherent(d) {
  if (!d || typeof d !== 'object' || d.v !== 1) return false;
  if (![d.id, d.a, d.s, d.u, d.l].every(texte)) return false;
  if (!produitValide(d.p)) return false;
  if (![d.tot, d.cb, d.esp, d.iat, d.exp].every(entier)) return false;
  if (d.tot <= 0 || d.cb < 0 || d.esp < 0) return false;
  if (d.p.t === 'heures_supp' && d.p.sc !== undefined && d.p.sc >= d.tot) return false;
  if (MOYENS_HISTORIQUES.includes(d.mo)) {
    // Les trois moyens d'avant les chèques : ni `chq` ni `ech`, et rien ne change.
    if (d.chq !== undefined || d.ech !== undefined || d.tot !== d.cb + d.esp) return false;
    if (d.mo === 'carte') return d.esp === 0 && d.cb >= CARTE_MIN_CENTS;
    if (d.mo === 'especes') return d.cb === 0;
    return d.esp > 0 && d.cb >= CARTE_MIN_CENTS;
  }
  if (d.mo === 'cheques' || d.mo === 'especes_cheques') {
    return d.tot === d.cb + d.esp + d.chq && partChequesCoherente(d);
  }
  return false;
}

/** Le devis se règle-t-il sans le lecteur (espèces, chèques, espèces + chèques) ? */
const sansCarte = (d) => Boolean(d) && d.cb === 0 && ['especes', 'cheques', 'especes_cheques'].includes(d.mo);

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
  sansCarte,
  TAILLE_MORCEAU,
  devisCoherent,
  lireDevis,
  decouperPourMetadonnees,
  recomposerDepuisMetadonnees,
  porteUnDevis,
};
