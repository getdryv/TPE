// lib/billetage.js
//
// ======================= Le détail des coupures (billetage) =======================
//
// La page fait compter les espèces coupure par coupure ; ce serveur ne croit
// pas la page sur parole : il vérifie que la somme tombe EXACTEMENT sur la
// part espèces du devis SIGNÉ (`devis.esp`) avant de la transmettre au CRM,
// qui revérifie. Forme : `{ "<coupure en centimes>": nombre }`.
//
// Pour un paiement espèces + carte, le détail voyage dans les métadonnées du
// paiement Stripe (une valeur ≤ 500 caractères : « 5000x4,2000x5 »), comme le
// devis : la capture ET le webhook le relisent sans rien demander à la page.

const COUPURES = [20000, 10000, 5000, 2000, 1000, 500, 200, 100, 50, 20, 10];
const NOMBRE_MAX = 999;

/**
 * Le billetage propre (coupures connues, nombres entiers 1..999), ou `null`
 * s'il est absent, vide ou mal formé. Ne lève jamais.
 */
function lireBilletage(brut) {
  if (!brut || typeof brut !== 'object' || Array.isArray(brut)) return null;
  const propre = {};
  for (const [cle, n] of Object.entries(brut)) {
    if (!COUPURES.includes(Number(cle)) || String(Number(cle)) !== cle) return null;
    if (!Number.isInteger(n) || n < 0 || n > NOMBRE_MAX) return null;
    if (n > 0) propre[cle] = n;
  }
  return Object.keys(propre).length ? propre : null;
}

const total = (b) => Object.entries(b || {}).reduce((s, [c, n]) => s + Number(c) * n, 0);

/**
 * Vérifie le billetage envoyé par la page contre la part espèces signée.
 * `{ ok: true, billetage: objet | null }` (absent = accepté, page plus
 * ancienne) ou `{ ok: false, message }`.
 */
function billetageDuDevis(brut, especesCents) {
  if (brut === undefined || brut === null) return { ok: true, billetage: null };
  const b = lireBilletage(brut);
  if (!b) return { ok: false, message: 'Détail des espèces illisible : recomptez.' };
  if (total(b) !== especesCents) return { ok: false, message: 'Le détail des espèces ne correspond pas au montant : recomptez.' };
  return { ok: true, billetage: b };
}

/** `{ "5000": 4, "2000": 5 }` → « 5000x4,2000x5 » (métadonnée Stripe). */
function versMetadonnee(b) {
  return b ? COUPURES.filter((c) => b[String(c)]).map((c) => `${c}x${b[String(c)]}`).join(',') : '';
}

/** « 5000x4,2000x5 » → `{ "5000": 4, "2000": 5 }`, ou `null`. */
function depuisMetadonnee(texte) {
  if (typeof texte !== 'string' || !texte) return null;
  const brut = {};
  for (const morceau of texte.split(',')) {
    const m = /^(\d+)x(\d+)$/.exec(morceau);
    if (!m) return null;
    brut[m[1]] = Number(m[2]);
  }
  return lireBilletage(brut);
}

module.exports = { COUPURES, lireBilletage, billetageDuDevis, versMetadonnee, depuisMetadonnee, total };
