// ─── Le comptage des espèces, PUR ────────────────────────────────────────────
//
// La secrétaire tape le nombre de chaque billet et de chaque pièce reçus. Ce
// module dit où en est le compte par rapport à la part en espèces : vide, il
// manque, juste, ou trop — et, si l'élève a trop donné, QUOI lui rendre parmi
// ce qu'il a donné (on ne rend jamais la monnaie de la caisse : « faites
// l'appoint »). Quand rien de ce qu'il a donné ne tombe juste, on rend la plus
// petite somme possible et on lui demande l'appoint de la différence.
//
// Les montants sont en centimes entiers ; le comptage est un objet
// `{ "<coupure en centimes>": nombre }` (la forme enregistrée dans le CRM).
// Aucun accès au DOM ni au réseau : ce module se teste sous node.

/** Billets de 200 € à 5 €, pièces de 2 € à 0,10 € (centimes), de la plus grande à la plus petite. */
export const COUPURES = [20000, 10000, 5000, 2000, 1000, 500, 200, 100, 50, 20, 10];
export const BILLETS = COUPURES.filter((c) => c >= 500);
export const PIECES = COUPURES.filter((c) => c < 500);
export const NOMBRE_MAX = 999;
// Au-delà de 5 000 € comptés, pas de calcul du rendu (mémoire bornée) : la phrase reste générique.
const CALCUL_RENDU_MAX = 500000;

/** « 200 € », « 2 € », « 50 c ». */
export function libelleCoupure(c) {
  return c >= 100 ? `${c / 100}\u00a0€` : `${c}\u00a0c`;
}

/** « 1 billet de 10 € », « 2 pièces de 0,50 € ». */
export function designation(c, nombre) {
  const nature = c >= 500 ? 'billet' : 'pièce';
  // Espaces insécables : « 1 pièce de 1 € » ne se coupe jamais avant le « € ».
  const valeur = c >= 100 ? `${c / 100}\u00a0€` : `0,${String(c).padStart(2, '0')}\u00a0€`;
  return `${nombre}\u00a0${nature}${nombre > 1 ? 's' : ''} de ${valeur}`;
}

/** Le nombre tapé dans un champ : entier de 0 à 999, ou null si illisible. Vide = 0. */
export function lireNombre(texte) {
  const t = String(texte ?? '').trim();
  if (t === '') return 0;
  if (!/^\d{1,3}$/.test(t)) return null;
  return Number(t);
}

/** Un NOUVEAU comptage avec `nombre` pour la coupure `c` (0 la retire). */
export function avecNombre(comptage, c, nombre) {
  if (!COUPURES.includes(c) || !Number.isInteger(nombre) || nombre < 0 || nombre > NOMBRE_MAX) return comptage;
  const cle = String(c);
  if ((comptage[cle] || 0) === nombre) return comptage;
  const suivant = { ...comptage };
  if (nombre === 0) delete suivant[cle];
  else suivant[cle] = nombre;
  return suivant;
}

export const plusUn = (comptage, c) => avecNombre(comptage, c, Math.min(NOMBRE_MAX, (comptage[String(c)] || 0) + 1));

export function totalCompte(comptage) {
  return COUPURES.reduce((s, c) => s + c * (comptage[String(c)] || 0), 0);
}

/**
 * La plus petite somme ≥ `exces` que l'on peut former avec ce que l'élève a
 * donné, en le moins de pièces possible : `{ somme, pieces: { coupure: n } }`,
 * ou null. Sac à dos borné en dizaines de centimes (aucune pièce plus petite).
 */
export function aRendre(comptage, exces) {
  if (!(exces > 0)) return null;
  const total = totalCompte(comptage);
  if (total < exces || total > CALCUL_RENDU_MAX) return null;
  const unites = total / 10;
  const INF = Number.MAX_SAFE_INTEGER;
  const min = new Array(unites + 1).fill(INF);
  min[0] = 0;
  // Découpage binaire de chaque coupure : 0/1 sur des paquets de 1, 2, 4… pièces.
  const paquets = [];
  for (const c of COUPURES) {
    let reste = comptage[String(c)] || 0;
    for (let k = 1; reste > 0; k *= 2) {
      const q = Math.min(k, reste);
      paquets.push({ c, q, v: (c / 10) * q });
      reste -= q;
    }
  }
  const pris = paquets.map(() => new Uint8Array(unites + 1));
  paquets.forEach((p, i) => {
    for (let s = unites; s >= p.v; s -= 1) {
      if (min[s - p.v] !== INF && min[s - p.v] + p.q < min[s]) {
        min[s] = min[s - p.v] + p.q;
        pris[i][s] = 1;
      }
    }
  });
  let cible = -1;
  for (let s = exces / 10; s <= unites; s += 1) {
    if (min[s] !== INF) { cible = s; break; }
  }
  if (cible < 0) return null;
  // Reconstruction : on remonte les paquets du dernier au premier.
  const pieces = {};
  let s = cible;
  for (let i = paquets.length - 1; i >= 0 && s > 0; i -= 1) {
    if (pris[i][s]) {
      const p = paquets[i];
      pieces[String(p.c)] = (pieces[String(p.c)] || 0) + p.q;
      s -= p.v;
    }
  }
  return { somme: cible * 10, pieces };
}

/**
 * Où en est le compte par rapport à `cible` (la part en espèces) :
 *   { compte, statut: 'vide' | 'manque' | 'juste' | 'arrondi' | 'trop', manque, trop,
 *     rendre: { pieces, appoint } | null, arrondi? }
 * `tolerance` (centimes, réglage d'agence) : un surplus jusque-là est un
 * ARRONDI laissé par l'élève (`arrondi`), encaissable sans rien rendre.
 * `appoint` > 0 : rien ne tombe juste ; rendre `pieces` et demander l'appoint.
 * Sans cible (paiement mixte : c'est le comptage qui FIXE la part espèces),
 * le statut est 'vide' ou 'juste'.
 */
export function analyser(comptage, cible, tolerance = 0) {
  const compte = totalCompte(comptage);
  if (compte === 0) return { compte, statut: 'vide', manque: cible || 0, trop: 0, rendre: null };
  if (!Number.isInteger(cible) || cible <= 0) return { compte, statut: 'juste', manque: 0, trop: 0, rendre: null };
  if (compte < cible) return { compte, statut: 'manque', manque: cible - compte, trop: 0, rendre: null };
  if (compte === cible) return { compte, statut: 'juste', manque: 0, trop: 0, rendre: null };
  const trop = compte - cible;
  // L'élève a arrondi (60 € pour 59,90 €) dans la tolérance de l'agence : on ne rend pas la monnaie.
  if (Number.isInteger(tolerance) && tolerance > 0 && trop <= tolerance) {
    return { compte, statut: 'arrondi', manque: 0, trop: 0, arrondi: trop, rendre: null };
  }
  const r = aRendre(comptage, trop);
  return { compte, statut: 'trop', manque: 0, trop, rendre: r ? { pieces: r.pieces, appoint: r.somme - trop } : null };
}

/** Le comptage après avoir rendu `pieces` à l'élève. */
export function apresRendu(comptage, pieces) {
  let suivant = comptage;
  for (const [cle, n] of Object.entries(pieces || {})) {
    const c = Number(cle);
    suivant = avecNombre(suivant, c, Math.max(0, (suivant[cle] || 0) - n));
  }
  return suivant;
}

/** Ce qui part au CRM : les coupures non nulles, ou null si rien n'est compté. */
export function billetage(comptage) {
  const b = {};
  for (const c of COUPURES) if ((comptage[String(c)] || 0) > 0) b[String(c)] = comptage[String(c)];
  return Object.keys(b).length ? b : null;
}

/** 30000 → « 300 », 30050 → « 300,50 » : la part espèces d'un paiement mixte, pour le devis. */
export function enSaisie(cents) {
  if (!Number.isInteger(cents) || cents <= 0) return '';
  const e = Math.floor(cents / 100);
  const c = cents % 100;
  return c ? `${e},${String(c).padStart(2, '0')}` : String(e);
}
