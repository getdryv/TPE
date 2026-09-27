// ─── Mise en forme des montants, PURE ────────────────────────────────────────
//
// Aucun accès au DOM ni au réseau : ce module se teste sous node. Les montants
// circulent TOUJOURS en centimes entiers ; l'euro décimal n'existe qu'à
// l'affichage et à la saisie.
//
// On n'utilise pas `Intl.NumberFormat` : selon le moteur, il sépare les milliers
// par une espace fine insécable ou une espace insécable, et l'affichage d'un
// même montant différerait d'un poste à l'autre. Ici, la sortie est fixe.

/** Espace insécable : « 1 049,00 € » ne se coupe jamais en fin de ligne. */
const ESPACE = ' ';

function milliers(entier) {
  return String(entier).replace(/\B(?=(\d{3})+(?!\d))/g, ESPACE);
}

/**
 * 104900 → « 1 049,00 € » ; -5000 → « −50,00 € » (vrai signe moins).
 * Une valeur non entière ou absente donne une chaîne vide plutôt qu'un
 * « NaN € » qui ressemblerait à un prix.
 */
export function euros(cents) {
  if (!Number.isInteger(cents)) return '';
  const signe = cents < 0 ? '−' : '';
  const abs = Math.abs(cents);
  const partieEntiere = Math.floor(abs / 100);
  const centimes = String(abs % 100).padStart(2, '0');
  return `${signe}${milliers(partieEntiere)},${centimes}${ESPACE}€`;
}

/**
 * Forme courte des pastilles : 5000 → « 50 € », 1250 → « 12,50 € ».
 * Réservée aux mentions (« Promo en cours · −50 € ») ; les prix gardent
 * toujours leurs centimes.
 */
export function eurosCourts(cents) {
  if (!Number.isInteger(cents)) return '';
  if (cents % 100 !== 0) return euros(cents);
  const signe = cents < 0 ? '−' : '';
  return `${signe}${milliers(Math.abs(cents) / 100)}${ESPACE}€`;
}

/**
 * Saisie d'un montant → centimes entiers, ou `null` si la saisie n'est pas un
 * montant positif lisible.
 *
 * Accepte ce qu'on tape au comptoir : « 300 », « 300,5 », « 300.50 »,
 * « 1 049,00 », « 1 049,00 € ». Refuse plus de deux décimales (« 12,345 »
 * serait arrondi en silence : mieux vaut faire corriger), les montants nuls
 * ou négatifs, et tout ce qui n'est pas un nombre.
 *
 * Le calcul se fait sur la CHAÎNE, jamais par `parseFloat × 100` :
 * 0,29 × 100 vaut 28,999… en virgule flottante.
 */
export function lireMontant(saisie) {
  if (typeof saisie !== 'string' && typeof saisie !== 'number') return null;
  const texte = String(saisie)
    .replace(/[\s  ]/g, '')
    .replace(/€$/, '')
    .replace(',', '.');
  const m = /^(\d{1,7})(?:\.(\d{1,2}))?$/.exec(texte);
  if (!m) return null;
  const cents = Number(m[1]) * 100 + Number((m[2] || '').padEnd(2, '0'));
  return cents > 0 ? cents : null;
}

/** 6 → « 6 h ». */
export function heures(n) {
  return Number.isFinite(n) ? `${n}${ESPACE}h` : '';
}

/** « 2026-09-12… » → « 12/09/2026 », ou chaîne vide si la date est illisible. */
export function dateCourte(iso) {
  if (typeof iso !== 'string') return '';
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso);
  return m ? `${m[3]}/${m[2]}/${m[1]}` : '';
}

/** « Lina » + « BENALI » → « Lina BENALI », sans espaces parasites. */
export function nomComplet(prenom, nom) {
  return [prenom, nom].map((s) => String(s ?? '').trim()).filter(Boolean).join(' ');
}

// ─── Construction d'éléments ─────────────────────────────────────────────────
//
// Le seul endroit où la page fabrique du DOM à partir de données. Tout texte
// est posé par `textContent`, jamais interpolé dans du HTML : un nom d'élève ou
// un libellé du catalogue contenant des chevrons ne doit pas pouvoir devenir du
// HTML. N'utilise `document` qu'à l'appel : le module reste importable sous
// node pour les tests des fonctions ci-dessus.

/**
 * `el('button', { class: 'btn', type: 'button', onclick: f }, 'Texte', autreNoeud)`.
 * Attributs : `class`, `on…` (écouteur), booléens (`disabled`, `hidden`), le
 * reste en `setAttribute`. Enfants : chaînes (en texte), nœuds, ou null ignorés.
 */
export function el(balise, attributs = {}, ...enfants) {
  const n = document.createElement(balise);
  for (const [cle, valeur] of Object.entries(attributs || {})) {
    if (valeur === null || valeur === undefined || valeur === false) continue;
    if (cle === 'class') n.className = valeur;
    else if (cle.startsWith('on') && typeof valeur === 'function') n.addEventListener(cle.slice(2), valeur);
    else if (valeur === true) n.setAttribute(cle, '');
    else n.setAttribute(cle, String(valeur));
  }
  for (const enfant of enfants.flat()) {
    if (enfant === null || enfant === undefined || enfant === false) continue;
    n.append(typeof enfant === 'string' || typeof enfant === 'number' ? document.createTextNode(String(enfant)) : enfant);
  }
  return n;
}

/** Remplace le contenu d'un nœud. */
export function remplir(noeud, ...enfants) {
  noeud.replaceChildren(...enfants.flat().filter((e) => e !== null && e !== undefined && e !== false)
    .map((e) => (typeof e === 'string' ? document.createTextNode(e) : e)));
}
