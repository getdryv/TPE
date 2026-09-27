// ─── La cascade de sélecteurs segmentés, PURE ────────────────────────────────
//
// Maquette validée par le gérant pour le contrat de formation, reprise telle
// quelle à la caisse : des sélecteurs segmentés, un par ligne, qui mènent à UN
// forfait du catalogue.
//
//   Permis  [Voiture | Moto]              (+ « Autre » si le catalogue en a)
//   Boîte   [Manuelle | Automatique]      voiture seulement
//   Formule [Classique | Accélérée | …]   masquée s'il n'y a qu'un choix
//   Heures  [10 h | 20 h | 30 h]          celles de la combinaison
//   Forfait [noms]                        seulement si plusieurs forfaits restent
//
// PORTAGE LIGNE À LIGNE de `features/contracts/domain/declaration-cascade.ts`
// du CRM (branche du contrat de formation) : mêmes règles, même ordre, seuls
// les noms de champs sont ceux de la caisse (`formuleId`, `nom`, `heures`).
// Une règle changée là-bas se change ici. Les DIMENSIONS de chaque forfait
// (permis, boîte, formule) ne sont jamais devinées ici : le CRM les envoie
// (`cascade.forfaits`, calculées par `features/caisse/domain/dimensions-formule.ts`).
//
// Une combinaison absente du catalogue est montrée DÉSACTIVÉE (grisée) pour
// que la grille reste stable d'un choix à l'autre. Aucun accès au DOM : ce
// module se teste sous node.

import { heures as heuresTexte } from './format.js';

const ORDRE = ['permis', 'boite', 'formule', 'heures', 'forfait'];
const LIBELLES = { permis: 'Permis', boite: 'Boîte', formule: 'Formule', heures: 'Heures', forfait: 'Forfait' };

const PERMIS = [
  { value: 'voiture', label: 'Voiture' },
  { value: 'moto', label: 'Moto' },
  { value: 'autre', label: 'Autre' },
];
const BOITES = [
  { value: 'manuelle', label: 'Manuelle' },
  { value: 'automatique', label: 'Automatique' },
];

export const CLASSIQUE = 'classique';
export const ACCELEREE = 'acceleree';

export const SELECTION_VIDE = Object.freeze({ permis: null, boite: null, formule: null, heures: null, forfait: null });

const estFormuleAHeures = (formule) => formule === CLASSIQUE || formule === ACCELEREE;
const cleHeures = (t) => String(t.heures ?? 0);
const libelleHeures = (valeur) => (valeur === '0' ? 'Sans heures' : heuresTexte(Number(valeur)));
const distincts = (valeurs) => Array.from(new Set(valeurs));

/** La boîte ne départage que les forfaits qui en ont une ; pas encore choisie : tout reste possible. */
const boiteOk = (t, sel) => t.boite === null || sel.boite === null || t.boite === sel.boite;

/** Les forfaits qui correspondent EXACTEMENT au choix (boîte comprise). */
function candidats(tuiles, sel) {
  if (!sel.permis || !sel.formule || sel.heures === null) return [];
  return tuiles.filter((t) => t.permis === sel.permis
    && (t.boite === null || t.boite === sel.boite)
    && t.formule === sel.formule
    && cleHeures(t) === sel.heures);
}

/** Une ligne pour le choix en cours ; `visible: false` = la ligne n'est pas montrée. */
function ligne(tuiles, sel, cle) {
  const duPermis = tuiles.filter((t) => t.permis === sel.permis);
  if (cle === 'permis') {
    const presents = new Set(tuiles.map((t) => t.permis));
    const options = PERMIS.filter((p) => p.value !== 'autre' || presents.has('autre'))
      .map((p) => ({ ...p, disabled: !presents.has(p.value) }));
    return { options, visible: tuiles.length > 0 };
  }
  if (cle === 'boite') {
    const avecBoite = duPermis.filter((t) => t.boite !== null);
    const options = BOITES.map((b) => ({ ...b, disabled: !avecBoite.some((t) => t.boite === b.value) }));
    return { options, visible: sel.permis === 'voiture' && avecBoite.length > 0 };
  }
  if (cle === 'formule') {
    // Classique puis accélérée, puis les formules à part dans l'ordre du catalogue.
    const rang = (v) => (v === CLASSIQUE ? 0 : v === ACCELEREE ? 1 : 2);
    const valeurs = distincts(duPermis.map((t) => t.formule)).sort((a, b) => rang(a) - rang(b));
    const options = valeurs.map((value) => ({
      value,
      label: (duPermis.find((t) => t.formule === value) || {}).formuleLabel || value,
      disabled: !duPermis.some((t) => t.formule === value && boiteOk(t, sel)),
    }));
    return { options, visible: options.length >= 2 };
  }
  if (cle === 'heures') {
    if (!sel.formule) return { options: [], visible: false };
    // Heures des formules classique et accélérée réunies : passer de l'une à
    // l'autre grise les heures absentes au lieu de les faire disparaître.
    const vivier = duPermis.filter((t) => boiteOk(t, sel)
      && (estFormuleAHeures(sel.formule) ? estFormuleAHeures(t.formule) : t.formule === sel.formule));
    const valeurs = distincts(vivier.map(cleHeures)).sort((a, b) => Number(a) - Number(b));
    const options = valeurs.map((value) => ({
      value,
      label: libelleHeures(value),
      disabled: !vivier.some((t) => t.formule === sel.formule && cleHeures(t) === value),
    }));
    return { options, visible: options.length > 0 };
  }
  const trouves = candidats(tuiles, sel);
  return { options: trouves.map((t) => ({ value: t.formuleId, label: t.nom, disabled: false })), visible: trouves.length >= 2 };
}

/** Le forfait désigné par le choix (son `formuleId`), ou null tant qu'il en manque un bout. */
export function resoudre(tuiles, sel) {
  const trouves = candidats(tuiles, sel);
  if (trouves.length === 1) return trouves[0].formuleId;
  return trouves.some((t) => t.formuleId === sel.forfait) ? sel.forfait : null;
}

/** Les lignes MONTRÉES, dans l'ordre : `{ cle, libelle, options, valeur }`. */
export function lignesCascade(tuiles, sel) {
  return ORDRE.flatMap((cle) => {
    const l = ligne(tuiles, sel, cle);
    return l.visible ? [{ cle, libelle: LIBELLES[cle], options: l.options, valeur: sel[cle] }] : [];
  });
}

function plusProche(cle, actives, precedent) {
  if (cle !== 'heures' || precedent === null) return actives[0].value;
  const cible = Number(precedent);
  return actives.reduce((m, o) => (Math.abs(Number(o.value) - cible) < Math.abs(Number(m.value) - cible) ? o : m)).value;
}

/**
 * Remet le choix d'aplomb, ligne après ligne : une valeur devenue impossible
 * est retirée ; une ligne masquée prend sa seule option (formule unique) ou se
 * vide (boîte d'une moto). Puis, selon `remplissage` :
 *  - `initial` (pré-sélection, sans geste) : une ligne à option unique est
 *    remplie, sauf heures et forfait — rien n'est désigné sans un geste ;
 *  - `unique` (geste, rien n'était désigné) : toute ligne à option unique ;
 *  - `proche` (geste, un forfait était désigné) : en plus, une ligne vidée
 *    reprend l'option la plus proche — la cascade désigne toujours un forfait.
 */
export function normaliser(tuiles, sel, remplissage) {
  const suivant = { ...sel };
  for (const cle of ORDRE) {
    const precedent = suivant[cle];
    const { options, visible } = ligne(tuiles, suivant, cle);
    const actives = options.filter((o) => !o.disabled);
    if (precedent !== null && !actives.some((o) => o.value === precedent)) suivant[cle] = null;
    if (!visible) {
      suivant[cle] = cle === 'formule' && actives.length === 1 ? actives[0].value : null;
      continue;
    }
    if (suivant[cle] !== null) continue;
    const differe = remplissage === 'initial' && (cle === 'heures' || cle === 'forfait');
    if (actives.length === 1 && !differe) suivant[cle] = actives[0].value;
    else if (remplissage === 'proche' && actives.length > 0) suivant[cle] = plusProche(cle, actives, precedent);
  }
  return suivant;
}

/** Le choix qui désigne ce forfait. */
export function selectionDe(t) {
  return { permis: t.permis, boite: t.boite, formule: t.formule, heures: cleHeures(t), forfait: t.formuleId };
}

/** Le choix de départ : le forfait retenu, sinon la pré-sélection de la fiche (jamais les heures). */
export function selectionInitiale(tuiles, formuleId, indices) {
  const t = tuiles.find((x) => x.formuleId === formuleId);
  if (t) return selectionDe(t);
  const i = indices || {};
  return normaliser(tuiles, { ...SELECTION_VIDE, permis: i.permis || null, boite: i.boite || null, formule: i.formule || null }, 'initial');
}

/** Un clic sur une ligne : les lignes du dessous gardent leur valeur si elle reste possible. */
export function choisir(tuiles, sel, cle, valeur, avaitUnForfait) {
  return normaliser(tuiles, { ...sel, [cle]: valeur }, avaitUnForfait ? 'proche' : 'unique');
}
