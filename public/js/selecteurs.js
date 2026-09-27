// ─── Onglets Forfait initial et Heures supp : sélecteurs segmentés ──────────
//
// Maquette validée par le gérant (celle du contrat de formation) : au lieu
// d'une grille de tuiles aux noms longs répétés, des lignes de segments,
// libellé à gauche — Permis, Boîte, Formule, Heures (cascade.js) —, puis le
// NOM du forfait retenu et son prix comptant (promotion comprise). Le panier
// reste la seule source du total : ce prix est indicatif, le devis fait foi.
//
// De VRAIS boutons radio (masqués, leur libellé fait le segment) : Tab entre
// dans le groupe, les flèches passent d'une option à l'autre en sautant les
// grisées ; cibles de 40 px au moins.
//
// Les lignes changent à chaque choix : le bloc est reconstruit, mais seulement
// quand ce qu'il montre change (signature), et le focus clavier est rendu au
// même bouton radio — sinon les flèches perdraient leur place à chaque geste.

import { el, remplir, euros, eurosCourts, heures } from './format.js';
import { choisirFormule } from './etat.js';
import { lignesCascade, resoudre, selectionDe, selectionInitiale, choisir } from './cascade.js';

const PERMIS = { voiture: 'Voiture', moto: 'Moto', autre: 'Autre' };
const BOITES = { manuelle: 'boîte manuelle', automatique: 'boîte automatique' };
const INDICES = ['permis', 'boite', 'formule'];

let magasin = null;
// Le choix en cours de la cascade (pas encore un forfait) : propre à l'élève affiché.
let memo = { source: null, sel: null };
const signatures = new WeakMap();

// ─── Pièces ──────────────────────────────────────────────────────────────────

/** Une ligne : libellé à gauche, groupe de radios segmentés à droite, mention « d'après la fiche ». */
function ligneSegments({ nom, libelle, options, valeur, mention, verrou, surChoix }) {
  const idLibelle = `seg-${nom}-libelle`;
  const segments = options.map((o) => {
    const radio = el('input', {
      type: 'radio', name: `seg-${nom}`, value: o.value,
      checked: o.value === valeur, disabled: o.disabled || verrou,
    });
    radio.addEventListener('change', () => surChoix(o.value));
    return el('label', {
      class: 'segment', title: o.disabled ? 'Absent du catalogue de l\'agence pour ce choix' : null,
    }, radio, el('span', {}, o.label));
  });
  return el('div', { class: 'ligne-seg' },
    el('span', { class: 'ligne-seg-libelle', id: idLibelle }, libelle),
    el('div', { class: 'ligne-seg-choix' },
      el('div', { class: 'segments', role: 'radiogroup', 'aria-labelledby': idLibelle }, segments),
      mention ? el('span', { class: 'mention' }, mention) : null));
}

/** Nom et prix comptant du forfait ou du pack retenu ; la promotion en cours, barrée. */
function retenu(t, precision) {
  const prix = t.promo
    ? [el('span', { class: 'retenu-prix' }, el('s', {}, euros(t.prixCents)), ' ', el('b', {}, euros(t.promo.prixRemiseCents))),
      el('span', { class: 'chip promo' }, `Promo en cours · ${eurosCourts(-t.promo.remiseCents)}`)]
    : [el('span', { class: 'retenu-prix' }, el('b', {}, euros(t.prixCents)))];
  return el('div', { class: 'retenu', role: 'status' },
    el('div', { class: 'retenu-nom' }, t.nom),
    el('div', { class: 'retenu-ligne' }, prix),
    el('p', { class: 'muted petit' }, precision));
}

/** Reconstruit `zone` seulement si ce qu'elle montre a changé ; rend le focus au même radio. */
function redessiner(zone, signature, construire) {
  if (signatures.get(zone) === signature) return;
  signatures.set(zone, signature);
  const actif = document.activeElement;
  const focus = actif && zone.contains(actif) && actif.name ? { name: actif.name, value: actif.value } : null;
  remplir(zone, construire());
  if (!focus) return;
  const cible = [...zone.querySelectorAll('input[type="radio"]')]
    .find((r) => r.name === focus.name && r.value === focus.value && !r.disabled);
  if (cible) cible.focus();
}

const produitDe = (etat, type) => (etat.produit && etat.produit.type === type ? etat.produit.formuleId : null);

// ─── Forfait initial ─────────────────────────────────────────────────────────

export function rendreForfait(zone, etat) {
  const c = etat.eleve.cascade;
  if (!c) {
    remplir(zone, el('p', { class: 'encart encart-warn' }, 'Le CRM de l\'agence n\'est pas à jour : le choix du forfait est indisponible. Prévenez un administrateur.'));
    return;
  }
  const tuiles = c.forfaits || [];
  if (!tuiles.length) {
    remplir(zone, el('p', { class: 'muted petit' }, 'Aucun forfait au catalogue de l\'agence.'));
    return;
  }
  if (memo.source !== etat.eleve) memo = { source: etat.eleve, sel: selectionInitiale(tuiles, null, c.indices) };
  const choisi = tuiles.find((t) => t.formuleId === produitDe(etat, 'forfait')) || null;
  // Panier vidé (autre onglet entre-temps) : les heures ne restent jamais cochées sans forfait au panier.
  if (!choisi && resoudre(tuiles, memo.sel)) memo.sel = { ...memo.sel, heures: null, forfait: null };
  // Le forfait du panier fait foi : la cascade le montre, même si elle n'est pas d'accord avec lui.
  const sel = choisi && resoudre(tuiles, memo.sel) !== choisi.formuleId ? selectionDe(choisi) : memo.sel;
  const verrou = Boolean(etat.paiement);
  const indices = c.indices || {};
  const mentionDe = (l) => (indices.source === 'fiche' && INDICES.includes(l.cle) && l.valeur !== null && indices[l.cle] === l.valeur
    ? 'd\'après la fiche' : null);

  const surChoix = (cle) => (valeur) => {
    memo.sel = choisir(tuiles, sel, cle, valeur, choisi !== null);
    const id = resoudre(tuiles, memo.sel);
    if (id) magasin.appliquer(choisirFormule, 'forfait', id);
    rendreForfait(zone, magasin.lire());
  };

  redessiner(zone, JSON.stringify([sel, choisi && choisi.formuleId, verrou]), () => [
    el('div', { class: 'cascade' }, lignesCascade(tuiles, sel).map((l) => ligneSegments({
      nom: l.cle, libelle: l.libelle, options: l.options, valeur: l.valeur,
      mention: mentionDe(l), verrou, surChoix: surChoix(l.cle),
    }))),
    choisi
      ? retenu(choisi, 'Prix comptant, payé en une fois au comptoir. Le panier fait foi.')
      : el('p', { class: 'muted petit' }, 'Choisissez les heures : le forfait et son prix s\'affichent ici.'),
  ]);
}

// ─── Heures supp ─────────────────────────────────────────────────────────────

/** « Voiture, boîte automatique » d'après la fiche ; les packs ne dépendent que de voiture / moto. */
function texteVehicule(etat) {
  const hs = etat.eleve.heuresSupp || {};
  const indices = (etat.eleve.cascade && etat.eleve.cascade.indices) || {};
  const permis = hs.famille === 'Moto' ? 'moto' : 'voiture';
  const boite = permis === 'voiture' && indices.boite ? `, ${BOITES[indices.boite]}` : '';
  return `${PERMIS[permis]}${boite}`;
}

export function rendreHeuresSupp(zone, etat) {
  const packs = (etat.eleve.heuresSupp && etat.eleve.heuresSupp.packs) || [];
  const choisi = packs.find((t) => t.formuleId === produitDe(etat, 'heures_supp')) || null;
  const verrou = Boolean(etat.paiement);
  // Deux packs aux mêmes heures (ou sans heures) : leur nom les départage.
  const compte = new Map();
  packs.forEach((t) => compte.set(t.heures, (compte.get(t.heures) || 0) + 1));
  const libelle = (t) => (t.heures && compte.get(t.heures) === 1 ? heures(t.heures) : t.nom);

  redessiner(zone, JSON.stringify([choisi && choisi.formuleId, verrou, packs.length]), () => [
    el('div', { class: 'cascade' },
      el('div', { class: 'ligne-seg' },
        el('span', { class: 'ligne-seg-libelle' }, 'Véhicule'),
        el('div', { class: 'ligne-seg-choix' },
          el('span', { class: 'gras' }, texteVehicule(etat)), el('span', { class: 'mention' }, 'd\'après la fiche'))),
      packs.length
        ? ligneSegments({
          nom: 'pack', libelle: 'Pack', valeur: choisi && choisi.formuleId, verrou,
          options: packs.map((t) => ({ value: t.formuleId, label: libelle(t), disabled: false })),
          surChoix: (id) => magasin.appliquer(choisirFormule, 'heures_supp', id),
        })
        : null),
    !packs.length
      ? el('p', { class: 'muted petit' }, `Aucun pack d'heures ${texteVehicule(etat).toLowerCase()} au catalogue de l'agence.`)
      : choisi
        ? retenu(choisi, 'Prix comptant, payé en une fois. Seuls les packs du véhicule de l\'élève sont proposés.')
        : el('p', { class: 'muted petit' }, 'Choisissez un pack : son prix s\'affiche ici.'),
  ]);
}

export function initSelecteurs(m) {
  magasin = m;
}
