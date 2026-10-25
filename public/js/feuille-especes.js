// ─── La feuille de comptage des espèces ──────────────────────────────────────
//
// Elle remplace les onglets dès qu'un moyen avec des espèces est choisi : un
// champ « nombre » par billet (200 € à 5 €) et par pièce (2 € à 0,10 €) ; un
// clic sur le billet ajoute 1. Entrée ou Tab passent à la coupure suivante,
// Maj + Tab reviennent ; Entrée encaisse quand le compte est juste. Le
// résultat s'affiche TOUJOURS au même endroit : le compteur du panier.
//
// Construite une fois ; chaque rendu ne met à jour que les valeurs : un champ
// en cours de frappe garde son texte et son focus.

import { el, eurosCourts } from './format.js';
import { BILLETS, PIECES, COUPURES, designation, libelleCoupure, lireNombre } from './especes-compte.js';
import { ajouterCoupure, analyseEspeces, feuilleAffichee, revenirPrestation, saisirCoupure, toutEffacer } from './etat-especes.js';

// Couleurs des coupures : les tons des vrais billets, en aplats pâles ; le texte reste #1a1f36.
const TEINTES = { 20000: '#fbefc2', 10000: '#d6efd8', 5000: '#fde0c2', 2000: '#d7e6fb', 1000: '#f8d6d6', 500: '#e4e7eb' };
// Pièces : 2 € à cœur argenté et couronne dorée, 1 € l'inverse, les centimes dorés.
const PIECES_TEINTES = { 200: ['#eceff2', '#c9a73f'], 100: ['#f3e2a0', '#9aa0a8'] };
const teinte = (c) => {
  if (c >= 500) return `background:${TEINTES[c]}`;
  const [fond, couronne] = PIECES_TEINTES[c] || ['#f3e2a0', '#8a7a3a'];
  return `background:${fond};box-shadow:inset 0 0 0 4px ${couronne}`;
};
const ICO_RETOUR = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>';

let magasin = null;
let valider = () => {};
const n = { lignes: new Map() };
const $ = (id) => document.getElementById(id);

const CONSIGNES = {
  especes: 'Tapez le nombre de chaque billet et pièce reçus, ou cliquez sur un billet pour en ajouter un.',
  mixte: 'Seules les espèces se comptent ici : le reste passe automatiquement sur la carte.',
  especes_cheques: 'Seules les espèces se comptent ici : le reste passe automatiquement en chèques.',
};

function suivant(c, pas) {
  const i = COUPURES.indexOf(c);
  return COUPURES[(i + pas + COUPURES.length) % COUPURES.length];
}

function ligne(c) {
  const nom = designation(c, 1).replace(/^1\u00a0/, '');
  const bouton = el('button', {
    type: 'button', class: `coupure${c < 500 ? ' piece' : ''}`, tabindex: '-1', 'aria-label': `Ajouter un ${nom}`,
    style: teinte(c),
    onclick: () => { magasin.appliquer(ajouterCoupure, c); entree.focus(); },
  }, libelleCoupure(c));
  const entree = el('input', {
    class: 'in-nb', type: 'text', inputmode: 'numeric', autocomplete: 'off', maxlength: '3', 'aria-label': `Nombre, ${nom}`, 'data-coupure': String(c),
  });
  entree.addEventListener('input', () => {
    const nombre = lireNombre(entree.value);
    entree.setAttribute('aria-invalid', String(nombre === null));
    if (nombre !== null) magasin.appliquer(saisirCoupure, c, nombre);
  });
  entree.addEventListener('focus', () => entree.select());
  entree.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter') return;
    ev.preventDefault();
    // Espèces seules, compte juste : Entrée encaisse (le bouton le dit) ; sinon, coupure suivante.
    if (magasin.lire().moyen === 'especes' && valider()) return;
    const cible = n.lignes.get(suivant(c, ev.shiftKey ? -1 : 1));
    if (cible) cible.entree.focus();
  });
  const montant = el('span', { class: 'st' });
  const rangee = el('div', { class: 'ligne-c' }, bouton, entree, montant);
  n.lignes.set(c, { rangee, entree, montant });
  return rangee;
}

const colonne = (titre, coupures) => el('div', {},
  el('div', { class: 'col-titre', 'aria-hidden': 'true' }, el('span', {}, titre), el('span', {}, 'Nombre'), el('span', {}, 'Montant')),
  coupures.map(ligne));

function construire(hote) {
  n.retour = el('button', { type: 'button', class: 'lien-btn retour', onclick: () => magasin.appliquer(revenirPrestation) });
  n.consigne = el('p', { class: 'consigne' });
  n.effacer = el('button', { type: 'button', class: 'lien-btn', onclick: () => { magasin.appliquer(toutEffacer); n.lignes.get(COUPURES[0]).entree.focus(); } }, 'Tout effacer');
  const kbd = (t) => el('kbd', {}, t);
  hote.append(
    el('div', { class: 'feuille-tete' }, n.retour, el('h2', { class: 'titre-feuille' }, 'Comptez les espèces reçues'), n.consigne),
    el('div', { class: 'encart encart-info' }, el('b', {}, 'On ne rend pas la monnaie : '), 'demandez l\'appoint à l\'élève.'),
    el('div', { class: 'coupures', role: 'group', 'aria-label': 'Billets et pièces reçus' }, colonne('Billets', BILLETS), colonne('Pièces', PIECES)),
    el('div', { class: 'raccourcis' },
      el('span', {}, kbd('Entrée'), ' ou ', kbd('Tab'), ' : coupure suivante'),
      el('span', {}, kbd('Maj'), ' + ', kbd('Tab'), ' : coupure précédente'),
      el('span', { class: 'espaceur' }), n.effacer));
}

let affichee = false;

export function rendreFeuille(etat) {
  const hote = $('feuilleEspeces');
  if (!hote) return;
  const visible = feuilleAffichee(etat);
  hote.hidden = !visible;
  $('onglets').hidden = visible;
  $('contenuOnglet').hidden = visible;
  if (!visible) { affichee = false; return; }

  const reprise = etat.onglet === 'reprise';
  n.retour.innerHTML = ICO_RETOUR; // pictogramme constant, sans donnée
  n.retour.append(document.createTextNode(reprise ? 'Revenir aux chèques' : 'Revenir au choix de la prestation'));
  n.consigne.textContent = CONSIGNES[etat.moyen] || CONSIGNES.especes;

  const a = analyseEspeces(etat);
  const rendre = a.statut === 'trop' && a.rendre ? a.rendre.pieces : {};
  const verrou = Boolean(etat.paiement);
  for (const [c, { rangee, entree, montant }] of n.lignes) {
    const nombre = (etat.comptage || {})[String(c)] || 0;
    if (document.activeElement !== entree && lireNombre(entree.value) !== nombre) entree.value = nombre ? String(nombre) : '';
    entree.disabled = verrou;
    rangee.querySelector('.coupure').disabled = verrou;
    const aRendre = rendre[String(c)] || 0;
    rangee.classList.toggle('a-rendre', aRendre > 0);
    montant.classList.toggle('rendre', aRendre > 0);
    montant.replaceChildren(...(nombre ? [document.createTextNode(eurosCourts(c * nombre))] : []),
      ...(aRendre > 0 ? [el('small', {}, `${aRendre} à rendre`)] : []));
  }
  n.effacer.hidden = a.compte === 0 || verrou;
  // La feuille vient d'apparaître : on tape tout de suite le premier billet.
  if (!affichee) setTimeout(() => n.lignes.get(COUPURES[0]).entree.focus(), 0);
  affichee = true;
}

/** `validerSiPret` : encaisse si le bouton du panier est actif et rend vrai, sinon faux. */
export function initFeuille(m, validerSiPret) {
  magasin = m;
  valider = validerSiPret;
  const hote = $('feuilleEspeces');
  if (hote) construire(hote);
}
