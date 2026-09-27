// ─── Écran 1 : choisir l'élève ───────────────────────────────────────────────
//
// Recherche dans le CRM (nom, e-mail, téléphone), puis chargement de l'élève
// avec tout ce que la caisse affiche pour lui (onglets, prix, prépa). Trois
// règles héritées de l'ancienne autocomplétion :
//   1. une réponse lente arrivée en retard n'écrase jamais des résultats plus
//      récents (chaque frappe annule la requête précédente) ;
//   2. aucune erreur de recherche ne bloque : au pire la liste reste vide et
//      « Créer la fiche » reste à portée ;
//   3. tout texte venu du CRM est posé par textContent (via `el`).

import * as api from './api.js';
import * as cadre from './cadre.js';
import { el, remplir, euros } from './format.js';
import { eleveCharge, basculerSecours, identificationRequise } from './etat.js';

// Assez court pour suivre la frappe, assez long pour ne pas lancer une requête
// par lettre.
const DELAI_FRAPPE_MS = 250;

let magasin = null;
let resultats = [];
let surligne = -1;
let minuteur = null;
let requeteEnCours = null;
let chargementEnCours = null;

const $ = (id) => document.getElementById(id);

function dire(texte) {
  $('etatRecherche').textContent = texte || '';
}

function fermer() {
  resultats = [];
  surligne = -1;
  $('resultats').hidden = true;
  $('recherche').setAttribute('aria-expanded', 'false');
  $('recherche').removeAttribute('aria-activedescendant');
}

function dessiner() {
  const lignes = resultats.map((e, i) => {
    const sousTitre = [e.email, e.phone].filter(Boolean).join(' · ');
    const pastille = e.paidOffer
      ? el('span', { class: 'chip ok' }, `${e.paidOffer} payé`)
      : el('span', { class: 'chip grey' }, 'Aucun forfait payé');
    return el('button', {
      type: 'button', class: 'ligne-eleve', role: 'option', id: `eleve-${i}`,
      'aria-selected': String(i === surligne), tabindex: '-1',
      // `mousedown` + preventDefault : le champ garde le focus, pas de `blur`
      // qui fermerait la liste avant que le clic n'aboutisse.
      onmousedown: (ev) => ev.preventDefault(),
      onclick: () => choisir(i),
    },
      el('span', { class: 'grandit' },
        el('span', { class: 'nom' }, [e.firstName, e.lastName].filter(Boolean).join(' ')),
        sousTitre ? el('span', { class: 'sub muted', style: 'display:block' }, sousTitre) : null),
      pastille,
      el('span', { class: 'chevron', 'aria-hidden': 'true' }, '›'));
  });
  remplir($('resultats'), lignes);
  $('resultats').hidden = false;
  $('recherche').setAttribute('aria-expanded', 'true');
  if (surligne >= 0) $('recherche').setAttribute('aria-activedescendant', `eleve-${surligne}`);
  else $('recherche').removeAttribute('aria-activedescendant');
}

async function chercher(terme) {
  if (terme.trim().length < 2) {
    dire('');
    return fermer();
  }
  if (requeteEnCours) requeteEnCours.abort();
  const controleur = new AbortController();
  requeteEnCours = controleur;
  const r = await api.chercherEleves(terme.trim(), controleur.signal);
  if (controleur !== requeteEnCours || r.annule) return; // une frappe plus récente a pris la main
  requeteEnCours = null;
  if (r.status === 401) return sessionPerdue(r.data);
  if (!r.ok) {
    fermer();
    return dire('Recherche indisponible pour le moment.');
  }
  resultats = (r.data && Array.isArray(r.data.students)) ? r.data.students : [];
  surligne = resultats.length ? 0 : -1;
  if (!resultats.length) {
    fermer();
    return dire(`Aucun élève trouvé pour « ${terme.trim()} ».`);
  }
  dire('');
  dessiner();
}

function choisir(i) {
  const e = resultats[i];
  if (!e || !e.id) return;
  fermer();
  chargerEleve(e.id, { id: e.id, prenom: e.firstName || '', nom: e.lastName || '', email: e.email || '' });
}

function sessionPerdue(data) {
  const raison = (data && (data.raison || data.code)) || 'jeton_expire';
  magasin.appliquer(identificationRequise, raison, (data && data.error) || null);
}

/**
 * Charge l'élève (onglets, prix, prépa) et ouvre le panier. `repli` pré-remplit
 * l'encaissement de secours si le CRM tombe à ce moment-là.
 * Appelé aussi pour l'élève du fragment et le message `caisse:eleve-choisi`.
 */
export async function chargerEleve(id, repli = null) {
  if (!id || chargementEnCours === id) return;
  const etat = magasin.lire();
  // Jamais pendant un paiement : l'élève du panier est celui du lecteur.
  if (etat.paiement || etat.mode !== 'catalogue') return;
  chargementEnCours = id;
  dire('Chargement de la fiche…');
  const r = await api.eleve(id);
  chargementEnCours = null;
  if (r.ok && r.data && r.data.eleve) {
    dire('');
    $('recherche').value = '';
    return magasin.appliquer(eleveCharge, r.data);
  }
  if (r.indisponible) return magasin.appliquer(basculerSecours, { indisponible: true, eleve: repli });
  if (r.status === 401) return sessionPerdue(r.data);
  dire(r.message || 'Fiche introuvable.');
}

/** Rendu de l'écran 1 à chaque changement d'état. */
export function rendreEcranEleve(etat, precedent) {
  const rappel = $('rappelEspeces');
  if (etat.especesARendre > 0) {
    rappel.textContent = `Paiement abandonné : rendez les ${euros(etat.especesARendre)} en espèces à l'élève.`;
    rappel.hidden = false;
  } else {
    rappel.hidden = true;
  }
  if (etat.ecran === 'eleve' && (!precedent || precedent.ecran !== 'eleve')) {
    fermer();
    dire('');
    // Le focus d'emblée dans la recherche : au comptoir, on tape tout de suite.
    setTimeout(() => $('recherche').focus(), 0);
  }
}

export function initEcranEleve(m) {
  magasin = m;
  const champ = $('recherche');

  champ.addEventListener('input', () => {
    clearTimeout(minuteur);
    const terme = champ.value;
    minuteur = setTimeout(() => chercher(terme), DELAI_FRAPPE_MS);
  });

  champ.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') return fermer();
    if ($('resultats').hidden || !resultats.length) return;
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      ev.preventDefault();
      const pas = ev.key === 'ArrowDown' ? 1 : -1;
      surligne = (surligne + pas + resultats.length) % resultats.length;
      dessiner();
      const ligne = $(`eleve-${surligne}`);
      if (ligne) ligne.scrollIntoView({ block: 'nearest' });
    } else if (ev.key === 'Enter' && surligne >= 0) {
      ev.preventDefault();
      choisir(surligne);
    }
  });

  champ.addEventListener('blur', () => setTimeout(fermer, 150));

  $('creerFiche').addEventListener('click', () => {
    if (!cadre.creerFiche(champ.value.trim())) {
      dire('La création de fiche se fait dans le CRM : ouvrez la caisse depuis le CRM.');
    }
  });
}
