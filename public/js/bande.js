// ─── La bande verte : l'encaissement est fait, la caisse est déjà prête ───────
//
// Aux heures de pointe, la file attend : après un encaissement, la caisse ne
// montre pas une page à fermer. Le panier est déjà vidé, le focus est dans la
// recherche d'élève (ecran-eleve.js), et une bande en haut dit ce qui vient
// d'être encaissé : « Encaissé · 1 760 € en 3 chèques · Léa MARTIN ». Le
// récapitulatif (échéancier, ce que le CRM a enregistré, liens vers la fiche
// et le contrat) se déplie sous « Voir le détail ». La bande reste jusqu'au
// prochain encaissement.
//
// Deux cas restent en orange, lisibles sans rien déplier : la carte est prise
// mais le CRM n'a pas encore répondu (« enregistrement en cours »), ou le CRM
// signale un écart de montant.

import * as cadre from './cadre.js';
import { el, remplir, euros, eurosCourts, jourCourt } from './format.js';

let detailOuvert = false;
let dessinee = null;
const $ = (id) => document.getElementById(id);

const ICO_OK = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>';

const nbCheques = (d) => (d.echeancier && d.echeancier.nombreCheques) || 0;
const pluriel = (n, mot) => `${n} ${mot}${n > 1 ? 's' : ''}`;

/** PURE. « 1 760 € en 3 chèques », « 1 760 € : 300 € en espèces + 2 chèques »… */
export function texteRepartition(d) {
  if (!d) return '';
  const tot = eurosCourts(d.totalCents);
  if (d.moyen === 'cheques') return `${tot} en ${pluriel(nbCheques(d), 'chèque')}`;
  if (d.moyen === 'especes_cheques') return `${tot} : ${eurosCourts(d.especesCents)} en espèces + ${pluriel(nbCheques(d), 'chèque')}`;
  if (d.moyen === 'mixte') return `${tot} : ${eurosCourts(d.especesCents)} en espèces + ${eurosCourts(d.carteCents)} par carte`;
  if (d.moyen === 'especes') return `${tot} en espèces`;
  return `${tot} par carte`;
}

/** PURE. Titre et ton de la bande selon la réponse du CRM. */
export function enteteBande(declaration) {
  const statut = declaration && declaration.statut;
  if (statut === 'en_attente') return { genre: 'warn', titre: 'Paiement accepté', suite: 'enregistrement dans le CRM en cours, rien à ressaisir' };
  if (statut === 'ecart') return { genre: 'warn', titre: 'Écart de montant', suite: 'rien n\'a été marqué payé : vérifiez dans Stripe' };
  if (statut === 'deja') return { genre: 'ok', titre: 'Déjà enregistré', suite: null };
  return { genre: 'ok', titre: 'Encaissé', suite: null };
}

function lignesEcheancier(d) {
  const ech = d.echeancier;
  if (!ech || !Array.isArray(ech.versements)) return null;
  return ech.versements.map((v) => el('span', { class: 'bloc' }, v.nature === 'especes'
    ? `aujourd'hui · ${euros(v.amountCents)} en espèces`
    : `${jourCourt(v.dueOn)} · ${euros(v.amountCents)}`));
}

function recapitulatif(r, utilisateur) {
  const d = r.devis || {};
  const declaration = r.declaration || {};
  const effets = Array.isArray(declaration.effets) ? declaration.effets : [];
  const lignes = [
    ['Élève', r.eleve],
    ['Pour', d.libelle],
    ['Montant', texteRepartition(d)],
    ['Échéancier', lignesEcheancier(d)],
    ['Enregistré dans le CRM', effets.length ? effets.map((e) => el('span', { class: 'bloc' }, e.texte)) : null],
    ['Encaissé par', utilisateur && utilisateur.nom],
  ].filter(([, v]) => v && (!Array.isArray(v) || v.length));
  const liens = declaration.liens || {};
  const boutons = [
    liens.fiche ? el('button', { type: 'button', class: 'btn', onclick: () => cadre.ouvrirDansCrm(liens.fiche) }, 'Ouvrir la fiche') : null,
    liens.contrat ? el('button', { type: 'button', class: 'btn', onclick: () => cadre.ouvrirDansCrm(liens.contrat) }, 'Préparer le contrat') : null,
  ].filter(Boolean);
  return el('div', { class: 'detail-bande', id: 'detailBande' },
    el('dl', { class: 'recap' }, lignes.map(([dt, dd]) => el('div', {}, el('dt', {}, dt), el('dd', {}, dd)))),
    boutons.length ? el('div', { class: 'boutons-bande' }, boutons) : null);
}

function dessiner(hote, etat) {
  const r = etat.bande;
  const { genre, titre, suite } = enteteBande(r.declaration);
  const ico = el('span', { class: 'ico', 'aria-hidden': 'true' });
  if (genre === 'ok') ico.innerHTML = ICO_OK; // pictogramme constant, sans donnée
  const resume = [texteRepartition(r.devis), r.eleve, suite].filter(Boolean).join(' · ');
  const bascule = el('button', {
    type: 'button', class: 'lien-btn', 'aria-expanded': String(detailOuvert), 'aria-controls': 'detailBande',
    onclick: () => { detailOuvert = !detailOuvert; dessiner(hote, etat); },
  }, detailOuvert ? 'Masquer le détail' : 'Voir le détail');
  remplir(hote,
    el('div', { class: `bande bande-${genre}`, role: 'status' }, ico,
      el('span', { class: 'grandit' }, el('b', {}, titre), resume ? ` · ${resume}` : ''), bascule),
    detailOuvert ? recapitulatif(r, etat.utilisateur) : null);
}

/** À chaque changement d'état : visible sur la recherche et le panier, jusqu'au prochain encaissement. */
export function rendreBande(etat) {
  const hote = $('bandeEncaisse');
  if (!hote) return;
  const visible = Boolean(etat.bande) && (etat.ecran === 'eleve' || etat.ecran === 'panier');
  hote.hidden = !visible;
  if (!visible) {
    if (!etat.bande) { dessinee = null; detailOuvert = false; }
    return;
  }
  if (dessinee === etat.bande) return;
  dessinee = etat.bande;
  detailOuvert = false;
  dessiner(hote, etat);
}
