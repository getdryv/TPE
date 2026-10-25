// ─── Écrans 2 à 6 : bandeau élève, onglets et contenus ───────────────────────
//
// On CHOISIT une formule, on ne tape jamais son prix. Les prix affichés sont
// indicatifs (ceux du catalogue, promotion comprise) : seul le devis du CRM
// fait foi, et c'est lui que le panier affiche et que le lecteur débite.
//
// Jamais de liste déroulante : Forfait initial et Heures supp sont des
// sélecteurs segmentés (selecteurs.js), l'onglet Examen une carte (examen.js),
// le montant libre un montant et un commentaire facultatif.
// L'onglet « Montant libre » est ouvert à tout compte qui encaisse, sans motif
// (décision du 27/09/2026) : le CRM trace le nom de la personne.
//
// Le contenu n'est reconstruit que quand l'élève ou l'onglet change ; sinon on
// ne met à jour que la sélection. Reconstruire à chaque frappe ferait perdre le
// focus du champ en cours de saisie (montant libre).

import { el, remplir, nomComplet } from './format.js';
import { changerEleve, choisirOnglet, saisirLibre } from './etat.js';
import { contenuExamen, initExamen, majExamen } from './examen.js';
import { initSelecteurs, rendreForfait, rendreHeuresSupp } from './selecteurs.js';
import { chequesReprenables } from './etat.js';
import { contenuReprise, initReprise, majReprise } from './reprise.js';

const LIBELLES = { forfait: 'Forfait initial', heures_supp: 'Heures supp', prepa: 'Examen', libre: 'Montant libre', reprise: 'Reprise de chèque' };

let magasin = null;
let rendu = { eleveId: null, onglet: null };
const $ = (id) => document.getElementById(id);

// ─── Pièces ──────────────────────────────────────────────────────────────────

function bandeauEleve(ec) {
  const e = ec.eleve;
  return [
    el('span', { class: 'nom' }, nomComplet(e.prenom, e.nom)),
    e.formation ? el('span', { class: 'muted petit' }, e.formation) : null,
    e.forfaitPaye
      ? el('span', { class: 'chip ok' }, `${e.forfaitPaye} payé`)
      : el('span', { class: 'chip grey' }, 'Aucun forfait payé'),
    el('button', { type: 'button', class: 'lien-btn', 'data-verrou': '', onclick: () => magasin.appliquer(changerEleve) },
      'Changer d\'élève'),
  ];
}

/** Le 5e onglet n'apparaît que si l'élève a des chèques reprenables (CRM à jour). */
function barreOnglets(etat) {
  const nbReprises = chequesReprenables(etat).length;
  const onglets = ['forfait', 'heures_supp', 'prepa', 'libre', ...(nbReprises ? ['reprise'] : [])];
  return onglets.map((o) => el('button', {
    type: 'button', role: 'tab', class: 'onglet', id: `onglet-${o}`, 'data-verrou': '',
    'aria-selected': String(etat.onglet === o),
    onclick: () => magasin.appliquer(choisirOnglet, o),
  }, LIBELLES[o]));
}

// ─── Contenus ────────────────────────────────────────────────────────────────

function contenuForfait(ec) {
  const blocs = [];
  if (ec.eleve.forfaitPaye) {
    blocs.push(el('div', { class: 'encart encart-warn' },
      `Un forfait est déjà enregistré : ${ec.eleve.forfaitPaye}. Un nouveau forfait sera encaissé et tracé, sans remplacer celui de la fiche.`));
  }
  // Rempli par `rendreForfait` (selecteurs.js), à chaque changement d'état.
  blocs.push(el('div', { id: 'selecteursForfait', class: 'selecteurs' }));
  return blocs;
}

/**
 * Montant libre : ouvert à tout compte qui encaisse et SANS MOTIF (décision du
 * 27/09/2026). Le montant, un commentaire facultatif (jamais obligatoire) —
 * repris dans le libellé, la liste des encaissements et le ticket ; le CRM
 * trace qui a encaissé.
 */
function contenuLibre(etat) {
  const p = etat.produit || {};
  const montant = el('input', {
    class: 'in in-montant', type: 'text', name: 'champL', inputmode: 'decimal', id: 'libreMontant',
    autocomplete: 'pas-de-remplissage-auto', placeholder: 'ex. 45,00', 'data-verrou': '',
  });
  montant.value = p.montantSaisie || '';
  montant.addEventListener('input', () => magasin.appliquer(saisirLibre, { montantSaisie: montant.value }));

  const note = el('input', {
    class: 'in', type: 'text', name: 'champP', maxlength: '80', id: 'libreNote', 'data-verrou': '',
    autocomplete: 'pas-de-remplissage-auto', placeholder: 'Ex. : n° de facture rattachée, solde de la leçon du 12/09…',
  });
  note.value = p.note || '';
  note.addEventListener('input', () => magasin.appliquer(saisirLibre, { note: note.value }));

  return [
    el('div', { class: 'encart encart-warn', style: 'display:flex;gap:10px;align-items:center;flex-wrap:wrap' },
      el('span', { class: 'chip warn' }, 'Hors catalogue'),
      el('span', {}, 'Pour ce qui n\'existe pas dans les autres onglets. Chaque montant libre est enregistré avec votre nom.')),
    el('div', { class: 'carte carte-libre' },
      el('label', { class: 'champ', for: 'libreMontant' }, 'Montant',
        el('span', { class: 'ligne-montant' }, montant, el('span', { 'aria-hidden': 'true' }, '€'))),
      el('label', { class: 'champ', for: 'libreNote' },
        el('span', {}, 'Commentaire ', el('span', { class: 'muted', style: 'font-weight:400' }, '(facultatif)')), note)),
  ];
}

// ─── Rendu ───────────────────────────────────────────────────────────────────

function contenu(etat) {
  if (etat.onglet === 'heures_supp') return [el('div', { id: 'selecteursHeures', class: 'selecteurs' })];
  if (etat.onglet === 'prepa') return contenuExamen(etat);
  if (etat.onglet === 'libre') return contenuLibre(etat);
  if (etat.onglet === 'reprise') return contenuReprise(etat);
  return contenuForfait(etat.eleve);
}

/** Sélection et verrous seulement : aucun nœud recréé. */
function majSelection(etat) {
  const forfait = $('selecteursForfait');
  if (forfait) rendreForfait(forfait, etat);
  const packs = $('selecteursHeures');
  if (packs) rendreHeuresSupp(packs, etat);
  majReprise(etat);
  majExamen(etat);
  // Pendant un paiement, le panier est figé : c'est lui qui est sur le lecteur.
  const verrou = Boolean(etat.paiement);
  document.querySelectorAll('.catalogue [data-verrou]').forEach((b) => { b.disabled = verrou; });
}

export function rendreOnglets(etat) {
  if (etat.ecran !== 'panier' || !etat.eleve) {
    rendu = { eleveId: null, onglet: null };
    return;
  }
  const eleveId = etat.eleve.eleve.id;
  if (rendu.eleveId !== eleveId || rendu.onglet !== etat.onglet) {
    // Les références d'objet changent à chaque chargement : on compare aussi
    // l'objet, pour qu'un élève rechargé (données fraîches) soit redessiné.
    remplir($('bandeauEleve'), bandeauEleve(etat.eleve));
    remplir($('onglets'), barreOnglets(etat));
    remplir($('contenuOnglet'), contenu(etat));
    $('contenuOnglet').setAttribute('aria-labelledby', `onglet-${etat.onglet}`);
    rendu = { eleveId, onglet: etat.onglet, source: etat.eleve };
  } else if (rendu.source !== etat.eleve) {
    rendu = { eleveId: null, onglet: null };
    return rendreOnglets(etat);
  }
  majSelection(etat);
}

export function initOnglets(m) {
  magasin = m;
  initSelecteurs(m);
  initReprise(m);
  initExamen(m);
}
