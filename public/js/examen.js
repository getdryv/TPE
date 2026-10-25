// ─── L'onglet « Examen » : la carte (maquettes ExamenBPE / Paye / Representation) ──
//
// En tête, la date d'examen prévue (module Examens du CRM), ou le bandeau
// orange d'un ajourné / absent. Puis : la préconisation du moniteur, les
// heures encore disponibles (recopiées du logiciel de gestion, enregistrées
// sur la fiche), les heures à payer, les heures en plus, l'accompagnement.
// Le total est dans le panier, à droite : la carte ne le répète pas.
//
// La carte est construite une fois par élève ; chaque rendu ne met à jour que
// des textes (aucun champ recréé pendant une frappe). Le calcul est celui
// d'etat-examen.js ; l'enregistrement des heures part au CRM 500 ms après le
// dernier changement.

import { el, euros, heures, dateEnLettres } from './format.js';
import { identificationRequise } from './etat.js';
import {
  prepaCourante, calculExamen, saisirHeuresDisponibles, heuresEnvoyees, heuresEnregistrees, heuresRefusees, choisirHeuresEnPlus,
} from './etat-examen.js';

const ANTI_REBOND_MS = 500;
const ICO_CALENDRIER = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>';

let magasin = null;
let n = {};
let envoi = { valeur: null, minuteur: null };

// ─── Textes (purs) ───────────────────────────────────────────────────────────

/** « Mohamed ABDOU, le 24 octobre : 6 h de préparation avant l'examen. » */
export function textePreconisation(c) {
  if (!c) return 'Aucune préconisation du moniteur pour l’instant.';
  const quand = dateEnLettres(c.date);
  return `${c.moniteur || 'Le moniteur'}${quand ? `, le ${quand}` : ''} : ${heures(c.heures)} de préparation avant l’examen.`;
}

/** « Ajourné le 21 octobre · forfait de représentation », « Absent le 21 octobre · … ». */
export function texteRepresentation(r) {
  const quand = dateEnLettres(r.le);
  return `${r.motif === 'absent' ? 'Absent' : 'Ajourné'}${quand ? ` le ${quand}` : ''} · forfait de représentation`;
}

/** Sous « Heures à payer » : le calcul, en clair. */
export function detailHeuresAPayer(c) {
  if (c.representation) return 'Forfait de l’agence';
  if (c.manquantes === 0) return 'Toutes les heures sont déjà réglées';
  if (c.plancher > c.saisie) return `${heures(c.preconisees)} préconisées − ${heures(c.disponibles)} comprises dans la formule`;
  return `${heures(c.preconisees)} préconisées − ${heures(c.disponibles)} disponibles`;
}

/** À droite de « Heures à payer » : « 4 h · 239,60 € », ou « aucune ». */
export function valeurHeuresAPayer(c) {
  if (c.manquantes <= 0) return 'aucune';
  return c.manquantesCents !== null ? `${heures(c.manquantes)} · ${euros(c.manquantesCents)}` : heures(c.manquantes);
}

// ─── Pièces ──────────────────────────────────────────────────────────────────

function enTete(p) {
  if (p.representation) {
    return el('div', { class: 'examen-bandeau examen-bandeau-warn' },
      el('span', { class: 'examen-bandeau-titre' }, texteRepresentation(p.representation)));
  }
  const ex = p.examen;
  const ico = el('span', { class: 'examen-ico', 'aria-hidden': 'true' });
  ico.innerHTML = ICO_CALENDRIER; // pictogramme constant, sans donnée
  if (!ex) {
    return el('div', { class: 'examen-bandeau examen-bandeau-gris' }, ico, el('span', { class: 'examen-bandeau-titre' }, 'Pas encore de date d’examen'));
  }
  const sous = [ex.epreuve, ex.centre].filter(Boolean).join(' · ');
  return el('div', { class: 'examen-bandeau examen-bandeau-info' }, ico,
    el('span', { class: 'examen-bandeau-texte' },
      el('span', { class: 'examen-bandeau-titre' }, `Examen prévu le ${dateEnLettres(ex.date, { jourSemaine: true })}`),
      sous ? el('span', { class: 'examen-bandeau-sous' }, sous) : null));
}

function ligne(titre, aide, droite, extra = null) {
  return el('div', { class: 'examen-ligne' },
    el('span', { class: 'examen-ligne-gauche' }, el('span', { class: 'examen-ligne-titre' }, titre),
      aide ? el('span', { class: 'examen-aide' }, aide) : null, extra),
    droite);
}

/** − / nombre / + : saisie au clavier possible, bornée par la transition. */
function compteur(id, libelle, auChangement) {
  const champ = el('input', {
    class: 'examen-champ', id, type: 'text', inputmode: 'numeric', autocomplete: 'off', 'aria-label': libelle, 'data-verrou': '',
  });
  champ.addEventListener('input', () => {
    const v = champ.value.replace(/\D/g, '');
    if (v !== '') auChangement(Number(v));
  });
  champ.addEventListener('blur', () => { champ.value = champ.dataset.valeur || '0'; });
  const bouton = (signe, delta, aria) => el('button', {
    type: 'button', class: 'examen-pas', 'aria-label': aria, 'data-verrou': '',
    onclick: () => auChangement((Number(champ.dataset.valeur) || 0) + delta),
  }, signe);
  const boite = el('span', { class: 'examen-valeur' }, champ, el('span', { 'aria-hidden': 'true' }, 'h'));
  return { noeud: el('span', { class: 'examen-compteur' }, bouton('−', -1, `${libelle} : une de moins`), boite, bouton('+', 1, `${libelle} : une de plus`)), champ };
}

function poser(champ, valeur) {
  champ.dataset.valeur = String(valeur);
  if (document.activeElement !== champ) champ.value = String(valeur);
}

// ─── Construction et mise à jour ─────────────────────────────────────────────

/** Le contenu de l'onglet, construit une fois par élève. */
export function contenuExamen(etat) {
  const p = prepaCourante(etat);
  n = {};
  if (!p) return [el('p', { class: 'muted petit' }, 'Examen indisponible.')];
  const c = calculExamen(etat);
  const carte = el('div', { class: 'carte carte-examen' }, enTete(p));
  const rep = p.representation;
  carte.append(el('div', { class: 'examen-titre' },
    el('span', { class: 'gras' }, rep ? 'Forfait de représentation' : 'Bon pour examen · préconisation du moniteur'),
    el('span', { class: 'examen-sous' }, rep
      ? `${heures(rep.heures)} de reprise + accompagnement à l’examen.`
      : textePreconisation(p.preconisation))));

  if (c && !c.ancien && c.passage) {
    const lignes = el('div', { class: 'examen-lignes' });
    if (!rep) {
      n.dispo = compteur('examenDisponibles', 'Heures encore disponibles', (v) => magasin.appliquer(saisirHeuresDisponibles, v));
      n.confirmation = el('span', { class: 'examen-confirmation', role: 'status' });
      lignes.append(ligne('Heures encore disponibles',
        'Ouvrez le logiciel de gestion, vérifiez combien d’heures il reste à l’élève, puis indiquez-les ici.', n.dispo.noeud, n.confirmation));
    }
    n.aPayerAide = el('span', { class: 'examen-aide' });
    n.aPayer = el('span', { class: 'examen-montant' });
    lignes.append(el('div', { class: 'examen-ligne' },
      el('span', { class: 'examen-ligne-gauche' }, el('span', { class: 'examen-ligne-titre' }, rep ? 'Heures de reprise' : 'Heures à payer'), n.aPayerAide),
      n.aPayer));
    n.enPlus = compteur('examenEnPlus', 'Heures en plus', (v) => magasin.appliquer(choisirHeuresEnPlus, v));
    lignes.append(ligne('Heures en plus', 'Si l’élève en demande', n.enPlus.noeud));
    n.acc = el('span', { class: 'examen-montant' });
    lignes.append(ligne('Accompagnement à l’examen', null, n.acc));
    carte.append(lignes);
  } else if (c && c.ancien) {
    // CRM d'avant le 26/10 : les lignes qu'il a calculées, telles quelles.
    for (const l of c.lignes) carte.append(ligne(l.libelle, null, el('span', { class: 'examen-montant' }, euros(l.montantCents))));
  }

  const blocs = [carte];
  if (p.indisponible) blocs.push(el('div', { class: 'encart encart-warn' }, p.indisponible));
  else if (!c || (!c.ancien && !c.passage) || (c.ancien && !c.lignes.length)) {
    blocs.push(el('div', { class: 'encart encart-info' }, 'Rien à régler pour l’examen : aucun bon pour examen du moniteur pour l’instant.'));
  }
  return blocs;
}

function texteConfirmation(ex, c) {
  if (!ex) return { texte: '', genre: '' };
  if (ex.statut === 'erreur') return { texte: ex.message, genre: 'erreur' };
  if (ex.statut === 'attente' || ex.statut === 'envoi') return { texte: 'Mise à jour de la fiche…', genre: 'attente' };
  if (ex.statut === 'ok') return { texte: `✓ Fiche mise à jour : ${heures(c.saisie)} disponibles`, genre: 'ok' };
  return { texte: '', genre: '' };
}

/** À chaque changement d'état, sur l'onglet Examen : textes et valeurs seulement. */
export function majExamen(etat) {
  if (etat.onglet !== 'prepa' || !n.aPayer) return;
  const c = calculExamen(etat);
  if (!c || c.ancien) return;
  if (n.dispo) {
    poser(n.dispo.champ, c.saisie);
    const conf = texteConfirmation(etat.examen, c);
    n.confirmation.textContent = conf.texte;
    n.confirmation.dataset.genre = conf.genre;
  }
  n.aPayerAide.textContent = detailHeuresAPayer(c);
  n.aPayer.textContent = valeurHeuresAPayer(c);
  poser(n.enPlus.champ, c.enPlus);
  n.acc.textContent = c.accCents ? euros(c.accCents) : 'rien à régler pour ce passage';
  planifierEnvoi(etat);
}

// ─── Enregistrement des heures sur la fiche ──────────────────────────────────

function planifierEnvoi(etat) {
  const ex = etat.examen;
  if (!ex || ex.statut !== 'attente') return;
  if (envoi.minuteur && envoi.valeur === ex.saisie) return;
  clearTimeout(envoi.minuteur);
  envoi = { valeur: ex.saisie, minuteur: setTimeout(() => envoyer(ex.saisie), ANTI_REBOND_MS) };
}

async function envoyer(valeur) {
  envoi.minuteur = null;
  const etat = magasin.lire();
  if (!etat.eleve || !etat.examen || etat.examen.saisie !== valeur) return;
  const id = etat.eleve.eleve.id;
  magasin.appliquer(heuresEnvoyees, valeur);
  // Chargé à la demande : ce module reste importable sous node (tests des textes).
  const api = await import('./api.js');
  const r = await api.heuresDisponibles(id, valeur);
  const apres = magasin.lire();
  if (!apres.eleve || apres.eleve.eleve.id !== id) return;
  if (r.ok && r.data && r.data.prepa) return magasin.appliquer(heuresEnregistrees, valeur, r.data.prepa);
  if (r.status === 401) return magasin.appliquer(identificationRequise, (r.data && r.data.code) || 'jeton_expire', r.message);
  return magasin.appliquer(heuresRefusees, valeur, r.message);
}

export function initExamen(m) {
  magasin = m;
}
