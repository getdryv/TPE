// ─── Le paiement en chèques : nombre, 1er chèque, échéancier ─────────────────
//
// Rendu SEUL : aucune date ni aucun montant n'est calculé ici. Les jours
// proposés pour le 1er chèque, les dates prévues, les bornes d'avance et la
// répartition viennent de `devis.echeancier`, que le CRM recalcule à chaque
// geste. La page envoie des CHOIX (etat-cheques.js) et redessine la réponse.
//
// Pendant qu'un nouveau devis est en route, le dernier échéancier reçu POUR CE
// PANIER (même élève, produit, moyen et nombre) reste affiché : le tableau ne
// clignote pas à chaque chiffre tapé, et le bouton reste bloqué tant que le
// devis n'est pas à jour. La zone n'est reconstruite que quand sa STRUCTURE
// change (lignes, dates, bornes) ; un montant tapé ne perd jamais le focus.

import { el, remplir, eurosCourts, jourCourt, jourEtQuantieme, lendemain, aujourdhuiParis } from './format.js';
import {
  devisAJour, requeteDevis, chequesProposes, nombreCheques,
  choisirNombreCheques, choisirPremierCheque, avancerCheque, saisirMontantCheque,
} from './etat.js';
import { avecCheques } from './etat-cheques.js';
import { sousNombres, cleZoneCheques, chequeFautif } from './panier-affiche.js';

const JOURS_MAX = 62; // garde-fou de la rangée de pastilles (le réglage d'agence va jusqu'à 30 jours ouvrés)

let magasin = null;
let zone = null;
let ui = { joursOuverts: false, avanceOuverte: null };
let memo = { contexte: null, echeancier: null };
let structure = null;
let champs = [];   // [{ index, input, cellule }] des chèques 1 à n−1
let restes = [];   // [{ rang, noeud }] montants affichés en texte
let alerte = null; // erreur du CRM sur un montant ou une date
let ligneAlerte = null; // rangée pleine largeur qui la porte sous le chèque fautif (A2)
let alerteVue = '';  // dernier message amené à l'écran

/** 58600 → « 586 », 58650 → « 586,50 » : la valeur d'un champ de montant. */
function enSaisie(cents) {
  if (!Number.isInteger(cents)) return '';
  const e = Math.floor(cents / 100);
  const c = cents % 100;
  return c ? `${e},${String(c).padStart(2, '0')}` : String(e);
}

const agir = (transition, ...args) => magasin.appliquer(transition, ...args);

// ─── Pièces ──────────────────────────────────────────────────────────────────

function rangeeNombre(etat, proposes, nombre, verrou) {
  const esp = etat.moyen === 'especes_cheques';
  if (proposes < 1) {
    return el('div', { class: 'encart encart-warn' },
      'Cette formule se règle en une seule fois : choisissez Chèques ou Espèces.');
  }
  // Le prix sous le nombre : l'œil n'a pas à faire l'aller-retour vers le total.
  const boutons = sousNombres(etat, proposes).map((sous, i) => {
    const k = i + 1;
    return el('button', {
      type: 'button', class: 'sel nb-choix', 'aria-pressed': String(nombre === k), disabled: verrou,
      onclick: () => agir(choisirNombreCheques, k),
    }, `En ${k + (esp ? 1 : 0)} fois`, el('small', {}, sous));
  });
  return el('div', {},
    el('span', { class: 'etiq', id: 'nbChequesLib' }, 'Payer en combien de fois ?'),
    el('div', { class: 'nb', role: 'group', 'aria-labelledby': 'nbChequesLib', style: `grid-template-columns:repeat(${proposes},minmax(0,1fr))` }, boutons),
  );
}

function libellePremier(ech, nombre) {
  const premier = ech.premier;
  const date = ech.versements.find((v) => v.nature === 'cheque').dueOn;
  const quand = date === lendemain(aujourdhuiParis())
    ? `demain, ${jourCourt(date)}`
    : date === premier.defaut ? `au prochain jour ouvré, ${jourCourt(date)}` : `le ${jourCourt(date)}`;
  return { date, texte: `${nombre === 1 ? 'Chèque remis' : '1er chèque remis'} ${quand}` };
}

/** Les jours de remise du 1er chèque : ceux que le CRM autorise, les autres grisés. */
function pastillesJours(ech, choisi, verrou, delai) {
  const { min, max, selectionnables, defaut } = ech.premier;
  const permis = new Set(selectionnables);
  const demain = lendemain(aujourdhuiParis());
  let jour = demain && demain < min ? demain : min;
  const pastilles = [];
  for (let i = 0; i < JOURS_MAX && jour && jour <= max; i += 1, jour = lendemain(jour)) {
    const iso = jour;
    const ouvert = permis.has(iso);
    pastilles.push(el('button', {
      type: 'button', class: 'sel', 'aria-pressed': String(iso === choisi), disabled: verrou || !ouvert,
      title: ouvert ? null : 'Banque fermée', 'aria-label': jourCourt(iso),
      onclick: () => { ui.joursOuverts = false; agir(choisirPremierCheque, iso === defaut ? null : iso); },
    }, jourEtQuantieme(iso)));
  }
  const limite = `Au plus tard le ${jourCourt(max)}${Number.isInteger(delai) ? ` : ${delai} jours ouvrés après l'encaissement.` : '.'}`;
  return [el('div', { class: 'jours', role: 'group', 'aria-label': 'Date du premier chèque' }, pastilles),
    el('p', { class: 'sousligne' }, limite)];
}

function blocPremier(etat, ech, nombre, verrou) {
  const { date, texte } = libellePremier(ech, nombre);
  const delai = etat.eleve && etat.eleve.cheques ? etat.eleve.cheques.delaiJoursOuvres : null;
  return [
    el('div', { class: 'ech-tete' }, el('span', {}, texte),
      el('button', {
        type: 'button', class: 'lien-btn', 'aria-expanded': String(ui.joursOuverts), disabled: verrou,
        onclick: () => { ui.joursOuverts = !ui.joursOuverts; rendreCheques(magasin.lire()); },
      }, ui.joursOuverts ? 'Fermer' : 'Changer')),
    ...(ui.joursOuverts ? pastillesJours(ech, date, verrou, delai) : []),
  ];
}

function celluleDate(v, verrou) {
  const index = v.numeroCheque - 1;
  const contenu = [el('span', {}, v.nature === 'especes' ? 'aujourd\'hui' : jourCourt(v.dueOn))];
  if (v.avance) contenu.push(el('span', { class: 'sousligne bloc gras' }, `avancé (prévu le ${jourCourt(v.prevuLe)})`));
  if (!v.avancable || v.nature !== 'cheque') return el('td', {}, contenu);
  if (ui.avanceOuverte === index && !verrou) {
    const champ = el('input', {
      class: 'in in-date', type: 'date', min: v.min, max: v.max, value: v.dueOn,
      'aria-label': `Date de remise du chèque ${v.numeroCheque}`,
    });
    champ.addEventListener('change', () => {
      ui.avanceOuverte = null;
      agir(avancerCheque, index, champ.value && champ.value !== v.prevuLe ? champ.value : null);
      rendreCheques(magasin.lire());
    });
    contenu.push(el('span', { class: 'bloc' }, champ),
      el('span', { class: 'sousligne bloc' }, `Jour ouvré, du ${jourCourt(v.min)} au ${jourCourt(v.max)}`));
  } else {
    contenu.push(el('button', {
      type: 'button', class: 'lien-btn bloc', disabled: verrou,
      onclick: () => { ui.avanceOuverte = index; rendreCheques(magasin.lire()); },
    }, 'Avancer'));
  }
  return el('td', {}, contenu);
}

function celluleMontant(v, nombre, verrou) {
  if (v.montantModifiable && v.nature === 'cheque') {
    const index = v.numeroCheque - 1;
    const input = el('input', {
      class: 'in in-cheque', type: 'text', inputmode: 'decimal', autocomplete: 'pas-de-remplissage-auto',
      'aria-label': `Montant du chèque ${v.numeroCheque}`, disabled: verrou,
    });
    input.addEventListener('input', () => agir(saisirMontantCheque, index, input.value));
    input.addEventListener('focus', () => input.select());
    champs.push({ index, input, rangee: null });
    return el('td', {}, el('span', { class: 'mt-ch' }, input, el('span', { 'aria-hidden': 'true' }, '€')));
  }
  const noeud = el('span', { class: 'num' }, eurosCourts(v.amountCents));
  restes.push({ rang: v.rang, noeud });
  const reste = v.nature === 'cheque' && nombre > 1 ? el('span', { class: 'sousligne bloc' }, 'ajusté au centime') : null;
  return el('td', {}, noeud, reste);
}

function libelleVersement(v, esp) {
  if (v.nature === 'especes') return [el('span', {}, `Versement ${v.rang}`), el('span', { class: 'sousligne bloc' }, 'espèces')];
  if (!esp) return [el('span', {}, `Chèque ${v.numeroCheque}`)];
  return [el('span', {}, `Versement ${v.rang}`), el('span', { class: 'sousligne bloc' }, `chèque ${v.numeroCheque}`)];
}

function tableau(ech, nombre, verrou) {
  const esp = ech.moyen === 'especes_cheques';
  const lignes = ech.versements.map((v) => {
    const avant = champs.length;
    const tr = el('tr', {}, el('td', {}, libelleVersement(v, esp)), celluleDate(v, verrou), celluleMontant(v, nombre, verrou));
    if (champs.length > avant) champs[champs.length - 1].rangee = tr;
    return tr;
  });
  const reglable = ech.versements.some((v) => v.montantModifiable || v.avancable);
  return [
    el('table', { class: 'ech', 'aria-label': 'Échéancier' }, el('tbody', {}, lignes)),
    el('div', { class: 'place-alerte' }),
    reglable ? el('p', { class: 'sousligne' },
      'Modifiez un montant (un gros 1er chèque, par exemple) : les autres se recalculent seuls. Une date peut être avancée à la demande de l\'élève, jamais reculée.') : null,
  ];
}

// ─── Rendu ───────────────────────────────────────────────────────────────────

/** Met les montants à jour sans reconstruire : le champ en cours de frappe garde son texte et son focus. */
function majMontants(etat, ech) {
  if (!ech) return;
  for (const { index, input } of champs) {
    if (document.activeElement === input) continue;
    const saisi = etat.cheques.montants[index];
    const v = ech.versements.find((x) => x.numeroCheque === index + 1);
    const valeur = saisi && saisi.trim() ? saisi : enSaisie(v && v.amountCents);
    if (input.value !== valeur) input.value = valeur;
  }
  for (const { rang, noeud } of restes) {
    const v = ech.versements.find((x) => x.rang === rang);
    noeud.textContent = v ? eurosCourts(v.amountCents) : '—';
  }
}

/**
 * L'erreur du CRM : sous le chèque fautif quand elle vise un montant (A2,
 * lisible sans défiler, à côté du champ entouré), sinon sous l'échéancier.
 * Déplacer le message ne touche pas au champ : la frappe garde son focus.
 */
function placerAlerte(etat, erreur) {
  const i = erreur ? chequeFautif(etat.devisChamp, etat.cheques.montants) : null;
  const cible = i === null ? null : champs.find((c) => c.index === i);
  const place = zone.querySelector('.place-alerte');
  if (cible && cible.rangee) {
    ligneAlerte.firstChild.appendChild(alerte);
    if (cible.rangee.nextSibling !== ligneAlerte) cible.rangee.after(ligneAlerte);
  } else {
    ligneAlerte.remove();
    if (place && alerte.parentNode !== place) place.appendChild(alerte);
    else if (!place && alerte.parentNode !== zone) zone.appendChild(alerte);
  }
  // Un nouveau message est amené à l'écran (le corps du panier défile) ; pas à chaque frappe.
  if (erreur && erreur !== alerteVue && typeof alerte.scrollIntoView === 'function') alerte.scrollIntoView({ block: 'nearest' });
  alerteVue = erreur || '';
}

/** L'erreur du CRM, placée près du champ fautif ; les montants saisis sont entourés. */
function majAlerte(etat, erreur) {
  alerte.hidden = !erreur;
  alerte.textContent = erreur || '';
  placerAlerte(etat, erreur);
  const montants = Boolean(erreur) && etat.devisChamp === 'montants';
  for (const { index, input } of champs) {
    const saisi = String(etat.cheques.montants[index] || '').trim();
    input.setAttribute('aria-invalid', String(montants && Boolean(saisi)));
  }
}

/** `erreur` : message du CRM qui désigne un montant ou une date (panier.js), ou null. */
export function rendreCheques(etat, erreur = null) {
  if (!zone) return;
  // Sans formule choisie, il n'y a rien à découper : la zone attend.
  if (etat.ecran !== 'panier' || !avecCheques(etat.moyen) || !etat.produit) {
    zone.hidden = true;
    ui = { joursOuverts: false, avanceOuverte: null };
    structure = null;
    return;
  }
  zone.hidden = false;
  const verrou = Boolean(etat.paiement);
  const proposes = chequesProposes(etat);
  const nombre = nombreCheques(etat);

  const contexte = JSON.stringify([etat.eleve && etat.eleve.eleve.id, etat.produit, etat.moyen, nombre]);
  if (contexte !== memo.contexte) memo = { contexte, echeancier: null };
  if (devisAJour(etat) && etat.devis.echeancier) memo.echeancier = etat.devis.echeancier;
  const ech = nombre ? memo.echeancier : null;

  const cle = cleZoneCheques(etat, { proposes, nombre, ech, verrou, ui });
  if (cle !== structure) {
    structure = cle;
    champs = [];
    restes = [];
    remplir(zone,
      rangeeNombre(etat, proposes, nombre, verrou),
      nombre && !ech && requeteDevis(etat).corps ? el('p', { class: 'sousligne' }, 'Calcul de l\'échéancier…') : null,
      ech && ech.premier ? blocPremier(etat, ech, nombre, verrou) : null,
      ech ? tableau(ech, nombre, verrou) : null);
  }
  majMontants(etat, ech);
  majAlerte(etat, erreur);
}

export function initCheques(m, conteneur) {
  magasin = m;
  zone = conteneur;
  alerte = el('p', { class: 'reste trop', role: 'alert', hidden: true });
  ligneAlerte = el('tr', { class: 'ligne-alerte' }, el('td', { colspan: '3' }));
}
