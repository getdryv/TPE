// ─── Le panier, piloté PAR LE DEVIS du CRM ───────────────────────────────────
//
// À chaque choix (tuile, moyen, espèces saisies), la page redemande un devis au
// CRM, qui renvoie les lignes, le total et la répartition espèces / carte. Le
// panier n'affiche QUE ce devis, et le bouton porte SON montant : ce qui est
// écrit sur le bouton est exactement ce que le lecteur débitera. Sans devis
// valide pour le panier affiché, le bouton reste désactivé.
//
// Les erreurs du CRM (rien à régler, espèces ≥ total, montants des chèques…)
// sont affichées telles quelles : c'est lui qui connaît la règle, pas la page.
// Aucun moyen n'est présélectionné ; le rendu des chèques vit dans cheques.js,
// le compteur des espèces dans compteur-especes.js : le bouton reste bloqué
// tant que le compté n'égale pas PILE la part espèces.
//
// Le squelette est construit une fois ; chaque rendu ne met à jour que des
// textes et des états (aucun champ recréé pendant une frappe).

import * as api from './api.js';
import { el, remplir, eurosCourts } from './format.js';
import {
  requeteDevis, devisAJour, choisirMoyen, devisRecu, devisRefuse,
  basculerSecours, identificationRequise, nombreCheques, chequesProposes, MOYENS_REPRISE,
} from './etat.js';
import { analyseEspeces, compteVisible, comptageAccepte } from './etat-especes.js';
import { construireCompteur, rendreCompteur, texteRendu } from './compteur-especes.js';
import { noteReprise } from './reprise.js';
import { avecCheques } from './etat-cheques.js';
import { envoyerCarte, annulerPaiement, lecteurPret, raisonLecteurActuel } from './paiement.js';
import { encaisserSansCarte, initSansCarte, MOYENS_SANS_CARTE } from './sans-carte.js';
import { initCheques, rendreCheques } from './cheques.js';
import {
  CHAMPS_DU_PANIER, retenirDevis, devisAffiche, resteAffiche, prixCatalogue, texteReste, libelleCorrection,
} from './panier-affiche.js';

// Assez pour laisser finir la frappe des espèces, assez court pour que le prix
// suive le doigt quand on touche une tuile.
const ANTI_REBOND_MS = 300;

// Deux rangées : Carte, Espèces, Chèques ; puis les deux paiements mixtes.
const MOYENS = [['carte', 'Carte', ''], ['especes', 'Espèces', ''], ['cheques', 'Chèques', ''],
  ['mixte', 'Espèces + carte', ' large'], ['especes_cheques', 'Espèces + chèques', ' large']];

const MANQUE = {
  produit: 'Touchez une formule',
  montant: 'Saisissez le montant',
  moyen: 'Choisissez le moyen de paiement',
  especes: 'Saisissez le montant reçu en espèces',
  nombre: 'Choisissez en combien de fois',
  montants: 'Corrigez les montants des chèques',
  cheque: 'Cochez le chèque repris',
};

// Le comptage pas encore juste : le bouton dit ce qui manque (maquettes 01 à 04).
const COMPTAGE = { vide: 'Comptez les espèces', manque: 'Complétez le comptage', trop: 'Rendez d\'abord le trop-perçu', attente: 'Calcul du prix…' };

const ETAPES = {
  envoi: 'Envoi au lecteur…',
  carte: 'Présentez la carte sur le lecteur…',
  capture: 'Carte acceptée. Encaissement…',
  especes: 'Enregistrement…',
};

let magasin = null;
let n = {};                 // nœuds du squelette
let minuteur = null;
let demande = { version: -1, controleur: null };
let dernier = null;         // dernier devis reçu pour ce panier (panier-affiche.js)

// ─── Devis ───────────────────────────────────────────────────────────────────

async function demanderDevis(version, corps) {
  if (demande.controleur) demande.controleur.abort();
  const controleur = new AbortController();
  demande = { version, controleur };
  const r = await api.devis(corps, controleur.signal);
  if (r.annule || demande.controleur !== controleur) return false;
  demande.controleur = null;
  if (r.ok && r.data && r.data.devis && r.data.jeton) {
    magasin.appliquer(devisRecu, version, r.data);
    return devisAJour(magasin.lire());
  }
  if (r.indisponible) magasin.appliquer(basculerSecours, { indisponible: true });
  else if (r.status === 401) magasin.appliquer(identificationRequise, (r.data && r.data.code) || 'jeton_expire', r.message);
  else magasin.appliquer(devisRefuse, version, r.message, r.data && typeof r.data.champ === 'string' ? r.data.champ : null);
  return false;
}

/** Redemande tout de suite le devis du panier affiché (devis expiré au lecteur). */
export async function redemanderDevis() {
  const etat = magasin.lire();
  const req = requeteDevis(etat);
  if (!req.corps) return false;
  return demanderDevis(etat.version, req.corps);
}

function planifierDevis(etat) {
  if (etat.ecran !== 'panier' || etat.paiement || devisAJour(etat) || etat.devisErreur) return;
  if (demande.version === etat.version) return; // déjà demandé pour ce panier
  const req = requeteDevis(etat);
  clearTimeout(minuteur);
  if (!req.corps) {
    if (demande.controleur) demande.controleur.abort();
    demande = { version: -1, controleur: null };
    return;
  }
  const version = etat.version;
  demande = { version, controleur: demande.controleur };
  minuteur = setTimeout(() => {
    if (magasin.lire().version === version) demanderDevis(version, req.corps);
  }, ANTI_REBOND_MS);
}

// ─── Squelette ───────────────────────────────────────────────────────────────

function construire() {
  n.lignes = el('div', { class: 'lignes-panier', style: 'display:flex;flex-direction:column;gap:10px' });
  n.total = el('span', {}, '—');
  n.surcout = el('p', { class: 'surcout' });
  n.note = el('p', { class: 'muted note' });
  n.moyens = MOYENS.map(([code, libelle, large]) => el('button', {
    type: 'button', class: `sel moyen${large}`, 'aria-pressed': 'false', 'data-moyen': code,
    onclick: () => magasin.appliquer(choisirMoyen, code),
  }, libelle));

  n.compteur = construireCompteur(magasin);
  n.zoneCheques = el('div', { class: 'zone-cheques' });
  n.erreur = el('div', { class: 'encart encart-erreur', role: 'alert' });
  n.statut = el('div', { class: 'statut', role: 'status' });
  // Sur téléphone, le compteur est hors de vue : la consigne de rendu monte dans le pied collant.
  n.consignePied = el('p', { class: 'consigne-pied', 'aria-hidden': 'true' });
  n.principal = el('button', { type: 'button', class: 'btn btnp', onclick: agir });
  n.secondaire = el('button', { type: 'button', class: 'btn', onclick: secondaire });

  n.totalBarre = el('span', {}, '—');
  n.action = el('div', { class: 'panier-action' },
    el('div', { class: 'barre-total', 'aria-hidden': 'true' }, el('span', {}, 'Total'), n.totalBarre),
    n.erreur, n.statut, n.consignePied, n.principal, n.secondaire);

  // Le corps défile, la barre d'action jamais : le bouton de validation reste
  // à l'écran (colonne collante sur ordinateur, barre fixe en bas sur mobile).
  remplir(document.getElementById('panier'),
    el('div', { class: 'panier-corps' },
      el('div', { class: 'panier-titre' }, 'À encaisser'),
      n.lignes,
      el('div', { class: 'total' }, el('span', {}, 'Total'), n.total),
      n.surcout,
      n.note,
      el('div', {},
        el('span', { class: 'etiq', id: 'moyensLib' }, 'Moyen de paiement'),
        el('div', { class: 'moyens', role: 'group', 'aria-labelledby': 'moyensLib' }, n.moyens)),
      n.compteur, n.zoneCheques),
    n.action);
  initCheques(magasin, n.zoneCheques);
  mesurer();
}

/**
 * Hauteurs réelles de l'en-tête (il passe à la ligne sur écran moyen) et de
 * la barre d'action mobile, publiées en variables CSS : la colonne du panier
 * tient dans la fenêtre, et la page garde la place de la barre fixe.
 */
function mesurer() {
  const entete = document.querySelector('.entete');
  const publier = () => {
    const racine = document.documentElement.style;
    if (entete) racine.setProperty('--entete-h', `${entete.offsetHeight}px`);
    racine.setProperty('--barre-h', `${n.action.offsetHeight + 16}px`);
  };
  publier();
  if (typeof ResizeObserver === 'function') {
    const o = new ResizeObserver(publier);
    if (entete) o.observe(entete);
    o.observe(n.action);
  }
}

// ─── Actions ─────────────────────────────────────────────────────────────────

// Le bouton atteste ce qu'il dit (« Encaisser 90 € en espèces », « J'ai les
// 3 chèques · Encaisser 1 760 € ») : pas de case à cocher ni de confirmation.
function agir() {
  const etat = magasin.lire();
  if (!devisAJour(etat) || etat.paiement || !comptageAccepte(etat)) return;
  if (MOYENS_SANS_CARTE.includes(etat.moyen)) return encaisserSansCarte();
  return envoyerCarte();
}

/** Entrée dans la feuille de comptage : encaisse si le bouton est actif (et le dit). */
export function validerSiPret() {
  if (!n.principal || n.principal.disabled) return false;
  agir();
  return true;
}

function secondaire() {
  if (magasin.lire().paiement) annulerPaiement();
}

// ─── Rendu ───────────────────────────────────────────────────────────────────

function lignesDevis(etat, affiche, catalogue) {
  const ligne = (libelle, cents, promo) => el('div', { class: `ligne-panier${promo ? ' ligne-promo' : ''}` },
    el('span', {}, libelle), el('span', {}, eurosCourts(cents)));
  if (affiche.devis) return affiche.devis.lignes.map((l) => ligne(l.libelle, l.montantCents, l.nature === 'promo'));
  if (catalogue) return [ligne(catalogue.libelle, catalogue.totalCents, false)];
  const req = requeteDevis(etat);
  if (!req.corps || etat.devisErreur) return [];
  return [el('div', { class: 'muted petit' }, 'Calcul du prix…')];
}

function texteNote(etat) {
  if (etat.onglet === 'reprise') return noteReprise(etat);
  if (etat.onglet === 'prepa') return 'Payer ici marque la prépa comme réglée : les relances par e-mail s\'arrêtent, comme avec le lien de paiement.';
  if (etat.onglet === 'heures_supp' && etat.accompagnement) {
    return 'L\'accompagnement payé ici vaut pour le passage en cours : les relances s\'arrêtent, comme avec la prépa.';
  }
  return '';
}

/** « Prix en 3 fois · 70 € de plus qu'en 1 fois », ou « Prix comptant » : lu dans le devis affiché. */
function texteSurcout(devis, catalogue, etat) {
  if (etat && etat.onglet === 'reprise') return ''; // une reprise n'a pas de prix « comptant » : c'est le montant du chèque
  if (!devis) return catalogue ? (catalogue.versements > 1 ? `Prix en ${catalogue.versements} fois` : 'Prix comptant') : '';
  const ech = devis.echeancier;
  if (!ech || ech.prix !== 'plusieurs_fois') return 'Prix comptant';
  const fois = `Prix en ${ech.nombreVersements} fois`;
  return ech.surcoutCents > 0 ? `${fois} · ${eurosCourts(ech.surcoutCents)} de plus qu'en 1 fois` : `${fois} · même prix qu'en 1 fois`;
}

/** Libellé du bouton une fois le devis à jour : il porte le montant qui sera encaissé. */
function libelleAction(etat) {
  const d = etat.devis;
  if (avecCheques(etat.moyen)) {
    const nb = nombreCheques(etat);
    return `${nb === 1 ? 'J\'ai le chèque' : `J'ai les ${nb} chèques`} · Encaisser ${eurosCourts(d.totalCents)}`;
  }
  if (etat.moyen === 'especes') return [`Encaisser ${eurosCourts(d.totalCents)} en espèces `, el('kbd', {}, 'Entrée')];
  return `Envoyer ${eurosCourts(d.carteCents)} au lecteur`;
}

function rendreBoutons(etat, aJour) {
  const a = compteVisible(etat) ? analyseEspeces(etat) : null;
  n.consignePied.textContent = a && a.statut === 'trop' && a.rendre
    ? `Rendez ${texteRendu(a.rendre.pieces)}${a.rendre.appoint ? `, puis demandez ${eurosCourts(a.rendre.appoint)} d'appoint` : ''}` : '';
  n.secondaire.hidden = true;
  n.statut.textContent = '';
  if (etat.paiement) {
    n.principal.disabled = true;
    n.principal.textContent = ETAPES[etat.paiement.etape] || 'Paiement en cours…';
    n.secondaire.hidden = !['envoi', 'carte'].includes(etat.paiement.etape);
    n.secondaire.textContent = 'Annuler l\'encaissement';
    return;
  }
  const req = requeteDevis(etat);
  if (!req.corps) {
    n.principal.disabled = true;
    // Formule en une seule fois après des espèces : aucun nombre ne convient.
    const impossible = req.manque === 'nombre' && chequesProposes(etat) < 1;
    const comptage = req.manque === 'especes' && compteVisible(etat) ? COMPTAGE.vide : null;
    n.principal.textContent = impossible ? 'Choisissez un autre moyen de paiement' : (comptage || MANQUE[req.manque] || 'Touchez une formule');
    return;
  }
  if (!aJour) {
    n.principal.disabled = true;
    n.principal.textContent = etat.devisErreur ? libelleCorrection(etat.moyen, etat.devisChamp) : 'Calcul du prix…';
    return;
  }
  if (compteVisible(etat) && !comptageAccepte(etat)) {
    n.principal.disabled = true;
    n.principal.textContent = COMPTAGE[analyseEspeces(etat).statut] || COMPTAGE.vide;
    return;
  }
  remplir(n.principal, libelleAction(etat));
  if (MOYENS_SANS_CARTE.includes(etat.moyen)) {
    n.principal.disabled = false;
    return;
  }
  const pret = lecteurPret();
  n.principal.disabled = !pret;
  if (!pret) n.statut.textContent = raisonLecteurActuel();
}

/** Une erreur qui désigne un champ s'affiche sous ce champ ; les autres juste au-dessus du bouton. */
function rendreErreurs(etat) {
  const sousChamp = etat.devisErreur && CHAMPS_DU_PANIER.includes(etat.devisChamp) ? etat.devisChamp : null;
  const message = etat.erreur || (sousChamp ? null : etat.devisErreur);
  n.erreur.hidden = !message;
  n.erreur.textContent = message || '';
  n.erreurEspeces = sousChamp === 'especes' ? etat.devisErreur : '';
  return sousChamp && sousChamp !== 'especes' ? etat.devisErreur : null;
}

export function rendrePanier(etat) {
  if (etat.ecran !== 'panier') {
    clearTimeout(minuteur);
    return;
  }
  const aJour = devisAJour(etat);
  dernier = retenirDevis(dernier, etat);
  const affiche = devisAffiche(dernier, etat);
  const catalogue = affiche.devis ? null : prixCatalogue(etat);
  const totalCents = affiche.devis ? affiche.devis.totalCents : catalogue && catalogue.totalCents;
  remplir(n.lignes, lignesDevis(etat, affiche, catalogue));
  n.total.textContent = Number.isInteger(totalCents) ? eurosCourts(totalCents) : '—';
  n.totalBarre.textContent = n.total.textContent;
  n.surcout.textContent = texteSurcout(affiche.devis, catalogue, etat);
  n.note.textContent = texteNote(etat);
  n.note.hidden = !n.note.textContent;

  const verrou = Boolean(etat.paiement);
  // Reprise de chèque : Carte ou Espèces seulement, sur une rangée (maquette « Reprise de chèque »).
  const reprise = etat.onglet === 'reprise';
  n.moyens.forEach((b) => {
    b.setAttribute('aria-pressed', String(b.dataset.moyen === etat.moyen));
    b.disabled = verrou;
    b.hidden = reprise && !MOYENS_REPRISE.includes(b.dataset.moyen);
    b.classList.toggle('large', reprise || ['mixte', 'especes_cheques'].includes(b.dataset.moyen));
  });
  const reste = resteAffiche(dernier, etat, affiche);
  const chequesErreur = rendreErreurs(etat);
  rendreCompteur(etat, { reste, texteReste: reste === null ? '' : texteReste(etat.moyen, eurosCourts(reste)), erreur: n.erreurEspeces });
  rendreCheques(etat, chequesErreur);

  rendreBoutons(etat, aJour);
  planifierDevis(etat);
}

export function initPanier(m) {
  magasin = m;
  initSansCarte(m);
  construire();
}
