// ─── Le lecteur et l'encaissement ────────────────────────────────────────────
//
// Cette page ne parle jamais au lecteur. Elle demande à notre serveur, qui
// demande à Stripe, qui pousse l'ordre au lecteur. En contrepartie, la page ne
// sait pas ce qui se passe sur le lecteur : elle demande où en est le paiement,
// régulièrement, jusqu'à une issue.
//
// Ce qui part au lecteur est le DEVIS (son jeton signé), jamais un montant : le
// serveur relit la part carte dans le devis vérifié. La page n'a aucun moyen de
// modifier le prix débité.
//
// Rien n'est enregistré dans le CRM tant que l'encaissement n'est pas complet :
// la déclaration part du serveur, après capture.

import * as api from './api.js';
import { el, remplir, nomComplet } from './format.js';
import {
  devisAJour, paiementEtape, paiementErreur, paiementRefuse, paiementAccepte, identificationRequise,
} from './etat.js';

export const DELAI_SONDAGE_MS = 1500;
// Deux minutes : au-delà, la carte ne viendra plus et laisser l'écran du
// lecteur bloqué empêcherait l'encaissement suivant.
export const DELAI_ABANDON_MS = 120000;

let magasin = null;
let redemanderDevis = async () => false;
let surLecteur = () => {};
let lecteurs = [];
let lecteurChoisi = null;
let enCours = null; // { pi, lecteur, annulation }

const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

export const lecteurActuel = () => lecteurChoisi;

// ─── Lecteurs ────────────────────────────────────────────────────────────────
//
// L'état du lecteur choisi est affiché EN PERMANENCE dans l'en-tête (nom +
// prêt / hors ligne / occupé), relu toutes les 30 secondes et au retour sur
// l'onglet. « Envoyer au lecteur » n'est actif que s'il est prêt ; sinon le
// panier dit pourquoi, en mots de comptoir. Une erreur technique (clé Stripe
// refusée…) n'est JAMAIS montrée brute à une secrétaire : message humain pour
// tous, détail technique en plus pour un administrateur.

const RELECTURE_LECTEURS_MS = 30000;
const LECTEURS_INDISPONIBLES = 'Lecteur indisponible : vérifiez la configuration Stripe de l\'agence';

let etatLecteurs = 'chargement'; // chargement | ok | erreur
let detailTechnique = null;       // message brut de l'erreur, pour un administrateur
let rendu = null;                 // ce que l'en-tête montre déjà (rôle, paiement en cours)

const estAdmin = () => Boolean(magasin && magasin.lire().utilisateur && magasin.lire().utilisateur.role === 'admin');
const choisi = () => lecteurs.find((x) => x.id === lecteurChoisi) || null;

/** PURE. Pourquoi le lecteur n'est pas prêt, en mots de comptoir ; null s'il l'est. */
export function raisonLecteur(etat, liste, id) {
  if (etat === 'chargement') return 'Recherche du lecteur…';
  if (etat === 'erreur') return `${LECTEURS_INDISPONIBLES}.`;
  if (!liste.length) return 'Aucun lecteur enregistré pour cette agence : un administrateur doit en ajouter un dans Stripe.';
  const l = liste.find((x) => x.id === id);
  if (!l) return 'Choisissez un lecteur.';
  if (!l.enLigne) return `Lecteur « ${l.label} » hors ligne : vérifiez qu'il est allumé et connecté à Internet.`;
  if (l.occupe) return `Lecteur « ${l.label} » occupé par un autre paiement : patientez, ou choisissez un autre lecteur.`;
  return null;
}

export const raisonLecteurActuel = () => raisonLecteur(etatLecteurs, lecteurs, lecteurChoisi);
export const lecteurPret = () => raisonLecteurActuel() === null;

function pastilleLecteur() {
  if (etatLecteurs === 'chargement') return el('span', { class: 'chip grey' }, 'Recherche du lecteur…');
  if (etatLecteurs === 'erreur') return el('span', { class: 'chip warn' }, LECTEURS_INDISPONIBLES);
  const l = choisi();
  if (!l) return el('span', { class: 'chip warn' }, 'Aucun lecteur');
  const enPaiement = Boolean(magasin && magasin.lire().paiement);
  if (enPaiement) return el('span', { class: 'chip info' }, `Lecteur « ${l.label} » : paiement en cours`);
  if (!l.enLigne) return el('span', { class: 'chip warn' }, `Lecteur « ${l.label} » hors ligne`);
  if (l.occupe) return el('span', { class: 'chip warn' }, `Lecteur « ${l.label} » occupé`);
  return el('span', { class: 'chip ok' }, `Lecteur « ${l.label} » prêt`);
}

function rendreLecteur() {
  const zone = document.getElementById('lecteur');
  const detail = etatLecteurs === 'erreur' && detailTechnique && estAdmin()
    ? el('span', { class: 'detail-technique' }, `Détail (administrateur) : ${detailTechnique}`)
    : null;
  if (lecteurs.length < 2) return remplir(zone, pastilleLecteur(), detail);
  // Quelques lecteurs au plus par agence : une petite liste suffit.
  const liste = el('select', { 'aria-label': 'Lecteur', disabled: Boolean(magasin && magasin.lire().paiement) },
    lecteurs.map((x) => el('option', { value: x.id },
      `${x.label}${!x.enLigne ? ' (hors ligne)' : x.occupe ? ' (occupé)' : ''}`)));
  liste.value = lecteurChoisi;
  liste.addEventListener('change', () => {
    lecteurChoisi = liste.value;
    rendreLecteur();
    surLecteur();
  });
  remplir(zone, pastilleLecteur(), liste, detail);
}

/** À chaque changement d'état : l'en-tête ne se redessine que si le rôle ou le paiement en cours change. */
export function rendreEnteteLecteur(etat) {
  const cle = `${etat.utilisateur ? etat.utilisateur.role : ''}|${Boolean(etat.paiement)}`;
  if (cle === rendu) return;
  rendu = cle;
  rendreLecteur();
}

/**
 * Charge (ou relit) les lecteurs de l'agence. Sans lecteur prêt, pas
 * d'encaissement carte. Le lecteur choisi est gardé s'il existe toujours.
 */
export async function chargerLecteurs() {
  const r = await api.lecteurs();
  if (!r.ok) {
    // Réseau coupé : le message de api.js est déjà humain. Sinon, erreur
    // technique (Stripe, configuration) : gardée pour l'administrateur.
    etatLecteurs = 'erreur';
    detailTechnique = r.status === 0 ? null : (r.message || null);
    lecteurs = [];
    lecteurChoisi = null;
  } else {
    etatLecteurs = 'ok';
    detailTechnique = null;
    lecteurs = (r.data && Array.isArray(r.data.lecteurs)) ? r.data.lecteurs : [];
    // On présélectionne un lecteur prêt : proposer d'emblée un lecteur éteint
    // ferait échouer l'encaissement sans raison apparente.
    if (!lecteurs.some((l) => l.id === lecteurChoisi)) {
      const pret = lecteurs.find((l) => l.enLigne && !l.occupe) || lecteurs.find((l) => l.enLigne);
      lecteurChoisi = lecteurs.length ? (pret || lecteurs[0]).id : null;
    }
  }
  rendreLecteur();
  surLecteur();
}

/** Relit l'état des lecteurs régulièrement (jamais pendant un paiement : le suivi s'en charge). */
export function surveillerLecteurs() {
  const relire = () => {
    if (document.hidden || (magasin && magasin.lire().paiement)) return;
    chargerLecteurs();
  };
  setInterval(relire, RELECTURE_LECTEURS_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) relire(); });
}

// ─── Suivi d'un paiement (commun au catalogue et au secours) ─────────────────

/**
 * Interroge le serveur jusqu'à une issue : autorisé, capturé, échec, annulé
 * par la page, ou abandon après deux minutes. Ne lève jamais.
 */
export async function suivrePaiement(pi, lecteur, estAnnule = () => false) {
  const limite = Date.now() + DELAI_ABANDON_MS;
  while (Date.now() < limite) {
    await attendre(DELAI_SONDAGE_MS);
    if (estAnnule()) return { ok: false, annule: true };
    const r = await api.etatPaiement(pi, lecteur);
    const etat = r.data && r.data.etat;
    // Déjà capturé : l'argent est pris, une annulation demandée entre-temps
    // n'y peut plus rien. Jamais d'échec affiché pour un paiement pris.
    if (etat === 'capture') return { ok: true, dejaCapture: true };
    if (estAnnule()) return { ok: false, annule: true };
    // Un incident réseau passager ne doit pas interrompre le suivi : la carte
    // est peut-être déjà sur le lecteur. On retentera au tour suivant.
    if (!r.ok) continue;
    if (etat === 'autorise') return { ok: true };
    if (etat === 'echec') return { ok: false, message: r.data.message };
  }
  return { ok: false, message: 'Délai dépassé : aucune carte présentée.' };
}

// ─── Encaissement catalogue ──────────────────────────────────────────────────

const devisExpire = (r) => r.status === 410 && Boolean(r.data && r.data.code === 'devis_expire');

/**
 * Devis périmé (panier resté ouvert au-delà de sa validité) : on redemande le
 * même panier, sans rien montrer, et on rend le NOUVEAU jeton. Si le prix a
 * bougé entre-temps, on s'arrête (rend `null`, erreur affichée) : le bouton
 * affichait l'ancien montant, et on n'encaisse que ce qu'on a montré.
 *
 * @param {(devis) => number} montantDe  la part qui compte (carte, ou total en espèces)
 */
async function devisRenouvele(montantDe, montantAffiche) {
  const ok = await redemanderDevis();
  const etat = magasin.lire();
  if (!ok || !devisAJour(etat)) {
    magasin.appliquer(paiementErreur, etat.devisErreur || 'Le prix n\'a pas pu être recalculé.');
    return null;
  }
  if (montantDe(etat.devis) !== montantAffiche) {
    magasin.appliquer(paiementErreur, 'Le prix a changé depuis l\'affichage : vérifiez le nouveau montant avant d\'encaisser.');
    return null;
  }
  return etat.jetonDevis;
}

function resultat(etat, extra) {
  const e = etat.eleve.eleve;
  return { devis: etat.devis, eleve: nomComplet(e.prenom, e.nom), ...extra };
}

/** Envoie au lecteur la part carte du devis en main. */
export async function envoyerCarte() {
  let etat = magasin.lire();
  if (!devisAJour(etat) || etat.paiement || !lecteurPret()) return;
  const montantAffiche = etat.devis.carteCents;
  const lecteur = lecteurChoisi;
  const e = etat.eleve.eleve;
  magasin.appliquer(paiementEtape, 'envoi');

  const envoyer = (jeton) => api.paiement(
    { lecteur, devis: jeton, email: e.email || '', nomComplet: nomComplet(e.prenom, e.nom) },
    api.nouvelleCle());

  let r = await envoyer(etat.jetonDevis);
  if (devisExpire(r)) {
    const jeton = await devisRenouvele((d) => d.carteCents, montantAffiche);
    if (!jeton) return;
    r = await envoyer(jeton);
  }
  if (r.status === 401) return magasin.appliquer(identificationRequise, (r.data && r.data.code) || 'jeton_expire', r.message);
  if (!r.ok || !r.data || !r.data.paymentIntentId) {
    return magasin.appliquer(paiementErreur, r.message || 'Envoi au lecteur impossible.');
  }

  const suivi = { pi: r.data.paymentIntentId, lecteur: r.data.lecteur || lecteur, annulation: false };
  enCours = suivi;
  magasin.appliquer(paiementEtape, 'carte');
  const issue = await suivrePaiement(suivi.pi, suivi.lecteur, () => suivi.annulation);

  if (!issue.ok) {
    enCours = null;
    // Libère le lecteur (déjà fait si la page a demandé l'annulation).
    if (!issue.annule) await api.annuler(suivi.pi, suivi.lecteur);
    return magasin.appliquer(paiementRefuse, issue.annule ? 'Encaissement annulé.' : (issue.message || 'Paiement non abouti.'));
  }

  magasin.appliquer(paiementEtape, 'capture');
  const c = await api.capture(suivi.pi);
  enCours = null;
  etat = magasin.lire();
  if (c.status === 409) {
    // Le serveur n'a PAS capturé (devis illisible, capture refusée) : rien
    // n'est débité. On libère l'autorisation et on revient au panier gardé.
    await api.annuler(suivi.pi, suivi.lecteur);
    return magasin.appliquer(paiementRefuse, c.message || 'Encaissement impossible : rien n\'a été débité.');
  }
  if (!c.ok || !c.data || c.data.success === false) {
    // L'autorisation tient encore : on ne l'annule surtout pas, elle peut être
    // capturée depuis Stripe. Mieux vaut un encaissement à terminer à la main
    // qu'un client débité deux fois.
    return magasin.appliquer(paiementAccepte, resultat(etat, {
      incomplet: `Carte acceptée mais encaissement incomplet${c.message ? ` : ${c.message}` : ''}. Terminez-le depuis Stripe, ne recommencez pas le paiement.`,
      paymentIntentId: suivi.pi,
    }));
  }
  magasin.appliquer(paiementAccepte, resultat(etat, {
    declaration: c.data.declaration || { statut: 'en_attente', effets: [] },
    paymentIntentId: suivi.pi,
  }));
}

/** Bouton « Annuler l'encaissement » pendant que le lecteur attend la carte. */
export async function annulerPaiement() {
  const suivi = enCours;
  if (!suivi || suivi.annulation) return;
  suivi.annulation = true;
  // Sans effet visible si la route échoue : l'affichage du lecteur retombera
  // seul, et le suivi s'arrête de toute façon.
  await api.annuler(suivi.pi, suivi.lecteur);
}

/** Espèces seules : aucun lecteur, la déclaration part tout de suite. */
export async function encaisserEspeces() {
  const etat = magasin.lire();
  if (!devisAJour(etat) || etat.paiement || etat.moyen !== 'especes') return;
  const montantAffiche = etat.devis.totalCents;
  magasin.appliquer(paiementEtape, 'especes');
  let r = await api.especes(etat.jetonDevis);
  if (devisExpire(r)) {
    const jeton = await devisRenouvele((d) => d.totalCents, montantAffiche);
    if (!jeton) return;
    r = await api.especes(jeton);
  }
  if (r.status === 401) return magasin.appliquer(identificationRequise, (r.data && r.data.code) || 'jeton_expire', r.message);
  const declaration = r.data && r.data.declaration;
  if (r.ok && declaration && (declaration.statut === 'enregistre' || declaration.statut === 'deja')) {
    return magasin.appliquer(paiementAccepte, resultat(magasin.lire(), { declaration }));
  }
  // Ici, « en attente » est une ERREUR : sans carte, rien ne garde la trace de
  // l'encaissement ailleurs que dans le CRM.
  const cause = r.indisponible || (declaration && declaration.statut === 'en_attente')
    ? 'le CRM ne répond pas'
    : ((declaration && declaration.message) || r.message || 'refus du CRM');
  magasin.appliquer(paiementErreur, `Rien n'est enregistré (${cause}). Réessayez dans un instant, ou rendez les espèces.`);
}

export function initPaiement(m, options = {}) {
  magasin = m;
  if (options.redemanderDevis) redemanderDevis = options.redemanderDevis;
  if (options.surLecteur) surLecteur = options.surLecteur;
}
