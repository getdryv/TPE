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

export const lecteurPret = () => Boolean(lecteurChoisi);
export const lecteurActuel = () => lecteurChoisi;

// ─── Lecteurs ────────────────────────────────────────────────────────────────

function rendreLecteur(message) {
  const zone = document.getElementById('lecteur');
  if (message) return remplir(zone, el('span', { class: 'chip warn' }, message));
  const l = lecteurs.find((x) => x.id === lecteurChoisi);
  const pastille = l
    ? el('span', { class: `chip ${l.enLigne ? 'ok' : 'warn'}` }, `Lecteur « ${l.label} » ${l.enLigne ? 'prêt' : 'hors ligne'}`)
    : el('span', { class: 'chip warn' }, 'Aucun lecteur');
  if (lecteurs.length < 2) return remplir(zone, pastille);
  // Quelques lecteurs au plus par agence : une petite liste suffit.
  const choix = el('select', { 'aria-label': 'Lecteur' }, lecteurs.map((x) =>
    el('option', { value: x.id }, `${x.label}${x.enLigne ? '' : ' (hors ligne)'}`)));
  choix.value = lecteurChoisi;
  choix.addEventListener('change', () => {
    lecteurChoisi = choix.value;
    rendreLecteur();
    surLecteur();
  });
  remplir(zone, pastille, choix);
}

/** Charge les lecteurs de l'agence. Sans lecteur, pas d'encaissement carte. */
export async function chargerLecteurs() {
  rendreLecteur('Recherche des lecteurs…');
  const r = await api.lecteurs();
  if (!r.ok) {
    rendreLecteur(r.message || 'Lecteurs indisponibles');
  } else {
    lecteurs = (r.data && Array.isArray(r.data.lecteurs)) ? r.data.lecteurs : [];
    // On présélectionne un lecteur en ligne : proposer d'emblée un lecteur
    // éteint ferait échouer l'encaissement sans raison apparente.
    const enLigne = lecteurs.find((l) => l.enLigne);
    lecteurChoisi = lecteurs.length ? (enLigne || lecteurs[0]).id : null;
    rendreLecteur(lecteurs.length ? null : 'Aucun lecteur enregistré pour cette agence');
  }
  surLecteur();
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
  if (!devisAJour(etat) || etat.paiement || !lecteurChoisi) return;
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
