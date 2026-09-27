// ─── Écran 8 : encaissement de secours (montant saisi) ───────────────────────
//
// Le chemin HISTORIQUE de la caisse, inchangé : prénom, nom, e-mail, montant
// tapé, puis `POST /api/paiement` → suivi du lecteur → `POST /api/paiement/capture`.
// Le serveur déclare ensuite le paiement au CRM (`/api/internal/tpe-payment`)
// et le rattache à la fiche dès que le CRM répond.
//
// Il sert dans deux cas :
//   - le CRM ne répond pas (au démarrage ou en cours de panier) : bandeau
//     « Le CRM ne répond pas », nom et e-mail de l'élève pré-remplis ;
//   - aucun CRM n'est configuré : la caisse est exactement celle d'avant, sans
//     bandeau. L'agence par défaut encaisse alors sans jamais dépendre du CRM.
//
// C'est le SEUL écran, avec le montant libre, où un montant se tape.

import * as api from './api.js';
import * as cadre from './cadre.js';
import { lireMontant, euros } from './format.js';
import { suivrePaiement, lecteurActuel } from './paiement.js';

let retenterCatalogue = () => {};

// Secours par RÉGLAGE, pas par panne : une note sobre plutôt que le bandeau
// « Le CRM ne répond pas », qui serait faux.
const NOTES_SECOURS = {
  agence_sans_slug: "Adresse sans agence : le catalogue n'est pas disponible ici, seul l'encaissement de secours l'est.",
  agence_inconnue: "Cette agence n'est pas reconnue par le CRM (réglage de la caisse à corriger) : seul l'encaissement de secours est possible.",
};
let studentId = null;
let enCours = null; // { pi, lecteur, annulation }

const $ = (id) => document.getElementById(id);
const champ = (nom) => $('formSecours').querySelector(`input[name="${nom}"]`);

function dire(texte, genre = '') {
  const s = $('statutSecours');
  s.textContent = texte || '';
  s.className = `statut${genre ? ` statut-${genre}` : ''}`;
}

function occupe(oui) {
  $('envoyerSecours').disabled = oui;
  $('annulerSecours').hidden = !oui;
  $('formSecours').querySelectorAll('input').forEach((i) => { i.disabled = oui; });
}

function reinitialiser() {
  $('formSecours').reset();
  studentId = null;
  $('nouveauSecours').hidden = true;
  occupe(false);
  dire('');
}

async function envoyer(ev) {
  ev.preventDefault();
  if (enCours) return dire('Un encaissement est déjà en cours.');
  const lecteur = lecteurActuel();
  if (!lecteur) return dire('Aucun lecteur sélectionné.', 'erreur');

  // Lecture par référence, et non par nom métier : les champs portent des
  // noms neutres pour tenir le remplissage automatique de Chrome à l'écart.
  const firstName = champ('champA').value.trim();
  const lastName = champ('champB').value.trim();
  const email = champ('champC').value.trim();
  const montant = lireMontant(champ('champD').value);
  const motif = champ('champE').value.trim();
  if (!firstName || !lastName || !email) return dire('Prénom, nom et e-mail sont nécessaires.', 'erreur');
  if (!montant) return dire('Montant invalide.', 'erreur');

  occupe(true);
  dire('Envoi au lecteur…');
  const r = await api.paiementSecours({
    lecteur, montant, email, firstName, lastName, studentId, motif: motif || undefined,
  });
  if (!r.ok || !r.data || !r.data.paymentIntentId) {
    occupe(false);
    dire(r.message || 'Envoi impossible.', 'erreur');
    // Le CRM est revenu entre-temps : le serveur ferme le secours, la caisse
    // repart sur le catalogue (rien n'a été envoyé au lecteur).
    if (r.status === 403 && r.data && r.data.code === 'secours_indisponible') retenterCatalogue();
    return;
  }

  const suivi = { pi: r.data.paymentIntentId, lecteur, annulation: false };
  enCours = suivi;
  dire('Présentez la carte sur le lecteur…');
  const issue = await suivrePaiement(suivi.pi, lecteur, () => suivi.annulation);

  if (!issue.ok) {
    enCours = null;
    if (!issue.annule) await api.annuler(suivi.pi, lecteur);
    occupe(false);
    return dire(issue.annule ? 'Encaissement annulé.' : (issue.message || 'Paiement non abouti.'), 'erreur');
  }

  dire('Carte acceptée. Encaissement…');
  const c = await api.captureSecours(suivi.pi);
  enCours = null;
  if (!c.ok) {
    // L'autorisation tient encore : on ne l'annule surtout pas, elle peut être
    // capturée depuis Stripe. Mieux vaut un encaissement à terminer à la main
    // qu'un client débité deux fois.
    $('annulerSecours').hidden = true;
    $('nouveauSecours').hidden = false;
    return dire(`Carte acceptée mais encaissement incomplet${c.message ? ` : ${c.message}` : ''}. `
      + 'Terminez-le depuis Stripe, ne recommencez pas le paiement.', 'erreur');
  }
  $('annulerSecours').hidden = true;
  $('nouveauSecours').hidden = false;
  const rattache = cadre.crmConfigure() ? ' Il sera rattaché à la fiche de l\'élève dès que le CRM répondra.' : '';
  dire(`Paiement accepté : ${euros(montant)}.${rattache}`, 'ok');
}

async function annuler() {
  const suivi = enCours;
  if (!suivi || suivi.annulation) return;
  suivi.annulation = true;
  await api.annuler(suivi.pi, suivi.lecteur);
}

/** Rendu à l'entrée sur l'écran 8 : bandeau et pré-remplissage. */
export function rendreSecours(etat, precedent) {
  const actif = etat.ecran === 'secours';
  $('bandeauSecours').hidden = !(actif && etat.secours && etat.secours.indisponible);
  $('retenterCatalogue').hidden = !(actif && cadre.crmConfigure() && etat.secours && etat.secours.indisponible);
  const note = NOTES_SECOURS[etat.raison];
  $('noteSecours').hidden = !(actif && note);
  if (note) $('noteSecours').textContent = note;
  if (!actif || (precedent && precedent.ecran === 'secours')) return;
  if (enCours) return; // un encaissement tourne : on ne touche à rien
  reinitialiser();
  const s = etat.secours || {};
  champ('champA').value = s.prenom || '';
  champ('champB').value = s.nom || '';
  champ('champC').value = s.email || '';
  // Poser les valeurs par programme ne déclenche aucun `input` : la remise à
  // zéro du rattachement (voir `initSecours`) ne s'annule donc pas toute seule.
  studentId = s.studentId || null;
}

export function initSecours(options = {}) {
  if (options.retenterCatalogue) retenterCatalogue = options.retenterCatalogue;
  $('formSecours').addEventListener('submit', envoyer);
  $('annulerSecours').addEventListener('click', annuler);
  $('nouveauSecours').addEventListener('click', reinitialiser);
  $('retenterCatalogue').addEventListener('click', () => retenterCatalogue());
  // Le rattachement à l'élève choisi ne survit pas à une correction du nom :
  // un identifiant qui resterait inscrirait le paiement sur la fiche de
  // quelqu'un d'autre. Mieux vaut cent paiements sans élève qu'un seul sur le
  // mauvais. L'e-mail, lui, ne délie pas : on le corrige couramment parce que
  // l'élève en donne un plus à jour que celui de sa fiche.
  [champ('champA'), champ('champB')].forEach((c) => c.addEventListener('input', () => { studentId = null; }));
}
