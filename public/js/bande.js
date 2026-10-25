// ─── La bande verte : l'encaissement est fait, la caisse est déjà prête ───────
//
// Aux heures de pointe, la file attend : après un encaissement, la caisse ne
// montre pas une page à fermer. Le panier est déjà vidé, le focus est dans la
// recherche d'élève (ecran-eleve.js), et une bande en haut dit ce qui vient
// d'être encaissé : « Encaissé · 1 760 € en 3 chèques · Léa MARTIN · E-mail
// envoyé ». Le
// récapitulatif (échéancier, ce que le CRM a enregistré, liens vers la fiche
// et le contrat) se déplie sous « Voir le détail ». La bande reste jusqu'au
// prochain encaissement.
//
// Deux cas restent en orange, lisibles sans rien déplier : la carte est prise
// mais le CRM n'a pas encore répondu (« enregistrement en cours »), ou le CRM
// signale un écart de montant.

import * as cadre from './cadre.js';
import { el, remplir, euros, eurosCourts, jourCourt } from './format.js';
import { imprimerBordereau } from './bordereau.js';

let detailOuvert = false;
let dessinee = null;
let messageImpression = '';   // « Réimpression impossible : … », jusqu'au prochain encaissement
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

/**
 * PURE. Ce que la bande dit de l'e-mail à l'élève, d'après le CODE de l'effet
 * renvoyé par le CRM (jamais d'après son texte) : `ticket_envoye` → « E-mail
 * envoyé », `ticket_echec` ou `ticket_sans_adresse` → « E-mail non envoyé »
 * (bande orange), `ticket_en_cours` → « E-mail en cours d'envoi » : le CRM
 * n'attend l'e-mail que 400 ms, la caisse ne reste jamais bloquée dessus.
 * Tout autre code (envoi désactivé, CRM plus ancien) : rien.
 */
export function etatEmail(declaration) {
  const effets = declaration && Array.isArray(declaration.effets) ? declaration.effets : [];
  const codes = effets.map((e) => e && e.code);
  if (codes.includes('ticket_echec') || codes.includes('ticket_sans_adresse')) return { texte: 'E-mail non envoyé', alerte: true };
  if (codes.includes('ticket_envoye')) return { texte: 'E-mail envoyé', alerte: false };
  if (codes.includes('ticket_en_cours')) return { texte: 'E-mail en cours d\'envoi', alerte: false };
  return null;
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

/** PURE. « Rendez-lui le chèque n° 0004521 » (reprise ; désignations de reprise.js), ou ''. */
export function texteChequesRendus(designations) {
  if (!Array.isArray(designations) || !designations.length) return '';
  return designations.length === 1 ? `Rendez-lui le chèque ${designations[0]}` : `Rendez-lui les chèques ${designations.join(', ')}`;
}

/**
 * PURE. Le rappel du logiciel de gestion (maquette « Rappel », 26/10) : « À
 * faire maintenant dans le logiciel de gestion : saisissez la facture de
 * 299,50 € pour Inès BENALI. » — sans numéro d'encaissement (le logiciel ne
 * permet pas de le saisir), et jamais le nom du logiciel. Aucun rappel pour
 * une reprise de chèque (rien de nouveau n'est vendu) ni pour un écart de
 * montant (rien n'est marqué payé). `{ consigne, texte }`, ou null.
 */
export function rappelFacture(r) {
  if (!r || !r.devis || r.produit === 'reprise_cheque') return null;
  if (r.declaration && r.declaration.statut === 'ecart') return null;
  if (!Number.isInteger(r.devis.totalCents) || r.devis.totalCents <= 0) return null;
  return {
    consigne: 'À faire maintenant dans le logiciel de gestion :',
    texte: ` saisissez la facture de ${eurosCourts(r.devis.totalCents)}${r.eleve ? ` pour ${r.eleve}` : ''}.`,
  };
}

/** « Réimprimer le bordereau » : le CRM renvoie un DUPLICATA et trace la demande. */
async function reimprimer(hote, etat) {
  // Chargé à la demande : ce module reste importable sous node (tests des fonctions pures).
  const api = await import('./api.js');
  const id = etat.bande && etat.bande.declaration && etat.bande.declaration.encaissementId;
  const r = id ? await api.bordereau(id) : { ok: false, message: 'Encaissement inconnu.' };
  const b = r.ok && r.data && r.data.bordereau;
  messageImpression = b && imprimerBordereau(b, { par: (etat.utilisateur && etat.utilisateur.nom) || '', le: new Date().toISOString() })
    ? '' : `Réimpression impossible : ${r.message || 'bordereau indisponible'}.`;
  dessiner(hote, etat);
}

function dessiner(hote, etat) {
  const r = etat.bande;
  const entete = enteteBande(r.declaration);
  const email = etatEmail(r.declaration);
  const genre = email && email.alerte ? 'warn' : entete.genre;
  const ico = el('span', { class: 'ico', 'aria-hidden': 'true' });
  if (genre === 'ok') ico.innerHTML = ICO_OK; // pictogramme constant, sans donnée
  const bordereau = r.declaration && r.declaration.bordereau;
  const rendus = texteChequesRendus(r.chequesRendus);
  const rappel = rappelFacture(r);
  const avant = [texteRepartition(r.devis), r.eleve].filter(Boolean).join(' · ');
  const apres = [entete.suite, bordereau ? 'Bordereau imprimé' : '', email && email.texte].filter(Boolean).join(' · ');
  const bascule = el('button', {
    type: 'button', class: 'lien-btn', 'aria-expanded': String(detailOuvert), 'aria-controls': 'detailBande',
    onclick: () => { detailOuvert = !detailOuvert; dessiner(hote, etat); },
  }, detailOuvert ? 'Masquer le détail' : 'Voir le détail');
  // Réimprimable dès que l'encaissement est connu et qu'il y avait des espèces, même sans bordereau dans
  // la réponse (déclaration passée par le webhook, CRM plus lent) : le CRM relit la ligne enregistrée.
  const encaissementId = r.declaration && r.declaration.encaissementId;
  const reimpression = encaissementId && (bordereau || (r.devis && r.devis.especesCents > 0))
    ? el('button', { type: 'button', class: 'lien-btn', onclick: () => reimprimer(hote, etat) }, 'Réimprimer le bordereau')
    : null;
  remplir(hote,
    el('div', { class: `bande bande-${genre}`, role: 'status' }, ico,
      el('span', { class: 'grandit' }, el('b', {}, entete.titre), avant ? ` · ${avant}` : '', apres ? ` · ${apres}` : '',
        // Reprise : la consigne à ne pas manquer, sur sa propre ligne.
        rendus ? el('span', { class: 'bloc consigne-rendu' }, rendus) : null,
        rappel ? el('span', { class: 'bloc consigne-facture' }, el('b', {}, rappel.consigne), rappel.texte) : null,
        messageImpression ? el('span', { class: 'bloc' }, messageImpression) : null),
      reimpression, bascule),
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
  messageImpression = '';
  dessiner(hote, etat);
  // Le bordereau d'espèces s'imprime de lui-même, une fois, à l'apparition de la bande.
  const b = etat.bande.declaration && etat.bande.declaration.bordereau;
  if (b) imprimerBordereau(b);
}
