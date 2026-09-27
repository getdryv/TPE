// ─── Le panier, piloté PAR LE DEVIS du CRM ───────────────────────────────────
//
// À chaque choix (tuile, moyen, espèces saisies), la page redemande un devis au
// CRM, qui renvoie les lignes, le total et la répartition espèces / carte. Le
// panier n'affiche QUE ce devis, et le bouton porte SON montant : ce qui est
// écrit sur le bouton est exactement ce que le lecteur débitera. Sans devis
// valide pour le panier affiché, le bouton reste désactivé.
//
// Les erreurs du CRM (rien à régler, espèces ≥ total…) sont affichées telles
// quelles : c'est lui qui connaît la règle, pas la page.
//
// Le squelette est construit une fois ; chaque rendu ne met à jour que des
// textes et des états. Reconstruire le champ « Reçu en espèces » à chaque
// frappe ferait perdre le focus au milieu de la saisie.

import * as api from './api.js';
import { el, remplir, euros } from './format.js';
import {
  requeteDevis, devisAJour, choisirMoyen, saisirEspeces, devisRecu, devisRefuse,
  basculerSecours, identificationRequise,
} from './etat.js';
import { envoyerCarte, encaisserEspeces, annulerPaiement, lecteurPret } from './paiement.js';

// Assez pour laisser finir la frappe des espèces, assez court pour que le prix
// suive le doigt quand on touche une tuile.
const ANTI_REBOND_MS = 300;

const MOYENS = [['carte', 'Carte (TPE)'], ['mixte', 'Espèces + carte'], ['especes', 'Espèces']];

const MANQUE = {
  produit: 'Touchez une formule',
  montant: 'Saisissez le montant',
  motif: 'Choisissez le motif',
  precision: 'Précisez le motif',
  especes: 'Saisissez le montant reçu en espèces',
};

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
let confirmationVersion = -1; // espèces seules : confirmation en attente pour cette version

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
  else magasin.appliquer(devisRefuse, version, r.message);
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
  n.note = el('p', { class: 'muted note' });
  n.moyens = MOYENS.map(([code, libelle]) => el('button', {
    type: 'button', class: 'moyen', 'aria-pressed': 'false', 'data-moyen': code,
    onclick: () => magasin.appliquer(choisirMoyen, code),
  }, el('span', { class: 'rond', 'aria-hidden': 'true' }), libelle));

  n.especes = el('input', {
    id: 'especesRecues', class: 'in-especes', type: 'text', name: 'champM', inputmode: 'decimal',
    autocomplete: 'pas-de-remplissage-auto', placeholder: 'ex. 300,00',
  });
  n.especes.addEventListener('input', () => magasin.appliquer(saisirEspeces, n.especes.value));
  n.reste = el('b', {}, '—');
  n.boiteEspeces = el('div', { class: 'boite-especes' },
    el('label', { for: 'especesRecues' }, 'Reçu en espèces'),
    el('div', { style: 'display:flex;align-items:center;gap:8px' }, n.especes, el('span', { style: 'font-size:18px' }, '€')),
    el('div', { class: 'reste' }, el('span', {}, 'Reste sur la carte'), n.reste),
    el('p', { class: 'muted note' }, 'Calculé tout seul. Les deux parts sont rattachées au même achat, avec votre nom.'));

  n.erreur = el('div', { class: 'encart encart-erreur', role: 'alert' });
  n.statut = el('div', { class: 'statut', role: 'status' });
  n.principal = el('button', { type: 'button', class: 'btn btnp', onclick: agir });
  n.secondaire = el('button', { type: 'button', class: 'btn', onclick: secondaire });

  remplir(document.getElementById('panier'),
    el('div', { class: 'panier-titre' }, 'À encaisser'),
    n.lignes,
    el('div', { class: 'total' }, el('span', {}, 'Total'), n.total),
    n.note,
    el('div', { class: 'muted moyens-titre' }, 'Moyen de paiement'),
    n.moyens, n.boiteEspeces, n.erreur,
    el('div', { class: 'boutons-panier' }, n.statut, n.principal, n.secondaire));
}

// ─── Actions ─────────────────────────────────────────────────────────────────

function agir() {
  const etat = magasin.lire();
  if (!devisAJour(etat) || etat.paiement) return;
  if (etat.moyen !== 'especes') return envoyerCarte();
  // Espèces seules : aucun lecteur pour faire barrage, donc une confirmation
  // explicite avant d'enregistrer.
  if (confirmationVersion !== etat.version) {
    confirmationVersion = etat.version;
    return rendrePanier(etat);
  }
  confirmationVersion = -1;
  encaisserEspeces();
}

function secondaire() {
  const etat = magasin.lire();
  if (etat.paiement) return annulerPaiement();
  confirmationVersion = -1;
  rendrePanier(etat);
}

// ─── Rendu ───────────────────────────────────────────────────────────────────

function lignesDevis(etat) {
  if (!devisAJour(etat)) {
    const req = requeteDevis(etat);
    if (!req.corps || etat.devisErreur) return [];
    return [el('div', { class: 'muted petit' }, 'Calcul du prix…')];
  }
  return etat.devis.lignes.map((l) => el('div', { class: `ligne-panier${l.nature === 'promo' ? ' ligne-promo' : ''}` },
    el('span', {}, l.libelle), el('span', {}, euros(l.montantCents))));
}

function texteNote(etat) {
  if (etat.onglet === 'prepa') return 'Payer ici marque la prépa comme réglée : les relances par e-mail s\'arrêtent, comme avec le lien de paiement.';
  if (etat.onglet === 'libre') return 'Au comptoir, paiement en une fois.';
  return 'Au comptoir, paiement en une fois. Prix fixé par le catalogue : rien à saisir.';
}

function rendreBoutons(etat, aJour) {
  const d = etat.devis;
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
    n.principal.textContent = MANQUE[req.manque] || 'Touchez une formule';
    return;
  }
  if (!aJour) {
    n.principal.disabled = true;
    n.principal.textContent = etat.devisErreur ? 'Prix indisponible' : 'Calcul du prix…';
    return;
  }
  if (etat.moyen === 'especes') {
    const enConfirmation = confirmationVersion === etat.version;
    n.principal.disabled = false;
    n.principal.textContent = enConfirmation
      ? `Confirmer : ${euros(d.totalCents)} reçus en espèces`
      : `Enregistrer ${euros(d.totalCents)} en espèces`;
    if (enConfirmation) {
      n.statut.textContent = 'Vérifiez le montant reçu avant de confirmer : aucun lecteur n\'intervient.';
      n.secondaire.hidden = false;
      n.secondaire.textContent = 'Annuler';
    }
    return;
  }
  const pret = lecteurPret();
  n.principal.disabled = !pret;
  n.principal.textContent = `Envoyer ${euros(d.carteCents)} au lecteur`;
  if (!pret) n.statut.textContent = 'Aucun lecteur prêt : vérifiez qu\'il est allumé et connecté.';
}

export function rendrePanier(etat) {
  if (etat.ecran !== 'panier') {
    clearTimeout(minuteur);
    return;
  }
  const aJour = devisAJour(etat);
  remplir(n.lignes, lignesDevis(etat));
  n.total.textContent = aJour ? euros(etat.devis.totalCents) : '—';
  n.note.textContent = texteNote(etat);

  const verrou = Boolean(etat.paiement);
  n.moyens.forEach((b) => {
    b.setAttribute('aria-pressed', String(b.dataset.moyen === etat.moyen));
    b.disabled = verrou;
  });
  n.boiteEspeces.hidden = etat.moyen !== 'mixte';
  if (n.especes.value !== etat.especesSaisie) n.especes.value = etat.especesSaisie;
  n.especes.disabled = verrou;
  n.reste.textContent = aJour ? euros(etat.devis.carteCents) : '—';

  const message = etat.erreur || etat.devisErreur;
  n.erreur.hidden = !message;
  n.erreur.textContent = message || '';

  rendreBoutons(etat, aJour);
  planifierDevis(etat);
}

export function initPanier(m) {
  magasin = m;
  construire();
}
