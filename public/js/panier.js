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
// Aucun moyen n'est présélectionné ; le rendu des chèques vit dans cheques.js.
//
// Le squelette est construit une fois ; chaque rendu ne met à jour que des
// textes et des états. Reconstruire le champ « Reçu en espèces » à chaque
// frappe ferait perdre le focus au milieu de la saisie.

import * as api from './api.js';
import { el, remplir, euros, eurosCourts } from './format.js';
import {
  requeteDevis, devisAJour, choisirMoyen, saisirEspeces, devisRecu, devisRefuse,
  basculerSecours, identificationRequise, nombreCheques, chequesProposes,
} from './etat.js';
import { avecCheques, avecEspeces } from './etat-cheques.js';
import { envoyerCarte, annulerPaiement, lecteurPret, raisonLecteurActuel } from './paiement.js';
import { encaisserSansCarte, initSansCarte, MOYENS_SANS_CARTE } from './sans-carte.js';
import { initCheques, rendreCheques } from './cheques.js';

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
  nombre: 'Choisissez le nombre de chèques',
  montants: 'Corrigez les montants des chèques',
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
let moyenAffiche = null;    // pour donner le focus au champ espèces quand on choisit un mixte

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
  n.surcout = el('p', { class: 'surcout' });
  n.note = el('p', { class: 'muted note' });
  n.moyens = MOYENS.map(([code, libelle, large]) => el('button', {
    type: 'button', class: `sel moyen${large}`, 'aria-pressed': 'false', 'data-moyen': code,
    onclick: () => magasin.appliquer(choisirMoyen, code),
  }, libelle));

  n.especes = el('input', {
    id: 'especesRecues', class: 'in-especes', type: 'text', name: 'champM', inputmode: 'decimal',
    autocomplete: 'pas-de-remplissage-auto', placeholder: 'ex. 300,00',
  });
  n.especes.addEventListener('input', () => magasin.appliquer(saisirEspeces, n.especes.value));
  n.reste = el('b', {}, '—');
  n.resteLibelle = el('span', {}, 'Reste sur la carte');
  n.boiteEspeces = el('div', { class: 'boite-especes' },
    el('label', { for: 'especesRecues' }, 'Reçu en espèces'),
    el('div', { style: 'display:flex;align-items:center;gap:8px' }, n.especes, el('span', { style: 'font-size:18px' }, '€')),
    el('div', { class: 'reste' }, n.resteLibelle, n.reste),
    el('p', { class: 'muted note' }, 'Calculé tout seul. Les deux parts sont rattachées au même achat, avec votre nom.'));

  n.zoneCheques = el('div', { class: 'zone-cheques' });
  n.erreur = el('div', { class: 'encart encart-erreur', role: 'alert' });
  n.statut = el('div', { class: 'statut', role: 'status' });
  n.principal = el('button', { type: 'button', class: 'btn btnp', onclick: agir });
  n.secondaire = el('button', { type: 'button', class: 'btn', onclick: secondaire });

  n.totalBarre = el('span', {}, '—');
  n.action = el('div', { class: 'panier-action' },
    el('div', { class: 'barre-total', 'aria-hidden': 'true' }, el('span', {}, 'Total'), n.totalBarre),
    n.statut, n.principal, n.secondaire);

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
      n.boiteEspeces, n.zoneCheques, n.erreur),
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
  if (!devisAJour(etat) || etat.paiement) return;
  if (MOYENS_SANS_CARTE.includes(etat.moyen)) return encaisserSansCarte();
  return envoyerCarte();
}

function secondaire() {
  if (magasin.lire().paiement) annulerPaiement();
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
  if (etat.onglet === 'heures_supp' && etat.accompagnement) {
    return 'L\'accompagnement payé ici vaut pour le passage en cours : les relances s\'arrêtent, comme avec la prépa.';
  }
  return '';
}

/** « Prix en 3 fois · 70 € de plus qu'en 1 fois », ou « Prix comptant » : lu dans le devis. */
function texteSurcout(etat, aJour) {
  if (!aJour) return '';
  const ech = etat.devis.echeancier;
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
  if (etat.moyen === 'especes') return `Encaisser ${eurosCourts(d.totalCents)} en espèces`;
  return `Envoyer ${eurosCourts(d.carteCents)} au lecteur`;
}

function rendreBoutons(etat, aJour) {
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
    n.principal.textContent = impossible ? 'Choisissez un autre moyen de paiement' : (MANQUE[req.manque] || 'Touchez une formule');
    return;
  }
  if (!aJour) {
    n.principal.disabled = true;
    const corriger = avecCheques(etat.moyen) ? 'Corrigez l\'échéancier' : 'Prix indisponible';
    n.principal.textContent = etat.devisErreur ? corriger : 'Calcul du prix…';
    return;
  }
  n.principal.textContent = libelleAction(etat);
  if (MOYENS_SANS_CARTE.includes(etat.moyen)) {
    n.principal.disabled = false;
    return;
  }
  const pret = lecteurPret();
  n.principal.disabled = !pret;
  if (!pret) n.statut.textContent = raisonLecteurActuel();
}

export function rendrePanier(etat) {
  if (etat.ecran !== 'panier') {
    clearTimeout(minuteur);
    return;
  }
  const aJour = devisAJour(etat);
  remplir(n.lignes, lignesDevis(etat));
  n.total.textContent = aJour ? euros(etat.devis.totalCents) : '—';
  n.totalBarre.textContent = n.total.textContent;
  n.surcout.textContent = texteSurcout(etat, aJour);
  n.note.textContent = texteNote(etat);
  n.note.hidden = !n.note.textContent;

  const verrou = Boolean(etat.paiement);
  n.moyens.forEach((b) => {
    b.setAttribute('aria-pressed', String(b.dataset.moyen === etat.moyen));
    b.disabled = verrou;
  });
  const mixte = avecEspeces(etat.moyen);
  n.boiteEspeces.hidden = !mixte;
  if (n.especes.value !== etat.especesSaisie) n.especes.value = etat.especesSaisie;
  n.especes.disabled = verrou;
  const enCheques = etat.moyen === 'especes_cheques';
  n.resteLibelle.textContent = enCheques ? 'Reste en chèques' : 'Reste sur la carte';
  n.reste.textContent = aJour ? euros(enCheques ? etat.devis.chequesCents : etat.devis.carteCents) : '—';
  // Un paiement mixte vient d'être choisi : le montant reçu se tape tout de suite.
  if (mixte && !avecEspeces(moyenAffiche) && !verrou) setTimeout(() => n.especes.focus(), 0);
  moyenAffiche = etat.moyen;
  rendreCheques(etat);

  const message = etat.erreur || etat.devisErreur;
  n.erreur.hidden = !message;
  n.erreur.textContent = message || '';

  rendreBoutons(etat, aJour);
  planifierDevis(etat);
}

export function initPanier(m) {
  magasin = m;
  initSansCarte(m);
  construire();
}
