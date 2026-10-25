// ─── Ce que le panier affiche en attendant le devis, PUR ────────────────────
//
// Le devis du CRM reste la seule source du montant ENCAISSÉ : le bouton ne
// s'active qu'avec un devis à jour (panier.js). Mais au comptoir, la
// secrétaire annonce le prix AVANT de demander « vous payez comment ? », et le
// total ne doit jamais disparaître pendant qu'elle corrige un montant. D'où
// deux replis, purement visuels :
//   1. le dernier devis reçu POUR LE MÊME PANIER (élève, produit, moyen,
//      nombre de chèques), tant que le nouveau n'est pas arrivé ou s'il est
//      refusé : un montant de chèque trop grand ne change pas le total ;
//   2. à défaut, le prix comptant affiché sur la tuile (catalogue du CRM).
// Aucun accès au DOM ni au réseau : ce module se teste sous node.

import { devisAJour, nombreCheques } from './etat.js';
import { avecCheques, avecEspeces } from './etat-cheques.js';
import { lireMontant, eurosCourts } from './format.js';

/** Les erreurs du CRM qui désignent un champ du panier : affichées sous ce champ. */
export const CHAMPS_DU_PANIER = ['montants', 'avances', 'premierLe', 'especes'];

/** La tuile (forfait ou pack) du produit du panier, ou null. */
export function tuileDuProduit(eleve, produit) {
  if (!eleve || !produit) return null;
  let tuiles = [];
  if (produit.type === 'forfait') tuiles = (eleve.cascade && eleve.cascade.forfaits) || [];
  else if (produit.type === 'heures_supp') tuiles = (eleve.heuresSupp && eleve.heuresSupp.packs) || [];
  return tuiles.find((t) => t.formuleId === produit.formuleId) || null;
}

/** Prix comptant de la tuile, promotion comprise (celui qu'elle affiche), ou null. */
export function prixComptantTuile(tuile) {
  if (!tuile) return null;
  const prix = tuile.promo && Number.isInteger(tuile.promo.prixRemiseCents) ? tuile.promo.prixRemiseCents : tuile.prixCents;
  return Number.isInteger(prix) ? prix : null;
}

/**
 * Le prix à écrire sous « N chèques » (Chèques seuls) : comptant pour 1, prix
 * en plusieurs fois du catalogue pour 2 ou 3. null si le CRM ne le donne pas.
 */
export function prixPourNombre(eleve, produit, k) {
  const tuile = tuileDuProduit(eleve, produit);
  if (k === 1) return prixComptantTuile(tuile);
  const plusieurs = tuile && tuile.cheques && tuile.cheques.prixPlusieursFoisCents;
  return Number.isInteger(plusieurs) ? plusieurs : null;
}

/**
 * Le texte sous chaque bouton « N chèques », de 1 à `proposes` : le prix de
 * CETTE formule (comptant pour 1, en plusieurs fois au-delà), ou le nombre de
 * versements d'un « Espèces + chèques ».
 */
export function sousNombres(etat, proposes) {
  const esp = etat.moyen === 'especes_cheques';
  const sous = [];
  for (let k = 1; k <= proposes; k += 1) {
    const prix = esp ? null : prixPourNombre(etat.eleve, etat.produit, k);
    // Le bouton dit « En N fois » ; dessous, le nombre de chèques et le TOTAL, jamais le montant d'un seul (retour du gérant, 17/10).
    const cheques = k === 1 ? '1 chèque' : `${k} chèques`;
    if (esp) sous.push(`espèces + ${cheques}`);
    else if (prix === null) sous.push(cheques);
    else sous.push(k === 1 ? `${cheques} de ${eurosCourts(prix)}` : `${cheques} · total ${eurosCourts(prix)}`);
  }
  return sous;
}

/**
 * Ce qui oblige à reconstruire la zone des chèques (tout sauf les montants
 * tapés). Les prix sous les boutons en font partie : changer de formule sans
 * toucher au moyen ni au nombre doit les redessiner.
 */
export function cleZoneCheques(etat, { proposes, nombre, ech, verrou, ui }) {
  const versements = ech ? ech.versements.map((v) => [v.rang, v.nature, v.dueOn, v.prevuLe, v.avance, v.avancable, v.min, v.max, v.montantModifiable]) : null;
  return JSON.stringify([etat.moyen, proposes, sousNombres(etat, proposes), nombre, verrou, ui, ech && ech.premier, versements]);
}

/** Ce qui fait le prix : tant que cette clé ne bouge pas, le total non plus. */
function cleDuPrix(etat) {
  const id = etat.eleve && etat.eleve.eleve ? etat.eleve.eleve.id : null;
  return JSON.stringify([id, etat.produit, Boolean(etat.accompagnement), etat.moyen, nombreCheques(etat)]);
}

/** Retient le devis à jour (avec les espèces pour lesquelles il a été émis). Rend un NOUVEL objet. */
export function retenirDevis(memo, etat) {
  if (!devisAJour(etat)) return memo;
  return { cle: cleDuPrix(etat), devis: etat.devis, especesSaisie: etat.especesSaisie };
}

/**
 * `{ devis, aJour }` à afficher : le devis à jour, sinon le dernier reçu pour
 * le même panier (aJour = false), sinon null.
 */
export function devisAffiche(memo, etat) {
  if (devisAJour(etat)) return { devis: etat.devis, aJour: true };
  if (memo && memo.devis && memo.cle === cleDuPrix(etat)) return { devis: memo.devis, aJour: false };
  return { devis: null, aJour: false };
}

/** Le reste ne vaut que pour les espèces tapées quand le devis a été émis. */
export function resteAffiche(memo, etat, affiche) {
  if (!affiche.devis || !avecEspeces(etat.moyen)) return null;
  if (!affiche.aJour && (!memo || memo.especesSaisie !== etat.especesSaisie)) return null;
  return etat.moyen === 'especes_cheques' ? affiche.devis.chequesCents : affiche.devis.carteCents;
}

/** Nombre de versements du panier : chèques choisis, plus les espèces d'un « Espèces + chèques ». */
function versementsDuPanier(etat) {
  const nb = avecCheques(etat.moyen) ? nombreCheques(etat) : null;
  if (!nb) return 1;
  return nb + (etat.moyen === 'especes_cheques' ? 1 : 0);
}

/**
 * Sans devis pour ce panier : le prix du catalogue (tuile : comptant, ou en
 * plusieurs fois dès que 2 ou 3 versements sont choisis) ou le montant libre
 * saisi. `{ libelle, totalCents, versements }`, ou null (prépa : le CRM seul
 * sait ce qui est dû).
 */
export function prixCatalogue(etat) {
  const p = etat.produit;
  if (!p) return null;
  if (p.type === 'libre') {
    const cents = lireMontant(p.montantSaisie);
    return cents ? { libelle: 'Montant libre', totalCents: cents, versements: 1 } : null;
  }
  if (p.type === 'reprise_cheque') {
    // Le montant des chèques cochés, tel que le CRM l'a lu (le devis le recalcule).
    const cheques = ((etat.eleve && etat.eleve.reprises && etat.eleve.reprises.cheques) || []).filter((c) => p.chequeIds.includes(c.id));
    if (!cheques.length) return null;
    const libelle = cheques.length === 1 ? `Reprise du chèque ${cheques[0].numero ? `n° ${cheques[0].numero}` : 'sans numéro'}` : `Reprise de ${cheques.length} chèques`;
    return { libelle, totalCents: cheques.reduce((s, c) => s + c.montantCents, 0), versements: 1 };
  }
  if (etat.accompagnement) return null; // la ligne d'accompagnement n'a de prix que dans le devis
  const tuile = tuileDuProduit(etat.eleve, p);
  if (!tuile) return null;
  const versements = versementsDuPanier(etat);
  const prix = prixPourNombre(etat.eleve, p, versements > 1 ? versements : 1);
  return prix === null ? null : { libelle: tuile.nom, totalCents: prix, versements };
}

/** « Reste 1 460 € en chèques » / « Reste 1 390 € par carte ». */
export function texteReste(moyen, montant) {
  return moyen === 'especes_cheques' ? `Reste ${montant} en chèques` : `Reste ${montant} par carte`;
}

/**
 * Le bouton bloqué dit OÙ est la faute (contre-recette N1) : les espèces, si le
 * CRM désigne ce champ ; l'échéancier pour les autres refus d'un paiement par
 * chèques ; sinon le prix.
 */
export function libelleCorrection(moyen, champ) {
  if (champ === 'especes') return 'Corrigez le montant en espèces';
  if (avecCheques(moyen)) return 'Corrigez l\'échéancier';
  return 'Prix indisponible';
}

/**
 * Le chèque sous lequel écrire une erreur de montant (contre-recette A2) : le
 * premier montant saisi à la main, celui que la secrétaire vient de taper.
 * null : l'erreur ne vise pas un montant, ou aucun n'est saisi (elle reste
 * alors sous l'échéancier).
 */
export function chequeFautif(champ, montants) {
  if (champ !== 'montants' || !Array.isArray(montants)) return null;
  const i = montants.findIndex((m) => String(m || '').trim() !== '');
  return i >= 0 ? i : null;
}
