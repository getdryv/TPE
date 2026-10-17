// ─── Les choix d'un paiement en chèques, PURS ────────────────────────────────
//
// Ce module ne connaît AUCUNE règle de date ni de montant : ni jours ouvrés, ni
// prix en plusieurs fois, ni répartition. Il garde les CHOIX de l'élève
// (nombre de chèques, date du 1er chèque, avances, montants saisis des chèques
// 1 à n−1) et les met dans la forme `DemandeCheques` du contrat (§ 2.2). Le
// CRM valide ces choix et renvoie l'échéancier complet dans le devis : c'est
// lui, et lui seul, que l'écran affiche et que le bouton encaisse.
//
// Chaque fonction prend un sous-état et rend un NOUVEL objet : l'ancien n'est
// jamais modifié (même discipline que etat.js).

import { lireMontant } from './format.js';

export const MOYENS_CHEQUES = ['cheques', 'especes_cheques'];
export const MOYENS_MIXTES = ['mixte', 'especes_cheques'];
// Borne de sûreté : le maximum réel vient de la formule et du plafond de l'agence (CRM).
const VERSEMENTS_PLAFOND = 24;

/** Aucun choix : c'est l'état après chaque changement de moyen. */
export function chequesVides() {
  return { nombre: null, premierLe: null, avances: [null, null, null], montants: ['', '', ''] };
}

export const avecCheques = (moyen) => MOYENS_CHEQUES.includes(moyen);
export const avecEspeces = (moyen) => MOYENS_MIXTES.includes(moyen);

// ─── Nombre de chèques proposés (affichage seulement) ────────────────────────

/**
 * Nombre maximal de VERSEMENTS donné par le CRM pour le produit du panier
 * (`TuileCaisse.cheques.max`, arbitrage P2 : les espèces comptent). La prépa et
 * le montant libre n'ont pas de formule : un seul versement (arbitrage P3).
 * Une tuile d'un CRM pas encore à jour (sans `cheques`) donne 1.
 */
export function versementsMaxProduit(eleve, produit) {
  if (!eleve || !produit) return 1;
  let tuiles = [];
  if (produit.type === 'forfait') tuiles = (eleve.cascade && eleve.cascade.forfaits) || [];
  else if (produit.type === 'heures_supp') tuiles = (eleve.heuresSupp && eleve.heuresSupp.packs) || [];
  else return 1;
  const tuile = tuiles.find((t) => t.formuleId === produit.formuleId);
  const max = tuile && tuile.cheques && Number.isInteger(tuile.cheques.max) ? tuile.cheques.max : 1;
  return Math.max(1, Math.min(max, VERSEMENTS_PLAFOND));
}

/**
 * Combien de boutons « N chèques » proposer. Le devis à jour fait foi
 * (`echeancier.nombreChequesMax`) ; avant le premier devis, la donnée de la
 * tuile suffit à dessiner les boutons. Le CRM refuse de toute façon un nombre
 * hors borne : ce chiffre ne décide de rien.
 */
export function nombreChequesProposes(moyen, versementsMax, echeancier) {
  if (!avecCheques(moyen)) return 0;
  if (echeancier && echeancier.moyen === moyen && Number.isInteger(echeancier.nombreChequesMax)) {
    return echeancier.nombreChequesMax;
  }
  return Math.max(0, versementsMax - (moyen === 'especes_cheques' ? 1 : 0));
}

/** Le nombre retenu : celui touché, ou le seul possible (un seul bouton, pas de geste inutile). */
export function nombreEffectif(cheques, proposes) {
  if (cheques.nombre && cheques.nombre <= proposes) return cheques.nombre;
  return proposes === 1 ? 1 : null;
}

// ─── Transitions du sous-état ────────────────────────────────────────────────

/** Changer le nombre efface les montants et les avances : ils valaient pour l'ancien découpage. */
export function avecNombre(cheques, nombre) {
  if (!Number.isInteger(nombre) || nombre < 1 || nombre > VERSEMENTS_PLAFOND || nombre === cheques.nombre) return cheques;
  return { ...chequesVides(), premierLe: cheques.premierLe, nombre };
}

/** Le 1er chèque change de date : les dates prévues des suivants aussi, les avances tombent. */
export function avecPremier(cheques, iso) {
  const valeur = typeof iso === 'string' && iso ? iso : null;
  if (valeur === cheques.premierLe) return cheques;
  return { ...cheques, premierLe: valeur, avances: [null, null, null] };
}

/** Avance d'un chèque (index 0 = 1er chèque) ; `null` = revenir à la date prévue. */
export function avecAvance(cheques, index, iso) {
  if (!Number.isInteger(index) || index < 0 || index >= VERSEMENTS_PLAFOND) return cheques;
  const valeur = typeof iso === 'string' && iso ? iso : null;
  if (cheques.avances[index] === valeur) return cheques;
  const avances = cheques.avances.slice();
  avances[index] = valeur;
  return { ...cheques, avances };
}

/** Montant tapé dans le champ d'un chèque, tel quel (converti à l'envoi). */
export function avecMontant(cheques, index, texte) {
  if (!Number.isInteger(index) || index < 0 || index >= VERSEMENTS_PLAFOND) return cheques;
  const valeur = String(texte ?? '');
  if (cheques.montants[index] === valeur) return cheques;
  const montants = cheques.montants.slice();
  montants[index] = valeur;
  return { ...cheques, montants };
}

// ─── Demande au CRM ──────────────────────────────────────────────────────────

/**
 * `DemandeCheques` pour le devis, ou `{ manque }` :
 *   - `nombre`   : le nombre de chèques n'est pas choisi ;
 *   - `montants` : un montant saisi n'est pas lisible.
 * Seuls les montants des chèques 1 à n−1 partent : le dernier est TOUJOURS
 * calculé par le CRM. Un champ vide = « à répartir » (null).
 */
export function demandeCheques(cheques, nombre) {
  if (!nombre) return { manque: 'nombre' };
  const demande = { nombre };
  if (cheques.premierLe) demande.premierLe = cheques.premierLe;

  const avances = Array.from({ length: nombre }, (_, i) => cheques.avances[i] || null);
  if (avances.some(Boolean)) demande.avances = avances;

  if (nombre > 1) {
    const montants = [];
    for (let i = 0; i < nombre - 1; i += 1) {
      const texte = String(cheques.montants[i] || '').trim();
      if (!texte) { montants.push(null); continue; }
      const cents = lireMontant(texte);
      if (!cents) return { manque: 'montants' };
      montants.push(cents);
    }
    if (montants.some((m) => m !== null)) demande.montantsCents = montants;
  }
  return { demande };
}
