// ─── Les espèces comptées dans l'état de la caisse, PUR ──────────────────────
//
// La feuille de comptage (feuille-especes.js) et le compteur du panier
// (compteur-especes.js) ne font que dessiner ce que ce module décide :
//   - Espèces seules : le comptage doit tomber PILE sur le total du devis ; il
//     ne change pas le prix, le devis n'est donc pas redemandé à chaque billet ;
//   - Espèces + carte, espèces + chèques : le comptage FIXE la part espèces
//     (`especesSaisie`), et le devis est redemandé (le reste par carte ou en
//     chèques en dépend).
// Retour arrière avant validation : « Revenir au choix de la prestation »,
// « Tout effacer ». Après l'encaissement, la secrétaire n'annule jamais.

import { perimer } from './etat-base.js';
import { avecEspeces } from './etat-cheques.js';
import { analyser, apresRendu, avecNombre, enSaisie, plusUn, totalCompte } from './especes-compte.js';
import { devisAJour } from './etat.js';
import { prixCatalogue } from './panier-affiche.js';

/** Le comptage est-il au cœur de l'écran (espèces seules ou mixte, prestation choisie) ? */
export function compteVisible(etat) {
  return etat.ecran === 'panier' && Boolean(etat.produit) && (etat.moyen === 'especes' || avecEspeces(etat.moyen));
}

/** La feuille remplace les onglets, sauf retour demandé à la prestation. */
export const feuilleAffichee = (etat) => compteVisible(etat) && !etat.retourPrestation;

/**
 * La part espèces attendue : le total du devis pour « Espèces » (en attendant
 * le devis, le prix affiché de la tuile, pour ne jamais dire « juste » à tort) ;
 * aucune pour un mixte (le comptage la fixe).
 */
export function cibleEspeces(etat) {
  if (etat.moyen !== 'especes') return null;
  if (devisAJour(etat)) return etat.devis.totalCents;
  const catalogue = prixCatalogue(etat);
  return catalogue ? catalogue.totalCents : null;
}

/**
 * L'arrondi accepté sans rendre la monnaie (réglage d'agence, CRM à jour) :
 * espèces SEULES ; un mixte fixe sa part au centime. CRM plus ancien : 0.
 */
export function toleranceArrondi(etat) {
  if (etat.moyen !== 'especes') return 0;
  const t = etat.eleve && etat.eleve.especes && etat.eleve.especes.toleranceArrondiCents;
  return Number.isInteger(t) && t > 0 ? Math.min(t, 500) : 0;
}

/**
 * Où en est le compte (especes-compte.js `analyser`), d'après l'état. Espèces
 * seules sans aucun prix connu (prépa dont le devis arrive) : `attente`.
 */
export function analyseEspeces(etat) {
  const cible = cibleEspeces(etat);
  const a = analyser(etat.comptage || {}, cible, toleranceArrondi(etat));
  if (etat.moyen === 'especes' && cible === null && a.statut !== 'vide') return { ...a, statut: 'attente' };
  return a;
}

/**
 * Espèces seules : prêt à encaisser seulement si le compté égale PILE le total
 * du devis à jour. Mixte : il faut au moins une coupure comptée.
 */
export function comptageAccepte(etat) {
  if (!compteVisible(etat)) return true;
  const a = analyseEspeces(etat);
  // Le bouton ne s'ouvre que sur le total du DEVIS (jamais sur le prix indicatif de la tuile).
  if (etat.moyen === 'especes') return devisAJour(etat) && (a.statut === 'juste' || a.statut === 'arrondi');
  return a.compte > 0;
}

function avecComptage(etat, comptage) {
  if (comptage === etat.comptage) return etat;
  // Mixte : la part espèces change, donc le devis (reste par carte ou en chèques).
  if (avecEspeces(etat.moyen)) return perimer(etat, { comptage, especesSaisie: enSaisie(totalCompte(comptage)) });
  return { ...etat, comptage, erreur: null };
}

const libre = (etat) => !etat.paiement;

export const saisirCoupure = (etat, coupure, nombre) => (libre(etat) ? avecComptage(etat, avecNombre(etat.comptage || {}, coupure, nombre)) : etat);
export const ajouterCoupure = (etat, coupure) => (libre(etat) ? avecComptage(etat, plusUn(etat.comptage || {}, coupure)) : etat);
export const toutEffacer = (etat) => (libre(etat) && totalCompte(etat.comptage || {}) > 0 ? avecComptage(etat, {}) : etat);

/** « C'est rendu » : les coupures rendues sortent du comptage. */
export function tropPercuRendu(etat) {
  const a = analyseEspeces(etat);
  if (!libre(etat) || a.statut !== 'trop' || !a.rendre) return etat;
  return avecComptage(etat, apresRendu(etat.comptage || {}, a.rendre.pieces));
}

export const revenirPrestation = (etat) => (compteVisible(etat) && !etat.retourPrestation && libre(etat) ? { ...etat, retourPrestation: true } : etat);
export const revenirComptage = (etat) => (etat.retourPrestation ? { ...etat, retourPrestation: false } : etat);
