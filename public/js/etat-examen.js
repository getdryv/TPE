// ─── L'onglet « Examen » (ex-« Prépa permis »), PUR ──────────────────────────
//
// Aucun accès au DOM ni au réseau : ce module se teste sous node.
//
// Le parcours (décrit par le gérant le 26/10) : le moniteur pose son « bon pour
// examen » avec sa préconisation (6 h) → l'élève vient payer → la caisse
// s'ouvre DIRECTEMENT sur cet onglet → la secrétaire indique les heures qu'il
// lui reste dans le logiciel de gestion (le CRM met la fiche à jour et le
// trace) → la caisse calcule 6 − 2 = 4 h + l'accompagnement. Heures en plus
// possibles, jamais bloquées. Ajourné ou absent : le forfait de représentation
// de l'agence.
//
// Le calcul ci-dessous ne sert qu'à AFFICHER tout de suite (avant le moyen de
// paiement) : le devis du CRM recalcule tout et reste la seule source du
// montant encaissé. Les heures disponibles voyagent dans la demande de devis :
// si la fiche a bougé entre-temps, le CRM refuse au lieu de deviner.

import { perimer } from './etat-base.js';

/** L'onglet tel que le CRM l'a calculé en dernier (après une saisie d'heures, sa réponse). */
export function prepaCourante(etat) {
  return (etat.examen && etat.examen.prepa) || (etat.eleve && etat.eleve.prepa) || null;
}

/** Un CRM d'avant le 26/10 n'envoie pas les heures : l'onglet garde l'ancien comportement. */
const aLesHeures = (p) => Boolean(p && p.heures && typeof p.heures.preconisees === 'number');
const passageEnVue = (p) => Boolean(p && (p.preconisation || p.representation));
const borne = (n, max) => Math.max(0, Math.min(Number.isFinite(max) ? max : 0, Math.round(Number(n) || 0)));

/** L'état de la saisie à l'ouverture de l'élève. */
export function examenPourEleve(eleveCaisse) {
  const p = eleveCaisse && eleveCaisse.prepa;
  const stock = aLesHeures(p) ? Number(p.heures.stock) || 0 : 0;
  return { saisie: stock, statut: null, message: null, prepa: null, confirme: null };
}

/** L'onglet de départ : « Examen » quand le CRM le demande (passage en jeu, quelque chose à régler). */
export function ongletInitial(eleveCaisse) {
  const p = eleveCaisse && eleveCaisse.prepa;
  return p && p.ouvrir === true && !p.indisponible ? 'prepa' : 'forfait';
}

/** Le produit du panier quand on arrive sur l'onglet, ou null (rien à encaisser ici). */
export function produitExamen(prepa) {
  if (!prepa || prepa.indisponible) return null;
  if (!aLesHeures(prepa)) {
    return prepa.mode !== 'rien' ? { type: 'prepa', accompagnementSeul: prepa.mode === 'accompagnement_seul' } : null;
  }
  if (!passageEnVue(prepa)) return null;
  return { type: 'prepa', heuresEnPlus: 0, heuresDisponibles: Number(prepa.heures.stock) || 0 };
}

/** « 4 h de préparation à l'examen »… — le libellé du CRM (`libelleHeuresPrepa`), que le devis remplacera. */
export function libelleHeures(heures, enPlus, representation) {
  const plus = Math.max(0, Math.min(enPlus, heures));
  const base = heures - plus;
  if (representation) return plus > 0 ? `Forfait de représentation : ${base} h + ${plus} h en plus` : `Forfait de représentation : ${heures} h`;
  if (plus > 0 && base > 0) return `${heures} h de préparation à l’examen, dont ${plus} h en plus`;
  if (plus > 0) return `${plus} h en plus avant l’examen`;
  return `${heures} h de préparation à l’examen`;
}

/**
 * Ce que l'onglet et le panier affichent, à l'instant : heures préconisées,
 * disponibles (saisie en cours comprise), à payer, en plus, lignes et total.
 * null si l'onglet n'a rien à calculer.
 */
export function calculExamen(etat) {
  const p = prepaCourante(etat);
  if (!p) return null;
  const produit = etat.produit && etat.produit.type === 'prepa' ? etat.produit : {};
  if (!aLesHeures(p)) {
    const lignes = (p.lignes || []).filter((l) => !produit.accompagnementSeul || l.nature === 'accompagnement');
    return { ancien: true, lignes, totalCents: lignes.reduce((t, l) => t + (Number.isFinite(l.montantCents) ? l.montantCents : 0), 0) };
  }
  const h = p.heures;
  const rep = p.representation || null;
  const saisie = etat.examen && Number.isFinite(etat.examen.saisie) ? etat.examen.saisie : Number(h.stock) || 0;
  const disponibles = rep ? 0 : Math.max(saisie, Number(h.plancher) || 0);
  const manquantes = rep ? Number(rep.heures) || 0 : Math.max(0, Math.ceil(h.preconisees - disponibles));
  const enPlus = passageEnVue(p) ? borne(produit.heuresEnPlus, h.enPlusMax) : 0;
  const heures = manquantes + enPlus;
  const grille = Array.isArray(p.grilleCents) ? p.grilleCents : [];
  const heuresCents = heures > 0 && Number.isInteger(grille[heures]) ? grille[heures] : null;
  const manquantesCents = manquantes > 0 && Number.isInteger(grille[manquantes]) ? grille[manquantes] : null;
  const accCents = Number.isInteger(p.accompagnementCents) && p.accompagnementCents > 0 ? p.accompagnementCents : null;

  const lignes = [];
  if (heures > 0 && heuresCents !== null) lignes.push({ libelle: libelleHeures(heures, enPlus, Boolean(rep)), montantCents: heuresCents, nature: 'produit' });
  if (accCents) lignes.push({ libelle: 'Accompagnement à l’examen', montantCents: accCents, nature: 'accompagnement' });
  return {
    ancien: false,
    representation: rep,
    preconisees: h.preconisees,
    saisie,
    disponibles,
    plancher: Number(h.plancher) || 0,
    manquantes,
    manquantesCents,
    enPlus,
    heures,
    heuresCents,
    accCents,
    lignes,
    totalCents: lignes.reduce((t, l) => t + l.montantCents, 0),
    passage: passageEnVue(p),
  };
}

/**
 * Pourquoi le devis ne peut pas encore partir (null : il peut) : la saisie des
 * heures n'est pas encore sur la fiche, ou il n'y a rien à régler.
 */
export function manqueExamen(etat) {
  const p = prepaCourante(etat);
  if (!aLesHeures(p)) return null;
  const ex = etat.examen || {};
  if (ex.statut === 'erreur') return 'heures_erreur';
  if (ex.statut === 'attente' || ex.statut === 'envoi') return 'heures';
  if (Number.isFinite(ex.saisie) && ex.saisie !== (Number(p.heures.stock) || 0)) return 'heures';
  const c = calculExamen(etat);
  return c && c.totalCents > 0 ? null : 'rien';
}

/** Le produit envoyé au devis : des DRAPEAUX et des heures, jamais un montant. */
export function produitDevisExamen(etat) {
  const p = etat.produit || {};
  if (p.accompagnementSeul) return { type: 'prepa', accompagnementSeul: true };
  const prepa = prepaCourante(etat);
  if (!aLesHeures(prepa)) return { type: 'prepa' };
  return { type: 'prepa', heuresEnPlus: borne(p.heuresEnPlus, prepa.heures.enPlusMax), heuresDisponibles: Number(prepa.heures.stock) || 0 };
}

// ─── Transitions ─────────────────────────────────────────────────────────────

/** « − / nombre / + » ou clavier : la saisie, bornée de 0 au plafond du compte. Le devis tombe. */
export function saisirHeuresDisponibles(etat, valeur) {
  const p = prepaCourante(etat);
  if (!aLesHeures(p) || p.representation) return etat;
  const n = borne(valeur, p.heures.max);
  const ex = etat.examen || examenPourEleve(etat.eleve);
  if (n === ex.saisie && ex.statut !== 'erreur') return etat;
  return perimer(etat, { examen: { ...ex, saisie: n, statut: 'attente', message: null } });
}

/** La saisie part au CRM. */
export function heuresEnvoyees(etat, valeur) {
  const ex = etat.examen;
  if (!ex || ex.saisie !== valeur) return etat;
  return { ...etat, examen: { ...ex, statut: 'envoi' } };
}

/** La fiche est à jour : l'onglet recalculé par le CRM remplace le précédent. */
export function heuresEnregistrees(etat, valeur, prepa) {
  const ex = etat.examen;
  if (!ex || !prepa) return etat;
  // Une autre saisie a suivi : on garde la réponse, la saisie en cours repartira.
  const aJour = ex.saisie === valeur;
  const produit = etat.produit && etat.produit.type === 'prepa' && aLesHeures(prepa)
    ? { ...etat.produit, heuresDisponibles: Number(prepa.heures.stock) || 0 }
    : etat.produit;
  return perimer(etat, {
    produit,
    examen: { ...ex, prepa, statut: aJour ? 'ok' : 'attente', confirme: aJour ? valeur : ex.confirme, message: null },
  });
}

/** Refus du CRM (borne, élève) ou CRM muet : la fiche n'a pas bougé, on le dit. */
export function heuresRefusees(etat, valeur, message) {
  const ex = etat.examen;
  if (!ex || ex.saisie !== valeur) return etat;
  return { ...etat, examen: { ...ex, statut: 'erreur', message: message || 'La fiche n’a pas été mise à jour.' } };
}

/** « Heures en plus » : 0 au plafond du CRM. */
export function choisirHeuresEnPlus(etat, valeur) {
  const p = etat.produit;
  const prepa = prepaCourante(etat);
  if (!p || p.type !== 'prepa' || !aLesHeures(prepa)) return etat;
  const n = borne(valeur, prepa.heures.enPlusMax);
  if (n === (p.heuresEnPlus || 0)) return etat;
  return perimer(etat, { produit: { ...p, heuresEnPlus: n } });
}
