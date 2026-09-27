// ─── L'état de la caisse et ses transitions, PUR ─────────────────────────────
//
// Aucun accès au DOM ni au réseau : chaque transition prend un état et rend un
// NOUVEL état (l'ancien n'est jamais modifié). Les écrans ne font que dessiner
// l'état ; les appels réseau vivent ailleurs et reviennent ici par une
// transition. Tout ce qui décide de ce qui part au lecteur se teste sous node.
//
// Le principe qui commande tout : le prix vient du DEVIS du CRM. Le panier ne
// connaît que « élève + produit + moyen (+ espèces) ». Toute modification de
// ces éléments incrémente `version`, ce qui périme le devis en main ; une
// réponse de devis arrivée pour une ancienne version est ignorée. On ne peut
// donc jamais envoyer au lecteur le prix d'un panier qui n'est plus affiché.

import { lireMontant } from './format.js';

export const ONGLETS = ['forfait', 'heures_supp', 'prepa', 'libre'];
export const MOYENS = ['carte', 'mixte', 'especes'];

/** Le panier vide, sans élève. Mode et utilisateur sont conservés à part. */
function panierVide() {
  return {
    eleve: null,          // EleveCaisse (ARCHITECTURE.md § 10.1)
    onglet: 'forfait',
    produit: null,        // voir `requeteDevis` pour les formes possibles
    moyen: 'carte',
    especesSaisie: '',    // texte tel que tapé ; converti à la demande
    version: 0,
    devis: null,          // DevisLisible
    jetonDevis: null,     // seul le jeton fait foi côté serveur
    devisVersion: -1,     // version du panier pour laquelle `devis` a été émis
    devisErreur: null,    // message du CRM, affiché tel quel
    paiement: null,       // { etape: 'envoi' | 'carte' | 'capture' | 'especes' }
    erreur: null,         // message affiché dans le panier (envoi impossible…)
    refus: null,          // motif du lecteur (écran 9)
    resultat: null,       // { declaration, montantCents, incomplet? } (écran 7)
  };
}

export function creerEtat() {
  return {
    ecran: 'chargement',  // chargement | eleve | panier | accepte | refuse | secours | identification
    mode: null,           // catalogue | secours | identification_requise
    utilisateur: null,    // { nom, role }
    raison: null,         // raison du mode (jeton_expire, crm_indisponible…)
    message: null,        // message lisible du serveur accompagnant la raison
    secours: null,        // { indisponible, prenom, nom, email, studentId }
    especesARendre: 0,    // rappel affiché sur l'écran 1 après un abandon
    ...panierVide(),
  };
}

// ─── Lectures ────────────────────────────────────────────────────────────────

/** Espèces saisies en centimes (mixte seulement), ou null si illisibles. */
export function especesCents(etat) {
  return etat.moyen === 'mixte' ? lireMontant(etat.especesSaisie) : null;
}

/**
 * Le corps de `POST /api/caisse/devis` pour ce panier, ou `{ manque }` si le
 * panier n'est pas complet (le bouton reste alors désactivé).
 */
export function requeteDevis(etat) {
  if (!etat.eleve) return { manque: 'eleve' };
  const p = etat.produit;
  if (!p) return { manque: 'produit' };

  let produit;
  if (p.type === 'forfait' || p.type === 'heures_supp') {
    produit = { type: p.type, formuleId: p.formuleId };
  } else if (p.type === 'prepa') {
    produit = p.accompagnementSeul ? { type: 'prepa', accompagnementSeul: true } : { type: 'prepa' };
  } else if (p.type === 'libre') {
    const montantCents = lireMontant(p.montantSaisie);
    if (!montantCents) return { manque: 'montant' };
    if (!p.motif) return { manque: 'motif' };
    const precision = String(p.precision || '').trim();
    if (p.precisionObligatoire && !precision) return { manque: 'precision' };
    produit = { type: 'libre', montantCents, motif: p.motif };
    if (precision) produit.precision = precision;
  } else {
    return { manque: 'produit' };
  }

  const corps = { studentId: etat.eleve.eleve.id, produit, moyen: etat.moyen };
  if (etat.moyen === 'mixte') {
    const esp = especesCents(etat);
    if (!esp) return { manque: 'especes' };
    corps.especesCents = esp;
  }
  return { corps };
}

/** Le devis en main correspond-il au panier affiché ? */
export function devisAJour(etat) {
  return Boolean(etat.devis && etat.jetonDevis && etat.devisVersion === etat.version);
}

/** Espèces à rendre si l'on abandonne : celles du devis, à défaut celles saisies. */
export function especesARendre(etat) {
  if (etat.moyen !== 'mixte') return 0;
  if (devisAJour(etat) && etat.devis.especesCents > 0) return etat.devis.especesCents;
  return especesCents(etat) || 0;
}

// ─── Transitions ─────────────────────────────────────────────────────────────

/** Tout changement du panier périme le devis en main. */
function panierModifie(etat, changements) {
  return {
    ...etat,
    ...changements,
    version: etat.version + 1,
    devis: null,
    jetonDevis: null,
    devisVersion: -1,
    devisErreur: null,
    erreur: null,
  };
}

/**
 * Réponse de `GET /api/caisse/session` → écran de départ (§ 7). En secours, le
 * bandeau « Le CRM ne répond pas » n'apparaît que si un CRM est configuré :
 * sans CRM, la caisse reste identique à celle d'avant.
 */
export function sessionOuverte(etat, session, crmConfigure = false) {
  const mode = session && session.mode;
  const base = {
    ...etat,
    mode,
    utilisateur: (session && session.utilisateur) || null,
    raison: (session && session.raison) || null,
    message: (session && session.message) || null,
  };
  if (mode === 'catalogue') return { ...base, ecran: 'eleve' };
  if (mode === 'identification_requise') return { ...base, ecran: 'identification' };
  // « Le CRM ne répond pas » seulement s'il est déclaré ET muet : sans CRM, ou
  // à une adresse sans agence, ce serait faux.
  const muet = crmConfigure && !['crm_non_configure', 'agence_sans_slug', 'agence_inconnue'].includes(base.raison);
  return basculerSecours({ ...base, mode: 'secours' }, { indisponible: muet });
}

export function identificationRequise(etat, raison, message = null) {
  return { ...etat, ...panierVide(), mode: 'identification_requise', raison: raison || null, message, ecran: 'identification' };
}

/** L'élève est chargé (EleveCaisse) : nouveau panier, onglet Forfait initial. */
export function eleveCharge(etat, eleveCaisse) {
  return { ...etat, ...panierVide(), version: etat.version + 1, eleve: eleveCaisse, ecran: 'panier', especesARendre: 0 };
}

export function changerEleve(etat) {
  return { ...etat, ...panierVide(), version: etat.version + 1, ecran: 'eleve' };
}

/**
 * Changer d'onglet vide le produit. Seule exception : la prépa, qui n'a pas de
 * tuile à toucher — le CRM a déjà calculé ce qui est dû, le panier le reprend
 * d'office (sauf mode « rien » : rien à encaisser).
 */
export function choisirOnglet(etat, onglet) {
  if (!ONGLETS.includes(onglet) || onglet === etat.onglet) return etat;
  if (onglet === 'libre' && !(etat.eleve && etat.eleve.libre && etat.eleve.libre.autorise)) return etat;
  let produit = null;
  if (onglet === 'prepa') {
    const prepa = etat.eleve && etat.eleve.prepa;
    if (prepa && prepa.mode !== 'rien' && !prepa.indisponible) {
      produit = { type: 'prepa', accompagnementSeul: prepa.mode === 'accompagnement_seul' };
    }
  }
  if (onglet === 'libre') {
    produit = { type: 'libre', montantSaisie: '', motif: null, precision: '', precisionObligatoire: false };
  }
  return panierModifie(etat, { onglet, produit });
}

/** Une tuile touchée : forfait ou pack d'heures. */
export function choisirFormule(etat, type, formuleId) {
  if (!formuleId || (type !== 'forfait' && type !== 'heures_supp')) return etat;
  const p = etat.produit;
  if (p && p.type === type && p.formuleId === formuleId) return etat;
  return panierModifie(etat, { produit: { type, formuleId } });
}

/** Prépa : bascule « heures + accompagnement » ↔ « accompagnement seul ». */
export function basculerAccompagnementSeul(etat, seul) {
  const p = etat.produit;
  if (!p || p.type !== 'prepa' || Boolean(p.accompagnementSeul) === Boolean(seul)) return etat;
  return panierModifie(etat, { produit: { type: 'prepa', accompagnementSeul: Boolean(seul) } });
}

/** Montant libre : champs saisis (montant, motif, précision). */
export function saisirLibre(etat, champs) {
  const p = etat.produit;
  if (!p || p.type !== 'libre') return etat;
  return panierModifie(etat, { produit: { ...p, ...champs } });
}

export function choisirMoyen(etat, moyen) {
  if (!MOYENS.includes(moyen) || moyen === etat.moyen) return etat;
  return panierModifie(etat, { moyen, especesSaisie: moyen === 'mixte' ? etat.especesSaisie : '' });
}

export function saisirEspeces(etat, texte) {
  if (etat.moyen !== 'mixte' || texte === etat.especesSaisie) return etat;
  return panierModifie(etat, { especesSaisie: String(texte ?? '') });
}

/** Réponse du devis : retenue seulement si le panier n'a pas bougé entre-temps. */
export function devisRecu(etat, version, reponse) {
  if (version !== etat.version || !reponse || !reponse.devis || !reponse.jeton) return etat;
  return { ...etat, devis: reponse.devis, jetonDevis: reponse.jeton, devisVersion: version, devisErreur: null };
}

export function devisRefuse(etat, version, message) {
  if (version !== etat.version) return etat;
  return { ...etat, devis: null, jetonDevis: null, devisVersion: -1, devisErreur: message || 'Prix indisponible.' };
}

// ─── Paiement ────────────────────────────────────────────────────────────────

export function paiementEtape(etat, etape) {
  return { ...etat, paiement: { etape }, erreur: null, refus: null };
}

/** Rien n'est parti (envoi refusé par le serveur) : on reste sur le panier. */
export function paiementErreur(etat, message) {
  return { ...etat, paiement: null, erreur: message || 'Envoi impossible.', ecran: 'panier' };
}

/** Carte refusée, annulée ou délai dépassé : écran 9, panier intact. */
export function paiementRefuse(etat, motif) {
  return { ...etat, paiement: null, refus: motif || 'Paiement non abouti.', ecran: 'refuse' };
}

export function paiementAccepte(etat, resultat) {
  return { ...etat, paiement: null, erreur: null, refus: null, resultat, ecran: 'accepte' };
}

/** Écran 9 → « Réessayer » : même panier, même devis (redemandé s'il expire). */
export function reessayer(etat) {
  return { ...etat, refus: null, ecran: 'panier' };
}

/** Écran 9 → « Changer de moyen » : retour au panier, le moyen se choisit à nouveau. */
export function changerDeMoyen(etat) {
  return { ...etat, refus: null, ecran: 'panier' };
}

/** Écran 9 → « Abandonner » : retour au choix de l'élève, rappel des espèces. */
export function abandonner(etat) {
  const aRendre = especesARendre(etat);
  return { ...etat, ...panierVide(), version: etat.version + 1, ecran: 'eleve', especesARendre: aRendre };
}

export function nouvelEncaissement(etat) {
  return { ...etat, ...panierVide(), version: etat.version + 1, ecran: 'eleve', especesARendre: 0 };
}

/**
 * CRM injoignable (au démarrage ou en cours de panier) : écran 8. L'élève déjà
 * choisi pré-remplit le formulaire, pour ne rien faire ressaisir.
 */
export function basculerSecours(etat, { indisponible, eleve = null }) {
  // `eleve` : un élève trouvé par la recherche mais pas encore chargé
  // ({ id, prenom, nom, email }) ; sinon celui du panier.
  const e = eleve || (etat.eleve && etat.eleve.eleve);
  return {
    ...etat,
    ecran: 'secours',
    paiement: null,
    secours: {
      indisponible: Boolean(indisponible),
      prenom: (e && e.prenom) || '',
      nom: (e && e.nom) || '',
      email: (e && e.email) || '',
      studentId: (e && e.id) || null,
    },
  };
}

// ─── Magasin ─────────────────────────────────────────────────────────────────

/**
 * Le seul endroit où l'état change. `appliquer(transition, …args)` calcule le
 * nouvel état et prévient les abonnés. Un abonné qui plante ne prive pas les
 * autres de leur rendu : un défaut d'affichage ne doit jamais bloquer la caisse.
 */
export function creerMagasin(initial = creerEtat()) {
  let etat = initial;
  const abonnes = [];
  return {
    lire: () => etat,
    appliquer(transition, ...args) {
      const suivant = transition(etat, ...args);
      if (suivant === etat) return etat;
      etat = suivant;
      for (const f of abonnes) {
        try { f(etat); } catch (e) { console.error('[caisse] rendu :', e); }
      }
      return etat;
    },
    ecouter(f) { abonnes.push(f); },
  };
}
