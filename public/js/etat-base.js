// ─── La règle qui protège le prix, PURE ──────────────────────────────────────
//
// Tout changement du panier périme le devis en main : `version` monte, le
// devis et ses erreurs tombent. Partagée par etat.js et etat-especes.js, pour
// qu'aucun changement du panier n'y échappe.

export function perimer(etat, changements) {
  return {
    ...etat,
    ...changements,
    version: etat.version + 1,
    devis: null,
    jetonDevis: null,
    devisVersion: -1,
    devisErreur: null,
    devisChamp: null,
    erreur: null,
  };
}
