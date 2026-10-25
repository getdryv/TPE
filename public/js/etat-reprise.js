// ─── L'onglet « Reprise de chèque », PUR ─────────────────────────────────────
//
// Extrait d'etat.js (qui le réexporte) : les chèques que l'élève peut
// reprendre, et la case cochée. Aucun accès au DOM ni au réseau.

import { perimer } from './etat-base.js';

/** Les chèques que l'élève peut reprendre (CRM à jour et migration passée), sinon []. */
export function chequesReprenables(etat) {
  const r = etat.eleve && etat.eleve.reprises;
  return r && Array.isArray(r.cheques) ? r.cheques : [];
}

/** Onglet « Reprise de chèque » : coche ou décoche un chèque. */
export function cocherChequeReprise(etat, id) {
  const p = etat.produit;
  if (!p || p.type !== 'reprise_cheque' || !chequesReprenables(etat).some((c) => c.id === id)) return etat;
  const coches = p.chequeIds.includes(id) ? p.chequeIds.filter((x) => x !== id) : [...p.chequeIds, id];
  // L'ordre de la liste fait foi : le devis et le reçu les citent dans cet ordre.
  const ordre = chequesReprenables(etat).map((c) => c.id).filter((x) => coches.includes(x));
  return perimer(etat, { produit: { type: 'reprise_cheque', chequeIds: ordre } });
}
