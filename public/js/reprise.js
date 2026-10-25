// ─── Onglet « Reprise de chèque » ────────────────────────────────────────────
//
// L'élève reprend un chèque pas encore déposé en banque et paie autrement. On
// coche le(s) chèque(s), on choisit Espèces (comptage + bordereau) ou Carte ;
// à l'encaissement, le CRM passe le chèque « Rendu à l'élève » dans le module
// Chèques. L'onglet n'existe que si le CRM en propose (`eleve.reprises`).

import { el, eurosCourts } from './format.js';
import { chequesReprenables, cocherChequeReprise } from './etat.js';
import { jourEtMois } from './bordereau-texte.js';

let magasin = null;
const ICO_COCHE = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>';

/** PURE. « À déposer le 15 novembre · forfait Permis B, versement 2 sur 3 ». */
export function sousTitreCheque(c) {
  const morceaux = [];
  if (c.dueOn) morceaux.push(`À déposer le ${jourEtMois(c.dueOn)}`);
  const quoi = [c.libelle, c.versement ? `versement ${c.versement.rang} sur ${c.versement.sur}` : null].filter(Boolean).join(', ');
  if (quoi) morceaux.push(quoi);
  if (c.banque) morceaux.push(c.banque);
  return morceaux.join(' · ');
}

/** PURE. « Chèque n° 0004521 », « Chèque sans numéro ». */
export const titreCheque = (c) => (c.numero ? `Chèque n° ${c.numero}` : 'Chèque sans numéro');

/** PURE. Les numéros des chèques cochés, dans l'ordre de la liste. */
export function numerosCoches(etat) {
  const p = etat.produit;
  if (!p || p.type !== 'reprise_cheque') return [];
  return chequesReprenables(etat).filter((c) => p.chequeIds.includes(c.id)).map((c) => c.numero || 'sans numéro');
}

/** PURE. La phrase sous les moyens : ce qui arrivera au(x) chèque(s). */
export function noteReprise(etat) {
  const numeros = numerosCoches(etat);
  if (!numeros.length) return '';
  const n = numeros.length;
  const qui = n > 1 ? `les chèques ${numeros.map((x) => `n° ${x}`).join(', ')} passent` : `le chèque n° ${numeros[0]} passe`;
  return `Une fois encaissé, ${qui} « Rendu à l'élève » et sort${n > 1 ? 'ent' : ''} du prochain dépôt en banque.`;
}

export function contenuReprise(etat) {
  const cases = chequesReprenables(etat).map((c) => {
    const coche = el('span', { class: 'case', 'aria-hidden': 'true' });
    return el('button', {
      type: 'button', class: 'case-option case-cheque', role: 'checkbox', 'aria-checked': 'false', 'data-cheque': c.id, 'data-verrou': '',
      onclick: () => magasin.appliquer(cocherChequeReprise, c.id),
    }, coche,
    el('span', { class: 'co-texte' }, el('span', { class: 'co-nom' }, titreCheque(c)), el('span', { class: 'muted petit' }, sousTitreCheque(c))),
    el('span', { class: 'co-mt' }, eurosCourts(c.montantCents)));
  });
  return [el('p', { class: 'petit' }, 'Chèques de l\'élève pas encore déposés en banque. Cochez celui qu\'il reprend.'),
    el('div', { class: 'liste-cheques' }, cases)];
}

/** Cases cochées seulement : aucun nœud recréé. */
export function majReprise(etat) {
  const p = etat.produit;
  const coches = p && p.type === 'reprise_cheque' ? p.chequeIds : [];
  document.querySelectorAll('.case-cheque').forEach((b) => {
    const oui = coches.includes(b.dataset.cheque);
    b.setAttribute('aria-checked', String(oui));
    b.classList.toggle('coche', oui);
    b.querySelector('.case').innerHTML = oui ? ICO_COCHE : ''; // pictogramme constant
  });
}

export function initReprise(m) {
  magasin = m;
}
