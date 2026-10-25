// ─── Le magasin de l'état de la caisse ───────────────────────────────────────
//
// Extrait d'etat.js (qui le réexporte) : le seul endroit où l'état change.

import { creerEtat } from './etat.js';

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
