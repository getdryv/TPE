// ─── Le bordereau d'espèces : mise en page et impression ─────────────────────
//
// Après chaque encaissement avec des espèces, la caisse imprime d'elle-même un
// bordereau noir et blanc, à glisser avec les billets : agence, n°
// d'encaissement, date et heure À LA SECONDE (celles du CRM), élève,
// prestation, montant en chiffres et en lettres, détail des coupures, part
// payée autrement, qui a encaissé. Ni signature ni recomptage (décision du
// 25/10/2026). « Réimprimer le bordereau » redemande les données au CRM, qui
// les marque DUPLICATA et trace qui les a demandées.
//
// Tout vient des données du CRM (`declaration.bordereau`) ; les phrases de
// bordereau-texte.js. Le format (A5 par défaut, A4) est un réglage d'agence.

import { el, remplir, euros, eurosCourts } from './format.js';
import { dateHeure, encadre, enveloppe, libelleLigne, montantEnLettres, nombreDeCoupures } from './bordereau-texte.js';

const $ = (id) => document.getElementById(id);

/** Le document du bordereau (un nœud), prêt à imprimer. `reimpression` : { par, le } pour un duplicata. */
export function documentBordereau(b, reimpression = null) {
  const lignes = (b.coupures || []).map((c) => el('tr', {},
    el('td', {}, libelleLigne(c.coupureCents)), el('td', {}, String(c.nombre)), el('td', {}, eurosCourts(c.montantCents))));
  const cadre = encadre(b);
  const env = enveloppe(b);
  const infos = [['Date', dateHeure(b.encaisseLe)], ['Élève', b.eleve], ['Prestation', b.prestation], ['Encaissé par', b.encaissePar]];
  return el('article', { class: `bordereau format-${b.format === 'A4' ? 'A4' : 'A5'}` },
    el('header', { class: 'b-haut' },
      el('div', {}, el('div', { class: 'b-agence' }, b.agence.nom), b.agence.adresse ? el('div', { class: 'b-adresse' }, b.agence.adresse) : null),
      el('div', { class: 'b-numero' }, 'Encaissement n°', el('b', {}, b.numero))),
    el('div', { class: 'b-titre' }, el('h1', {}, 'BORDEREAU D\'ESPÈCES'), b.duplicata ? el('span', { class: 'b-duplicata' }, 'DUPLICATA') : null),
    el('dl', { class: 'b-infos' }, infos.flatMap(([dt, dd]) => [el('dt', {}, dt), el('dd', {}, dd)])),
    el('div', { class: 'b-boite' },
      el('div', { class: 'b-boite-l' }, el('span', {}, env.libelle), el('span', {}, env.detail ? euros(env.cents) : eurosCourts(env.cents))),
      el('div', { class: 'b-lettres' }, montantEnLettres(env.cents)),
      env.detail ? el('div', { class: 'b-arrondi' }, env.detail) : null),
    lignes.length
      ? el('table', { class: 'b-coupures' },
        el('thead', {}, el('tr', {}, el('th', {}, 'Billets et pièces'), el('th', {}, 'Nombre'), el('th', {}, 'Montant'))),
        el('tbody', {}, lignes),
        el('tfoot', {}, el('tr', {}, el('td', {}, 'Total'), el('td', {}, String(nombreDeCoupures(b.coupures))), el('td', {}, eurosCourts(env.cents)))))
      : el('p', { class: 'b-sans-detail' }, 'Détail des billets et des pièces non enregistré.'),
    cadre ? el('div', { class: 'b-autre' }, el('b', {}, cadre.titre), cadre.lignes.map((t) => el('span', { class: 'bloc' }, t))) : null,
    el('footer', { class: 'b-pied' },
      reimpression ? el('span', { class: 'bloc' }, `Duplicata réimprimé le ${dateHeure(reimpression.le).replace(/^./, (x) => x.toLowerCase())}${reimpression.par ? ` par ${reimpression.par}` : ''}.`) : null,
      el('span', { class: 'bloc' }, 'Glissez les espèces avec ce bordereau.')));
}

/** Pose le format de page (A5 ou A4, portrait, sans marge : la mise en page a les siennes). */
function formatDePage(format) {
  let style = $('pageBordereau');
  if (!style) {
    style = el('style', { id: 'pageBordereau' });
    document.head.append(style);
  }
  style.textContent = `@page { size: ${format === 'A4' ? 'A4' : 'A5'} portrait; margin: 0; }`;
}

/**
 * Imprime le bordereau (la boîte d'impression du navigateur s'ouvre, une
 * imprimante par défaut l'imprime d'un geste). Rend faux si rien à imprimer.
 * Ne lève jamais : une impression ratée n'annule rien, « Réimprimer » reste là.
 */
export function imprimerBordereau(b, reimpression = null) {
  try {
    const hote = $('impressionBordereau');
    if (!b || !hote) return false;
    remplir(hote, documentBordereau(b, reimpression));
    formatDePage(b.format);
    // Après le rendu : sinon le navigateur imprime la page d'avant.
    setTimeout(() => { try { window.print(); } catch (e) { console.warn('[caisse] impression :', e); } }, 50);
    return true;
  } catch (e) {
    console.error('[caisse] bordereau :', e);
    return false;
  }
}
