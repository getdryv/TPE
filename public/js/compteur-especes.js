// ─── Le compteur « Espèces comptées » du panier ──────────────────────────────
//
// Toujours au même endroit, juste sous les moyens de paiement : ce qui a été
// compté, et ce que ça veut dire (il manque, le compte est juste, trop donné et
// quoi rendre, reste par carte ou en chèques). Le calcul vit dans
// etat-especes.js et especes-compte.js ; ici, seulement le dessin. Construit
// une fois, mis à jour à chaque rendu (aucun nœud recréé à chaque billet).

import { el, eurosCourts } from './format.js';
import { analyseEspeces, compteVisible, revenirComptage, tropPercuRendu } from './etat-especes.js';
import { designation, COUPURES } from './especes-compte.js';

const ICO_OK = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>';

let magasin = null;
const n = {};

/** PURE. « 1 billet de 10 € et 1 pièce de 1 € » : de la plus grande coupure à la plus petite. */
export function texteRendu(pieces) {
  const morceaux = COUPURES.filter((c) => (pieces[String(c)] || 0) > 0).map((c) => designation(c, pieces[String(c)]));
  if (morceaux.length <= 1) return morceaux.join('');
  return `${morceaux.slice(0, -1).join(', ')} et ${morceaux[morceaux.length - 1]}`;
}

/** PURE. Le bouton du trop-perçu : « Billet de 50 € rendu » s'il n'y a qu'une coupure à rendre, sinon « C'est rendu ». */
export function libelleRendu(pieces) {
  const cles = Object.keys(pieces || {}).filter((k) => pieces[k] > 0);
  if (cles.length === 1 && pieces[cles[0]] === 1) {
    const d = designation(Number(cles[0]), 1).replace(/^1\u00a0b/, 'B').replace(/^1\u00a0p/, 'P');
    return `${d} rendu${d.startsWith('P') ? 'e' : ''}`;
  }
  return 'C\'est rendu';
}

export function construireCompteur(m) {
  magasin = m;
  n.valeur = el('span', { class: 'compteur-val' }, '0 €');
  n.etat = el('p', { class: 'compteur-etat', 'aria-live': 'polite' });
  n.aide = el('p', { class: 'compteur-aide' });
  n.erreur = el('p', { class: 'reste trop', role: 'alert', hidden: true });
  n.rendu = el('button', { type: 'button', class: 'btn', onclick: () => magasin.appliquer(tropPercuRendu) }, 'C\'est rendu');
  n.retour = el('button', { type: 'button', class: 'lien-btn', onclick: () => magasin.appliquer(revenirComptage) }, 'Compter les espèces');
  n.boite = el('div', { class: 'compteur' },
    el('div', { class: 'compteur-ligne' }, el('span', { class: 'compteur-lib' }, 'Espèces comptées'), n.valeur),
    n.etat, n.aide, n.erreur, n.rendu, n.retour);
  return n.boite;
}

function poser(noeud, texte) {
  noeud.textContent = texte || '';
  noeud.hidden = !texte;
}

/** Une phrase avec des passages en gras (« Rendez à l'élève **1 billet de 10 €** … »). */
function phrase(noeud, morceaux) {
  noeud.replaceChildren(...morceaux.map((m) => (typeof m === 'string' ? document.createTextNode(m) : el('b', {}, m.gras))));
  noeud.hidden = morceaux.length === 0;
}

/**
 * `reste` : le reste par carte / en chèques du devis affiché (mixte), ou null.
 * `erreur` : le refus du CRM sur la part espèces (« les espèces couvrent tout »).
 */
export function rendreCompteur(etat, { reste = null, texteReste = '', erreur = '' } = {}) {
  if (!n.boite) return;
  const visible = compteVisible(etat);
  n.boite.hidden = !visible;
  if (!visible) return;
  const a = analyseEspeces(etat);
  const mixte = etat.moyen !== 'especes';
  n.valeur.textContent = eurosCourts(a.compte);
  n.boite.className = 'compteur';
  n.rendu.hidden = true;
  n.etat.className = 'compteur-etat';
  phrase(n.aide, []);
  if (a.statut === 'vide') {
    poser(n.etat, '');
    phrase(n.aide, ['Comptez les billets et les pièces que l\'élève vous donne.']);
  } else if (mixte) {
    poser(n.etat, reste !== null ? texteReste : '');
  } else if (a.statut === 'attente') {
    poser(n.etat, 'Calcul du prix…');
  } else if (a.statut === 'manque') {
    n.etat.classList.add('etat-manque');
    poser(n.etat, `Il manque ${eurosCourts(a.manque)}`);
  } else if (a.statut === 'juste') {
    n.boite.classList.add('juste');
    n.etat.classList.add('etat-juste');
    n.etat.innerHTML = ICO_OK; // pictogramme constant, sans donnée
    n.etat.append(document.createTextNode('Le compte est juste'));
    n.etat.hidden = false;
  } else {
    n.boite.classList.add('trop');
    n.etat.classList.add('etat-trop');
    poser(n.etat, `${eurosCourts(a.trop)} de trop`);
    const r = a.rendre;
    if (r && r.appoint === 0) {
      phrase(n.aide, ['Rendez à l\'élève ', { gras: texteRendu(r.pieces) }, ', pris parmi ce qu\'il vous a donné.']);
    } else if (r) {
      phrase(n.aide, [`Impossible de rendre ${eurosCourts(a.trop)} avec ce que l'élève a donné. Rendez-lui `, { gras: texteRendu(r.pieces) },
        ' et demandez\u2011lui ', { gras: eurosCourts(r.appoint) }, ' en appoint.']);
    } else {
      phrase(n.aide, [`Rendez ${eurosCourts(a.trop)} à l'élève parmi ce qu'il vous a donné, puis corrigez le comptage.`]);
    }
    if (r) {
      n.rendu.textContent = libelleRendu(r.pieces);
      n.rendu.hidden = false;
    }
  }
  poser(n.erreur, erreur);
  n.rendu.disabled = Boolean(etat.paiement);
  n.retour.hidden = !etat.retourPrestation;
}
