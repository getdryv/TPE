// ─── Écrans d'issue : accepté (7), refusé (9), identification requise ───────
//
// Accepté : ce que le CRM a enregistré, en ses propres mots (`effets[].texte`).
// Refusé : le panier est GARDÉ tel quel ; rien n'a été débité ni enregistré.
// Identification : la caisse ne sait pas qui encaisse, elle s'ouvre depuis le CRM.

import * as cadre from './cadre.js';
import { el, remplir, euros } from './format.js';
import { reessayer, changerDeMoyen, abandonner, nouvelEncaissement } from './etat.js';
import { envoyerCarte, lecteurPret } from './paiement.js';

let magasin = null;
const $ = (id) => document.getElementById(id);

// Pictogrammes constants (aucune donnée dedans) : seul contenu posé en HTML.
const PICTO = {
  ok: '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#0d6832" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  ko: '<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#a4161a" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M7 7l10 10M17 7L7 17"/></svg>',
  warn: '<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#8a4b00" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M12 7v6M12 17h.01"/></svg>',
};

function tete(genre, titre, ...lignes) {
  const pastille = el('div', { class: `pastille-issue pastille-${genre}` });
  pastille.innerHTML = PICTO[genre];
  return el('div', { class: 'tete-issue' }, pastille, el('h1', { tabindex: '-1' }, titre), lignes);
}

/** « 300,00 € espèces + 749,00 € carte ». */
function repartition(d) {
  if (!d) return '';
  if (d.especesCents > 0 && d.carteCents > 0) return `${euros(d.especesCents)} espèces + ${euros(d.carteCents)} carte`;
  if (d.especesCents > 0) return `${euros(d.especesCents)} espèces`;
  return `${euros(d.carteCents)} carte`;
}

function focaliserTitre(conteneur) {
  const h = conteneur.querySelector('h1');
  if (h) setTimeout(() => h.focus(), 0);
}

// ─── 7 · Paiement accepté ────────────────────────────────────────────────────

function blocDeclaration(declaration) {
  const statut = declaration.statut;
  const effets = Array.isArray(declaration.effets) ? declaration.effets : [];
  const liste = effets.map((e) => el('div', { class: 'li' },
    el('span', { class: 'ck', 'aria-hidden': 'true' }, '✓'), el('span', {}, e.texte)));

  if (statut === 'en_attente') {
    return [el('div', { class: 'carte effets' }, el('div', { class: 'gras' },
      'Enregistrement dans le CRM en cours ; rien à ressaisir.'))];
  }
  if (statut === 'refus') {
    return [el('div', { class: 'encart encart-warn' },
      `Le CRM n'a pas enregistré cet encaissement${declaration.message ? ` : ${declaration.message}` : ''}. `
      + 'L\'argent est pris : ne recommencez pas le paiement et signalez-le à un administrateur.')];
  }
  const blocs = [];
  if (statut === 'ecart') {
    blocs.push(el('div', { class: 'encart encart-warn' },
      'Écart de montant : l\'encaissement est tracé, mais rien n\'a été marqué payé. Vérifiez dans Stripe.'));
  }
  if (liste.length) {
    blocs.push(el('div', { class: 'carte effets' },
      el('div', { class: 'gras', style: 'margin-bottom:4px' }, 'Ce que le CRM a enregistré tout seul'), liste));
  } else if (statut === 'deja') {
    blocs.push(el('div', { class: 'carte effets' }, el('div', { class: 'gras' }, 'Cet encaissement était déjà enregistré dans le CRM.')));
  }
  if (statut === 'enregistre') {
    blocs.push(el('div', { class: 'encart encart-info' },
      'Rien à ressaisir. Chaque encaissement est tracé : l\'élève, l\'agence et le responsable reçoivent le même ticket, avec le nom de la personne qui a encaissé.'));
  }
  return blocs;
}

function rendreAccepte(etat) {
  const r = etat.resultat || {};
  const d = r.devis;
  const resume = [r.eleve, d && d.libelle, repartition(d)].filter(Boolean).join(' · ');
  const boutons = [];
  const liens = r.declaration && r.declaration.liens;
  if (liens && liens.fiche) {
    boutons.push(el('button', { type: 'button', class: 'btn', onclick: () => cadre.ouvrirDansCrm(liens.fiche) }, 'Ouvrir la fiche'));
  }
  if (liens && liens.contrat) {
    boutons.push(el('button', { type: 'button', class: 'btn', onclick: () => cadre.ouvrirDansCrm(liens.contrat) }, 'Préparer le contrat'));
  }
  boutons.push(el('button', { type: 'button', class: 'btn btnp', onclick: () => magasin.appliquer(nouvelEncaissement) }, 'Nouvel encaissement'));

  const corps = r.incomplet
    ? [tete('warn', 'Carte acceptée', el('div', { class: 'muted resume' }, resume)),
      el('div', { class: 'encart encart-warn', role: 'alert' }, r.incomplet)]
    : [tete('ok', 'Paiement accepté', el('div', { class: 'muted resume' }, resume)),
      ...blocDeclaration(r.declaration || { statut: 'en_attente', effets: [] })];

  remplir($('ecranAccepte'), corps, el('div', { class: 'boutons-issue' }, boutons));
  focaliserTitre($('ecranAccepte'));
}

// ─── 9 · Paiement refusé ─────────────────────────────────────────────────────

function rendreRefuse(etat) {
  const d = etat.devis;
  const e = etat.eleve && etat.eleve.eleve;
  const nom = e ? [e.prenom, e.nom].filter(Boolean).join(' ') : '';
  const especes = d ? d.especesCents : 0;
  const lignes = [el('div', { class: 'gras', style: 'margin-bottom:6px' }, 'Le panier est gardé')];
  if (d) {
    lignes.push(el('div', { class: 'l' }, el('span', {}, [nom, d.libelle].filter(Boolean).join(' · ')), el('span', {}, euros(d.totalCents))));
    if (especes > 0) {
      lignes.push(el('div', { class: 'l' }, el('span', {}, 'Espèces reçues (pas encore enregistrées)'), el('span', {}, euros(especes))));
    }
    lignes.push(el('div', { class: 'l l-total' }, el('span', {}, 'Reste à encaisser par carte'), el('span', {}, euros(d.carteCents))));
  }
  const note = 'Rien n\'est enregistré tant que la carte n\'est pas passée.'
    + (especes > 0 ? ` Si vous abandonnez, rendez les ${euros(especes)} en espèces à l'élève.` : '');

  remplir($('ecranRefuse'),
    tete('ko', 'Paiement refusé',
      el('div', { class: 'motif-refus' }, etat.refus || 'Paiement non abouti.'),
      el('div', { class: 'muted', style: 'font-size:15px' }, 'Rien n\'a été débité et rien n\'est enregistré comme payé.')),
    el('div', { class: 'carte', style: 'padding:16px 22px' }, lignes),
    el('div', { class: 'boutons-issue' },
      el('button', {
        type: 'button', class: 'btn btnp', disabled: !lecteurPret(),
        onclick: () => { magasin.appliquer(reessayer); envoyerCarte(); },
      }, 'Réessayer sur le lecteur'),
      el('button', { type: 'button', class: 'btn', onclick: () => magasin.appliquer(changerDeMoyen) }, 'Changer de moyen de paiement'),
      el('button', { type: 'button', class: 'btn', onclick: () => magasin.appliquer(abandonner) }, 'Abandonner')),
    el('p', { class: 'muted note centre' }, note));
  focaliserTitre($('ecranRefuse'));
}

// ─── Identification requise ──────────────────────────────────────────────────

function rendreIdentification(etat) {
  const expire = etat.raison === 'jeton_expire';
  // Dans le cadre, le CRM ré-émet un jeton et recharge la caisse tout seul.
  const rechargement = expire && cadre.signalerJetonExpire();
  const adresse = cadre.adresseCaisseCrm();
  const texte = rechargement
    ? 'La session a expiré : la caisse se recharge.'
    : expire
      ? 'La session a expiré. Rouvrez la caisse depuis le CRM : elle saura qui encaisse.'
      : 'La caisse s\'ouvre depuis la page Paiements du CRM : elle sait ainsi qui encaisse.';
  // Refus explicite du CRM (compte inactif, hors agence…) : son message d'abord.
  const precision = !expire && etat.message ? el('div', { class: 'encart encart-warn' }, etat.message) : null;
  remplir($('ecranIdentification'),
    tete('warn', expire ? 'Session de caisse expirée' : 'Ouvrez la caisse depuis le CRM',
      el('div', { class: 'muted resume' }, texte)),
    precision,
    !rechargement && adresse
      ? el('div', { class: 'boutons-issue' }, el('a', { class: 'btn btnp', href: adresse, target: '_top' }, 'Ouvrir la caisse dans le CRM'))
      : null);
}

// ─── Rendu ───────────────────────────────────────────────────────────────────

export function rendreIssues(etat, precedent) {
  const entre = (ecran) => etat.ecran === ecran && (!precedent || precedent.ecran !== ecran);
  if (entre('accepte')) rendreAccepte(etat);
  if (entre('refuse')) rendreRefuse(etat);
  if (entre('identification')) rendreIdentification(etat);
}

export function initIssues(m) {
  magasin = m;
}
