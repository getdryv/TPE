// ─── Écrans 2 à 6 : bandeau élève, onglets et tuiles ─────────────────────────
//
// On TOUCHE une formule, on ne tape jamais son prix. Les prix des tuiles sont
// indicatifs (ceux du catalogue, promotion comprise) : seul le devis du CRM
// fait foi, et c'est lui que le panier affiche et que le lecteur débite.
//
// Jamais de liste déroulante : des tuiles, groupées comme le CRM les envoie.
// L'onglet « Montant libre » n'apparaît que si le CRM le dit (`libre.autorise`,
// rôle administrateur relu dans le CRM). Ce n'est qu'un masquage : le CRM
// refuse de toute façon le devis d'un montant libre à une secrétaire.
//
// Le contenu n'est reconstruit que quand l'élève ou l'onglet change ; sinon on
// ne met à jour que la sélection. Reconstruire à chaque frappe ferait perdre le
// focus du champ en cours de saisie (montant libre).

import { el, remplir, euros, eurosCourts, heures, dateCourte, nomComplet } from './format.js';
import {
  changerEleve, choisirOnglet, choisirFormule, basculerAccompagnementSeul, saisirLibre,
} from './etat.js';

const LIBELLES = { forfait: 'Forfait initial', heures_supp: 'Heures supp', prepa: 'Prépa permis', libre: 'Montant libre' };

const INDISPONIBLE = {
  tarif_absent: 'Le tarif des heures n\'est pas au catalogue de l\'agence : la prépa ne peut pas être encaissée ici.',
};

let magasin = null;
let rendu = { eleveId: null, onglet: null };
const $ = (id) => document.getElementById(id);

// ─── Pièces ──────────────────────────────────────────────────────────────────

function prixTuile(t) {
  if (t.promo) {
    return [
      el('span', {}, el('s', {}, euros(t.prixCents)), ' ', el('b', {}, euros(t.promo.prixRemiseCents))),
      el('span', { class: 'chip promo' }, `Promo en cours · ${eurosCourts(-t.promo.remiseCents)}`),
    ];
  }
  return el('span', { class: 'muted' }, euros(t.prixCents));
}

function tuile(type, t) {
  return el('button', {
    type: 'button', class: 'tuile', 'data-formule': t.formuleId, 'aria-pressed': 'false',
    onclick: () => magasin.appliquer(choisirFormule, type, t.formuleId),
  }, el('b', {}, t.nom), prixTuile(t));
}

function grille(type, tuiles, classe = 'tuiles') {
  return el('div', { class: classe }, tuiles.map((t) => tuile(type, t)));
}

function bandeauEleve(ec) {
  const e = ec.eleve;
  return [
    el('span', { class: 'nom' }, nomComplet(e.prenom, e.nom)),
    e.formation ? el('span', { class: 'muted petit' }, e.formation) : null,
    e.forfaitPaye
      ? el('span', { class: 'chip ok' }, `${e.forfaitPaye} payé`)
      : el('span', { class: 'chip grey' }, 'Aucun forfait payé'),
    el('button', { type: 'button', class: 'lien-btn', 'data-verrou': '', onclick: () => magasin.appliquer(changerEleve) },
      'Changer d\'élève'),
  ];
}

function barreOnglets(etat) {
  const visibles = ['forfait', 'heures_supp', 'prepa'];
  if (etat.eleve.libre && etat.eleve.libre.autorise) visibles.push('libre');
  return visibles.map((o) => el('button', {
    type: 'button', role: 'tab', class: 'onglet', id: `onglet-${o}`, 'data-verrou': '',
    'aria-selected': String(etat.onglet === o),
    onclick: () => magasin.appliquer(choisirOnglet, o),
  }, LIBELLES[o]));
}

// ─── Contenus ────────────────────────────────────────────────────────────────

function contenuForfait(ec) {
  const blocs = [];
  if (ec.eleve.forfaitPaye) {
    blocs.push(el('div', { class: 'encart encart-warn' },
      `Un forfait est déjà enregistré : ${ec.eleve.forfaitPaye}. Un nouveau forfait sera encaissé et tracé, sans remplacer celui de la fiche.`));
  }
  const groupes = (ec.forfaits || []).filter((g) => g.formules && g.formules.length);
  if (!groupes.length) blocs.push(el('p', { class: 'muted petit' }, 'Aucun forfait au catalogue de l\'agence.'));
  for (const g of groupes) blocs.push(el('div', { class: 'cat' }, g.titre), grille('forfait', g.formules));
  return blocs;
}

function contenuHeuresSupp(ec) {
  const hs = ec.heuresSupp || { famille: '', packs: [] };
  const famille = hs.famille === 'Moto' ? 'moto' : 'voiture';
  if (!hs.packs || !hs.packs.length) {
    return [el('p', { class: 'muted petit' }, `Aucun pack d'heures ${famille} au catalogue de l'agence.`)];
  }
  return [
    el('div', { class: 'cat' }, `Packs d'heures · ${famille}`),
    grille('heures_supp', hs.packs, 'tuiles tuiles-4'),
    el('p', { class: 'muted petit' }, 'Seuls les packs de la boîte de l\'élève sont proposés.'),
  ];
}

function textePreconisation(p) {
  if (p.retourEnFile) {
    return `Ajourné au dernier passage : ${heures(p.heuresManquantes)} de reprise avant de revenir en file d'examen.`;
  }
  const c = p.preconisation;
  if (!c) return 'Aucune préconisation du moniteur pour l\'instant.';
  const qui = c.moniteur || 'Le moniteur';
  const quand = dateCourte(c.date);
  return `${qui}${quand ? `, le ${quand}` : ''} : ${heures(c.heures)} de préparation avant l'examen.`;
}

function contenuPrepa(ec) {
  const p = ec.prepa;
  if (!p) return [el('p', { class: 'muted petit' }, 'Prépa indisponible.')];
  const blocs = [];
  const accompagnementDu = (p.lignes || []).some((l) => l.nature === 'accompagnement');

  const carte = el('div', { class: 'carte carte-prepa' },
    el('div', { class: 'gras' }, p.retourEnFile ? 'Retour en file après ajournement' : 'Préconisation du moniteur'),
    el('div', { class: 'muted petit' }, textePreconisation(p)));
  if (p.mode !== 'rien') {
    const detail = p.heuresFacturees > p.heuresManquantes && p.heuresManquantes > 0
      ? `${heures(p.heuresFacturees)} (${heures(p.heuresManquantes)} manquantes, arrondi au pack)`
      : heures(p.heuresFacturees);
    carte.append(
      el('div', { class: 'l l-total' }, el('span', {}, 'Heures à payer'),
        el('span', { id: 'prepaHeures' }, p.heuresFacturees > 0 ? detail : 'aucune')),
      el('div', { class: 'l' }, el('span', {}, 'Accompagnement à l\'examen'),
        el('span', {}, accompagnementDu ? 'dû pour ce passage' : 'rien à régler')));
  }
  blocs.push(carte);

  if (p.indisponible) {
    blocs.push(el('div', { class: 'encart encart-warn' }, INDISPONIBLE[p.indisponible] || p.indisponible));
  } else if (p.mode === 'rien') {
    blocs.push(el('div', { class: 'encart encart-info' },
      'Rien à régler pour la prépa : aucune heure ne manque et aucun accompagnement n\'est dû pour ce passage.'));
  } else if (p.mode === 'heures' && p.accompagnementSeulPossible) {
    blocs.push(el('div', {},
      el('button', {
        type: 'button', class: 'pill', id: 'accompagnementSeul', 'aria-pressed': 'false', 'data-verrou': '',
        onclick: () => {
          const prod = magasin.lire().produit;
          magasin.appliquer(basculerAccompagnementSeul, !(prod && prod.accompagnementSeul));
        },
      }, 'Accompagnement seul')));
  }
  if (p.mode !== 'rien' && !p.indisponible) {
    blocs.push(el('div', { class: 'encart encart-info' }, el('b', {}, 'Accompagnement seul : '),
      'quand il ne manque aucune heure, cet onglet ne propose que l\'accompagnement. C\'est le même calcul que le lien de paiement envoyé par e-mail : le comptoir et la boutique donnent toujours le même prix.'));
  }
  return blocs;
}

function contenuLibre(etat) {
  const motifs = (etat.eleve.libre && etat.eleve.libre.motifs) || [];
  const p = etat.produit || {};
  const montant = el('input', {
    class: 'in in-montant', type: 'text', name: 'champL', inputmode: 'decimal', id: 'libreMontant',
    autocomplete: 'pas-de-remplissage-auto', placeholder: 'ex. 45,00', 'data-verrou': '',
  });
  montant.value = p.montantSaisie || '';
  montant.addEventListener('input', () => magasin.appliquer(saisirLibre, { montantSaisie: montant.value }));

  const precision = el('input', {
    class: 'in', type: 'text', name: 'champP', maxlength: '80', id: 'librePrecision', 'data-verrou': '',
    autocomplete: 'pas-de-remplissage-auto', placeholder: 'Ex. : solde de la leçon du 12/09',
  });
  precision.value = p.precision || '';
  precision.addEventListener('input', () => magasin.appliquer(saisirLibre, { precision: precision.value }));

  const pills = motifs.map((m) => el('button', {
    type: 'button', class: 'pill', 'data-motif': m.code, 'aria-pressed': 'false', 'data-verrou': '',
    onclick: () => magasin.appliquer(saisirLibre, { motif: m.code, precisionObligatoire: Boolean(m.precisionObligatoire) }),
  }, m.libelle));

  return [
    el('div', { class: 'encart encart-warn', style: 'display:flex;gap:10px;align-items:center;flex-wrap:wrap' },
      el('span', { class: 'chip warn' }, 'Hors catalogue'),
      el('span', {}, 'Pour ce qui n\'existe pas dans les autres onglets. Chaque montant libre est tracé avec votre nom et son motif.')),
    el('div', { class: 'carte carte-libre' },
      el('label', { class: 'champ', for: 'libreMontant' }, 'Montant',
        el('span', { class: 'ligne-montant' }, montant, el('span', { 'aria-hidden': 'true' }, '€'))),
      el('div', { class: 'gras' }, 'Motif ', el('span', { class: 'muted', style: 'font-weight:400' }, '(obligatoire)')),
      el('div', { class: 'pills', role: 'group', 'aria-label': 'Motif' }, pills),
      el('label', { class: 'champ', for: 'librePrecision' },
        el('span', { id: 'librePrecisionLibelle' }, 'Précision'), precision)),
    el('p', { class: 'muted petit' }, 'Réservé aux administrateurs : une secrétaire ne voit pas cet onglet.'),
  ];
}

// ─── Rendu ───────────────────────────────────────────────────────────────────

function contenu(etat) {
  if (etat.onglet === 'heures_supp') return contenuHeuresSupp(etat.eleve);
  if (etat.onglet === 'prepa') return contenuPrepa(etat.eleve);
  if (etat.onglet === 'libre') return contenuLibre(etat);
  return contenuForfait(etat.eleve);
}

/** Sélection et verrous seulement : aucun nœud recréé. */
function majSelection(etat) {
  const p = etat.produit || {};
  document.querySelectorAll('#contenuOnglet [data-formule]').forEach((b) => {
    b.setAttribute('aria-pressed', String(p.formuleId === b.dataset.formule));
  });
  document.querySelectorAll('#contenuOnglet [data-motif]').forEach((b) => {
    b.setAttribute('aria-pressed', String(p.motif === b.dataset.motif));
  });
  const seul = $('accompagnementSeul');
  if (seul) seul.setAttribute('aria-pressed', String(Boolean(p.accompagnementSeul)));
  const libelle = $('librePrecisionLibelle');
  if (libelle) libelle.textContent = p.precisionObligatoire ? 'Précision (obligatoire)' : 'Précision';
  // Pendant un paiement, le panier est figé : c'est lui qui est sur le lecteur.
  const verrou = Boolean(etat.paiement);
  document.querySelectorAll('.catalogue [data-verrou], .catalogue [data-formule]').forEach((b) => { b.disabled = verrou; });
}

export function rendreOnglets(etat) {
  if (etat.ecran !== 'panier' || !etat.eleve) {
    rendu = { eleveId: null, onglet: null };
    return;
  }
  const eleveId = etat.eleve.eleve.id;
  if (rendu.eleveId !== eleveId || rendu.onglet !== etat.onglet) {
    // Les références d'objet changent à chaque chargement : on compare aussi
    // l'objet, pour qu'un élève rechargé (données fraîches) soit redessiné.
    remplir($('bandeauEleve'), bandeauEleve(etat.eleve));
    remplir($('onglets'), barreOnglets(etat));
    remplir($('contenuOnglet'), contenu(etat));
    $('contenuOnglet').setAttribute('aria-labelledby', `onglet-${etat.onglet}`);
    rendu = { eleveId, onglet: etat.onglet, source: etat.eleve };
  } else if (rendu.source !== etat.eleve) {
    rendu = { eleveId: null, onglet: null };
    return rendreOnglets(etat);
  }
  majSelection(etat);
}

export function initOnglets(m) {
  magasin = m;
}
