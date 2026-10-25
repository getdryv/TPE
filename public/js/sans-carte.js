// ─── Encaisser sans le lecteur : espèces, chèques, espèces + chèques ─────────
//
// Aucun terminal ne fait barrage : le bouton lui-même atteste (« Encaisser
// 90 € en espèces », « J'ai les 3 chèques · Encaisser 1 760 € »), et la
// déclaration part tout de suite au CRM par `POST /api/caisse/especes`, qui
// sert les trois moyens (contrat Encaisser § 3.4).
//
// Ici, « en attente » est une ERREUR : sans carte, rien ne garde la trace de
// l'encaissement ailleurs que dans le CRM. La secrétaire le voit et garde les
// espèces ou les chèques en main.
//
// On n'encaisse que ce qui a été MONTRÉ : si le devis doit être renouvelé
// (expiré, ou émis la veille), le nouveau doit dire exactement la même chose —
// même total et, pour les chèques, mêmes dates et mêmes montants. Sinon on
// s'arrête et l'écran affiche le nouvel échéancier à vérifier.

import * as api from './api.js';
import { devisAJour, paiementEtape, paiementErreur, paiementAccepte, identificationRequise } from './etat.js';
import { avecCheques } from './etat-cheques.js';
import { devisExpire, devisRenouvele, resultat } from './paiement.js';
import { billetage } from './especes-compte.js';

export const MOYENS_SANS_CARTE = ['especes', 'cheques', 'especes_cheques'];

let magasin = null;

/** PURE. Ce que la secrétaire a vu : total, et l'échéancier pour les chèques. */
export function empreinteAffichee(devis) {
  if (!devis) return '';
  const ech = devis.echeancier;
  const versements = ech && Array.isArray(ech.versements)
    ? ech.versements.map((v) => `${v.dueOn}:${v.amountCents}`).join(',')
    : '';
  return `${devis.totalCents}|${versements}`;
}

/** PURE. Le devis a été émis un autre jour : ses dates de remise ne valent plus. */
export const devisAutreJour = (r) => r.status === 409 && Boolean(r.data && r.data.code === 'devis_autre_jour');

/** PURE. Pourquoi rien n'est enregistré, en mots de comptoir. */
export function messageEchec(r, moyen) {
  const declaration = r.data && r.data.declaration;
  const cause = r.indisponible || (declaration && declaration.statut === 'en_attente')
    ? 'le CRM ne répond pas'
    : ((declaration && declaration.message) || r.message || 'refus du CRM');
  const aRendre = { especes: 'les espèces', cheques: 'les chèques', especes_cheques: 'les espèces et les chèques' }[moyen] || 'l\'argent';
  return `Rien n'est enregistré (${cause}). Réessayez dans un instant, ou rendez ${aRendre}.`;
}

const MESSAGE_ECART_CHEQUES = 'L\'échéancier a changé depuis l\'affichage : vérifiez les dates et les montants, puis encaissez.';

/** Espèces, chèques ou espèces + chèques : la déclaration part tout de suite. */
export async function encaisserSansCarte() {
  const etat = magasin.lire();
  if (!devisAJour(etat) || etat.paiement || !MOYENS_SANS_CARTE.includes(etat.moyen)) return;
  const moyen = etat.moyen;
  const affiche = empreinteAffichee(etat.devis);
  const messageEcart = avecCheques(moyen) ? MESSAGE_ECART_CHEQUES : null;
  // Le détail des espèces comptées (coupures gardées) : enregistré et imprimé sur le bordereau.
  const detail = moyen === 'cheques' ? null : billetage(etat.comptage || {});
  magasin.appliquer(paiementEtape, 'especes');

  let r = await api.especes(etat.jetonDevis, detail);
  if (devisExpire(r) || devisAutreJour(r)) {
    const jeton = await devisRenouvele(empreinteAffichee, affiche, messageEcart);
    if (!jeton) return;
    r = await api.especes(jeton, detail);
  }
  if (r.status === 401) return magasin.appliquer(identificationRequise, (r.data && r.data.code) || 'jeton_expire', r.message);
  const declaration = r.data && r.data.declaration;
  if (r.ok && declaration && (declaration.statut === 'enregistre' || declaration.statut === 'deja')) {
    return magasin.appliquer(paiementAccepte, resultat(magasin.lire(), { declaration }));
  }
  magasin.appliquer(paiementErreur, messageEchec(r, moyen));
}

export function initSansCarte(m) {
  magasin = m;
}
