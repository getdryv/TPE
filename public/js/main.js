// ─── Chef d'orchestre de la caisse ───────────────────────────────────────────
//
// 1. lit le jeton de qui encaisse dans le fragment de l'adresse (cadre du CRM) ;
// 2. demande au serveur le MODE de la caisse (ARCHITECTURE.md § 7) :
//      catalogue              → écrans 1 à 7 et 9 ;
//      secours                → écran 8, montant saisi (chemin historique) ;
//      identification_requise → « Ouvrez la caisse depuis le CRM » ;
// 3. dessine l'écran courant à chaque changement d'état.
//
// Toute erreur d'un confort (nom de l'agence, recherche, un rendu) est
// contenue : elle ne doit jamais empêcher d'encaisser.

import * as api from './api.js';
import * as cadre from './cadre.js';
import { creerMagasin, sessionOuverte } from './etat.js';
import { initEcranEleve, rendreEcranEleve, chargerEleve } from './ecran-eleve.js';
import { initOnglets, rendreOnglets } from './onglets.js';
import { initPanier, rendrePanier, redemanderDevis } from './panier.js';
import { initPaiement, chargerLecteurs, surveillerLecteurs, rendreEnteteLecteur } from './paiement.js';
import { initIssues, rendreIssues } from './ecrans-issue.js';
import { initSecours, rendreSecours } from './secours.js';

const magasin = creerMagasin();
let precedent = null;

const RENDUS = [rendreEcranEleve, rendreOnglets, rendrePanier, rendreIssues, rendreSecours, rendreEnteteLecteur];

function rendre(etat) {
  document.querySelectorAll('[data-ecran]').forEach((s) => { s.hidden = s.dataset.ecran !== etat.ecran; });
  const qui = document.getElementById('quiEncaisse');
  qui.textContent = etat.mode === 'catalogue' && etat.utilisateur ? etat.utilisateur.nom || '' : '';
  for (const f of RENDUS) {
    try { f(etat, precedent); } catch (e) { console.error('[caisse] rendu :', e); }
  }
  precedent = etat;
}

/** Nom de l'agence dans l'en-tête et le titre. Purement cosmétique. */
function afficherAgence(r) {
  const nom = r.ok && r.data && r.data.name;
  if (!nom) return;
  document.getElementById('nomAgence').textContent = nom;
  document.title = `Caisse ${nom}`;
}

/**
 * Ouvre l'écran du mode rendu par le serveur. Un serveur sans
 * route de session (404) ou injoignable donne l'encaissement de secours : la
 * caisse d'avant, qui ne dépend de rien.
 */
function appliquerSession(r, eleveInitial) {
  const session = r.ok && r.data && r.data.mode
    ? r.data
    : { mode: 'secours', utilisateur: null, raison: r.status === 404 ? 'sans_catalogue' : 'session_indisponible' };
  // Le bandeau « Le CRM ne répond pas » n'a de sens que si un CRM est déclaré
  // et que le serveur sait déjà parler au catalogue.
  magasin.appliquer(sessionOuverte, session, cadre.crmConfigure() && r.status !== 404);
  if (session.mode === 'catalogue' && eleveInitial) chargerEleve(eleveInitial);
}

const ouvrirSession = async (eleveInitial) => appliquerSession(await api.session(), eleveInitial);

async function demarrer() {
  const { jeton, eleve } = cadre.consommerFragment();
  api.poserJeton(jeton);

  magasin.ecouter(rendre);
  initPaiement(magasin, {
    redemanderDevis,
    // Un lecteur trouvé (ou changé) après coup active le bouton du panier.
    surLecteur: () => { try { rendrePanier(magasin.lire()); } catch (_) { /* confort */ } },
  });
  initPanier(magasin);
  initOnglets(magasin);
  initIssues(magasin);
  initSecours({ retenterCatalogue: () => ouvrirSession(null) });
  try {
    initEcranEleve(magasin);
  } catch (e) {
    // Sans recherche, on peut encore encaisser en secours : on ne s'arrête pas.
    console.warn('[caisse] recherche indisponible :', e);
  }
  rendre(magasin.lire());

  // Les lecteurs se chargent en parallèle : ils ne décident pas du mode.
  chargerLecteurs();
  surveillerLecteurs();

  // Agence et session en parallèle : l'agence dit si un CRM est déclaré, ce
  // qui décide du bandeau de secours ; la session dit le mode.
  const [r, rs] = await Promise.all([api.agence(), api.session()]);
  try { afficherAgence(r); } catch (_) { /* cosmétique */ }
  cadre.initCadre(r.ok && r.data ? r.data.crmUrl : null, {
    // Le CRM vient de créer la fiche demandée par « Créer la fiche ».
    surEleveChoisi: (id) => chargerEleve(id),
    // Jeton ré-émis par le CRM : on le prend sans rien recharger ; on ne
    // rouvre la session que si elle attendait justement un jeton valide.
    surJeton: (j) => {
      api.poserJeton(j);
      if (magasin.lire().mode === 'identification_requise') ouvrirSession(null);
    },
  });

  appliquerSession(rs, eleve);

  // Nouveau fragment sans rechargement (même adresse, autre élève ou jeton).
  window.addEventListener('hashchange', () => {
    const lu = cadre.consommerFragment();
    if (lu.jeton) {
      api.poserJeton(lu.jeton);
      ouvrirSession(lu.eleve);
    } else if (lu.eleve) {
      chargerEleve(lu.eleve);
    }
  });
}

demarrer().catch((e) => {
  // Dernier filet : quoi qu'il arrive, l'encaissement de secours reste possible.
  console.error('[caisse] démarrage :', e);
  try { magasin.appliquer(sessionOuverte, { mode: 'secours' }, false); } catch (_) { /* rien de plus à tenter */ }
});
