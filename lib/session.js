// lib/session.js
//
// ======================= Le mode de la caisse =======================
//
// Contrat : ARCHITECTURE.md § 7. C'est CE serveur qui décide du mode, pas la
// page : lui seul sait si le CRM est configuré et s'il répond.
//
//   catalogue               — jeton valide et CRM qui répond : la secrétaire
//                             touche une formule, le prix vient du CRM ;
//   secours                 — CRM non configuré, muet, agence par défaut
//                             sans slug ou inconnue du CRM : formulaire de
//                             toujours, montant saisi.
//                             Une panne du CRM n'empêche JAMAIS d'encaisser ;
//   identification_requise  — le CRM répond mais personne n'est identifié
//                             (pas de jeton, jeton refusé ou expiré) : on
//                             n'encaisse pas au catalogue sans savoir qui.
//
// Jeton expiré : raison `jeton_expire`, que la page traduit en message
// `caisse:jeton-expire` au CRM, qui recharge le cadre avec un jeton neuf. On
// sonde quand même le CRM avant : s'il est muet, le recharger ne servirait à
// rien et la caisse passe en secours (« jeton valide ou non, CRM muet »).

const { appelerCrm, configurationCrm, DELAIS_MS } = require('./crm');
const { lireJetonCaisse, jetonDeLaRequete } = require('./jeton');
const { slugEffectif } = require('./agences');

/** Traduit le refus du CRM en raison lisible par la page. */
function raisonDuRefus(status) {
  if (status === 401) return 'jeton_refuse';
  if (status === 403) return 'compte_refuse';
  if (status === 404) return 'agence_inconnue';
  return 'refus_crm';
}

/**
 * Décision PURE du mode (testée sans réseau).
 *
 * @param {object} e
 * @param {boolean} e.crmConfigure   CRM_BASE_URL et INTERNAL_API_SECRET posés
 * @param {string}  e.slug           slug effectif de l'agence (vide possible)
 * @param {object}  e.lectureJeton   résultat de `lireJetonCaisse`
 * @param {object|null} e.reponseCrm résultat de `appelerCrm` (null : non sondé)
 */
function deciderMode({ crmConfigure, slug, lectureJeton, reponseCrm }) {
  const secours = (raison) => ({ mode: 'secours', utilisateur: null, raison });
  const identification = (raison, message) => ({
    mode: 'identification_requise',
    utilisateur: null,
    raison,
    ...(message ? { message } : {}),
  });

  if (!crmConfigure) return secours('crm_non_configure');
  // Adresse nue et DEFAULT_AGENCY_SLUG vide : le CRM ne saurait pas de quelle
  // agence il s'agit. Seul le secours est possible, et la caisse le dit.
  if (!slug) return secours('agence_sans_slug');
  if (!reponseCrm || reponseCrm.indisponible) return secours('crm_indisponible');

  // Agence inconnue du CRM : défaut de RÉGLAGE (DEFAULT_AGENCY_SLUG), que
  // personne ne corrigera au comptoir. L'agence par défaut ne doit jamais
  // dépendre d'une donnée du CRM : on encaisse en secours. (Une autre agence
  // inconnue n'a de toute façon pas de clés : `exigerAgence` la refuse.)
  if (!reponseCrm.ok && reponseCrm.status === 404) return secours('agence_inconnue');
  if (!lectureJeton.ok) return identification(`jeton_${lectureJeton.motif}`);
  if (!reponseCrm.ok) return identification(raisonDuRefus(reponseCrm.status), reponseCrm.error);

  const u = reponseCrm.data?.utilisateur;
  if (!u || typeof u.nom !== 'string') return secours('crm_indisponible');
  return {
    mode: 'catalogue',
    utilisateur: { nom: u.nom, role: u.role === 'admin' ? 'admin' : 'secretary' },
    raison: null,
  };
}

/** Sonde le CRM et décide du mode de la caisse pour cette requête. */
async function sessionCaisse(req) {
  const { configure } = configurationCrm();
  const slug = slugEffectif(req);
  const jeton = jetonDeLaRequete(req);
  const lectureJeton = lireJetonCaisse(jeton, slug);

  let reponseCrm = null;
  if (configure && slug) {
    // Un jeton refusé ici n'est pas transmis : le CRM n'est sondé que pour
    // savoir s'il répond (il répondra 401 à un jeton vide).
    reponseCrm = await appelerCrm('/api/internal/caisse/session', {
      corps: { agencySlug: slug, jeton: lectureJeton.ok ? jeton : '' },
      delaiMs: DELAIS_MS.session,
    });
  }
  return deciderMode({ crmConfigure: configure, slug, lectureJeton, reponseCrm });
}

module.exports = { deciderMode, sessionCaisse };
