// lib/crm.js
//
// ======================= Client des routes internes du CRM =======================
//
// Toutes les routes `/api/internal/*` du CRM passent par ici : même secret
// partagé (`x-internal-secret`), même coupure au bout d'un délai, même forme
// de réponse. Le secret reste sur ce serveur : ces routes exposent des données
// d'élèves et décident des prix, elles n'ont rien à faire dans un navigateur.
//
// ─── Ne lève JAMAIS ─────────────────────────────────────────────────────────
// Une panne du CRM ne doit pas pouvoir faire tomber la caisse. Chaque appel
// rend l'une de ces trois formes, et c'est à l'appelant de décider :
//   { ok: true,  status, data }            — le CRM a répondu oui ;
//   { ok: false, status, error, code? }    — le CRM a répondu non (4xx), avec
//                                            son message lisible ;
//   { indisponible: true, raison }         — pas de réponse exploitable : CRM
//                                            non configuré, éteint, trop lent,
//                                            en erreur (5xx) ou illisible.
// Un 5xx est rangé avec les pannes : c'est le CRM qui va mal, pas la demande,
// et le réessayer plus tard a un sens (relances de la déclaration).

// Délais, du plus impatient au plus patient. Au-delà, on considère que le CRM
// ne répondra pas : mieux vaut une réponse claire tout de suite qu'une caisse
// qui semble figée.
const DELAIS_MS = {
  // Quelqu'un tape un nom au comptoir : une seconde est déjà long.
  recherche: 1200,
  // Ouverture de la caisse et chargement d'un élève.
  session: 2500,
  eleve: 2500,
  // Le devis recalcule la prépa et la promotion : un peu plus de marge.
  devis: 3000,
  // L'argent est pris : on attend la déclaration un peu plus longtemps avant
  // d'annoncer « enregistrement en cours ».
  declaration: 5000,
};

/** Adresse et secret du CRM, relus à chaque appel. Vides si non configurés. */
function configurationCrm() {
  const baseUrl = (process.env.CRM_BASE_URL || '').trim().replace(/\/+$/, '');
  const secret = (process.env.INTERNAL_API_SECRET || '').trim();
  return { baseUrl, secret, configure: Boolean(baseUrl && secret) };
}

/**
 * Appelle une route interne du CRM.
 *
 * @param {string} chemin   ex. `/api/internal/caisse/devis`
 * @param {object} options  { methode = 'POST', corps, query, delaiMs }
 */
async function appelerCrm(chemin, { methode = 'POST', corps, query, delaiMs = DELAIS_MS.session } = {}) {
  const { baseUrl, secret, configure } = configurationCrm();
  if (!configure) return { indisponible: true, raison: 'non_configure' };

  // `AbortController` coupe la requête elle-même, là où un simple délai
  // laisserait la connexion ouverte et le client en attente.
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), delaiMs);
  try {
    const qs = query ? `?${new URLSearchParams(query).toString()}` : '';
    const r = await fetch(`${baseUrl}${chemin}${qs}`, {
      method: methode,
      headers: {
        ...(corps !== undefined ? { 'Content-Type': 'application/json' } : {}),
        'x-internal-secret': secret,
      },
      body: corps !== undefined ? JSON.stringify(corps) : undefined,
      signal: abort.signal,
    });

    if (r.status >= 500) {
      console.warn(`[CRM] ${chemin} : HTTP ${r.status}`);
      return { indisponible: true, raison: 'erreur_crm', status: r.status };
    }

    let body = null;
    try {
      body = await r.json();
    } catch {
      console.warn(`[CRM] ${chemin} : réponse illisible (HTTP ${r.status})`);
      return { indisponible: true, raison: 'illisible', status: r.status };
    }

    if (r.ok && body && body.ok !== false) {
      return { ok: true, status: r.status, data: body.data ?? null };
    }
    return {
      ok: false,
      status: r.status,
      error: (body && typeof body.error === 'string' && body.error) || `Refus du CRM (HTTP ${r.status}).`,
      ...(body && typeof body.code === 'string' ? { code: body.code } : {}),
    };
  } catch (err) {
    // `AbortError` au bout du délai, ou CRM injoignable : les deux se règlent
    // de la même façon, en laissant la caisse tranquille.
    console.warn(`[CRM] ${chemin} indisponible :`, err.name || err.message);
    return { indisponible: true, raison: err.name === 'AbortError' ? 'delai' : 'injoignable' };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { configurationCrm, appelerCrm, DELAIS_MS };
