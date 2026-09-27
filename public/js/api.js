// ─── Les appels au serveur de la caisse (ARCHITECTURE.md § 10.2) ─────────────
//
// Règle unique : AUCUNE fonction de ce module ne lève d'exception. Chaque appel
// rend `{ ok, status, data, indisponible, annule, message }` :
//   - `indisponible` : le serveur dit que le CRM ne répond pas (503
//     `{ crm: 'indisponible' }`) → la page bascule sur l'encaissement de secours ;
//   - `annule` : la requête a été abandonnée par la page (recherche dépassée) ;
//   - `message` : texte lisible à afficher tel quel (erreur du CRM relayée,
//     réseau coupé…).
// Une caisse qui planterait sur une réponse inattendue empêcherait d'encaisser.
//
// Le jeton de caisse (qui encaisse) vit en mémoire seulement, jamais dans le
// stockage du navigateur : il part dans l'en-tête `x-caisse-jeton` vers NOTRE
// serveur, qui le transmet au CRM.

// L'agence est portée par l'adresse : /simply-permis-marseille,
// /getdryv-marseille. Adresse nue = agence par défaut du service, celle dont
// les clés sont dans son environnement.
export const AGENCE = decodeURIComponent(location.pathname.replace(/^\/+|\/+$/g, '')).toLowerCase();

let jeton = null;

export function poserJeton(valeur) {
  jeton = typeof valeur === 'string' && valeur ? valeur : null;
}

/** Message lisible d'une réponse d'erreur, quelle que soit sa forme. */
function messageDe(data, status) {
  if (data && typeof data.error === 'string' && data.error) return data.error;
  if (data && typeof data.message === 'string' && data.message) return data.message;
  if (data && data.error && typeof data.error.message === 'string') return data.error.message;
  if (status === 401) return 'Session de caisse expirée : rouvrez la caisse depuis le CRM.';
  return `Réponse inattendue du serveur (${status}).`;
}

async function appel(methode, chemin, { query, corps, signal, entetes } = {}) {
  const params = new URLSearchParams({ slug: AGENCE, ...(query || {}) });
  const url = `${chemin}?${params}`;
  const headers = { ...(entetes || {}) };
  // `/api/paiement` (secours) : le jeton y dit QUI encaisse, quand il est connu.
  if (jeton && (chemin.startsWith('/api/caisse/') || chemin === '/api/students' || chemin === '/api/paiement')) {
    headers['x-caisse-jeton'] = jeton;
  }
  let body;
  if (corps !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify({ slug: AGENCE, ...corps });
  }
  try {
    const r = await fetch(url, { method: methode, headers, body, signal });
    const data = await r.json().catch(() => null);
    const indisponible = r.status === 503 && Boolean(data && data.crm === 'indisponible');
    return {
      ok: r.ok,
      status: r.status,
      data,
      indisponible,
      annule: false,
      message: r.ok ? null : messageDe(data, r.status),
    };
  } catch (e) {
    const annule = Boolean(e && e.name === 'AbortError');
    return {
      ok: false,
      status: 0,
      data: null,
      indisponible: false,
      annule,
      message: annule ? null : 'Le serveur de la caisse ne répond pas. Vérifiez la connexion Internet.',
    };
  }
}

// ─── Agence, session, lecteurs ───────────────────────────────────────────────

/** `{ name, logoUrl, crmUrl }` — confort : un échec n'empêche rien. */
export const agence = () => appel('GET', '/api/agence');

/** `{ mode, utilisateur, raison }` (§ 7). */
export const session = () => appel('GET', '/api/caisse/session');

/** `{ lecteurs: [{ id, label, enLigne }] }` — route historique inchangée. */
export const lecteurs = () => appel('GET', '/api/lecteurs');

// ─── Élève et devis ──────────────────────────────────────────────────────────

/** `{ students: [{ id, firstName, lastName, email, phone, paidOffer }] }`. */
export const chercherEleves = (q, signal) => appel('GET', '/api/students', { query: { q }, signal });

/** `EleveCaisse` (§ 10.1). */
export const eleve = (id) => appel('GET', '/api/caisse/eleve', { query: { id } });

/** `{ devis, jeton }` ; corps = `{ studentId, produit, moyen, especesCents? }`. */
export const devis = (corps, signal) => appel('POST', '/api/caisse/devis', { corps, signal });

// ─── Encaissement catalogue ──────────────────────────────────────────────────

/**
 * `{ paymentIntentId, lecteur }` ; `410 { code: 'devis_expire' }` si le devis a
 * périmé. La clé d'idempotence est propre à CHAQUE tentative : un double clic
 * ne crée pas deux paiements, un « Réessayer » en crée bien un nouveau.
 */
export const paiement = ({ lecteur, devis: jetonDevis, email, nomComplet }, cleIdempotence) =>
  appel('POST', '/api/caisse/paiement', {
    corps: { lecteur, devis: jetonDevis, email, nomComplet },
    entetes: { 'Idempotency-Key': cleIdempotence },
  });

/** `{ success, montant, declaration }`. */
export const capture = (paymentIntentId) => appel('POST', '/api/caisse/capture', { corps: { paymentIntentId } });

/** Espèces seules : `{ declaration }`. */
export const especes = (jetonDevis) => appel('POST', '/api/caisse/especes', { corps: { devis: jetonDevis } });

// ─── Lecteur (routes historiques, communes aux deux modes) ───────────────────

/** `{ etat: 'attente' | 'autorise' | 'capture' | 'echec', message? }`. */
export const etatPaiement = (pi, lecteur) => appel('GET', '/api/paiement/etat', { query: { pi, lecteur } });

export const annuler = (paymentIntentId, lecteur) =>
  appel('POST', '/api/paiement/annuler', { corps: { paymentIntentId, lecteur } });

// ─── Secours (montant saisi, chemins historiques + motif) ────────────────────

export const paiementSecours = (corps) => appel('POST', '/api/paiement', { corps });

export const captureSecours = (paymentIntentId) =>
  appel('POST', '/api/paiement/capture', { corps: { paymentIntentId } });

/** Clé d'idempotence d'une tentative. */
export function nouvelleCle() {
  if (globalThis.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
