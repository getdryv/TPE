// ─── La caisse dans le cadre du CRM (ARCHITECTURE.md § 3, § 10.2) ───────────
//
// Le CRM affiche la caisse dans un `iframe` et lui passe, dans le FRAGMENT de
// l'adresse, le jeton de qui encaisse et éventuellement un élève à
// présélectionner : `#jeton=…&eleve=<uuid>`. Un fragment ne part ni dans les
// journaux du serveur ni dans l'en-tête `Referer`.
//
// Les messages ne partent QUE vers l'origine du CRM déclaré (`crmUrl` de
// /api/agence) et ne sont écoutés QUE depuis elle : une page tierce qui
// encadrerait la caisse ne pourrait ni lui choisir un élève ni lire ce qu'elle
// envoie. Sans CRM déclaré, aucun message ne part.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * PURE. `#jeton=abc&eleve=<uuid>` → `{ jeton, eleve }`. Un élève qui n'est pas
 * un uuid est ignoré (jamais transmis tel quel au serveur).
 */
export function lireFragment(hash) {
  const params = new URLSearchParams(String(hash || '').replace(/^#/, ''));
  const jeton = (params.get('jeton') || '').trim() || null;
  const eleve = (params.get('eleve') || '').trim();
  return { jeton, eleve: UUID.test(eleve) ? eleve : null };
}

/** PURE. Origine d'une adresse (`https://crm.exemple.fr`), ou null. */
export function origineDe(url) {
  if (typeof url !== 'string' || !url) return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;
  } catch (_) {
    return null;
  }
}

/** PURE. Un chemin du CRM acceptable : relatif, un seul « / » en tête. */
export function cheminSur(chemin) {
  if (typeof chemin !== 'string') return null;
  if (!chemin.startsWith('/') || chemin.startsWith('//') || chemin.includes('\\')) return null;
  return chemin;
}

/**
 * PURE. Un message du CRM, validé : `{ type: 'eleve-choisi', studentId }`,
 * `{ type: 'jeton', jeton }` (jeton ré-émis, remis SANS recharger la caisse),
 * ou null. Tout le reste est ignoré.
 */
export function messageDuCrm(data) {
  const m = data || {};
  if (m.type === 'caisse:eleve-choisi' && typeof m.studentId === 'string' && UUID.test(m.studentId)) {
    return { type: 'eleve-choisi', studentId: m.studentId };
  }
  if (m.type === 'caisse:jeton' && typeof m.jeton === 'string' && /^[\w-]+\.[\w-]+$/.test(m.jeton) && m.jeton.length < 2048) {
    return { type: 'jeton', jeton: m.jeton };
  }
  return null;
}

let crmUrl = null;
let origineCrm = null;

export function dansUnCadre() {
  try {
    return window.top !== window.self;
  } catch (_) {
    // Accès refusé à `window.top` : on est forcément dans un cadre d'une autre origine.
    return true;
  }
}

/**
 * Lit le fragment puis l'efface de la barre d'adresse : le jeton ne reste ni
 * dans l'historique ni dans une adresse copiée-collée.
 */
export function consommerFragment() {
  const lu = lireFragment(location.hash);
  if (location.hash) {
    try {
      history.replaceState(null, '', location.pathname + location.search);
    } catch (_) { /* sans effet sur l'encaissement */ }
  }
  return lu;
}

/**
 * Déclare le CRM (adresse publique de /api/agence) et écoute ses messages.
 * `surEleveChoisi(studentId)` est appelé quand le CRM vient de créer la fiche ;
 * `surJeton(jeton)` quand il a ré-émis le jeton (le cadre n'est plus rechargé
 * pour ça : un rechargement perdrait le panier en plein encaissement).
 */
export function initCadre(url, { surEleveChoisi, surJeton } = {}) {
  crmUrl = typeof url === 'string' && url ? url.replace(/\/+$/, '') : null;
  origineCrm = origineDe(crmUrl);
  if (!origineCrm) return;
  window.addEventListener('message', (event) => {
    if (event.origin !== origineCrm || event.source !== window.parent) return;
    const m = messageDuCrm(event.data);
    if (m && m.type === 'eleve-choisi' && surEleveChoisi) surEleveChoisi(m.studentId);
    if (m && m.type === 'jeton' && surJeton) surJeton(m.jeton);
  });
}

export const crmConfigure = () => Boolean(origineCrm);

/** Adresse de la page caisse du CRM (écran d'identification), ou null. */
export const adresseCaisseCrm = () => (crmUrl ? `${crmUrl}/paiements` : null);

function poster(message) {
  if (!origineCrm || !dansUnCadre()) return false;
  try {
    window.parent.postMessage(message, origineCrm);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * « Créer la fiche » : dans le cadre, le CRM ouvre sa fenêtre de création et
 * nous rend l'élève ; hors cadre, on ouvre la caisse du CRM, qui recharge la
 * caisse avec l'élève sélectionné une fois la fiche créée.
 */
export function creerFiche(recherche) {
  if (poster({ type: 'caisse:creer-fiche', recherche: String(recherche || '').slice(0, 120) })) return true;
  if (!crmUrl) return false;
  window.open(`${crmUrl}/paiements?nouvelle-fiche=1`, '_blank', 'noopener');
  return true;
}

/** Ouvre la fiche ou le contrat dans le CRM, hors du cadre (la caisse reste affichée). */
export function ouvrirDansCrm(chemin) {
  const sur = cheminSur(chemin);
  if (!sur) return false;
  if (poster({ type: 'caisse:ouvrir', chemin: sur })) return true;
  if (!crmUrl) return false;
  window.open(crmUrl + sur, '_blank', 'noopener');
  return true;
}

/** Jeton expiré : le CRM ré-émet un jeton et recharge le cadre. */
export function signalerJetonExpire() {
  return poster({ type: 'caisse:jeton-expire' });
}
