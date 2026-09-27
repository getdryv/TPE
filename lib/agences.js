// lib/agences.js
//
// ======================= Agences =======================
//
// Une seule caisse sert désormais plusieurs agences. L'agence est portée par
// l'adresse : `/simply-permis-marseille`, `/getdryv-marseille`. Sans rien dans
// l'URL, on sert l'agence par défaut — celle dont les clés sont dans
// l'environnement du service.
//
// ─── Pourquoi l'agence par défaut ne passe JAMAIS par le CRM ────────────────
// Elle lit ses clés dans ses variables d'environnement, comme depuis toujours.
// C'est délibéré : une panne du CRM ne doit pas pouvoir empêcher un
// encaissement au comptoir. Seules les agences suivantes lisent leur
// configuration dans leur fiche, et pour elles une panne du CRM se traduit par
// une caisse indisponible — c'est le prix de ne pas avoir à toucher à
// l'hébergement pour ouvrir une agence.

const { configurationCrm } = require('./crm');

/**
 * Slug de l'agence par défaut. Relu à chaque appel (et non figé au
 * chargement) : les tests font varier l'environnement sans relancer le
 * processus ; en production la valeur ne change pas.
 */
function slugParDefaut() {
  return (process.env.DEFAULT_AGENCY_SLUG || '').trim().toLowerCase();
}

// Au-delà, on considère que le CRM ne répondra pas (même délai que la
// recherche d'élèves).
const CRM_TIMEOUT_MS = 1200;

// La fiche d'une agence change rarement, et une lecture par paiement ferait
// dépendre chaque encaissement de la latence du CRM. Dix minutes, comme
// l'application d'achat d'heures : un changement de clé met jusqu'à ce délai à
// se voir.
const AGENCE_CACHE_MS = 10 * 60 * 1000;
const cacheAgences = new Map();

// Le client Stripe se fabrique ici et nulle part ailleurs : les tests y
// substituent un faux client (aucun appel réseau, aucun paiement réel).
let fabriqueStripe = (cle) => require('stripe')(cle);

/** Réservé aux tests : remplace la fabrique du client Stripe et vide le cache. */
function definirFabriqueStripe(fabrique) {
  fabriqueStripe = fabrique;
  cacheAgences.clear();
}

/** Configuration de l'agence par défaut, lue dans l'environnement du service. */
function agenceParDefaut() {
  return {
    slug: slugParDefaut() || null,
    stripe: fabriqueStripe(process.env.STRIPE_SECRET_KEY),
    terminalLocation: (process.env.STRIPE_TERMINAL_LOCATION || '').trim() || null,
    // L'agence par défaut ne passant jamais par le CRM, son nom d'affichage ne
    // peut venir que de son environnement.
    agencyName: (process.env.DEFAULT_AGENCY_NAME || '').trim() || null,
    logoUrl: null,
    source: 'environnement',
  };
}

/** L'agence demandée est-elle l'agence par défaut (adresse nue ou son slug) ? */
function estAgenceParDefaut(slugDemande) {
  const slug = (slugDemande || '').trim().toLowerCase();
  const parDefaut = slugParDefaut();
  return !slug || (parDefaut && slug === parDefaut);
}

/**
 * Résout l'agence d'une requête.
 *
 * Renvoie `null` si l'agence est inconnue ou non configurée — l'appelant
 * répond alors clairement plutôt que d'encaisser sur le mauvais compte, ce qui
 * serait bien pire qu'un refus.
 */
async function resoudreAgence(slugDemande) {
  const slug = (slugDemande || '').trim().toLowerCase();

  // Pas de slug, ou celui de l'agence par défaut : on ne sort pas du service.
  if (estAgenceParDefaut(slug)) {
    return agenceParDefaut();
  }

  const enCache = cacheAgences.get(slug);
  if (enCache && enCache.expire > Date.now()) return enCache.agence;

  const { baseUrl: crmBaseUrl, secret: internalSecret } = configurationCrm();
  if (!crmBaseUrl || !internalSecret) return null;

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), CRM_TIMEOUT_MS);
  try {
    const url = `${crmBaseUrl}/api/internal/agency-tpe-config?slug=${encodeURIComponent(slug)}`;
    const r = await fetch(url, {
      headers: { 'x-internal-secret': internalSecret },
      signal: abort.signal,
    });
    if (!r.ok) {
      console.warn(`[CRM] configuration TPE de « ${slug} » : HTTP ${r.status}`);
      return null;
    }
    const body = await r.json();
    const conf = body?.data;
    if (!conf?.stripeSecretKey || !conf?.terminalLocation) return null;

    const agence = {
      slug,
      stripe: fabriqueStripe(conf.stripeSecretKey),
      terminalLocation: conf.terminalLocation,
      agencyName: conf.agencyName || null,
      logoUrl: conf.logoUrl || null,
      source: 'CRM',
    };
    cacheAgences.set(slug, { agence, expire: Date.now() + AGENCE_CACHE_MS });
    return agence;
  } catch (err) {
    console.warn(`[CRM] configuration TPE de « ${slug} » indisponible :`, err.name || err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Lit le slug d'une requête : corps JSON d'abord, puis paramètre d'URL. */
function slugDeLaRequete(req) {
  return (req.body?.slug || req.query?.slug || '').toString();
}

/**
 * Le slug sous lequel l'agence est connue du CRM : celui de l'adresse, à
 * défaut celui de l'agence par défaut. Vide si aucun des deux n'est posé.
 * Sert aux appels du catalogue, qui n'ont besoin que du slug, pas des clés.
 */
function slugEffectif(req) {
  return (slugDeLaRequete(req).trim().toLowerCase() || slugParDefaut());
}

/**
 * Résout l'agence ou répond 400. Un encaissement sur le mauvais compte Stripe
 * est irrattrapable ; refuser est le comportement sûr.
 */
async function exigerAgence(req, res) {
  const agence = await resoudreAgence(slugDeLaRequete(req));
  if (!agence) {
    res.status(400).json({ error: "Agence inconnue ou terminal non configuré pour cette agence." });
    return null;
  }
  return agence;
}

module.exports = {
  agenceParDefaut,
  resoudreAgence,
  slugDeLaRequete,
  slugEffectif,
  slugParDefaut,
  estAgenceParDefaut,
  exigerAgence,
  definirFabriqueStripe,
};
