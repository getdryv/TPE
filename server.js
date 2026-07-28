// server.js
require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser'); // RAW pour le webhook Stripe
const crypto = require('crypto');

const app = express();

// ----- Stripe -----
if (!process.env.STRIPE_SECRET_KEY) {
  console.error('❌ STRIPE_SECRET_KEY manquant');
  process.exit(1);
}

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

const DEFAULT_AGENCY_SLUG = (process.env.DEFAULT_AGENCY_SLUG || '').trim().toLowerCase();

// La fiche d'une agence change rarement, et une lecture par paiement ferait
// dépendre chaque encaissement de la latence du CRM. Dix minutes, comme
// l'application d'achat d'heures : un changement de clé met jusqu'à ce délai à
// se voir.
const AGENCE_CACHE_MS = 10 * 60 * 1000;
const cacheAgences = new Map();

/** Configuration de l'agence par défaut, lue dans l'environnement du service. */
function agenceParDefaut() {
  return {
    slug: DEFAULT_AGENCY_SLUG || null,
    stripe: require('stripe')(process.env.STRIPE_SECRET_KEY),
    terminalLocation: (process.env.STRIPE_TERMINAL_LOCATION || '').trim() || null,
    // L'agence par défaut ne passant jamais par le CRM, son nom d'affichage ne
    // peut venir que de son environnement.
    agencyName: (process.env.DEFAULT_AGENCY_NAME || '').trim() || null,
    logoUrl: null,
    source: 'environnement',
  };
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
  if (!slug || (DEFAULT_AGENCY_SLUG && slug === DEFAULT_AGENCY_SLUG)) {
    return agenceParDefaut();
  }

  const enCache = cacheAgences.get(slug);
  if (enCache && enCache.expire > Date.now()) return enCache.agence;

  const crmBaseUrl = process.env.CRM_BASE_URL?.trim();
  const internalSecret = process.env.INTERNAL_API_SECRET?.trim();
  if (!crmBaseUrl || !internalSecret) return null;

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), CRM_TIMEOUT_MS);
  try {
    const url =
      `${crmBaseUrl.replace(/\/+$/, '')}/api/internal/agency-tpe-config` +
      `?slug=${encodeURIComponent(slug)}`;
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
      stripe: require('stripe')(conf.stripeSecretKey),
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

// ----- Middlewares globaux -----
// (ne pas parser /webhook/stripe)
app.use(cors());

// Qui a le droit d'afficher la caisse dans un cadre. Sans CRM déclaré, on ne
// pose pas l'en-tête et rien ne change. Avec, seul le CRM peut l'encadrer :
// une page de paiement encadrable par n'importe quel site se détourne (on
// superpose un faux écran par-dessus et l'utilisateur clique sans le savoir).
app.use((req, res, next) => {
  const crmBaseUrl = process.env.CRM_BASE_URL?.trim();
  if (crmBaseUrl) {
    res.setHeader('Content-Security-Policy', `frame-ancestors 'self' ${crmBaseUrl.replace(/\/+$/, '')}`);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook/stripe') return next();
  return express.json()(req, res, next);
});

app.get('/health', (_req, res) => res.json({ ok: true }));

/**
 * GET /api/agence?slug=…
 *
 * De quoi la caisse s'annonce : le nom de l'agence pour laquelle elle encaisse.
 * Écrire « Simply Permis » en dur dans la page était juste tant qu'il n'y avait
 * qu'une agence ; affiché dans le CRM de Getdryv, c'était faux et inquiétant
 * pour qui encaisse.
 *
 * Ne renvoie jamais d'erreur : sans nom, la caisse garde son titre générique et
 * encaisse quand même. Aucun secret ne sort d'ici.
 */
app.get('/api/agence', async (req, res) => {
  const agence = await resoudreAgence(slugDeLaRequete(req));
  res.json({
    name: agence?.agencyName ?? null,
    logoUrl: agence?.logoUrl ?? null,
  });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ======================= Recherche d'élèves (CRM) =======================
// Au-delà, on considère que le CRM ne répondra pas : mieux vaut une liste vide
// tout de suite qu'une caisse qui semble figée. Une seconde est déjà long pour
// quelqu'un qui tape un nom au comptoir.
const CRM_TIMEOUT_MS = 1200;

/**
 * GET /api/students?q=…
 *
 * Relaie la recherche d'élèves du CRM pour l'autocomplétion de la caisse. Le
 * secret partagé reste ici, sur le serveur : la route interne du CRM expose des
 * données personnelles d'élèves et n'a rien à faire dans un navigateur.
 *
 * ─── Cette route ne peut pas empêcher un encaissement ───────────────────────
 * L'autocomplétion est un confort de saisie, jamais un préalable au paiement.
 * Toute défaillance — CRM éteint, lent, mal configuré, réseau coupé, agence
 * inconnue — se traduit par une liste vide et un HTTP 200, jamais par une
 * erreur. La caisse continue alors exactement comme avant : on tape le nom à la
 * main et on encaisse. C'est aussi pourquoi rien n'est configuré par défaut :
 * sans CRM_BASE_URL, le TPE fonctionne comme aujourd'hui.
 */
app.get('/api/students', async (req, res) => {
  const vide = () => res.json({ students: [] });

  const crmBaseUrl = process.env.CRM_BASE_URL?.trim();
  const internalSecret = process.env.INTERNAL_API_SECRET?.trim();
  // L'agence vient de l'URL de la caisse ; à défaut, celle du service. On ne
  // cherche que dans les élèves de cette agence, jamais dans ceux d'une autre.
  const agencySlug = (slugDeLaRequete(req) || DEFAULT_AGENCY_SLUG).trim();
  if (!crmBaseUrl || !internalSecret || !agencySlug) return vide();

  const q = (req.query.q || '').toString().trim();
  if (q.length < 2) return vide();

  // `AbortController` coupe la requête elle-même, là où un simple délai
  // laisserait la connexion ouverte et le client en attente.
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), CRM_TIMEOUT_MS);

  try {
    const url =
      `${crmBaseUrl.replace(/\/+$/, '')}/api/internal/student-search` +
      `?slug=${encodeURIComponent(agencySlug)}&q=${encodeURIComponent(q)}`;

    const r = await fetch(url, {
      headers: { 'x-internal-secret': internalSecret },
      signal: abort.signal,
    });

    if (!r.ok) {
      console.warn(`[CRM] recherche élève : HTTP ${r.status}`);
      return vide();
    }

    const body = await r.json();
    return res.json({ students: body?.data?.students ?? [] });
  } catch (err) {
    // `AbortError` au bout du délai, ou CRM injoignable : les deux se règlent
    // de la même façon, en laissant la caisse tranquille.
    console.warn('[CRM] recherche élève indisponible :', err.name || err.message);
    return vide();
  } finally {
    clearTimeout(timer);
  }
});

// ======================= Encaissement, piloté par le serveur =======================
//
// Le navigateur ne parle plus jamais au lecteur. Il demande à notre serveur, qui
// demande à Stripe, qui pousse l'ordre au lecteur par la liaison nuage que
// celui-ci maintient en permanence.
//
// ─── Pourquoi avoir abandonné le SDK navigateur ─────────────────────────────
// Le SDK JavaScript exige une connexion directe entre le navigateur et le
// lecteur, sur le réseau local. Éprouvé le 2026-07-28 sur le WisePOS E de
// Getdryv : nom résolu correctement, appareil présent sur le réseau (réponse
// ARP), mais aucune connexion acceptée — et la même chose depuis un terminal,
// donc ni le navigateur ni le système n'étaient en cause. Le pilotage par le
// serveur a fonctionné du premier coup sur ce même lecteur.
//
// Ce qu'on y gagne, au-delà du déblocage : plus aucune dépendance au réseau
// local, donc la caisse fonctionne depuis n'importe où — un autre bureau, un
// téléphone en 4G — tant que le lecteur, lui, a Internet.
//
// Ce qu'on y perd : le navigateur ne connaît plus l'état du lecteur en direct,
// il faut le demander régulièrement. D'où la route d'état ci-dessous.

/** Lecteurs de l'agence, pour que la caisse sache lequel solliciter. */
app.get('/api/lecteurs', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    // Sans emplacement on ne filtre pas : mieux vaut proposer trop de lecteurs
    // que zéro. Avec, on ne voit que ceux de cette agence — indispensable dès
    // que deux agences partagent un compte Stripe.
    const params = { limit: 20 };
    if (agence.terminalLocation) params.location = agence.terminalLocation;

    const liste = await agence.stripe.terminal.readers.list(params);
    res.json({
      lecteurs: (liste.data || []).map((r) => ({
        id: r.id,
        label: r.label || r.serial_number || r.id,
        enLigne: r.status === 'online',
      })),
    });
  } catch (err) {
    console.error('liste des lecteurs :', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Lance un encaissement : crée le paiement et l'affiche sur le lecteur.
 *
 * Montant en CENTIMES. Capture manuelle : la carte est autorisée à l'écran du
 * lecteur, mais rien n'est prélevé tant que `/api/paiement/capture` n'a pas été
 * appelé. C'est ce qui permet d'annuler sans frais si quelque chose cloche
 * entre l'autorisation et la fin.
 */
app.post('/api/paiement', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const { montant, email, firstName, lastName, lecteur } = req.body;

    if (!Number.isInteger(montant) || montant <= 0) {
      return res.status(400).json({ error: 'Montant invalide.' });
    }
    if (!lecteur) {
      return res.status(400).json({ error: 'Aucun lecteur sélectionné.' });
    }

    const fName = (firstName || '').toString().trim();
    const lName = (lastName || '').toString().trim();
    const fullName = [fName, lName].filter(Boolean).join(' ').trim();
    const emailSafe = (email || '').toString().trim();

    // Deux clics rapides sur « Envoyer au TPE » ne doivent pas créer deux
    // paiements : la même clé donne le même PaymentIntent.
    const idempotencyKey = req.headers['idempotency-key'] || crypto.randomUUID();

    const customer = await agence.stripe.customers.create({
      name: fullName || undefined,
      email: emailSafe || undefined,
    });

    const pi = await agence.stripe.paymentIntents.create(
      {
        amount: montant,
        currency: 'eur',
        payment_method_types: ['card_present'],
        capture_method: 'manual',
        customer: customer.id,
        receipt_email: emailSafe || undefined,
        metadata: {
          source: 'terminal',
          agence: agence.slug || '',
          firstName: fName,
          lastName: lName,
          fullName,
          email: emailSafe,
        },
      },
      { idempotencyKey }
    );

    await agence.stripe.terminal.readers.processPaymentIntent(lecteur, {
      payment_intent: pi.id,
    });

    res.json({ paymentIntentId: pi.id, lecteur });
  } catch (err) {
    console.error('paiement :', err.message);
    // Le message de Stripe est plus utile que le nôtre : il distingue un
    // lecteur hors ligne d'un lecteur déjà occupé par un autre encaissement.
    res.status(500).json({ error: err.message });
  }
});

/**
 * Où en est l'encaissement ?
 *
 * Interrogée en boucle par la caisse. Renvoie un état unique plutôt que l'état
 * brut de Stripe, pour que la page n'ait pas à connaître son vocabulaire :
 *   attente   — le lecteur affiche le montant, la carte n'est pas passée
 *   autorise  — la carte a été acceptée, il reste à capturer
 *   echec     — refus, annulation, ou erreur du lecteur
 *   capture   — déjà encaissé
 */
app.get('/api/paiement/etat', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const pi = (req.query.pi || '').toString();
    if (!pi) return res.status(400).json({ error: 'Paiement non précisé.' });

    const intent = await agence.stripe.paymentIntents.retrieve(pi);

    if (intent.status === 'requires_capture') return res.json({ etat: 'autorise' });
    if (intent.status === 'succeeded') return res.json({ etat: 'capture' });
    if (intent.status === 'canceled') return res.json({ etat: 'echec', message: 'Paiement annulé.' });

    // Toujours en attente côté paiement : le lecteur peut néanmoins avoir
    // échoué (carte refusée, annulation sur l'écran). Son action porte alors le
    // motif, bien plus parlant que « en attente ».
    const lecteur = (req.query.lecteur || '').toString();
    if (lecteur) {
      const r = await agence.stripe.terminal.readers.retrieve(lecteur);
      if (r.action && r.action.status === 'failed') {
        return res.json({ etat: 'echec', message: r.action.failure_message || 'Le lecteur a refusé le paiement.' });
      }
    }

    res.json({ etat: 'attente' });
  } catch (err) {
    console.error('état du paiement :', err.message);
    res.status(500).json({ error: err.message });
  }
});

/** Capture : c'est ici, et seulement ici, que l'argent part. */
app.post('/api/paiement/capture', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const { paymentIntentId } = req.body;
    if (!paymentIntentId) return res.status(400).json({ error: 'Paiement non précisé.' });

    const capture = await agence.stripe.paymentIntents.capture(paymentIntentId);
    res.json({ success: true, montant: capture.amount, id: capture.id });
  } catch (err) {
    console.error('capture :', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Annule l'encaissement en cours : efface l'écran du lecteur et le paiement.
 *
 * Les deux annulations sont indépendantes et chacune peut échouer sans que
 * l'autre en pâtisse — un lecteur qui n'affiche déjà plus rien ne doit pas
 * empêcher d'annuler le paiement, sinon on laisserait une autorisation ouverte.
 */
app.post('/api/paiement/annuler', async (req, res) => {
  const agence = await exigerAgence(req, res);
  if (!agence) return;

  const { paymentIntentId, lecteur } = req.body;

  if (lecteur) {
    try {
      await agence.stripe.terminal.readers.cancelAction(lecteur);
    } catch (err) {
      console.warn('annulation de l\'affichage :', err.message);
    }
  }
  if (paymentIntentId) {
    try {
      await agence.stripe.paymentIntents.cancel(paymentIntentId);
    } catch (err) {
      console.warn('annulation du paiement :', err.message);
    }
  }
  res.json({ ok: true });
});

// ======================= Webhook Stripe =======================
// Le journal des paiements (Firestore) a été retiré : Stripe reste la source de
// vérité de l'encaissement, et le tableau de bord qui le lisait ne servait pas.
//
// L'endpoint est conservé volontairement. Une destination webhook est déclarée
// dans le compte Stripe et pointe ici : supprimer la route ferait tomber Stripe
// sur des 404 et déclencherait ses relances en boucle. On accuse donc réception
// et on journalise, sans rien écrire nulle part.
//
// La vérification de signature est maintenue : sans elle, n'importe qui pourrait
// écrire dans nos logs en appelant cette URL publique.
app.post('/webhook/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET manquant');
    // La vérification de signature est purement cryptographique : elle n'appelle
    // pas Stripe et ne dépend donc d'aucune clé de compte. N'importe quelle
    // instance du client convient, ici celle de l'agence par défaut.
    event = agenceParDefaut().stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'payment_intent.succeeded': {
      const pi = event.data.object;
      const amount = ((pi.amount || 0) / 100).toFixed(2);
      const who = pi.metadata?.fullName || '';
      console.log(`✅ ${pi.id} — ${amount} ${(pi.currency || 'eur').toUpperCase()} — ${who}`);
      break;
    }

    case 'payment_intent.payment_failed':
    case 'payment_intent.canceled':
    case 'terminal.reader.action_failed':
    case 'terminal.reader.action_succeeded':
    case 'charge.captured':
    case 'charge.refunded':
      console.log(`ℹ️ ${event.type}`);
      break;

    default:
      console.log(`(ignored) ${event.type}`);
  }

  res.json({ received: true });
});

// ======================= La caisse d'une agence =======================
//
// `/simply-permis-marseille`, `/getdryv-marseille` : la même page, qui lit
// l'agence dans son adresse. Déclarée en dernier pour ne rien intercepter :
// les fichiers statiques, /health et les routes d'API ont déjà répondu.
//
// On ne vérifie pas ici que l'agence existe. Servir la page ne coûte rien, et
// la caisse dira elle-même « agence non configurée » après avoir demandé son
// jeton de connexion — un message clair dans l'écran vaut mieux qu'un 404 nu.
app.get('/:slug', (req, res, next) => {
  if (!/^[a-z0-9-]+$/i.test(req.params.slug)) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ----- Lancement -----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Serveur démarré sur le port ${PORT}`);
  console.log(
    DEFAULT_AGENCY_SLUG
      ? `   agence par défaut : ${DEFAULT_AGENCY_SLUG} (clés lues dans l'environnement)`
      : `   agence par défaut : aucune — toute adresse sans slug utilise les clés de l'environnement`
  );
  console.log(
    process.env.CRM_BASE_URL
      ? `   autres agences : lues dans le CRM ${process.env.CRM_BASE_URL}`
      : `   autres agences : désactivées (CRM_BASE_URL non défini)`
  );
});
