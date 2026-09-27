// server.js
//
// Démarrage seulement : environnement, en-têtes, fichiers statiques, montage
// des routes. Le métier vit dans `lib/` (agences, CRM, signature, jeton, devis,
// mode de la caisse, terminal, déclaration) et les routes dans `routes/`.
// Contrat de la caisse au catalogue : docs/caisse-tpe/ARCHITECTURE.md (CRM).
require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');

const { slugParDefaut } = require('./lib/agences');

const app = express();

// ----- Stripe -----
if (!process.env.STRIPE_SECRET_KEY) {
  console.error('❌ STRIPE_SECRET_KEY manquant');
  process.exit(1);
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

// ----- Routes -----
app.use(require('./routes/agence'));
app.use(require('./routes/eleves'));
app.use(require('./routes/caisse'));
app.use(require('./routes/paiement'));
app.use(require('./routes/webhook'));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
const serveur = app.listen(PORT, () => {
  const parDefaut = slugParDefaut();
  console.log(`✅ Serveur démarré sur le port ${serveur.address().port}`);
  console.log(
    parDefaut
      ? `   agence par défaut : ${parDefaut} (clés lues dans l'environnement)`
      : `   agence par défaut : aucune — toute adresse sans slug utilise les clés de l'environnement`
  );
  console.log(
    process.env.CRM_BASE_URL
      ? `   autres agences : lues dans le CRM ${process.env.CRM_BASE_URL}`
      : `   autres agences : désactivées (CRM_BASE_URL non défini)`
  );
  console.log(
    process.env.CRM_BASE_URL && process.env.INTERNAL_API_SECRET
      ? `   caisse au catalogue : active (repli en secours si le CRM ne répond pas)`
      : `   caisse au catalogue : inactive — mode secours (montant saisi)`
  );
});

// Exporté pour les tests (démarrage sur un port libre, puis arrêt).
module.exports = { app, serveur };
