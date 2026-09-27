// routes/eleves.js
const express = require('express');
const { slugEffectif } = require('../lib/agences');
const { appelerCrm, configurationCrm, DELAIS_MS } = require('../lib/crm');
const { lireJetonCaisse, jetonDeLaRequete, exigerJeton } = require('../lib/jeton');

const router = express.Router();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * GET /api/students?q=…
 *
 * Relaie la recherche d'élèves du CRM pour l'autocomplétion de la caisse. Le
 * secret partagé reste ici, sur le serveur : la route interne du CRM expose des
 * données personnelles d'élèves et n'a rien à faire dans un navigateur.
 *
 * ─── Identification exigée ──────────────────────────────────────────────────
 * Jusqu'ici, quiconque connaissait l'adresse de la caisse pouvait parcourir le
 * fichier élèves. Désormais un jeton de caisse valide pour CETTE agence est
 * exigé (vérifié ici, sans appel au CRM). Sans jeton : liste vide, comme si
 * rien ne correspondait.
 *
 * ─── Cette route ne peut pas empêcher un encaissement ───────────────────────
 * L'autocomplétion est un confort de saisie, jamais un préalable au paiement.
 * Toute défaillance — CRM éteint, lent, mal configuré, réseau coupé, agence
 * inconnue, jeton absent — se traduit par une liste vide et un HTTP 200, jamais
 * par une erreur. La caisse continue alors exactement comme avant : on tape le
 * nom à la main et on encaisse. C'est aussi pourquoi rien n'est configuré par
 * défaut : sans CRM_BASE_URL, le TPE fonctionne comme aujourd'hui.
 */
router.get('/api/students', async (req, res) => {
  const vide = () => res.json({ students: [] });

  // L'agence vient de l'URL de la caisse ; à défaut, celle du service. On ne
  // cherche que dans les élèves de cette agence, jamais dans ceux d'une autre.
  const agencySlug = slugEffectif(req);
  if (!configurationCrm().configure || !agencySlug) return vide();
  if (!lireJetonCaisse(jetonDeLaRequete(req), agencySlug).ok) return vide();

  const q = (req.query.q || '').toString().trim();
  if (q.length < 2) return vide();

  const r = await appelerCrm('/api/internal/student-search', {
    methode: 'GET',
    query: { slug: agencySlug, q },
    delaiMs: DELAIS_MS.recherche,
  });
  if (!r.ok) {
    if (!r.indisponible) console.warn(`[CRM] recherche élève : HTTP ${r.status}`);
    return vide();
  }
  return res.json({ students: r.data?.students ?? [] });
});

/**
 * GET /api/caisse/eleve?slug=…&id=<uuid>
 *
 * Tout ce que la caisse affiche pour un élève : tuiles du catalogue (promotion
 * comprise), packs de sa boîte, prépa permis, montant libre.
 * Les prix y sont indicatifs : seul le devis fait foi.
 *
 * CRM muet : 503 `{ crm: 'indisponible' }`, que la page traduit en écran
 * « CRM indisponible » (encaissement de secours). Refus du CRM : relayé avec
 * son code et son message.
 */
router.get('/api/caisse/eleve', async (req, res) => {
  const slug = slugEffectif(req);
  // Sans CRM (ou sans slug d'agence), pas de catalogue : c'est le secours.
  if (!configurationCrm().configure || !slug) return res.status(503).json({ crm: 'indisponible' });
  const auth = exigerJeton(req, res, slug);
  if (!auth) return;

  const studentId = (req.query.id || '').toString().trim();
  if (!UUID.test(studentId)) return res.status(400).json({ error: 'Élève non précisé.' });

  const r = await appelerCrm('/api/internal/caisse/eleve', {
    corps: { agencySlug: slug, jeton: auth.jeton, studentId },
    delaiMs: DELAIS_MS.eleve,
  });
  if (r.indisponible) return res.status(503).json({ crm: 'indisponible' });
  if (!r.ok) return res.status(r.status).json({ error: r.error, ...(r.code ? { code: r.code } : {}) });
  return res.json(r.data);
});

module.exports = router;
