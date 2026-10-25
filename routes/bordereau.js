// routes/bordereau.js
//
// ======================= Réimprimer le bordereau d'espèces =======================
//
// « Réimprimer le bordereau » (bande verte) : le CRM relit l'encaissement
// ENREGISTRÉ, le marque DUPLICATA et trace qui l'a demandé. Cette route ne
// fait que relayer, jeton compris (qui réimprime) : aucune donnée du
// bordereau ne vient de la page.

const express = require('express');
const { slugEffectif } = require('../lib/agences');
const { appelerCrm, configurationCrm, DELAIS_MS } = require('../lib/crm');
const { exigerJeton } = require('../lib/jeton');

const router = express.Router();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** POST /api/caisse/bordereau { slug, encaissementId } → `{ bordereau }` (duplicata). */
router.post('/api/caisse/bordereau', async (req, res) => {
  const slug = slugEffectif(req);
  if (!configurationCrm().configure || !slug) return res.status(503).json({ crm: 'indisponible' });
  const auth = exigerJeton(req, res, slug);
  if (!auth) return;
  const encaissementId = String(req.body?.encaissementId ?? '').trim();
  if (!UUID.test(encaissementId)) return res.status(400).json({ error: 'Encaissement non précisé.' });

  const r = await appelerCrm('/api/internal/caisse/bordereau', {
    corps: { agencySlug: slug, jeton: auth.jeton, encaissementId },
    delaiMs: DELAIS_MS.eleve,
  });
  if (r.indisponible) return res.status(503).json({ crm: 'indisponible', error: 'Le CRM ne répond pas : réessayez dans un instant.' });
  if (!r.ok) return res.status(r.status).json({ error: r.error });
  return res.json({ bordereau: r.data?.bordereau ?? null });
});

module.exports = router;
