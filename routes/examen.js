// routes/examen.js
//
// ======================= Onglet Examen : heures encore disponibles =======================
//
// La secrétaire recopie le reste d'heures du logiciel de gestion : le CRM met
// à jour la fiche (`students.exam_stock_hours`, la donnée de la fiche élève et
// du module Examens), trace qui, quand, avant → après, et renvoie l'onglet
// recalculé. Cette route relaie, jeton compris (qui a changé) : le CRM borne
// la saisie et fait autorité.

const express = require('express');
const { slugEffectif } = require('../lib/agences');
const { appelerCrm, configurationCrm, DELAIS_MS } = require('../lib/crm');
const { exigerJeton } = require('../lib/jeton');

const router = express.Router();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** POST /api/caisse/heures-disponibles { slug, studentId, heures } → `{ prepa, avant, apres, trace }`. */
router.post('/api/caisse/heures-disponibles', async (req, res) => {
  const slug = slugEffectif(req);
  if (!configurationCrm().configure || !slug) return res.status(503).json({ crm: 'indisponible' });
  const auth = exigerJeton(req, res, slug);
  if (!auth) return;
  const studentId = String(req.body?.studentId ?? '').trim();
  if (!UUID.test(studentId)) return res.status(400).json({ error: 'Élève non précisé.' });
  const heures = req.body?.heures;
  if (typeof heures !== 'number' || !Number.isFinite(heures)) return res.status(422).json({ error: 'Indiquez un nombre d’heures.' });

  const r = await appelerCrm('/api/internal/caisse/heures-disponibles', {
    corps: { agencySlug: slug, jeton: auth.jeton, studentId, heures },
    delaiMs: DELAIS_MS.eleve,
  });
  if (r.indisponible) return res.status(503).json({ crm: 'indisponible', error: 'Le CRM ne répond pas : la fiche n’a pas été mise à jour.' });
  if (!r.ok) return res.status(r.status).json({ error: r.error });
  return res.json(r.data ?? {});
});

module.exports = router;
