// test/sans-carte.test.js — `POST /api/caisse/especes` (espèces, chèques, espèces + chèques)
// et le relais des choix de chèques dans `POST /api/caisse/devis`.
//
// Le vrai serveur de la caisse (`app` de server.js) parle à un CRM SIMULÉ sur
// un port local : aucun appel à Stripe, aucun CRM réel, aucun envoi.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const SECRET = 'secret-de-test';
const SLUG = 'simply-permis-marseille';

// ─── CRM simulé ──────────────────────────────────────────────────────────────
const recus = [];
let reponseCrm = () => ({ status: 200, body: { ok: true, data: { statut: 'enregistre', effets: [], encaissementId: 'enc-1' } } });
const crm = http.createServer((req, res) => {
  let brut = '';
  req.on('data', (c) => { brut += c; });
  req.on('end', () => {
    const corps = brut ? JSON.parse(brut) : null;
    recus.push({ chemin: req.url, secret: req.headers['x-internal-secret'], corps });
    const { status, body } = reponseCrm(req.url, corps);
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  });
});

let base;
let serveur;
let signer;
let CONTEXTE_DEVIS;
let CONTEXTE_JETON;
let relancesPlanifiees;

test.before(async () => {
  await new Promise((ok) => crm.listen(0, '127.0.0.1', ok));
  process.env.CRM_BASE_URL = `http://127.0.0.1:${crm.address().port}`;
  process.env.INTERNAL_API_SECRET = SECRET;
  process.env.STRIPE_SECRET_KEY = 'sk_test_factice_jamais_appele';
  process.env.PORT = '0';
  delete process.env.DEFAULT_AGENCY_SLUG;
  ({ serveur } = require('../server'));
  if (!serveur.listening) await new Promise((ok) => serveur.once('listening', ok));
  base = `http://127.0.0.1:${serveur.address().port}`;
  ({ signer, CONTEXTE_DEVIS, CONTEXTE_JETON } = require('../lib/signature'));
  ({ relancesPlanifiees } = require('../lib/declaration'));
});

test.after(() => {
  serveur.close();
  crm.close();
});

test.beforeEach(() => {
  recus.length = 0;
  reponseCrm = () => ({ status: 200, body: { ok: true, data: { statut: 'enregistre', effets: [], encaissementId: 'enc-1' } } });
});

const maintenant = () => Math.floor(Date.now() / 1000);
const jetonCaisse = () => signer(CONTEXTE_JETON, { v: 1, u: '11111111-1111-4111-8111-111111111111', a: SLUG, iat: maintenant(), exp: maintenant() + 3600 }, SECRET);

function devis(champs) {
  const payload = {
    v: 1, id: champs.id || '55555555-5555-4555-8555-555555555555', a: SLUG, s: '33333333-3333-4333-8333-333333333333',
    u: '11111111-1111-4111-8111-111111111111', p: { t: 'forfait', f: '44444444-4444-4444-8444-444444444444' },
    l: 'Permis B 30 heures', tot: champs.tot, cb: champs.cb, esp: champs.esp, mo: champs.mo,
    ...(champs.chq !== undefined ? { chq: champs.chq, ech: champs.ech } : {}),
    iat: maintenant(), exp: maintenant() + 1800,
  };
  return signer(CONTEXTE_DEVIS, payload, SECRET);
}

const CHEQUES = { mo: 'cheques', tot: 176000, cb: 0, esp: 0, chq: 176000, ech: [['2026-10-19', 58800, '2026-10-19'], ['2026-11-19', 58600, '2026-11-19'], ['2026-12-21', 58600, '2026-12-21']] };
const ESPECES_CHEQUES = { mo: 'especes_cheques', tot: 176000, cb: 0, esp: 30000, chq: 146000, ech: [['2026-11-17', 73000, '2026-11-17'], ['2026-12-17', 73000, '2026-12-17']] };

async function poster(chemin, corps) {
  const r = await fetch(`${base}${chemin}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-caisse-jeton': jetonCaisse() },
    body: JSON.stringify({ slug: SLUG, ...corps }),
  });
  return { status: r.status, data: await r.json() };
}

const declarations = () => recus.filter((r) => r.chemin === '/api/internal/caisse/encaissement');

test('chèques : une seule déclaration, sans carte, et la réponse du CRM', async () => {
  const jeton = devis(CHEQUES);
  const r = await poster('/api/caisse/especes', { devis: jeton });
  assert.equal(r.status, 200);
  assert.equal(r.data.declaration.statut, 'enregistre');
  const d = declarations();
  assert.equal(d.length, 1);
  assert.equal(d[0].secret, SECRET);
  assert.deepEqual({ ...d[0].corps, paidAt: null }, {
    agencySlug: SLUG, devis: jeton, stripePaymentIntentId: null, montantCarteCents: 0, paidAt: null,
  });
});

test('espèces + chèques : même chemin', async () => {
  const r = await poster('/api/caisse/especes', { devis: devis(ESPECES_CHEQUES) });
  assert.equal(r.status, 200);
  assert.equal(declarations().length, 1);
});

test('espèces seules : inchangé', async () => {
  const r = await poster('/api/caisse/especes', { devis: devis({ mo: 'especes', tot: 9000, cb: 0, esp: 9000 }) });
  assert.equal(r.status, 200);
  assert.equal(declarations().length, 1);
});

test('CRM muet : ERREUR 503, rien d\'enregistré, aucune relance (relancer:false)', async () => {
  reponseCrm = () => ({ status: 500, body: { ok: false } });
  const r = await poster('/api/caisse/especes', { devis: devis({ ...CHEQUES, id: '77777777-7777-4777-8777-777777777777' }) });
  assert.equal(r.status, 503);
  assert.equal(r.data.crm, 'indisponible');
  assert.match(r.data.error, /rien n'est enregistré.*rendez les chèques/);
  assert.equal(declarations().length, 1, 'une seule tentative');
  assert.deepEqual(relancesPlanifiees(), []);
});

test('carte ou espèces + carte : refusés sur cette route, le CRM n\'est pas appelé', async () => {
  const carte = await poster('/api/caisse/especes', { devis: devis({ mo: 'carte', tot: 9000, cb: 9000, esp: 0 }) });
  assert.equal(carte.status, 400);
  assert.equal(carte.data.code, 'devis_avec_carte');
  const mixte = await poster('/api/caisse/especes', { devis: devis({ mo: 'mixte', tot: 9000, cb: 4000, esp: 5000 }) });
  assert.equal(mixte.status, 400);
  assert.equal(declarations().length, 0);
});

test('un devis chèques ne part jamais au lecteur', async () => {
  const r = await poster('/api/caisse/paiement', { devis: devis(CHEQUES), lecteur: 'tmr_1' });
  assert.equal(r.status, 400);
  assert.equal(r.data.code, 'devis_sans_carte');
});

test('échéancier incohérent : devis refusé avant tout appel au CRM', async () => {
  const faux = { ...CHEQUES, ech: [['2026-10-19', 58800, '2026-10-19'], ['2026-11-19', 58600, '2026-11-19'], ['2026-12-21', 58000, '2026-12-21']] };
  const r = await poster('/api/caisse/especes', { devis: devis(faux) });
  assert.equal(r.status, 400);
  assert.equal(r.data.code, 'devis_invalide');
  assert.equal(declarations().length, 0);
});

test('devis de la veille : le refus `devis_autre_jour` du CRM est relayé (409 + code)', async () => {
  reponseCrm = () => ({ status: 409, body: { ok: false, error: 'Devis d\'un autre jour : redemandez le prix.', code: 'devis_autre_jour' } });
  const r = await poster('/api/caisse/especes', { devis: devis(CHEQUES) });
  assert.equal(r.status, 409);
  assert.equal(r.data.code, 'devis_autre_jour');
});

test('devis : les choix de chèques sont relayés, et eux seuls', async () => {
  reponseCrm = () => ({ status: 200, body: { ok: true, data: { devis: { totalCents: 176000 }, jeton: 'j' } } });
  const r = await poster('/api/caisse/devis', {
    studentId: 's1', produit: { type: 'forfait', formuleId: 'f1' }, moyen: 'cheques',
    cheques: { nombre: 3, premierLe: '2026-10-22', avances: [null, '2026-11-10', null, 'trop'], montantsCents: [80000, null], prixCents: 1, intrus: true },
  });
  assert.equal(r.status, 200);
  const corps = recus.find((x) => x.chemin === '/api/internal/caisse/devis').corps;
  assert.deepEqual(corps.cheques, { nombre: 3, premierLe: '2026-10-22', avances: [null, '2026-11-10', null], montantsCents: [80000, null] });
  assert.equal(corps.moyen, 'cheques');
  assert.equal(typeof corps.jeton, 'string');
});

test('devis carte : aucune clé chèques ajoutée (corps d\'avant)', async () => {
  reponseCrm = () => ({ status: 200, body: { ok: true, data: { devis: { totalCents: 9000 }, jeton: 'j' } } });
  await poster('/api/caisse/devis', { studentId: 's1', produit: { type: 'forfait', formuleId: 'f1' }, moyen: 'carte' });
  const corps = recus.find((x) => x.chemin === '/api/internal/caisse/devis').corps;
  assert.deepEqual(Object.keys(corps).sort(), ['agencySlug', 'jeton', 'moyen', 'produit', 'studentId']);
});

test('refus 422 du CRM sur un devis chèques : message relayé tel quel', async () => {
  reponseCrm = () => ({ status: 422, body: { ok: false, error: 'Les montants saisis dépassent le total', champ: 'montants' } });
  const r = await poster('/api/caisse/devis', { studentId: 's1', produit: { type: 'forfait', formuleId: 'f1' }, moyen: 'cheques', cheques: { nombre: 2, montantsCents: [999999] } });
  assert.equal(r.status, 422);
  assert.equal(r.data.error, 'Les montants saisis dépassent le total');
});
