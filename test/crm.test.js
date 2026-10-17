// Client des routes internes du CRM : un refus 422 d'échéancier garde son `champ`.
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');

const { appelerCrm } = require('../lib/crm');

function crmSimule(status, corps) {
  return new Promise((resolve) => {
    const serveur = http.createServer((req, res) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(corps));
    });
    serveur.listen(0, '127.0.0.1', () => resolve(serveur));
  });
}

async function avecCrm(status, corps, essai) {
  const serveur = await crmSimule(status, corps);
  const avant = { url: process.env.CRM_BASE_URL, secret: process.env.INTERNAL_API_SECRET };
  process.env.CRM_BASE_URL = `http://127.0.0.1:${serveur.address().port}`;
  process.env.INTERNAL_API_SECRET = 'secret-de-test';
  try {
    await essai();
  } finally {
    serveur.close();
    if (avant.url === undefined) delete process.env.CRM_BASE_URL; else process.env.CRM_BASE_URL = avant.url;
    if (avant.secret === undefined) delete process.env.INTERNAL_API_SECRET; else process.env.INTERNAL_API_SECRET = avant.secret;
  }
}

test('422 d’échéancier : le message et le champ fautif sont transmis', async () => {
  await avecCrm(422, { ok: false, error: 'Les montants saisis dépassent le total.', champ: 'montants' }, async () => {
    const r = await appelerCrm('/api/internal/caisse/devis', { corps: {} });
    assert.deepEqual(r, { ok: false, status: 422, error: 'Les montants saisis dépassent le total.', champ: 'montants' });
  });
});

test('refus sans champ : forme inchangée (code gardé, pas de champ)', async () => {
  await avecCrm(409, { ok: false, error: 'Ce devis date d’un autre jour.', code: 'devis_autre_jour' }, async () => {
    const r = await appelerCrm('/api/internal/caisse/encaissement', { corps: {} });
    assert.deepEqual(r, { ok: false, status: 409, error: 'Ce devis date d’un autre jour.', code: 'devis_autre_jour' });
  });
});
