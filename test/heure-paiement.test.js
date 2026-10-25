// test/heure-paiement.test.js — capture et webhook déclarent la MÊME heure pour un paiement par carte.

const test = require('node:test');
const assert = require('node:assert/strict');
const { heurePaiement } = require('../lib/declaration');

test('une seule source d’heure : la création du paiement Stripe, à la seconde', () => {
  assert.equal(heurePaiement({ created: 1790000000 }), '2026-09-21T14:13:20.000Z');
  assert.equal(heurePaiement({}), null);
  assert.equal(heurePaiement(null), null);
});
