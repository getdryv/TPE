// test/billetage.test.js — le serveur vérifie le détail des espèces contre le devis signé.

const test = require('node:test');
const assert = require('node:assert/strict');
const { billetageDuDevis, versMetadonnee, depuisMetadonnee } = require('../lib/billetage');
const { devisCoherent } = require('../lib/devis');

test('absent : accepté (page plus ancienne) ; présent : la somme tombe pile sur la part espèces', () => {
  assert.deepEqual(billetageDuDevis(undefined, 104900), { ok: true, billetage: null });
  const b = { 5000: 20, 2000: 2, 500: 1, 200: 2 };
  assert.deepEqual(billetageDuDevis(b, 104900), { ok: true, billetage: { 5000: 20, 2000: 2, 500: 1, 200: 2 } });
  assert.equal(billetageDuDevis(b, 105000).ok, false, 'un euro d’écart : refusé');
  assert.equal(billetageDuDevis({ 300: 1 }, 300).ok, false, 'coupure inconnue');
  assert.equal(billetageDuDevis({ 5000: 1.5 }, 7500).ok, false);
  assert.equal(billetageDuDevis({ 5000: 0 }, 0).ok, false, 'vide : illisible');
});

test('métadonnée Stripe : aller-retour, illisible = null', () => {
  const b = { 5000: 4, 2000: 5 };
  assert.equal(versMetadonnee(b), '5000x4,2000x5');
  assert.deepEqual(depuisMetadonnee('5000x4,2000x5'), { 5000: 4, 2000: 5 });
  assert.equal(depuisMetadonnee('5000x4;x'), null);
  assert.equal(depuisMetadonnee(undefined), null);
  assert.ok(versMetadonnee({ 20000: 999, 10000: 999, 5000: 999, 2000: 999, 1000: 999, 500: 999, 200: 999, 100: 999, 50: 999, 20: 999, 10: 999 }).length <= 500);
});

test('devis de reprise de chèque : espèces ou carte, jamais un mélange', () => {
  const base = { v: 1, id: 'd', a: 'agence', s: 'e', u: 'u', l: 'Reprise du chèque n° 1', p: { t: 'reprise_cheque', c: ['c1'] }, iat: 1, exp: 2 };
  assert.equal(devisCoherent({ ...base, tot: 25000, cb: 0, esp: 25000, mo: 'especes' }), true);
  assert.equal(devisCoherent({ ...base, tot: 25000, cb: 25000, esp: 0, mo: 'carte' }), true);
  assert.equal(devisCoherent({ ...base, tot: 25000, cb: 15000, esp: 10000, mo: 'mixte' }), false);
  assert.equal(devisCoherent({ ...base, p: { t: 'reprise_cheque', c: [] }, tot: 25000, cb: 0, esp: 25000, mo: 'especes' }), false);
});
