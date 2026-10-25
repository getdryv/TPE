// test/especes-compte.test.js — le comptage des espèces : total, statut, ce qu'il faut rendre, appoint.

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let C;
test.before(async () => {
  C = await importerPublic('especes-compte.js');
});

const comptage = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [String(k), v]));

test('total au centime près, pièces de 0,10 € comprises', () => {
  assert.equal(C.totalCompte(comptage({ 5000: 20, 2000: 2, 500: 1, 200: 2 })), 104900);
  assert.equal(C.totalCompte(comptage({ 50: 1, 20: 2, 10: 1 })), 100);
  assert.equal(C.totalCompte({}), 0);
});

test('saisie : vide = 0, chiffres seulement, 999 au plus ; clic = +1', () => {
  assert.equal(C.lireNombre(''), 0);
  assert.equal(C.lireNombre(' 12 '), 12);
  for (const t of ['-1', '1,5', 'a', '1000']) assert.equal(C.lireNombre(t), null, t);
  let c = C.plusUn({}, 5000);
  c = C.plusUn(c, 5000);
  assert.deepEqual(c, { 5000: 2 });
  assert.deepEqual(C.avecNombre(c, 5000, 0), {}, '0 retire la coupure');
  assert.equal(C.avecNombre(c, 300, 1), c, 'coupure inconnue ignorée');
});

test('statuts : vide, il manque, juste (maquettes 01, 02, 05)', () => {
  assert.equal(C.analyser({}, 104900).statut, 'vide');
  const manque = C.analyser(comptage({ 5000: 20, 2000: 2 }), 104900);
  assert.deepEqual([manque.statut, manque.manque], ['manque', 900]);
  assert.equal(C.analyser(comptage({ 5000: 20, 2000: 2, 500: 1, 200: 2 }), 104900).statut, 'juste');
});

test('trop donné : rendre 1 billet de 10 € et 1 pièce de 1 €, pris parmi ce qu’il a donné (maquette 03)', () => {
  const a = C.analyser(comptage({ 5000: 20, 2000: 2, 1000: 1, 500: 1, 200: 2, 100: 1 }), 104900);
  assert.equal(a.statut, 'trop');
  assert.equal(a.trop, 1100);
  assert.deepEqual(a.rendre, { pieces: { 1000: 1, 100: 1 }, appoint: 0 });
});

test('rien ne tombe juste : rendre 1 billet de 50 € et demander 49 € d’appoint (maquette 04)', () => {
  const a = C.analyser(comptage({ 5000: 21 }), 104900);
  assert.deepEqual(a.rendre, { pieces: { 5000: 1 }, appoint: 4900 });
  const apres = C.apresRendu(comptage({ 5000: 21 }), a.rendre.pieces);
  assert.deepEqual(apres, { 5000: 20 });
  const b = C.analyser(apres, 104900);
  assert.deepEqual([b.statut, b.manque], ['manque', 4900]);
});

test('le moins de pièces possible pour une somme exacte', () => {
  // 30 € de trop : 1 billet de 20 + 1 de 10, plutôt que 3 de 10.
  const a = C.analyser(comptage({ 2000: 1, 1000: 3, 5000: 2 }), 12000);
  assert.deepEqual(a.rendre, { pieces: { 2000: 1, 1000: 1 }, appoint: 0 });
});

test('mixte : sans cible, le comptage fixe la part espèces ; billetage et saisie du devis', () => {
  assert.equal(C.analyser(comptage({ 5000: 4, 2000: 5 }), null).statut, 'juste');
  assert.deepEqual(C.billetage(comptage({ 5000: 4, 2000: 5 })), { 5000: 4, 2000: 5 });
  assert.equal(C.billetage({}), null);
  assert.equal(C.enSaisie(30000), '300');
  assert.equal(C.enSaisie(30050), '300,50');
});

test('libellés : coupures et désignations', () => {
  assert.equal(C.libelleCoupure(20000), '200\u00a0€');
  assert.equal(C.libelleCoupure(50), '50\u00a0c');
  assert.equal(C.designation(1000, 1), '1\u00a0billet de 10\u00a0€');
  assert.equal(C.designation(50, 2), '2\u00a0pièces de 0,50\u00a0€');
});
