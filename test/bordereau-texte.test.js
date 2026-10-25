// test/bordereau-texte.test.js — le bordereau d'espèces : montant en lettres, heure à la seconde, encadrés.

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let T;
test.before(async () => {
  T = await importerPublic('bordereau-texte.js');
});

const net = (s) => s.replace(/[\u00a0\u202f]/g, ' ');

test('montant en lettres (orthographe traditionnelle)', () => {
  assert.equal(T.montantEnLettres(104900), 'Mille quarante-neuf euros');
  assert.equal(T.montantEnLettres(30000), 'Trois cents euros');
  assert.equal(T.montantEnLettres(30100), 'Trois cent un euros');
  assert.equal(T.montantEnLettres(100), 'Un euro');
  assert.equal(T.montantEnLettres(8000), 'Quatre-vingts euros');
  assert.equal(T.montantEnLettres(8100), 'Quatre-vingt-un euros');
  assert.equal(T.montantEnLettres(7100), 'Soixante et onze euros');
  assert.equal(T.montantEnLettres(9900), 'Quatre-vingt-dix-neuf euros');
  assert.equal(T.montantEnLettres(2100), 'Vingt et un euros');
  assert.equal(T.montantEnLettres(200000), 'Deux mille euros');
  assert.equal(T.montantEnLettres(28000000), 'Deux cent quatre-vingt mille euros');
  assert.equal(T.montantEnLettres(25050), 'Deux cent cinquante euros et cinquante centimes');
  assert.equal(T.montantEnLettres(10), 'Dix centimes');
});

test('date et heure de Paris, à la seconde, jour de la semaine en tête', () => {
  assert.equal(T.dateHeure('2026-10-24T08:15:42.900Z'), 'Samedi 24 octobre 2026 à 10:15:42');
  assert.equal(T.dateHeure('2026-12-31T23:30:05Z'), 'Vendredi 1 janvier 2027 à 00:30:05');
  assert.equal(T.dateHeure('pas une date'), '');
});

test('encadré d’un espèces + chèques (maquette 09)', () => {
  const e = T.encadre({ especesCents: 30000, carteCents: 0, chequesCents: 124900, totalCents: 154900,
    cheques: [{ dueOn: '2026-11-05', montantCents: 62500 }, { dueOn: '2026-12-05', montantCents: 62400 }] });
  assert.equal(net(e.titre), 'Paiement mixte : 1 549 € au total');
  assert.deepEqual(e.lignes.map(net), ['300 € en espèces, joints à ce bordereau.',
    '1 249 € en 2 chèques (625 € à déposer le 5 novembre, 624 € le 5 décembre), rangés avec les chèques.']);
});

test('encadré d’un espèces + carte, d’une reprise ; rien pour des espèces seules', () => {
  const carte = T.encadre({ especesCents: 30000, carteCents: 74900, chequesCents: 0, totalCents: 104900 });
  assert.deepEqual(carte.lignes.map(net), ['300 € en espèces, joints à ce bordereau.', '749 € par carte bancaire.']);
  const reprise = T.encadre({ especesCents: 25000, carteCents: 0, chequesCents: 0, chequesRendus: ['0004521'] });
  assert.equal(reprise.titre, 'Reprise de chèque');
  assert.equal(reprise.lignes[0], 'Chèque n° 0004521 rendu à l\'élève, remplacé par ces espèces.');
  assert.equal(T.encadre({ especesCents: 104900, carteCents: 0, chequesCents: 0, chequesRendus: null }), null);
});

test('lignes du tableau des coupures', () => {
  assert.equal(net(T.libelleLigne(5000)), 'Billet de 50 €');
  assert.equal(net(T.libelleLigne(200)), 'Pièce de 2 €');
  assert.equal(net(T.libelleLigne(50)), 'Pièce de 0,50 €');
  assert.equal(T.nombreDeCoupures([{ nombre: 20 }, { nombre: 5 }]), 25);
});
