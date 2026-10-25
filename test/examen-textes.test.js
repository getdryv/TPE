// test/examen-textes.test.js — textes de l'onglet Examen et du rappel de facture : dates en toutes lettres.

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

const ESP = /[\u00a0\u202f]/g;
const net = (t) => t.replace(ESP, ' ');
let F;
let B;
let EX;
test.before(async () => {
  F = await importerPublic('format.js');
  B = await importerPublic('bande.js');
  EX = await importerPublic('examen.js');
});

test('dates en toutes lettres, année seulement si ce n’est pas l’année en cours', () => {
  const le = new Date('2026-10-26T10:00:00Z');
  assert.equal(net(F.dateEnLettres('2026-10-24', { maintenant: le })), '24 octobre');
  assert.equal(net(F.dateEnLettres('2026-11-12', { jourSemaine: true, maintenant: le })), 'jeudi 12 novembre');
  assert.equal(net(F.dateEnLettres('2026-11-01', { maintenant: le })), '1er novembre');
  assert.equal(net(F.dateEnLettres('2025-08-26', { maintenant: le })), '26 août 2025');
  // Un horodatage tard le soir en UTC est déjà le lendemain à Paris.
  assert.equal(net(F.dateEnLettres('2026-10-23T22:30:00Z', { maintenant: le })), '24 octobre');
  assert.equal(F.dateEnLettres('n’importe quoi'), '');
});

test('préconisation et bandeau de représentation', () => {
  assert.match(net(EX.textePreconisation({ heures: 6, date: '2026-10-24', moniteur: 'Mohamed ABDOU' })), /^Mohamed ABDOU, le 24 octobre : 6 h de préparation avant l’examen\.$/);
  assert.equal(EX.textePreconisation(null), 'Aucune préconisation du moniteur pour l’instant.');
  assert.match(net(EX.texteRepresentation({ motif: 'failed', le: '2026-10-21' })), /^Ajourné le 21 octobre · forfait de représentation$/);
  assert.match(net(EX.texteRepresentation({ motif: 'absent', le: '2026-10-21' })), /^Absent le 21 octobre/);
});

test('heures à payer : le détail du calcul et la valeur', () => {
  const c = { representation: null, manquantes: 4, manquantesCents: 23960, preconisees: 6, disponibles: 2, saisie: 2, plancher: 0, enPlus: 0 };
  assert.equal(net(EX.detailHeuresAPayer(c)), '6 h préconisées − 2 h disponibles');
  assert.equal(net(EX.valeurHeuresAPayer(c)), '4 h · 239,60 €');
  assert.equal(EX.detailHeuresAPayer({ ...c, manquantes: 0 }), 'Toutes les heures sont déjà réglées');
  assert.equal(EX.valeurHeuresAPayer({ ...c, manquantes: 0 }), 'aucune');
  assert.equal(EX.detailHeuresAPayer({ ...c, representation: { heures: 6 } }), 'Forfait de l’agence');
});

test('rappel de facture : montant et élève, sans numéro ni nom du logiciel ; rien pour une reprise ou un écart', () => {
  const r = { devis: { totalCents: 29950 }, eleve: 'Inès BENALI', produit: 'prepa', declaration: { statut: 'ok' } };
  const rappel = B.rappelFacture(r);
  assert.equal(net(rappel.consigne + rappel.texte), 'À faire maintenant dans le logiciel de gestion : saisissez la facture de 299,50 € pour Inès BENALI.');
  assert.doesNotMatch(rappel.consigne + rappel.texte, /DrivUp|E-\d|n°/i);
  assert.equal(B.rappelFacture({ ...r, produit: 'reprise_cheque' }), null);
  assert.equal(B.rappelFacture({ ...r, declaration: { statut: 'ecart' } }), null);
  assert.ok(B.rappelFacture({ ...r, produit: 'forfait' }));
});
