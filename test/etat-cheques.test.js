// test/etat-cheques.test.js — les choix d'un paiement en chèques (aucune règle de date ni de montant).

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let C;
let E;
test.before(async () => {
  C = await importerPublic('etat-cheques.js');
  E = await importerPublic('etat.js');
});

const ELEVE = {
  eleve: { id: 'e1', prenom: 'Léa', nom: 'MARTIN', email: 'lea@exemple.fr' },
  cascade: { forfaits: [
    { formuleId: 'b30', nom: 'Permis B 30 h', prixCents: 169000, cheques: { max: 3, prixPlusieursFoisCents: 176000 } },
    { formuleId: 'b20', nom: 'Permis B 20 h', prixCents: 129000, cheques: { max: 1, prixPlusieursFoisCents: null } },
    { formuleId: 'ancien', nom: 'Sans donnée chèques', prixCents: 99000 },
  ], indices: {} },
  heuresSupp: { packs: [{ formuleId: 'h5', nom: '5 h', prixCents: 22500, cheques: { max: 9, prixPlusieursFoisCents: null } }] },
  prepa: { mode: 'rien' },
};

function panier(formuleId = 'b30', moyen = 'cheques') {
  const m = E.creerMagasin();
  m.appliquer(E.eleveCharge, ELEVE);
  m.appliquer(E.choisirFormule, 'forfait', formuleId);
  m.appliquer(E.choisirMoyen, moyen);
  return m;
}

test('nombre maximal de versements : la tuile, bornée à 3 ; 1 sans donnée, prépa ou libre', () => {
  assert.equal(C.versementsMaxProduit(ELEVE, { type: 'forfait', formuleId: 'b30' }), 3);
  assert.equal(C.versementsMaxProduit(ELEVE, { type: 'forfait', formuleId: 'ancien' }), 1);
  assert.equal(C.versementsMaxProduit(ELEVE, { type: 'heures_supp', formuleId: 'h5' }), 3);
  assert.equal(C.versementsMaxProduit(ELEVE, { type: 'prepa' }), 1);
  assert.equal(C.versementsMaxProduit(ELEVE, { type: 'libre', montantCents: 5000 }), 1);
});

test('boutons proposés : espèces = 1er versement ; le devis à jour fait foi', () => {
  assert.equal(C.nombreChequesProposes('cheques', 3, null), 3);
  assert.equal(C.nombreChequesProposes('especes_cheques', 3, null), 2);
  assert.equal(C.nombreChequesProposes('especes_cheques', 1, null), 0);
  assert.equal(C.nombreChequesProposes('carte', 3, null), 0);
  assert.equal(C.nombreChequesProposes('cheques', 3, { moyen: 'cheques', nombreChequesMax: 2 }), 2);
});

test('un seul bouton possible : retenu sans geste', () => {
  assert.equal(C.nombreEffectif(C.chequesVides(), 1), 1);
  assert.equal(C.nombreEffectif(C.chequesVides(), 3), null);
  assert.equal(C.nombreEffectif({ ...C.chequesVides(), nombre: 3 }, 2), null, 'au-delà du possible : à rechoisir');
});

test('changer de moyen efface tous les choix de chèques', () => {
  const m = panier();
  m.appliquer(E.choisirNombreCheques, 3);
  m.appliquer(E.choisirPremierCheque, '2026-10-22');
  m.appliquer(E.saisirMontantCheque, 0, '800');
  m.appliquer(E.avancerCheque, 1, '2026-11-10');
  assert.equal(m.lire().cheques.nombre, 3);
  m.appliquer(E.choisirMoyen, 'especes_cheques');
  assert.deepEqual(m.lire().cheques, C.chequesVides());
  m.appliquer(E.choisirNombreCheques, 2);
  m.appliquer(E.choisirMoyen, 'cheques');
  assert.deepEqual(m.lire().cheques, C.chequesVides());
});

test('changer de formule efface aussi les choix (montants et nombre d\'une autre formule)', () => {
  const m = panier();
  m.appliquer(E.choisirNombreCheques, 2);
  m.appliquer(E.saisirMontantCheque, 0, '900');
  m.appliquer(E.choisirFormule, 'forfait', 'b20');
  assert.deepEqual(m.lire().cheques, C.chequesVides());
});

test('un montant saisi au-delà du chèque n−1 n\'est jamais envoyé', () => {
  const choix = { ...C.chequesVides(), nombre: 3, montants: ['600', '500', '400'] };
  assert.deepEqual(C.demandeCheques(choix, 3).demande.montantsCents, [60000, 50000]);
  assert.deepEqual(C.demandeCheques(choix, 2).demande.montantsCents, [60000]);
  assert.equal(C.demandeCheques(choix, 1).demande.montantsCents, undefined);
});

test('montants : vide = à répartir (null), illisible = bouton bloqué', () => {
  const vide = { ...C.chequesVides(), montants: ['', '450,50', ''] };
  assert.deepEqual(C.demandeCheques(vide, 3).demande.montantsCents, [null, 45050]);
  assert.equal(C.demandeCheques(C.chequesVides(), 3).demande.montantsCents, undefined);
  assert.deepEqual(C.demandeCheques({ ...C.chequesVides(), montants: ['abc', '', ''] }, 3), { manque: 'montants' });
});

test('demande : nombre requis ; 1er chèque et avances seulement s\'ils sont choisis', () => {
  assert.deepEqual(C.demandeCheques(C.chequesVides(), null), { manque: 'nombre' });
  assert.deepEqual(C.demandeCheques(C.chequesVides(), 2), { demande: { nombre: 2 } });
  const choix = { ...C.chequesVides(), premierLe: '2026-10-22', avances: [null, '2026-11-10', '2026-12-01'] };
  assert.deepEqual(C.demandeCheques(choix, 2), { demande: { nombre: 2, premierLe: '2026-10-22', avances: [null, '2026-11-10'] } });
});

test('changer le nombre efface montants et avances, garde le 1er chèque', () => {
  const avant = { nombre: 3, premierLe: '2026-10-22', avances: [null, '2026-11-10', null], montants: ['800', '', ''] };
  const apres = C.avecNombre(avant, 2);
  assert.deepEqual(apres, { nombre: 2, premierLe: '2026-10-22', avances: [null, null, null], montants: ['', '', ''] });
  assert.equal(C.avecNombre(avant, 3), avant, 'même nombre : état inchangé');
  assert.equal(C.avecNombre(avant, 4), avant, 'hors plafond : ignoré');
});

test('changer le 1er chèque fait tomber les avances ; les transitions ne modifient jamais l\'ancien état', () => {
  const avant = { ...C.chequesVides(), nombre: 3, avances: [null, '2026-11-10', null] };
  const gele = JSON.stringify(avant);
  assert.deepEqual(C.avecPremier(avant, '2026-10-23').avances, [null, null, null]);
  assert.equal(C.avecAvance(avant, 2, '2026-12-01').avances[2], '2026-12-01');
  assert.equal(C.avecMontant(avant, 0, '900').montants[0], '900');
  assert.equal(JSON.stringify(avant), gele);
});

test('les choix de chèques sont ignorés hors des moyens chèques', () => {
  const m = panier('b30', 'carte');
  const avant = m.lire();
  m.appliquer(E.choisirNombreCheques, 2);
  assert.equal(m.lire(), avant);
});

test('requête de devis : la demande de chèques part avec le panier', () => {
  const m = panier();
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'nombre' });
  m.appliquer(E.choisirNombreCheques, 3);
  m.appliquer(E.saisirMontantCheque, 0, '800');
  assert.deepEqual(E.requeteDevis(m.lire()).corps, {
    studentId: 'e1', produit: { type: 'forfait', formuleId: 'b30' }, moyen: 'cheques',
    cheques: { nombre: 3, montantsCents: [80000, null] },
  });
});

test('espèces + chèques : les espèces d\'abord, puis le nombre', () => {
  const m = panier('b30', 'especes_cheques');
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'especes' });
  m.appliquer(E.saisirEspeces, '300');
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'nombre' });
  m.appliquer(E.choisirNombreCheques, 2);
  const { corps } = E.requeteDevis(m.lire());
  assert.equal(corps.especesCents, 30000);
  assert.deepEqual(corps.cheques, { nombre: 2 });
});

test('formule à un seul versement : un chèque, sans geste ; pas de chèque après des espèces', () => {
  const m = panier('b20', 'cheques');
  assert.equal(E.nombreCheques(m.lire()), 1);
  assert.deepEqual(E.requeteDevis(m.lire()).corps.cheques, { nombre: 1 });
  m.appliquer(E.choisirMoyen, 'especes_cheques');
  m.appliquer(E.saisirEspeces, '300');
  assert.equal(E.chequesProposes(m.lire()), 0);
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'nombre' });
});
