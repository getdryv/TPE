// test/etat-examen.test.js — l'onglet Examen : ouverture directe, heures à payer, heures en plus,
// représentation, saisie des heures disponibles et devis.

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let E;
let X;
test.before(async () => {
  E = await importerPublic('etat.js');
  X = await importerPublic('etat-examen.js');
});

const GRILLE = [0, 5990, 11980, 17970, 23960, 29950, 35940, 41930, 47920, 53910, 54900, 65890, 71880];
const prepa = (over = {}) => ({
  mode: 'heures', ouvrir: true, indisponible: null, lignes: [],
  preconisation: { heures: 6, date: '2026-10-24T09:00:00Z', moniteur: 'Mohamed ABDOU' },
  examen: { date: '2026-11-12', centre: 'Marseille', epreuve: 'Épreuve de circulation' },
  representation: null,
  heures: { preconisees: 6, stock: 0, disponibles: 0, plancher: 0, max: 30, enPlusMax: 20 },
  grilleCents: GRILLE, accompagnementCents: 5990,
  ...over,
});
const eleve = (p) => ({
  eleve: { id: 'e1', prenom: 'Inès', nom: 'BENALI', email: 'ines@exemple.fr' },
  cascade: { forfaits: [], indices: {} }, heuresSupp: { packs: [] }, prepa: p,
});

function caisse(p = prepa()) {
  const m = E.creerMagasin();
  m.appliquer(E.sessionOuverte, { mode: 'catalogue', utilisateur: { nom: 'Sarah', role: 'secretary' } }, true);
  m.appliquer(E.eleveCharge, eleve(p));
  return m;
}

test('ouverture directe sur l’onglet Examen quand le CRM le demande, sinon Forfait initial', () => {
  const m = caisse();
  assert.equal(m.lire().onglet, 'prepa');
  assert.deepEqual(m.lire().produit, { type: 'prepa', heuresEnPlus: 0, heuresDisponibles: 0 });
  assert.equal(caisse(prepa({ ouvrir: false })).lire().onglet, 'forfait');
  assert.equal(caisse(prepa({ ouvrir: true, indisponible: 'tarif absent' })).lire().onglet, 'forfait');
  assert.equal(caisse({ mode: 'rien' }).lire().onglet, 'forfait');
});

test('heures à payer = préconisées − disponibles, jamais négatif ; total avant le moyen', () => {
  const m = caisse();
  m.appliquer(X.saisirHeuresDisponibles, 2);
  let c = X.calculExamen(m.lire());
  assert.deepEqual([c.manquantes, c.manquantesCents, c.totalCents], [4, 23960, 29950]);
  m.appliquer(X.saisirHeuresDisponibles, 9);
  c = X.calculExamen(m.lire());
  assert.deepEqual([c.manquantes, c.totalCents], [0, 5990]);
  assert.deepEqual(c.lignes.map((l) => l.nature), ['accompagnement']);
});

test('saisie bornée : jamais sous 0, jamais au-delà du plafond du compte', () => {
  const m = caisse();
  m.appliquer(X.saisirHeuresDisponibles, -3);
  assert.equal(m.lire().examen.saisie, 0);
  m.appliquer(X.saisirHeuresDisponibles, 99);
  assert.equal(m.lire().examen.saisie, 30);
});

test('heures en plus : jamais bloquées, même tout réglé ; bornées par le CRM', () => {
  const m = caisse(prepa({ heures: { preconisees: 6, stock: 6, disponibles: 6, plancher: 0, max: 30, enPlusMax: 20 } }));
  assert.equal(X.calculExamen(m.lire()).manquantes, 0);
  m.appliquer(X.choisirHeuresEnPlus, 2);
  const c = X.calculExamen(m.lire());
  assert.deepEqual([c.heures, c.totalCents], [2, 11980 + 5990]);
  assert.equal(c.lignes[0].libelle, '2 h en plus avant l’examen');
  m.appliquer(X.choisirHeuresEnPlus, 50);
  assert.equal(m.lire().produit.heuresEnPlus, 20);
});

test('représentation (ajourné ou absent) : le forfait de l’agence, pas de saisie d’heures', () => {
  const m = caisse(prepa({ representation: { heures: 6, motif: 'absent', le: '2026-10-21' } }));
  const avant = m.lire();
  m.appliquer(X.saisirHeuresDisponibles, 4);
  assert.equal(m.lire(), avant, 'la saisie est sans objet');
  const c = X.calculExamen(m.lire());
  assert.deepEqual(c.lignes.map((l) => [l.libelle, l.montantCents]), [['Forfait de représentation : 6 h', 35940], ['Accompagnement à l’examen', 5990]]);
  assert.equal(c.totalCents, 41930);
});

test('le devis attend que la fiche soit à jour, puis part avec les heures de la fiche', () => {
  const m = caisse();
  m.appliquer(E.choisirMoyen, 'carte');
  m.appliquer(X.saisirHeuresDisponibles, 2);
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'heures' });
  m.appliquer(X.heuresEnvoyees, 2);
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'heures' });
  const versionAvant = m.lire().version;
  m.appliquer(X.heuresEnregistrees, 2, prepa({ heures: { preconisees: 6, stock: 2, disponibles: 2, plancher: 0, max: 30, enPlusMax: 20 } }));
  assert.equal(m.lire().examen.statut, 'ok');
  assert.ok(m.lire().version > versionAvant, 'le devis en main est périmé');
  assert.deepEqual(E.requeteDevis(m.lire()).corps.produit, { type: 'prepa', heuresEnPlus: 0, heuresDisponibles: 2 });
});

test('réponse d’une saisie dépassée : gardée, mais la saisie en cours repartira ; refus affiché', () => {
  const m = caisse();
  m.appliquer(X.saisirHeuresDisponibles, 2);
  m.appliquer(X.saisirHeuresDisponibles, 3);
  m.appliquer(X.heuresEnregistrees, 2, prepa({ heures: { preconisees: 6, stock: 2, disponibles: 2, plancher: 0, max: 30, enPlusMax: 20 } }));
  assert.equal(m.lire().examen.statut, 'attente');
  assert.equal(m.lire().examen.saisie, 3);
  m.appliquer(X.heuresRefusees, 3, 'Au plus 30 h.');
  assert.deepEqual([m.lire().examen.statut, m.lire().examen.message], ['erreur', 'Au plus 30 h.']);
  m.appliquer(E.choisirMoyen, 'carte');
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'heures_erreur' });
});

test('rien à régler (tout réglé, accompagnement compris) : pas de devis', () => {
  const m = caisse(prepa({ mode: 'rien', accompagnementCents: null, heures: { preconisees: 6, stock: 6, disponibles: 6, plancher: 0, max: 30, enPlusMax: 20 } }));
  m.appliquer(E.choisirOnglet, 'forfait');
  m.appliquer(E.choisirOnglet, 'prepa');
  m.appliquer(E.choisirMoyen, 'carte');
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'rien' });
});

test('accéléré : les heures de l’offre comptent comme disponibles (calcul de la fiche)', () => {
  const m = caisse(prepa({ heures: { preconisees: 20, stock: 0, disponibles: 20, plancher: 20, max: 30, enPlusMax: 20 } }));
  assert.equal(X.calculExamen(m.lire()).manquantes, 0);
});
