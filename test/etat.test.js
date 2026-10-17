// test/etat.test.js — l'état du panier : moyen sans présélection, bande, non-régression carte et espèces.

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let E;
test.before(async () => {
  E = await importerPublic('etat.js');
});

const ELEVE = {
  eleve: { id: 'e1', prenom: 'Léa', nom: 'MARTIN', email: 'lea@exemple.fr' },
  cascade: { forfaits: [{ formuleId: 'b30', nom: 'Permis B 30 h', prixCents: 169000, cheques: { max: 3, prixPlusieursFoisCents: 176000 } }], indices: {} },
  heuresSupp: { packs: [] },
  prepa: { mode: 'rien' },
};

function panier() {
  const m = E.creerMagasin();
  m.appliquer(E.sessionOuverte, { mode: 'catalogue', utilisateur: { nom: 'Camille', role: 'secretaire' } }, true);
  m.appliquer(E.eleveCharge, ELEVE);
  m.appliquer(E.choisirFormule, 'forfait', 'b30');
  return m;
}

const DEVIS = { id: 'd1', libelle: 'Permis B 30 h', lignes: [], totalCents: 169000, especesCents: 0, carteCents: 169000, moyen: 'carte', chequesCents: 0, echeancier: null };

test('aucun moyen présélectionné, ni au départ ni après un nouvel élève', () => {
  assert.equal(E.creerEtat().moyen, null);
  const m = panier();
  assert.equal(m.lire().moyen, null);
  assert.deepEqual(E.MOYENS, ['carte', 'especes', 'cheques', 'mixte', 'especes_cheques']);
});

test('sans moyen, aucun devis ne part : le bouton dit « Choisissez le moyen de paiement »', () => {
  const m = panier();
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'moyen' });
  assert.equal(E.choisirMoyen(m.lire(), 'virement'), m.lire(), 'moyen inconnu ignoré');
});

test('carte, espèces, mixte : la requête de devis garde sa forme d\'avant (pas de clé chèques)', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'carte');
  assert.deepEqual(E.requeteDevis(m.lire()).corps, { studentId: 'e1', produit: { type: 'forfait', formuleId: 'b30' }, moyen: 'carte' });
  m.appliquer(E.choisirMoyen, 'especes');
  assert.deepEqual(E.requeteDevis(m.lire()).corps, { studentId: 'e1', produit: { type: 'forfait', formuleId: 'b30' }, moyen: 'especes' });
  m.appliquer(E.choisirMoyen, 'mixte');
  assert.deepEqual(E.requeteDevis(m.lire()), { manque: 'especes' });
  m.appliquer(E.saisirEspeces, '300');
  assert.deepEqual(E.requeteDevis(m.lire()).corps, { studentId: 'e1', produit: { type: 'forfait', formuleId: 'b30' }, moyen: 'mixte', especesCents: 30000 });
});

test('les espèces tapées passent d\'un mixte à l\'autre, et s\'effacent ailleurs', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'mixte');
  m.appliquer(E.saisirEspeces, '300');
  m.appliquer(E.choisirMoyen, 'especes_cheques');
  assert.equal(m.lire().especesSaisie, '300');
  m.appliquer(E.choisirMoyen, 'carte');
  assert.equal(m.lire().especesSaisie, '');
});

test('tout changement périme le devis ; une réponse en retard est ignorée', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'carte');
  const v = m.lire().version;
  m.appliquer(E.devisRecu, v, { devis: DEVIS, jeton: 'j' });
  assert.equal(E.devisAJour(m.lire()), true);
  m.appliquer(E.choisirMoyen, 'cheques');
  assert.equal(E.devisAJour(m.lire()), false);
  m.appliquer(E.devisRecu, v, { devis: DEVIS, jeton: 'j' });
  assert.equal(m.lire().devis, null);
});

test('après l\'encaissement : panier remis à zéro, bande gardée, caisse sur la recherche', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'cheques');
  m.appliquer(E.choisirNombreCheques, 3);
  m.appliquer(E.devisRecu, m.lire().version, { devis: { ...DEVIS, moyen: 'cheques' }, jeton: 'j' });
  m.appliquer(E.paiementEtape, 'especes');
  const resultat = { devis: m.lire().devis, eleve: 'Léa MARTIN', declaration: { statut: 'enregistre', effets: [] } };
  m.appliquer(E.paiementAccepte, resultat);
  const e = m.lire();
  assert.equal(e.ecran, 'eleve');
  assert.equal(e.bande, resultat);
  assert.equal(e.eleve, null);
  assert.equal(e.produit, null);
  assert.equal(e.moyen, null);
  assert.equal(e.cheques.nombre, null);
  assert.equal(e.devis, null);
  assert.equal(e.paiement, null);
  assert.equal(e.utilisateur.nom, 'Camille', 'qui encaisse est gardé');

  // La bande reste quand on choisit l'élève suivant, et s'efface au prochain encaissement.
  m.appliquer(E.eleveCharge, ELEVE);
  assert.equal(m.lire().bande, resultat);
  m.appliquer(E.changerEleve);
  assert.equal(m.lire().bande, resultat);
  m.appliquer(E.paiementEtape, 'envoi');
  assert.equal(m.lire().bande, null);
});

test('carte prise mais encaissement incomplet, ou refus du CRM : l\'écran 7 reste, panier gardé', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'carte');
  m.appliquer(E.paiementAccepte, { devis: DEVIS, incomplet: 'Terminez-le depuis Stripe.' });
  assert.equal(m.lire().ecran, 'accepte');
  assert.equal(m.lire().produit.formuleId, 'b30');
  const m2 = panier();
  m2.appliquer(E.paiementAccepte, { devis: DEVIS, declaration: { statut: 'refus', message: 'non' } });
  assert.equal(m2.lire().ecran, 'accepte');
  assert.equal(m2.lire().bande, null);
});

test('« en attente » après une carte : bande (orange côté rendu), caisse prête', () => {
  const m = panier();
  m.appliquer(E.paiementAccepte, { devis: DEVIS, declaration: { statut: 'en_attente', effets: [] } });
  assert.equal(m.lire().ecran, 'eleve');
  assert.equal(m.lire().bande.declaration.statut, 'en_attente');
});

test('rappel des espèces à rendre après un abandon (espèces + carte refusée)', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'mixte');
  m.appliquer(E.saisirEspeces, '300');
  m.appliquer(E.devisRecu, m.lire().version, { devis: { ...DEVIS, moyen: 'mixte', especesCents: 30000, carteCents: 139000 }, jeton: 'j' });
  m.appliquer(E.paiementRefuse, 'Carte refusée');
  assert.equal(m.lire().ecran, 'refuse');
  m.appliquer(E.abandonner);
  assert.equal(m.lire().ecran, 'eleve');
  assert.equal(m.lire().especesARendre, 30000);
});

test('une erreur d\'envoi garde le panier et le moyen choisi', () => {
  const m = panier();
  m.appliquer(E.choisirMoyen, 'cheques');
  m.appliquer(E.paiementEtape, 'especes');
  m.appliquer(E.paiementErreur, 'Rien n\'est enregistré.');
  assert.equal(m.lire().ecran, 'panier');
  assert.equal(m.lire().moyen, 'cheques');
  assert.equal(m.lire().erreur, 'Rien n\'est enregistré.');
});
