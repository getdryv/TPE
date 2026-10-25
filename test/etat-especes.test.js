// test/etat-especes.test.js — le comptage dans l'état : bouton bloqué tant que le compte n'est pas juste,
// part espèces d'un mixte, trop-perçu rendu, reprise de chèque, retour arrière.

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let E; let X; let R; let K;
test.before(async () => {
  E = await importerPublic('etat.js');
  X = await importerPublic('etat-especes.js');
  R = await importerPublic('reprise.js');
  K = await importerPublic('compteur-especes.js');
});

const TUILE = { formuleId: 'b20', nom: 'Permis B 20 h', prixCents: 104900, cheques: { max: 3, prixPlusieursFoisCents: 104900 } };
const CHEQUES = [
  { id: 'c1', numero: '0004521', montantCents: 25000, dueOn: '2026-11-15', libelle: 'forfait Permis B', versement: { rang: 2, sur: 3 } },
  { id: 'c2', numero: '0004522', montantCents: 25000, dueOn: '2026-12-15', libelle: 'forfait Permis B', versement: null },
];
const eleve = (reprises) => ({
  eleve: { id: 'e1', prenom: 'Inès', nom: 'BENALI', email: '' }, cascade: { forfaits: [TUILE], indices: {} },
  heuresSupp: { packs: [] }, prepa: { mode: 'rien' }, ...(reprises ? { reprises: { cheques: CHEQUES } } : {}),
});
function panier(moyen, reprises = false) {
  const m = E.creerMagasin();
  m.appliquer(E.sessionOuverte, { mode: 'catalogue', utilisateur: { nom: 'Sarah', role: 'secretary' } }, true);
  m.appliquer(E.eleveCharge, eleve(reprises));
  m.appliquer(E.choisirFormule, 'forfait', 'b20');
  if (moyen) m.appliquer(E.choisirMoyen, moyen);
  return m;
}
const devis = (m, d) => m.appliquer(E.devisRecu, m.lire().version, { devis: { id: 'd', lignes: [], promo: null, chequesCents: 0, echeancier: null, ...d }, jeton: 'j' });

test('espèces seules : le comptage ne redemande pas le devis ; bouton prêt seulement si le compte est PILE juste', () => {
  const m = panier('especes');
  devis(m, { totalCents: 104900, especesCents: 104900, carteCents: 0, moyen: 'especes' });
  const v = m.lire().version;
  assert.equal(X.compteVisible(m.lire()), true);
  assert.equal(X.comptageAccepte(m.lire()), false, 'rien compté');
  m.appliquer(X.saisirCoupure, 5000, 20);
  m.appliquer(X.saisirCoupure, 2000, 2);
  assert.equal(m.lire().version, v, 'le prix ne dépend pas des billets');
  assert.equal(X.analyseEspeces(m.lire()).statut, 'manque');
  m.appliquer(X.saisirCoupure, 500, 1);
  m.appliquer(X.ajouterCoupure, 200);
  m.appliquer(X.ajouterCoupure, 200);
  assert.equal(X.comptageAccepte(m.lire()), true);
  assert.equal(E.devisAJour(m.lire()), true);
  m.appliquer(X.ajouterCoupure, 100);
  assert.equal(X.comptageAccepte(m.lire()), false, 'un euro de trop : bloqué');
});

test('trop donné : « C’est rendu » retire les coupures rendues et débloque', () => {
  const m = panier('especes');
  devis(m, { totalCents: 104900, especesCents: 104900, carteCents: 0, moyen: 'especes' });
  for (const [c, n] of [[5000, 20], [2000, 2], [1000, 1], [500, 1], [200, 2], [100, 1]]) m.appliquer(X.saisirCoupure, c, n);
  assert.equal(K.texteRendu(X.analyseEspeces(m.lire()).rendre.pieces).replace(/ /g, ' '), '1 billet de 10 € et 1 pièce de 1 €');
  m.appliquer(X.tropPercuRendu);
  assert.equal(X.comptageAccepte(m.lire()), true);
  assert.deepEqual(m.lire().comptage, { 5000: 20, 2000: 2, 500: 1, 200: 2 });
});

test('appoint : le bouton nomme la coupure à rendre', () => {
  assert.equal(K.libelleRendu({ 5000: 1 }).replace(/ /g, ' '), 'Billet de 50 € rendu');
  assert.equal(K.libelleRendu({ 200: 1 }).replace(/ /g, ' '), 'Pièce de 2 € rendue');
  assert.equal(K.libelleRendu({ 1000: 1, 100: 1 }), 'C\'est rendu');
});

test('espèces + chèques : le comptage FIXE la part espèces du devis', () => {
  const m = panier('especes_cheques');
  assert.equal(E.requeteDevis(m.lire()).manque, 'especes');
  m.appliquer(X.saisirCoupure, 5000, 4);
  m.appliquer(X.saisirCoupure, 2000, 5);
  assert.equal(m.lire().especesSaisie, '300');
  m.appliquer(E.choisirNombreCheques, 2);
  assert.equal(E.requeteDevis(m.lire()).corps.especesCents, 30000);
  m.appliquer(E.choisirMoyen, 'mixte');
  assert.equal(m.lire().especesSaisie, '300', 'l’argent compté reste quand on passe à espèces + carte');
});

test('retour arrière : revenir à la prestation garde le comptage ; tout effacer le vide ; abandon = rendre ce qui est compté', () => {
  const m = panier('especes');
  m.appliquer(X.saisirCoupure, 5000, 3);
  m.appliquer(X.revenirPrestation);
  assert.equal(X.feuilleAffichee(m.lire()), false);
  assert.deepEqual(m.lire().comptage, { 5000: 3 });
  m.appliquer(X.revenirComptage);
  assert.equal(X.feuilleAffichee(m.lire()), true);
  assert.equal(E.abandonner(m.lire()).especesARendre, 15000);
  m.appliquer(X.toutEffacer);
  assert.deepEqual(m.lire().comptage, {});
});

test('pendant l’encaissement, le comptage est figé', () => {
  const m = panier('especes');
  m.appliquer(E.paiementEtape, 'especes');
  m.appliquer(X.saisirCoupure, 5000, 3);
  assert.deepEqual(m.lire().comptage, {});
});

test('reprise : onglet seulement avec des chèques ; espèces ou carte ; devis par identifiants ; phrases', () => {
  const sans = panier(null);
  assert.equal(sans.appliquer(E.choisirOnglet, 'reprise').onglet, 'forfait', 'pas de chèques : pas d’onglet');
  const m = panier('especes_cheques', true);
  m.appliquer(E.choisirOnglet, 'reprise');
  assert.equal(m.lire().moyen, null, 'un moyen interdit en reprise est retiré');
  assert.equal(E.requeteDevis(m.lire()).manque, 'cheque');
  m.appliquer(E.cocherChequeReprise, 'c2');
  m.appliquer(E.cocherChequeReprise, 'c1');
  assert.deepEqual(m.lire().produit.chequeIds, ['c1', 'c2'], 'ordre de la liste');
  assert.equal(m.appliquer(E.choisirMoyen, 'mixte').moyen, null, 'pas de mélange');
  m.appliquer(E.choisirMoyen, 'especes');
  assert.deepEqual(E.requeteDevis(m.lire()).corps, { studentId: 'e1', produit: { type: 'reprise_cheque', chequeIds: ['c1', 'c2'] }, moyen: 'especes' });
  assert.deepEqual(R.numerosCoches(m.lire()), ['n° 0004521', 'n° 0004522']);
  assert.match(R.noteReprise(m.lire()), /les chèques n° 0004521, n° 0004522 passent «\u00a0Rendu à l'élève\u00a0» et sortent du prochain dépôt/);
  assert.equal(R.sousTitreCheque(CHEQUES[0]), 'À déposer le 15 novembre · forfait Permis B, versement 2 sur 3');
  m.appliquer(E.cocherChequeReprise, 'c2');
  assert.deepEqual(m.lire().produit.chequeIds, ['c1']);
  m.appliquer(E.choisirOnglet, 'forfait');
  assert.equal(m.lire().moyen, null, 'quitter la reprise remet le moyen à choisir');
});

test('devis pas encore arrivé : jamais « juste » à tort, et le bouton reste fermé', () => {
  const m = panier('especes');
  for (const [c, n] of [[5000, 20], [2000, 2], [500, 1], [200, 2]]) m.appliquer(X.saisirCoupure, c, n);
  assert.equal(X.analyseEspeces(m.lire()).statut, 'juste', 'comparé au prix affiché de la tuile');
  assert.equal(X.comptageAccepte(m.lire()), false, 'sans devis à jour, rien ne part');
  m.appliquer(X.ajouterCoupure, 1000);
  assert.equal(X.analyseEspeces(m.lire()).statut, 'trop');
});

test('jamais « n° sans numéro » : le chèque de 250 € du 15 novembre', async () => {
  const T = await importerPublic('bordereau-texte.js');
  const B = await importerPublic('bande.js');
  const net = (t) => t.replace(/[\u00a0\u202f]/g, ' ');
  assert.equal(T.designationCheque({ numero: '0004521' }), 'n° 0004521');
  assert.equal(net(T.designationCheque({ numero: null, montantCents: 25000, dueOn: '2026-11-15' })), 'de 250 € du 15 novembre');
  assert.equal(net(B.texteChequesRendus([T.designationCheque({ numero: '', montantCents: 25000, dueOn: '2026-11-15' })])), 'Rendez-lui le chèque de 250 € du 15 novembre');
  const e = T.encadre({ especesCents: 25000, carteCents: 0, chequesCents: 0, chequesRendus: [''], chequesRendusTextes: ['de 250\u00a0€ du 15 novembre'] });
  assert.equal(net(e.lignes[0]), 'Chèque de 250 € du 15 novembre rendu à l\'élève, remplacé par ces espèces.');
  assert.ok(!T.encadre({ especesCents: 25000, carteCents: 0, chequesCents: 0, chequesRendus: [''] }).lignes[0].includes('n° sans'));
  assert.match(K.texteRendu({ 5000: 1 }), /billet/);
});

test('arrondi : 60 € pour 59,90 € dans la tolérance de l’agence, encaissable sans rien rendre', async () => {
  const C = await importerPublic('especes-compte.js');
  const T = await importerPublic('bordereau-texte.js');
  const net = (t) => t.replace(/[  ]/g, ' ');
  assert.deepEqual(C.analyser({ 5000: 1, 1000: 1 }, 5990, 100), { compte: 6000, statut: 'arrondi', manque: 0, trop: 0, arrondi: 10, rendre: null });
  assert.equal(C.analyser({ 5000: 1, 1000: 1 }, 5990, 0).statut, 'trop', '0 = désactivé');
  assert.equal(C.analyser({ 5000: 1, 2000: 1 }, 5990, 100).statut, 'trop', '10,10 € de trop : au-delà, on rend');
  const m = E.creerMagasin();
  m.appliquer(E.sessionOuverte, { mode: 'catalogue', utilisateur: { nom: 'Sarah', role: 'secretary' } }, true);
  m.appliquer(E.eleveCharge, { ...eleve(false), especes: { toleranceArrondiCents: 100 }, cascade: { forfaits: [{ ...TUILE, prixCents: 5990 }], indices: {} } });
  m.appliquer(E.choisirFormule, 'forfait', 'b20');
  m.appliquer(E.choisirMoyen, 'especes');
  devis(m, { totalCents: 5990, especesCents: 5990, carteCents: 0, moyen: 'especes' });
  m.appliquer(X.saisirCoupure, 5000, 1);
  m.appliquer(X.saisirCoupure, 1000, 1);
  assert.equal(X.comptageAccepte(m.lire()), true);
  assert.equal(net(K.texteArrondi(X.analyseEspeces(m.lire()).arrondi)), '0,10 € d\'arrondi laissé par l\'élève');
  m.appliquer(E.choisirMoyen, 'mixte');
  assert.equal(X.toleranceArrondi(m.lire()), 0, 'un mixte fixe sa part au centime');
  const env = T.enveloppe({ especesCents: 5990, arrondiCents: 10, especesRecuesCents: 6000 });
  assert.deepEqual([env.libelle, env.cents, net(env.detail)], ['Espèces dans cette enveloppe', 6000, 'dont 0,10 € d\'arrondi laissé par l\'élève · Montant encaissé : 59,90 €']);
  assert.equal(T.enveloppe({ especesCents: 5990 }).detail, null);
});
