// test/panier-affiche.test.js — ce que le panier affiche en attendant le devis,
// et ce que la bande dit de l'e-mail (revue UX, passe F1).

const test = require('node:test');
const assert = require('node:assert/strict');
const { importerPublic } = require('./module-public');

let A;
let E;
let B;
test.before(async () => {
  A = await importerPublic('panier-affiche.js');
  E = await importerPublic('etat.js');
  B = await importerPublic('bande.js');
});

const ELEVE = {
  eleve: { id: 'e1', prenom: 'Léa', nom: 'MARTIN', email: 'lea@exemple.fr' },
  cascade: { forfaits: [
    { formuleId: 'b30', nom: 'Permis B 30 h', prixCents: 169000, promo: null, cheques: { max: 3, prixPlusieursFoisCents: 176000 } },
    { formuleId: 'promo', nom: 'Promo', prixCents: 100000, promo: { prixRemiseCents: 90000, remiseCents: 10000 }, cheques: { max: 1 } },
  ], indices: {} },
  heuresSupp: { packs: [] },
  prepa: { mode: 'rien' },
};

const devis = (totalCents, extra = {}) => ({
  devis: { lignes: [{ libelle: 'Permis B 30 h', montantCents: totalCents, nature: 'produit' }], totalCents, carteCents: 0, chequesCents: 0, ...extra },
  jeton: 'j',
});

function panier(moyen) {
  let e = E.eleveCharge(E.creerEtat(), ELEVE);
  e = E.choisirFormule(e, 'forfait', 'b30');
  return moyen ? E.choisirMoyen(e, moyen) : e;
}

test('formule touchée, moyen pas encore choisi : le prix comptant de la tuile, jamais « — »', () => {
  const e = panier(null);
  assert.deepEqual(A.prixCatalogue(e), { libelle: 'Permis B 30 h', totalCents: 169000, versements: 1 });
  assert.equal(A.devisAffiche(null, e).devis, null);
});

test('la promotion en cours fait le prix comptant affiché', () => {
  const e = E.choisirFormule(E.eleveCharge(E.creerEtat(), ELEVE), 'forfait', 'promo');
  assert.equal(A.prixCatalogue(e).totalCents, 90000);
});

test('3 chèques choisis, devis pas encore arrivé : le prix en plusieurs fois du catalogue', () => {
  const e = E.choisirNombreCheques(panier('cheques'), 3);
  assert.deepEqual(A.prixCatalogue(e), { libelle: 'Permis B 30 h', totalCents: 176000, versements: 3 });
});

test('montant de chèque refusé : le total du dernier devis reste affiché', () => {
  let e = E.choisirNombreCheques(panier('cheques'), 3);
  e = E.devisRecu(e, e.version, devis(176000));
  const memo = A.retenirDevis(null, e);
  e = E.saisirMontantCheque(e, 0, '99999');
  e = E.devisRefuse(e, e.version, 'Les montants saisis dépassent le total', 'montants');
  assert.equal(e.devisChamp, 'montants');
  const affiche = A.devisAffiche(memo, e);
  assert.equal(affiche.devis.totalCents, 176000);
  assert.equal(affiche.aJour, false);
});

test('autre moyen ou autre nombre : l\'ancien devis ne s\'affiche plus', () => {
  let e = E.choisirNombreCheques(panier('cheques'), 3);
  e = E.devisRecu(e, e.version, devis(176000));
  const memo = A.retenirDevis(null, e);
  assert.equal(A.devisAffiche(memo, E.choisirNombreCheques(e, 2)).devis, null);
  assert.equal(A.devisAffiche(memo, E.choisirMoyen(e, 'carte')).devis, null);
});

test('le reste ne vaut que pour les espèces tapées quand le devis a été émis', () => {
  let e = E.saisirEspeces(panier('mixte'), '300');
  e = E.devisRecu(e, e.version, devis(169000, { carteCents: 139000 }));
  const memo = A.retenirDevis(null, e);
  assert.equal(A.resteAffiche(memo, e, A.devisAffiche(memo, e)), 139000);
  const autre = E.saisirEspeces(e, '400');
  assert.equal(A.resteAffiche(memo, autre, A.devisAffiche(memo, autre)), null);
  assert.equal(A.texteReste('mixte', '1 390 €'), 'Reste 1 390 € par carte');
  assert.equal(A.texteReste('especes_cheques', '1 460 €'), 'Reste 1 460 € en chèques');
});

test('prix sous « N chèques » : comptant pour 1, en plusieurs fois pour 2 et 3', () => {
  const p = { type: 'forfait', formuleId: 'b30' };
  assert.equal(A.prixPourNombre(ELEVE, p, 1), 169000);
  assert.equal(A.prixPourNombre(ELEVE, p, 3), 176000);
  assert.equal(A.prixPourNombre(ELEVE, { type: 'forfait', formuleId: 'promo' }, 2), null);
});

test('bande : « E-mail envoyé » ou « non envoyé » selon le CODE de l\'effet, jamais le texte', () => {
  const decl = (code, texte = 'Ticket de paiement envoyé') => ({ statut: 'enregistre', effets: [{ code, texte }] });
  assert.deepEqual(B.etatEmail(decl('ticket_envoye')), { texte: 'E-mail envoyé', alerte: false });
  assert.deepEqual(B.etatEmail(decl('ticket_echec')), { texte: 'E-mail non envoyé', alerte: true });
  assert.deepEqual(B.etatEmail(decl('ticket_sans_adresse')), { texte: 'E-mail non envoyé', alerte: true });
  assert.equal(B.etatEmail(decl('ticket')), null);
  // N2 : le CRM n'attend l'e-mail que 400 ms ; au-delà, il est annoncé en cours, sans alerte.
  assert.deepEqual(B.etatEmail(decl('ticket_en_cours')), { texte: 'E-mail en cours d\'envoi', alerte: false });
  assert.equal(B.etatEmail(null), null);
});

test('N1 : le bouton bloqué désigne le vrai champ fautif', () => {
  assert.equal(A.libelleCorrection('especes_cheques', 'especes'), 'Corrigez le montant en espèces');
  assert.equal(A.libelleCorrection('mixte', 'especes'), 'Corrigez le montant en espèces');
  assert.equal(A.libelleCorrection('especes_cheques', 'montants'), 'Corrigez l\'échéancier');
  assert.equal(A.libelleCorrection('cheques', null), 'Corrigez l\'échéancier');
  assert.equal(A.libelleCorrection('carte', null), 'Prix indisponible');
});

test('A2 : l’erreur de montant va sous le premier chèque saisi ; les autres restent sous l’échéancier', () => {
  assert.equal(A.chequeFautif('montants', ['2000', null, '']), 0);
  assert.equal(A.chequeFautif('montants', ['', ' 900 ']), 1);
  assert.equal(A.chequeFautif('montants', ['', null]), null);
  assert.equal(A.chequeFautif('avances', ['2000']), null);
  assert.equal(A.chequeFautif(null, undefined), null);
});

// Bug de production du 17/10 : moyen Chèques choisi, aucun nombre, puis une
// autre formule (20 h → 30 h en promo) : le total suivait, les prix sous
// « N chèques » restaient ceux de la formule d'avant.
test('changer de formule sous Chèques redessine les prix sous « N chèques »', () => {
  const eleve = {
    ...ELEVE,
    cascade: { forfaits: [
      { formuleId: 'a20', nom: 'Auto 20 h', prixCents: 99900, promo: null, cheques: { max: 3, prixPlusieursFoisCents: 104900 } },
      { formuleId: 'a30', nom: 'Auto 30 h', prixCents: 154900, promo: { prixRemiseCents: 149900, remiseCents: 5000 }, cheques: { max: 3, prixPlusieursFoisCents: 159900 } },
    ], indices: {} },
  };
  let s = E.eleveCharge(E.creerEtat(), eleve);
  s = E.choisirFormule(s, 'forfait', 'a20');
  s = E.choisirMoyen(s, 'cheques');
  const zone = (st) => A.cleZoneCheques(st, { proposes: E.chequesProposes(st), nombre: E.nombreCheques(st), ech: null, verrou: false, ui: {} });
  const avant = zone(s);
  assert.deepEqual(A.sousNombres(s, 3).map((t) => t.replace(/\s/g, ' ')), ['999 €', '1 049 €', '1 049 €']);
  s = E.choisirFormule(s, 'forfait', 'a30');
  assert.equal(E.nombreCheques(s), null);
  assert.deepEqual(A.sousNombres(s, 3).map((t) => t.replace(/\s/g, ' ')), ['1 499 €', '1 599 €', '1 599 €']);
  assert.notEqual(zone(s), avant, 'la zone doit être reconstruite : ses prix ont changé');
});
