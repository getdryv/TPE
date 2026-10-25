// test/devis.test.js — le devis signé, côté caisse (contrat Encaisser § 3.1).
//
// Les vecteurs sont ceux du contrat et de ARCHITECTURE.md § 2 : le CRM rejoue
// les mêmes. Si l'un d'eux casse, les deux côtés ne se comprennent plus.

const test = require('node:test');
const assert = require('node:assert/strict');
const { signer, lire, CONTEXTE_DEVIS, CONTEXTE_JETON } = require('../lib/signature');
const { devisCoherent, lireDevis, sansCarte } = require('../lib/devis');

const SECRET = 'secret-de-test';
const MAINTENANT = 1792224100; // entre iat et exp des vecteurs chèques

const CHEQUES = {"v":1,"id":"55555555-5555-4555-8555-555555555555","a":"simply-permis-marseille","s":"33333333-3333-4333-8333-333333333333","u":"11111111-1111-4111-8111-111111111111","p":{"t":"forfait","f":"44444444-4444-4444-8444-444444444444"},"l":"Permis B 30 heures","tot":176000,"cb":0,"esp":0,"mo":"cheques","chq":176000,"ech":[["2026-10-19",58800,"2026-10-19"],["2026-11-19",58600,"2026-11-19"],["2026-12-21",58600,"2026-12-21"]],"iat":1792224000,"exp":1792225800};
const ESPECES_CHEQUES = {"v":1,"id":"66666666-6666-4666-8666-666666666666","a":"simply-permis-marseille","s":"33333333-3333-4333-8333-333333333333","u":"11111111-1111-4111-8111-111111111111","p":{"t":"forfait","f":"44444444-4444-4444-8444-444444444444"},"l":"Permis B 30 heures","tot":176000,"cb":0,"esp":30000,"mo":"especes_cheques","chq":146000,"ech":[["2026-11-17",73000,"2026-11-17"],["2026-12-17",73000,"2026-12-17"]],"iat":1792224000,"exp":1792225800};
const MIXTE = {"v":1,"id":"22222222-2222-4222-8222-222222222222","a":"simply-permis-marseille","s":"33333333-3333-4333-8333-333333333333","u":"11111111-1111-4111-8111-111111111111","p":{"t":"forfait","f":"44444444-4444-4444-8444-444444444444"},"l":"Permis B 20 heures","tot":99900,"cb":69900,"esp":30000,"mo":"mixte","pr":{"c":"RENTREE50","r":5000},"iat":1790000000,"exp":1790001800};
const JETON_CAISSE = {"v":1,"u":"11111111-1111-4111-8111-111111111111","a":"simply-permis-marseille","iat":1790000000,"exp":1790043200};

const copie = (o) => JSON.parse(JSON.stringify(o));

test('vecteur chèques ×3 : signature, longueur, relecture', () => {
  const jeton = signer(CONTEXTE_DEVIS, CHEQUES, SECRET);
  assert.equal(jeton.split('.')[1], 'deXvOapo2uPqe7TbneXhyRisOuxIU1A4SkRvfcOeZSM');
  assert.equal(jeton.length, 651);
  const lu = lireDevis(jeton, { slug: 'simply-permis-marseille', exigerExpiration: true, maintenant: MAINTENANT, secret: SECRET });
  assert.equal(lu.ok, true);
  assert.deepEqual(lu.devis, CHEQUES);
});

test('vecteur espèces + 2 chèques : signature, longueur, relecture', () => {
  const jeton = signer(CONTEXTE_DEVIS, ESPECES_CHEQUES, SECRET);
  assert.equal(jeton.split('.')[1], 'qzKgKmCDKJwzXWJaYIJ94uoNUq2x4sCjdlRdJbBBCe8');
  assert.equal(jeton.length, 622);
  assert.equal(lireDevis(jeton, { maintenant: MAINTENANT, secret: SECRET }).ok, true);
});

test('vecteurs historiques (ARCHITECTURE.md § 2) : toujours valides', () => {
  const jetonCaisse = signer(CONTEXTE_JETON, JETON_CAISSE, SECRET);
  assert.equal(jetonCaisse, 'eyJ2IjoxLCJ1IjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTExMTExMTExMTExIiwiYSI6InNpbXBseS1wZXJtaXMtbWFyc2VpbGxlIiwiaWF0IjoxNzkwMDAwMDAwLCJleHAiOjE3OTAwNDMyMDB9.GunJX2bPau0F2degz-SEC1hnKPiPZKAHFQD6IaMxQHs');
  const jeton = signer(CONTEXTE_DEVIS, MIXTE, SECRET);
  assert.equal(jeton.split('.')[1], 'J5pzKqhJH9QlrKXYy64cSu-CmvyBT3Gib6Nm4crkUbA');
  assert.equal(jeton.length, 536);
  assert.equal(lireDevis(jeton, { secret: SECRET }).ok, true);
  // Un devis ne se relit pas comme un jeton de caisse, ni l'inverse.
  assert.equal(lire(CONTEXTE_JETON, jeton, SECRET), null);
});

test('les trois moyens historiques restent acceptés tels quels', () => {
  assert.equal(devisCoherent(MIXTE), true);
  assert.equal(devisCoherent({ ...MIXTE, mo: 'carte', esp: 0, cb: 99900 }), true);
  assert.equal(devisCoherent({ ...MIXTE, mo: 'especes', esp: 99900, cb: 0 }), true);
});

test('chq ou ech sur un moyen historique : refusé', () => {
  assert.equal(devisCoherent({ ...MIXTE, chq: 0 }), false);
  assert.equal(devisCoherent({ ...MIXTE, mo: 'especes', esp: 99900, cb: 0, ech: [] }), false);
});

test('chèques : chq incohérent refusé', () => {
  assert.equal(devisCoherent({ ...copie(CHEQUES), chq: 175000 }), false);
  assert.equal(devisCoherent({ ...copie(CHEQUES), chq: undefined }), false);
  assert.equal(devisCoherent({ ...copie(ESPECES_CHEQUES), chq: 176000 }), false);
});

test('chèques : part carte ou espèces interdite', () => {
  assert.equal(devisCoherent({ ...copie(CHEQUES), cb: 100, tot: 176100 }), false);
  assert.equal(devisCoherent({ ...copie(CHEQUES), esp: 100, tot: 176100 }), false);
  assert.equal(devisCoherent({ ...copie(ESPECES_CHEQUES), esp: 0, chq: 176000 }), false);
});

test('échéancier vide, absent, ou trop long : refusé', () => {
  assert.equal(devisCoherent({ ...copie(CHEQUES), ech: [] }), false);
  assert.equal(devisCoherent({ ...copie(CHEQUES), ech: undefined }), false);
  // Au-delà de la borne de sûreté (24 chèques, 23 après des espèces) : refusé. Le vrai maximum est signé par le CRM.
  const trop = copie(CHEQUES);
  trop.ech = Array.from({ length: 25 }, () => ['2026-10-19', 100, '2026-10-19']);
  assert.equal(devisCoherent(trop), false);
  const tropApresEspeces = copie(ESPECES_CHEQUES);
  tropApresEspeces.ech = Array.from({ length: 24 }, () => ['2026-11-17', 100, '2026-11-17']);
  assert.equal(devisCoherent(tropApresEspeces), false);
});

test('échéancier : somme, minimum, ordre, avance et dates', () => {
  const avec = (ech) => ({ ...copie(CHEQUES), ech });
  assert.equal(devisCoherent(avec([['2026-10-19', 58800, '2026-10-19'], ['2026-11-19', 58600, '2026-11-19'], ['2026-12-21', 58500, '2026-12-21']])), false, 'somme');
  assert.equal(devisCoherent({ ...avec([['2026-10-19', 175950, '2026-10-19'], ['2026-11-19', 50, '2026-11-19']]), tot: 176000 }), false, 'moins de 1 €');
  assert.equal(devisCoherent(avec([['2026-11-19', 58800, '2026-11-19'], ['2026-10-19', 58600, '2026-10-19'], ['2026-12-21', 58600, '2026-12-21']])), false, 'ordre');
  assert.equal(devisCoherent(avec([['2026-10-19', 58800, '2026-10-19'], ['2026-10-19', 58600, '2026-11-19'], ['2026-12-21', 58600, '2026-12-21']])), false, 'même jour');
  assert.equal(devisCoherent(avec([['2026-10-19', 58800, '2026-10-19'], ['2026-11-20', 58600, '2026-11-19'], ['2026-12-21', 58600, '2026-12-21']])), false, 'recul');
  assert.equal(devisCoherent(avec([['2026-10-19', 58800, '2026-10-19'], ['2026-11-31', 58600, '2026-11-31'], ['2026-12-21', 58600, '2026-12-21']])), false, 'date impossible');
  assert.equal(devisCoherent(avec([['2026-10-19', 58800, '2026-10-19'], ['2026-11-05', 58600, '2026-11-19'], ['2026-12-21', 58600, '2026-12-21']])), true, 'avance');
});

test('moyen inconnu : refusé', () => {
  assert.equal(devisCoherent({ ...copie(CHEQUES), mo: 'virement' }), false);
});

test('sansCarte : espèces, chèques, espèces + chèques ; jamais la carte', () => {
  assert.equal(sansCarte(CHEQUES), true);
  assert.equal(sansCarte(ESPECES_CHEQUES), true);
  assert.equal(sansCarte({ ...MIXTE, mo: 'especes', cb: 0 }), true);
  assert.equal(sansCarte(MIXTE), false);
  assert.equal(sansCarte({ ...MIXTE, mo: 'carte' }), false);
});

test('onglet Examen : heures en plus (hp ≤ h) acceptées, au-delà refusées', () => {
  const prepa = (p) => ({ ...MIXTE, mo: 'carte', esp: 0, cb: 99900, pr: undefined, p });
  assert.equal(devisCoherent(prepa({ t: 'prepa', h: 6, acc: true, rf: false, sc: 5990, hp: 2 })), true);
  assert.equal(devisCoherent(prepa({ t: 'prepa', h: 6, acc: true, rf: true, sc: 5990 })), true);
  assert.equal(devisCoherent(prepa({ t: 'prepa', h: 2, acc: true, rf: false, sc: 5990, hp: 3 })), false);
  assert.equal(devisCoherent(prepa({ t: 'prepa', h: 2, acc: true, rf: false, sc: 5990, hp: 1.5 })), false);
});
