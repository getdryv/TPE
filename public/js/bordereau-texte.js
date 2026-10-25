// ─── Les textes du bordereau d'espèces, PURS ─────────────────────────────────
//
// Le CRM envoie les DONNÉES du bordereau (numéro, heure enregistrée, coupures,
// répartition) ; ici, les phrases imprimées : le montant en lettres, la date
// à la seconde, l'encadré d'un paiement mixte ou d'une reprise de chèque.
// Aucun accès au DOM ni au réseau : ce module se teste sous node.

import { eurosCourts } from './format.js';
import { designation } from './especes-compte.js';

const UNITES = ['zéro', 'un', 'deux', 'trois', 'quatre', 'cinq', 'six', 'sept', 'huit', 'neuf', 'dix',
  'onze', 'douze', 'treize', 'quatorze', 'quinze', 'seize'];
const DIZAINES = { 2: 'vingt', 3: 'trente', 4: 'quarante', 5: 'cinquante', 6: 'soixante' };

/** 0 à 99, orthographe traditionnelle (traits d'union sous cent, « et un »). */
function moinsDeCent(n) {
  if (n <= 16) return UNITES[n];
  if (n < 20) return `dix-${UNITES[n - 10]}`;
  const d = Math.floor(n / 10);
  const u = n % 10;
  if (d === 7 || d === 9) {
    const base = d === 7 ? 'soixante' : 'quatre-vingt';
    const reste = 10 + u;
    if (d === 7 && u === 1) return 'soixante et onze';
    return `${base}-${moinsDeCent(reste)}`;
  }
  if (d === 8) return u === 0 ? 'quatre-vingts' : `quatre-vingt-${UNITES[u]}`;
  if (u === 0) return DIZAINES[d];
  if (u === 1) return `${DIZAINES[d]} et un`;
  return `${DIZAINES[d]}-${UNITES[u]}`;
}

/** 0 à 999. `finale` : « cents » et « quatre-vingts » ne prennent le s qu'en fin de nombre. */
function moinsDeMille(n, finale) {
  const c = Math.floor(n / 100);
  const r = n % 100;
  let texte = '';
  if (c === 1) texte = 'cent';
  else if (c > 1) texte = `${UNITES[c]} cent${r === 0 && finale ? 's' : ''}`;
  if (r === 0) return texte || 'zéro';
  let fin = moinsDeCent(r);
  if (!finale && fin === 'quatre-vingts') fin = 'quatre-vingt';
  return texte ? `${texte} ${fin}` : fin;
}

/** Un entier en lettres : « mille quarante-neuf », « deux cents », « un million ». */
export function nombreEnLettres(n) {
  if (!Number.isInteger(n) || n < 0) return '';
  if (n === 0) return 'zéro';
  const millions = Math.floor(n / 1000000);
  const milliers = Math.floor((n % 1000000) / 1000);
  const reste = n % 1000;
  const parties = [];
  if (millions) parties.push(`${millions === 1 ? 'un' : moinsDeMille(millions, true)} million${millions > 1 ? 's' : ''}`);
  if (milliers) parties.push(milliers === 1 ? 'mille' : `${moinsDeMille(milliers, false)} mille`);
  if (reste) parties.push(moinsDeMille(reste, true));
  return parties.join(' ');
}

const capitale = (t) => (t ? t.charAt(0).toLocaleUpperCase('fr-FR') + t.slice(1) : t);

/** 104900 → « Mille quarante-neuf euros » ; 30050 → « Trois cents euros et cinquante centimes ». */
export function montantEnLettres(cents) {
  if (!Number.isInteger(cents) || cents < 0) return '';
  const e = Math.floor(cents / 100);
  const c = cents % 100;
  const euros = e > 0 ? `${nombreEnLettres(e)} euro${e > 1 ? 's' : ''}` : '';
  const centimes = c > 0 ? `${nombreEnLettres(c)} centime${c > 1 ? 's' : ''}` : '';
  return capitale([euros, centimes].filter(Boolean).join(' et ') || 'zéro euro');
}

const PARTIES = new Intl.DateTimeFormat('fr-FR', {
  timeZone: 'Europe/Paris', weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});

/** « Samedi 24 octobre 2026 à 10:15:42 », heure de Paris À LA SECONDE (celle du CRM). */
export function dateHeure(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const p = Object.fromEntries(PARTIES.formatToParts(d).map((x) => [x.type, x.value]));
  return capitale(`${p.weekday} ${p.day} ${p.month} ${p.year} à ${p.hour}:${p.minute}:${p.second}`);
}

const MOIS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];

/** « 2026-11-05 » → « 5 novembre ». */
export function jourEtMois(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso || ''));
  return m ? `${Number(m[3])} ${MOIS[Number(m[2]) - 1]}` : '';
}

/** « Billet de 50 € », « Pièce de 0,50 € ». */
export function libelleLigne(coupureCents) {
  return designation(coupureCents, 1).replace(/^1\u00a0b/, 'B').replace(/^1\u00a0p/, 'P');
}

/**
 * L'encadré sous le tableau, ou null : la part payée autrement (paiement
 * mixte), ou le chèque rendu (reprise). `{ titre, lignes: string[] }`.
 */
export function encadre(b) {
  if (Array.isArray(b.chequesRendus) && b.chequesRendus.length) {
    const n = b.chequesRendus.length;
    const numeros = b.chequesRendus.map((x) => `n° ${x}`).join(', ');
    return {
      titre: n > 1 ? `Reprise de ${n} chèques` : 'Reprise de chèque',
      lignes: [`${n > 1 ? 'Chèques' : 'Chèque'} ${numeros} rendu${n > 1 ? 's' : ''} à l'élève, remplacé${n > 1 ? 's' : ''} par ces espèces.`],
    };
  }
  if (b.carteCents > 0 || b.chequesCents > 0) {
    const lignes = [`${eurosCourts(b.especesCents)} en espèces, joints à ce bordereau.`];
    if (b.carteCents > 0) lignes.push(`${eurosCourts(b.carteCents)} par carte bancaire.`);
    if (b.chequesCents > 0) {
      const ch = Array.isArray(b.cheques) ? b.cheques : [];
      const detail = ch.map((c, i) => `${eurosCourts(c.montantCents)} ${i === 0 ? 'à déposer ' : ''}le ${jourEtMois(c.dueOn)}`).join(', ');
      const nb = ch.length || 1;
      lignes.push(`${eurosCourts(b.chequesCents)} en ${nb} chèque${nb > 1 ? 's' : ''}${detail ? ` (${detail})` : ''}, rangé${nb > 1 ? 's' : ''} avec les chèques.`);
    }
    return { titre: `Paiement mixte : ${eurosCourts(b.totalCents)} au total`, lignes };
  }
  return null;
}

/** Le nombre total de billets et de pièces. */
export const nombreDeCoupures = (coupures) => (coupures || []).reduce((s, c) => s + c.nombre, 0);
