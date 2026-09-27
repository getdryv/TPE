// lib/declaration.js
//
// ======================= Déclaration des paiements au CRM =======================
//
// Le CRM tient une section « Paiements » sur la fiche élève : les chèques et les
// heures d'examen y figurent depuis longtemps, la carte au comptoir n'y laissait
// rien. Retrouver ce qu'un élève avait réglé demandait d'ouvrir le tableau de
// bord Stripe et d'y chercher un nom — celui-là même qui a pu être tapé de
// travers ici.
//
// Deux déclarations coexistent :
//   - HISTORIQUE (mode secours) : `POST /api/internal/tpe-payment`, un montant
//     et un élève éventuel ;
//   - CAISSE (mode catalogue) : `POST /api/internal/caisse/encaissement`, le
//     devis signé relu DANS le paiement Stripe. Le CRM revérifie la signature,
//     compare le montant débité à `cb` et enregistre l'achat.
// Le paiement porte ses métadonnées `devis_*` ou non : c'est ce qui aiguille
// (`declarerDepuisPaiement`), où que la déclaration parte.
//
// ─── Pourquoi déclarer depuis la CAPTURE, et pas depuis le webhook ──────────
// Parce que la capture est le seul moment dont CE serveur est certain : c'est
// lui qui la demande, et à cet instant il connaît l'agence, le montant
// réellement pris et l'élève choisi à la caisse.
//
// Le webhook ne pouvait pas porter cette responsabilité. Il n'est vérifié que
// par STRIPE_WEBHOOK_SECRET, une variable UNIQUE du service, alors que chaque
// agence encaisse sur SON compte Stripe : la migration qui a ouvert le TPE aux
// agences (20260759000000) note explicitement qu'aucun secret de webhook n'est
// réglé par agence. Une agence ouverte depuis le CRM n'a donc pas de
// destination webhook qui pointe ici, et ses paiements ne seraient jamais
// déclarés.
//
// Le webhook déclare quand même, en FILET : il rattrape le seul cas que la
// capture manque — le paiement déjà capturé quand la caisse l'interroge (état
// « capture »), où la page saute l'appel de capture. Les deux chemins peuvent
// donc annoncer le même paiement, et c'est sans conséquence : le CRM refuse le
// doublon (identifiant du paiement, ou du devis) et répond « déjà enregistré ».
//
// ─── Une panne du CRM n'empêche JAMAIS un encaissement ──────────────────────
// Toute défaillance — CRM éteint, lent, mal configuré — se termine dans le
// journal de ce serveur, puis en RELANCES à +30 s, +2 min et +10 min. Au pire,
// un paiement manque dans le CRM ; il est dans Stripe, et se rattrape. Aucune
// fonction d'ici ne rejette : appelées sans `await`, une promesse rejetée
// ferait tomber le processus (`unhandledRejection`) — une caisse morte pour un
// CRM enrhumé.

const { appelerCrm, configurationCrm, DELAIS_MS } = require('./crm');
const { slugParDefaut } = require('./agences');
const { lireDevis, recomposerDepuisMetadonnees, porteUnDevis } = require('./devis');

// Plus long que la recherche d'élèves (1,2 s) : personne n'attend cette
// requête, alors qu'un caissier attend ses suggestions.
const CRM_DECLARATION_TIMEOUT_MS = 4000;

// ─── Relances ───────────────────────────────────────────────────────────────
let delaisRelanceMs = [30 * 1000, 2 * 60 * 1000, 10 * 60 * 1000];
const relancesEnCours = new Set();

/** Réservé aux tests : raccourcit les délais de relance. */
function configurerRelances(delais) {
  delaisRelanceMs = delais;
}

/**
 * Planifie les relances d'une déclaration restée sans réponse. `tenter` rend
 * `true` quand le CRM a enfin répondu (oui ou non : un refus ne se relance
 * pas). Une seule série de relances par clé, même si la capture et le webhook
 * échouent tous deux.
 */
function planifierRelances(cle, tenter, rang = 0) {
  if (rang === 0 && relancesEnCours.has(cle)) return;
  if (rang >= delaisRelanceMs.length) {
    relancesEnCours.delete(cle);
    console.error(`[CRM] déclaration ${cle} abandonnée après ${rang} relances : à rattacher à la main.`);
    return;
  }
  relancesEnCours.add(cle);
  const minuterie = setTimeout(async () => {
    let repondu = false;
    try {
      repondu = await tenter();
    } catch (err) {
      console.warn(`[CRM] relance ${cle} :`, err.message);
    }
    if (repondu) relancesEnCours.delete(cle);
    else planifierRelances(cle, tenter, rang + 1);
  }, delaisRelanceMs[rang]);
  // Une relance en attente ne doit pas empêcher le processus de s'arrêter.
  if (typeof minuterie.unref === 'function') minuterie.unref();
}

/** Réservé aux tests : clés dont les relances sont planifiées. */
const relancesPlanifiees = () => [...relancesEnCours];

// ─── Déclaration historique (mode secours) ───────────────────────────────────

/**
 * Annonce au CRM un paiement réellement encaissé, par le chemin historique.
 *
 * `slugSecours` sert quand le paiement ne porte pas son agence : les paiements
 * créés avant cet ajout, ou l'agence par défaut dont le slug peut être vide.
 *
 * Rend `true` si le CRM a répondu (ou s'il n'y avait rien à déclarer), `false`
 * s'il est resté muet — auquel cas les relances sont planifiées.
 */
async function declarerPaiementAuCrm(pi, slugSecours, { relancer = true } = {}) {
  try {
    // Rien de configuré : le TPE fonctionne comme avant, sans rien déclarer.
    if (!configurationCrm().configure) return true;

    const meta = pi?.metadata || {};
    // Un compte Stripe peut servir d'autres applications de la maison — la
    // boutique en ligne, l'achat d'heures. Seul le comptoir se déclare ici.
    if (meta.source !== 'terminal') return true;

    const agencySlug = (meta.agence || slugSecours || slugParDefaut() || '').trim();
    // Sans agence, le CRM ne saurait pas qui a le droit de voir la ligne : il
    // refuserait, et l'appel n'aurait servi qu'à remplir les journaux.
    if (!agencySlug) return true;

    // Le montant CAPTURÉ, jamais l'autorisé : entre les deux, un encaissement
    // peut très bien ne pas aboutir.
    const amountCents = Number(pi.amount_received || pi.amount || 0);
    if (!Number.isInteger(amountCents) || amountCents <= 0) return true;

    // La date de Stripe plutôt que l'heure d'ici : elle est la même quel que
    // soit le chemin de déclaration, donc deux annonces du même paiement
    // racontent la même chose.
    const paidAt = pi.created ? new Date(pi.created * 1000).toISOString() : null;

    const r = await appelerCrm('/api/internal/tpe-payment', {
      corps: {
        agencySlug,
        stripePaymentIntentId: pi.id,
        amountCents,
        // Vide quand le nom a été tapé à la main : le CRM enregistre alors le
        // paiement sans le rattacher, ce qui vaut mieux que de le perdre.
        studentId: meta.studentId || null,
        payerName: meta.fullName || null,
        payerEmail: meta.email || null,
        paidAt,
        // Motif facultatif du mode secours (additif, § 7).
        ...(meta.motif ? { motif: meta.motif } : {}),
        // Qui a encaissé en secours (compte du jeton) : le CRM l'ajoute au motif.
        ...(meta.auteurId ? { auteurUserId: meta.auteurId } : {}),
      },
      delaiMs: CRM_DECLARATION_TIMEOUT_MS,
    });
    if (r.indisponible) {
      if (relancer) planifierRelances(`tpe:${pi.id}`, () => declarerPaiementAuCrm(pi, slugSecours, { relancer: false }));
      return false;
    }
    if (!r.ok) console.warn(`[CRM] paiement ${pi.id} non enregistré : HTTP ${r.status}`);
    return true;
  } catch (err) {
    console.warn('[CRM] déclaration du paiement indisponible :', err.name || err.message);
    return false;
  }
}

// ─── Déclaration de caisse (mode catalogue) ──────────────────────────────────

/** Met la réponse du CRM dans la forme promise à la page (§ 10.2). */
function formeDeclaration(r) {
  if (r.indisponible) return { statut: 'en_attente', effets: [] };
  if (!r.ok) {
    return { statut: 'refus', effets: [], message: r.error, ...(r.code ? { code: r.code } : {}), status: r.status };
  }
  const d = r.data || {};
  return {
    statut: d.statut || 'enregistre',
    effets: Array.isArray(d.effets) ? d.effets : [],
    ...(d.liens ? { liens: d.liens } : {}),
    ...(d.encaissementId ? { encaissementId: d.encaissementId } : {}),
  };
}

/**
 * Déclare un encaissement de caisse COMPLET (carte capturée, ou espèces
 * seules). Attendue au plus 5 s ; ne rejette jamais.
 *
 * `relancer` : vrai après une capture (l'argent est pris, il faut que le CRM
 * finisse par le savoir) ; faux pour les espèces seules, où une absence de
 * réponse est une ERREUR affichée — la secrétaire a les billets en main.
 */
async function declarerEncaissementCaisse(slug, { devis, stripePaymentIntentId, montantCarteCents, paidAt }, { relancer = true, devisId } = {}) {
  try {
    const corps = {
      agencySlug: slug,
      devis,
      stripePaymentIntentId: stripePaymentIntentId || null,
      montantCarteCents,
      paidAt: paidAt || null,
    };
    const r = await appelerCrm('/api/internal/caisse/encaissement', { corps, delaiMs: DELAIS_MS.declaration });
    const declaration = formeDeclaration(r);
    if (declaration.statut === 'refus') {
      console.error(`[CRM] encaissement ${stripePaymentIntentId || devisId || ''} refusé : ${declaration.message}`);
    }
    if (declaration.statut === 'en_attente' && relancer) {
      planifierRelances(`caisse:${devisId || stripePaymentIntentId}`, async () => {
        const nouvelle = await declarerEncaissementCaisse(slug, corps, { relancer: false, devisId });
        return nouvelle.statut !== 'en_attente';
      });
    }
    return declaration;
  } catch (err) {
    console.warn('[CRM] déclaration de caisse indisponible :', err.name || err.message);
    return { statut: 'en_attente', effets: [] };
  }
}

/**
 * Déclare un paiement Stripe capturé, par le bon chemin : devis dans les
 * métadonnées → déclaration de caisse ; sinon → chemin historique. Sert au
 * webhook et à la capture du mode secours. Ne rejette jamais.
 */
async function declarerDepuisPaiement(pi, slugSecours) {
  try {
    const meta = pi?.metadata || {};
    if (!porteUnDevis(meta)) return declarerPaiementAuCrm(pi, slugSecours);
    if (meta.source !== 'terminal' || !configurationCrm().configure) return true;

    const jeton = recomposerDepuisMetadonnees(meta);
    const lecture = lireDevis(jeton);
    if (!lecture.ok) {
      console.error(`[CRM] paiement ${pi.id} : devis illisible dans les métadonnées, déclaration impossible.`);
      return true;
    }
    const declaration = await declarerEncaissementCaisse(
      lecture.devis.a,
      {
        devis: jeton,
        stripePaymentIntentId: pi.id,
        // Le montant CAPTURÉ : c'est lui que le CRM compare à `cb`.
        montantCarteCents: Number(pi.amount_received || 0),
        paidAt: pi.created ? new Date(pi.created * 1000).toISOString() : null,
      },
      { devisId: lecture.devis.id }
    );
    return declaration.statut !== 'en_attente';
  } catch (err) {
    console.warn('[CRM] déclaration du paiement indisponible :', err.name || err.message);
    return false;
  }
}

module.exports = {
  declarerPaiementAuCrm,
  declarerEncaissementCaisse,
  declarerDepuisPaiement,
  configurerRelances,
  relancesPlanifiees,
};
