// routes/caisse.js
//
// ======================= La caisse au catalogue =======================
//
// Contrat : ARCHITECTURE.md § 4 et § 10.2. La secrétaire ne tape plus de
// montant : elle touche une formule, le CRM renvoie un DEVIS SIGNÉ, et ce
// serveur débite EXACTEMENT sa part carte (`cb`). Aucun montant venu du
// navigateur n'atteint Stripe par ces routes : le seul qui y parvient est
// celui relu dans un devis dont la signature a été vérifiée ici.
//
// Toutes exigent l'en-tête `x-caisse-jeton` (qui encaisse), vérifié ici sans
// appel au CRM, puis transmis au CRM qui fait autorité.

const express = require('express');
const { exigerAgence, slugEffectif } = require('../lib/agences');
const { appelerCrm, configurationCrm, DELAIS_MS } = require('../lib/crm');
const { exigerJeton } = require('../lib/jeton');
const { lireDevis, decouperPourMetadonnees, recomposerDepuisMetadonnees } = require('../lib/devis');
const { sessionCaisse } = require('../lib/session');
const { lancerEncaissement, capturerSiBesoin } = require('../lib/terminal');
const { declarerEncaissementCaisse } = require('../lib/declaration');

const router = express.Router();

const MESSAGES_DEVIS = {
  invalide: 'Devis invalide : redemandez le prix.',
  expire: 'Devis expiré : redemandez le prix pour le même panier.',
  autre_agence: 'Ce devis vaut pour une autre agence.',
};
const STATUTS_DEVIS = { invalide: 400, expire: 410, autre_agence: 403 };

/** Relit le devis du corps, ou répond (410 `devis_expire` si périmé). */
function exigerDevis(res, jeton, slug) {
  const lecture = lireDevis(jeton, { slug, exigerExpiration: true });
  if (lecture.ok) return lecture.devis;
  res.status(STATUTS_DEVIS[lecture.motif]).json({ error: MESSAGES_DEVIS[lecture.motif], code: `devis_${lecture.motif}` });
  return null;
}

/** Sans CRM configuré ni slug d'agence, pas de catalogue : c'est le secours. */
function exigerCatalogue(res, slug) {
  if (configurationCrm().configure && slug) return true;
  res.status(503).json({ crm: 'indisponible' });
  return false;
}

// Une valeur de métadonnée Stripe tient en 500 caractères.
const court = (v, max = 200) => (v || '').toString().trim().slice(0, max);

/**
 * GET /api/caisse/session?slug=…
 * `{ mode: 'catalogue' | 'secours' | 'identification_requise', utilisateur, raison }`.
 * Toujours 200 : le mode EST la réponse (§ 7).
 */
router.get('/api/caisse/session', async (req, res) => {
  res.json(await sessionCaisse(req));
});

/**
 * POST /api/caisse/devis { slug, studentId, produit, moyen, especesCents? }
 *
 * Relaie la demande au CRM, qui DÉCIDE du prix. Seuls les champs du contrat
 * passent ; l'agence et le jeton sont ajoutés ici. Refus du CRM relayés avec
 * leur code HTTP et leur message ; CRM muet : 503 `{ crm: 'indisponible' }`.
 */
router.post('/api/caisse/devis', async (req, res) => {
  const slug = slugEffectif(req);
  if (!exigerCatalogue(res, slug)) return;
  const auth = exigerJeton(req, res, slug);
  if (!auth) return;

  const { studentId, produit, moyen, especesCents } = req.body || {};
  const r = await appelerCrm('/api/internal/caisse/devis', {
    corps: {
      agencySlug: slug,
      jeton: auth.jeton,
      studentId,
      produit,
      moyen,
      ...(especesCents !== undefined ? { especesCents } : {}),
    },
    delaiMs: DELAIS_MS.devis,
  });
  if (r.indisponible) return res.status(503).json({ crm: 'indisponible' });
  if (!r.ok) return res.status(r.status).json({ error: r.error, ...(r.code ? { code: r.code } : {}) });
  return res.json({ devis: r.data?.devis ?? null, jeton: r.data?.jeton ?? null });
});

/**
 * POST /api/caisse/paiement { slug, lecteur, devis, email?, nomComplet? }
 *
 * Envoie au lecteur la part carte d'un devis vérifié (§ 4.2). Le montant du
 * paiement est `devis.cb`, et RIEN d'autre : aucun champ du corps n'y
 * contribue. Le devis voyage dans les métadonnées du paiement, découpé, pour
 * que la capture et le webhook le relisent sans rien demander au navigateur.
 */
router.post('/api/caisse/paiement', async (req, res) => {
  try {
    const slug = slugEffectif(req);
    if (!exigerCatalogue(res, slug)) return;
    if (!exigerJeton(req, res, slug)) return;
    const devis = exigerDevis(res, req.body?.devis, slug);
    if (!devis) return;

    if (devis.mo === 'especes' || devis.cb < 50) {
      return res.status(400).json({ error: "Ce devis ne comporte pas de part carte.", code: 'devis_sans_carte' });
    }
    const lecteur = court(req.body?.lecteur);
    if (!lecteur) return res.status(400).json({ error: 'Aucun lecteur sélectionné.' });

    const morceaux = decouperPourMetadonnees(req.body.devis);
    if (!morceaux) return res.status(400).json({ error: MESSAGES_DEVIS.invalide, code: 'devis_invalide' });

    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const nomComplet = court(req.body.nomComplet);
    const email = court(req.body.email);
    const pi = await lancerEncaissement(agence, {
      montant: devis.cb,
      lecteur,
      nomComplet,
      email,
      idempotencyKey: req.headers['idempotency-key'],
      metadata: {
        source: 'terminal',
        agence: agence.slug || '',
        studentId: devis.s,
        devisId: devis.id,
        libelle: devis.l,
        // Pour le seul reçu Stripe : ils ne décident de rien.
        fullName: nomComplet,
        email,
        ...morceaux,
      },
    });
    res.json({ paymentIntentId: pi.id, lecteur });
  } catch (err) {
    console.error('paiement (caisse) :', err.message);
    // Le message de Stripe est plus utile que le nôtre : il distingue un
    // lecteur hors ligne d'un lecteur déjà occupé par un autre encaissement.
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/caisse/capture { slug, paymentIntentId }
 *
 * Capture (ou constate « déjà capturé »), puis déclare au CRM en attendant au
 * plus 5 s (§ 4.3). Le devis est relu DANS le paiement, jamais dans le corps.
 *
 * L'argent pris, la réponse est TOUJOURS un succès : un CRM muet donne
 * `declaration.statut = 'en_attente'` et des relances en arrière-plan, un
 * refus du CRM est rapporté tel quel. Jamais d'échec affiché pour un paiement
 * pris.
 *
 * Jeton : signature et agence exigées, expiration tolérée — la carte est déjà
 * autorisée sur un devis vérifié ; refuser ici laisserait l'autorisation
 * ouverte.
 */
router.post('/api/caisse/capture', async (req, res) => {
  let etape = 'lecture';
  try {
    const slug = slugEffectif(req);
    if (!exigerCatalogue(res, slug)) return;
    if (!exigerJeton(req, res, slug, { tolererExpiration: true })) return;
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const piId = court(req.body?.paymentIntentId);
    if (!piId) return res.status(400).json({ error: 'Paiement non précisé.' });

    const pi = await agence.stripe.paymentIntents.retrieve(piId);
    const jetonDevis = recomposerDepuisMetadonnees(pi.metadata);
    const lecture = lireDevis(jetonDevis, { slug });
    // Vérifié AVANT de prendre l'argent : un paiement dont on ne pourrait pas
    // déclarer l'achat n'est pas capturé (rien n'est débité, la page propose
    // de réessayer ou d'abandonner).
    if (!lecture.ok) {
      return res.status(409).json({ error: "Ce paiement ne porte pas de devis valide pour cette agence : rien n'a été débité." });
    }

    etape = 'capture';
    const capture = await capturerSiBesoin(agence, pi);
    if (!capture.ok) return res.status(409).json({ error: capture.message });

    etape = 'declaration';
    const pris = capture.pi;
    const montant = Number(pris.amount_received || pris.amount || 0);
    const declaration = await declarerEncaissementCaisse(
      lecture.devis.a,
      {
        devis: jetonDevis,
        stripePaymentIntentId: pris.id,
        montantCarteCents: montant,
        paidAt: pris.created ? new Date(pris.created * 1000).toISOString() : null,
      },
      { devisId: lecture.devis.id }
    );
    res.json({ success: true, montant, declaration });
  } catch (err) {
    console.error(`capture (caisse, ${etape}) :`, err.message);
    // Après la capture, seule la déclaration a pu lever (elle ne le fait
    // jamais) : on ne dit pas « échec » d'un paiement pris.
    if (etape === 'declaration') {
      return res.json({ success: true, montant: null, declaration: { statut: 'en_attente', effets: [] } });
    }
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/caisse/especes { slug, devis }
 *
 * Espèces seules : aucun terminal, déclaration attendue. Ici un CRM muet est
 * une ERREUR (503) : rien n'est enregistré, la secrétaire a les billets en
 * main et doit le savoir — jamais un « en attente » silencieux. Un nouvel
 * essai avec le même devis est sans risque (le CRM répond « déjà »).
 */
router.post('/api/caisse/especes', async (req, res) => {
  const slug = slugEffectif(req);
  if (!exigerCatalogue(res, slug)) return;
  if (!exigerJeton(req, res, slug)) return;
  const devis = exigerDevis(res, req.body?.devis, slug);
  if (!devis) return;
  if (devis.mo !== 'especes') {
    return res.status(400).json({ error: "Ce devis comporte une part carte : passez par le lecteur.", code: 'devis_avec_carte' });
  }

  const declaration = await declarerEncaissementCaisse(
    devis.a,
    { devis: req.body.devis, stripePaymentIntentId: null, montantCarteCents: 0, paidAt: new Date().toISOString() },
    { relancer: false, devisId: devis.id }
  );
  if (declaration.statut === 'en_attente') {
    return res.status(503).json({
      crm: 'indisponible',
      error: "Le CRM ne répond pas : rien n'est enregistré. Réessayez, ou rendez les espèces.",
      declaration,
    });
  }
  if (declaration.statut === 'refus') {
    return res.status(declaration.status || 400).json({
      error: declaration.message,
      ...(declaration.code ? { code: declaration.code } : {}),
      declaration,
    });
  }
  res.json({ declaration });
});

module.exports = router;
