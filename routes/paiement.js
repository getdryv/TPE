// routes/paiement.js
//
// ======================= Encaissement historique (mode secours) =======================
//
// Le formulaire de toujours : prénom, nom, e-mail, MONTANT SAISI. C'est le
// seul chemin où un montant venu du navigateur atteint Stripe, et il doit le
// rester : quand le CRM est éteint, lent ou non configuré, c'est lui qui permet
// d'encaisser quand même (ARCHITECTURE.md § 7). Il est donc FERMÉ dès que le
// CRM répond (403 `secours_indisponible`, `lib/secours.js`). Ajouts : un
// `motif` facultatif et l'auteur (jeton), portés en métadonnées et déclarés.
//
// `/api/lecteurs`, `/api/paiement/etat` et `/api/paiement/annuler` servent
// aussi le mode catalogue : le pilotage du lecteur est le même.

const express = require('express');
const { exigerAgence } = require('../lib/agences');
const { listerLecteurs, lancerEncaissement, etatDuPaiement, capturer, annuler } = require('../lib/terminal');
const { declarerDepuisPaiement } = require('../lib/declaration');
const { autoriserSecours } = require('../lib/secours');

const router = express.Router();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Lecteurs de l'agence, pour que la caisse sache lequel solliciter. */
router.get('/api/lecteurs', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;
    res.json({ lecteurs: await listerLecteurs(agence) });
  } catch (err) {
    console.error('liste des lecteurs :', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Lance un encaissement au montant SAISI (mode secours).
 *
 * Montant en CENTIMES. Capture manuelle : voir `lib/terminal.js`.
 */
router.post('/api/paiement', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const { montant, email, firstName, lastName, lecteur, studentId, motif } = req.body;

    if (!Number.isInteger(montant) || montant <= 0) {
      return res.status(400).json({ error: 'Montant invalide.' });
    }
    if (!lecteur) {
      return res.status(400).json({ error: 'Aucun lecteur sélectionné.' });
    }

    // Le montant saisi n'est permis que si le CRM ne peut pas décider du prix
    // (voir `lib/secours.js`) : refusé ici, pas seulement caché dans la page.
    const droit = await autoriserSecours(req);
    if (!droit.ok) return res.status(droit.status).json(droit.corps);

    const fName = (firstName || '').toString().trim();
    const lName = (lastName || '').toString().trim();
    const fullName = [fName, lName].filter(Boolean).join(' ').trim();
    const emailSafe = (email || '').toString().trim();
    // Pourquoi on encaisse hors catalogue (CRM indisponible…). Facultatif,
    // borné : une métadonnée Stripe tient en 500 caractères.
    const motifSafe = (motif || '').toString().trim().slice(0, 200);

    // L'élève, seulement s'il a été CHOISI dans les suggestions : la caisse
    // l'oublie dès que le nom est retouché à la main. On ne garde qu'un
    // identifiant en bonne et due forme — un reste de saisie n'a rien à faire
    // dans les métadonnées d'un paiement, et le CRM le refuserait de toute
    // façon. C'est lui qui vérifie ensuite que l'élève est bien de l'agence :
    // rattacher un paiement au mauvais élève est le seul vrai danger ici.
    const eleve = (studentId || '').toString().trim();
    const eleveSafe = UUID.test(eleve) ? eleve : '';

    const pi = await lancerEncaissement(agence, {
      montant,
      lecteur,
      nomComplet: fullName,
      email: emailSafe,
      idempotencyKey: req.headers['idempotency-key'],
      metadata: {
        source: 'terminal',
        agence: agence.slug || '',
        firstName: fName,
        lastName: lName,
        fullName,
        email: emailSafe,
        // Ce qui rattachera le paiement à une fiche du CRM. Porté par le
        // paiement lui-même et non par une table d'ici : la déclaration au
        // CRM part de deux endroits, et Stripe est le seul état que les deux
        // partagent.
        studentId: eleveSafe,
        ...(motifSafe ? { motif: motifSafe } : {}),
        // Qui a encaissé, quand la caisse le sait (jeton encore valable).
        ...(droit.auteurId ? { auteurId: droit.auteurId } : {}),
      },
    });

    res.json({ paymentIntentId: pi.id, lecteur });
  } catch (err) {
    console.error('paiement :', err.message);
    // Le message de Stripe est plus utile que le nôtre : il distingue un
    // lecteur hors ligne d'un lecteur déjà occupé par un autre encaissement.
    res.status(500).json({ error: err.message });
  }
});

/**
 * Où en est l'encaissement ? Interrogée en boucle par la caisse ; états
 * `attente`, `autorise`, `echec`, `capture` (voir `lib/terminal.js`).
 */
router.get('/api/paiement/etat', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const pi = (req.query.pi || '').toString();
    if (!pi) return res.status(400).json({ error: 'Paiement non précisé.' });

    const lecteur = (req.query.lecteur || '').toString();
    res.json(await etatDuPaiement(agence, pi, lecteur));
  } catch (err) {
    console.error('état du paiement :', err.message);
    res.status(500).json({ error: err.message });
  }
});

/** Capture : c'est ici, et seulement ici, que l'argent part. */
router.post('/api/paiement/capture', async (req, res) => {
  try {
    const agence = await exigerAgence(req, res);
    if (!agence) return;

    const { paymentIntentId } = req.body;
    if (!paymentIntentId) return res.status(400).json({ error: 'Paiement non précisé.' });

    const capture = await capturer(agence, paymentIntentId);
    res.json({ success: true, montant: capture.amount, id: capture.id });

    // L'argent est pris et la caisse a sa réponse : le CRM est prévenu APRÈS,
    // sans être attendu. Volontairement sans `await` — voir
    // `lib/declaration.js`. Un paiement de caisse (devis dans ses métadonnées)
    // capturé par ici est déclaré par le bon chemin.
    declarerDepuisPaiement(capture, agence.slug);
  } catch (err) {
    console.error('capture :', err.message);
    res.status(500).json({ error: err.message });
  }
});

/** Annule l'encaissement en cours : efface l'écran du lecteur et le paiement. */
router.post('/api/paiement/annuler', async (req, res) => {
  const agence = await exigerAgence(req, res);
  if (!agence) return;

  const { paymentIntentId, lecteur } = req.body;
  await annuler(agence, { paymentIntentId, lecteur });
  res.json({ ok: true });
});

module.exports = router;
