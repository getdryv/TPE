// routes/agence.js
const express = require('express');
const { resoudreAgence, slugDeLaRequete } = require('../lib/agences');
const { configurationCrm } = require('../lib/crm');

const router = express.Router();

/**
 * GET /api/agence?slug=…
 *
 * De quoi la caisse s'annonce : le nom de l'agence pour laquelle elle encaisse.
 * Écrire « Simply Permis » en dur dans la page était juste tant qu'il n'y avait
 * qu'une agence ; affiché dans le CRM de Getdryv, c'était faux et inquiétant
 * pour qui encaisse.
 *
 * `crmUrl` : l'adresse publique du CRM, pour le lien « Ouvrez la caisse depuis
 * le CRM », la création de fiche hors cadre, et l'origine des messages que la
 * page accepte du cadre parent. Une adresse, jamais un secret.
 *
 * Ne renvoie jamais d'erreur : sans nom, la caisse garde son titre générique et
 * encaisse quand même. Aucun secret ne sort d'ici.
 */
router.get('/api/agence', async (req, res) => {
  const agence = await resoudreAgence(slugDeLaRequete(req));
  res.json({
    name: agence?.agencyName ?? null,
    logoUrl: agence?.logoUrl ?? null,
    crmUrl: configurationCrm().baseUrl || null,
  });
});

module.exports = router;
