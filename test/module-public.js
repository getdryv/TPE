// test/module-public.js
//
// Les fichiers de `public/js` sont des modules ES servis tels quels au
// navigateur, alors que le dépôt est en CommonJS (`"type": "commonjs"`) : sous
// node, ils seraient lus comme du CommonJS et `export` échouerait. Ce crochet
// de chargement les déclare modules ES, pour les SEULS tests, sans rien
// changer à ce qui est servi.

const fs = require('node:fs');
const path = require('node:path');
const { registerHooks } = require('node:module');
const { pathToFileURL, fileURLToPath } = require('node:url');

const DOSSIER = pathToFileURL(path.join(__dirname, '..', 'public', 'js') + path.sep).href;
let pose = false;

function poserCrochet() {
  if (pose) return;
  pose = true;
  registerHooks({
    load(url, context, suivant) {
      if (!url.startsWith(DOSSIER)) return suivant(url, context);
      return { format: 'module', source: fs.readFileSync(fileURLToPath(url), 'utf8'), shortCircuit: true };
    },
  });
}

/** `await importerPublic('etat.js')` : le module de `public/js`, chargé comme dans le navigateur. */
async function importerPublic(nom) {
  poserCrochet();
  return import(DOSSIER + nom);
}

module.exports = { importerPublic };
