const fs = require('fs');
const path = require('path');

/**
 * Vérifie si une valeur est strictement un objet (pas null, pas un tableau).
 * @param {any} val - La valeur à tester.
 * @returns {boolean}
 */
function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val);
}

/**
 * Valide un site individuel.
 * @param {object} site - Les données du site.
 * @param {number} index - L'index du site dans le tableau.
 * @returns {object} Un objet contenant les listes d'erreurs et d'avertissements.
 */
function validateSite(site, index) {
  const errors = [];
  const warnings = [];

  const siteId = `[Site #${index} ${site.url || 'URL Inconnue'}]`;

  if (!isObject(site)) {
    errors.push(`${siteId} N'est pas un objet JSON valide.`);
    return { errors, warnings };
  }

  // === 1. Vérification des champs requis ===
  if (typeof site.url !== 'string' || site.url.trim() === '') {
    errors.push(`${siteId} Champ requis 'url' manquant ou invalide (attendu: chaîne de caractères non vide).`);
  }
  if (typeof site.finalUrl !== 'string' || site.finalUrl.trim() === '') {
    errors.push(`${siteId} Champ requis 'finalUrl' manquant ou invalide (attendu: chaîne de caractères non vide).`);
  }
  if (!Number.isInteger(site.status)) {
    errors.push(`${siteId} Champ requis 'status' manquant ou invalide (attendu: nombre entier).`);
  }

  // === 2. Vérification des types pour les champs optionnels ===
  if (site.headers !== undefined && !isObject(site.headers)) {
    errors.push(`${siteId} Champ 'headers' invalide (attendu: objet).`);
  }
  if (site.setCookies !== undefined && !Array.isArray(site.setCookies)) {
    errors.push(`${siteId} Champ 'setCookies' invalide (attendu: tableau).`);
  }
  // tls peut être un objet ou null s'il s'agit d'un site en clair (HTTP)
  if (site.tls !== undefined && site.tls !== null && !isObject(site.tls)) {
    errors.push(`${siteId} Champ 'tls' invalide (attendu: objet ou null).`);
  }
  if (site.thirdPartyDomains !== undefined && !Array.isArray(site.thirdPartyDomains)) {
    errors.push(`${siteId} Champ 'thirdPartyDomains' invalide (attendu: tableau).`);
  }
  if (site.thirdPartyScripts !== undefined && !Array.isArray(site.thirdPartyScripts)) {
    errors.push(`${siteId} Champ 'thirdPartyScripts' invalide (attendu: tableau).`);
  }
  if (site.technologies !== undefined && !Array.isArray(site.technologies)) {
    errors.push(`${siteId} Champ 'technologies' invalide (attendu: tableau).`);
  }
  if (site.findings !== undefined && !Array.isArray(site.findings)) {
    errors.push(`${siteId} Champ 'findings' invalide (attendu: tableau).`);
  }
  if (site.metadata !== undefined && !isObject(site.metadata)) {
    errors.push(`${siteId} Champ 'metadata' invalide (attendu: objet).`);
  }

  // === 3. Avertissements non bloquants (Warnings) ===
  const allowedKeys = [
    'url', 'finalUrl', 'status', 'headers', 'setCookies', 'tls',
    'thirdPartyDomains', 'thirdPartyScripts', 'technologies', 'findings', 'metadata'
  ];

  // Détection de clés inattendues
  for (const key of Object.keys(site)) {
    if (!allowedKeys.includes(key)) {
      warnings.push(`${siteId} Clé non reconnue trouvée: '${key}'.`);
    }
  }

  // Conseils de bonnes pratiques
  if (site.status === 200 && site.headers === undefined) {
    warnings.push(`${siteId} L'objet 'headers' n'est pas défini, bien que le statut soit 200. Il est recommandé de documenter au moins les en-têtes de sécurité.`);
  }
  if (site.status === 200 && (!site.findings || site.findings.length === 0)) {
    warnings.push(`${siteId} La liste 'findings' est vide. Confirmez-vous qu'aucune vulnérabilité ou mauvaise pratique n'a été détectée ?`);
  }

  return { errors, warnings };
}

/**
 * Valide l'ensemble des données d'entrée.
 * @param {any} data - Les données parsées depuis le JSON.
 * @returns {object} Le rapport global de validation.
 */
function validateData(data) {
  const report = {
    totalSites: 0,
    errors: [],
    warnings: []
  };

  if (!Array.isArray(data)) {
    report.errors.push("Erreur critique : Le document racine du fichier JSON doit être un tableau.");
    return report;
  }

  report.totalSites = data.length;

  data.forEach((site, index) => {
    const { errors, warnings } = validateSite(site, index);
    report.errors.push(...errors);
    report.warnings.push(...warnings);
  });

  return report;
}

/**
 * Point d'entrée principal du script.
 */
function main() {
  const inputFilePath = path.join(__dirname, '../data/input.json');

  console.log(`\n🔍 Validation de ${inputFilePath}...\n`);

  if (!fs.existsSync(inputFilePath)) {
    console.error(`❌ Erreur: Le fichier est introuvable à l'emplacement ${inputFilePath}`);
    process.exit(1);
  }

  let fileContent;
  let jsonData;

  try {
    fileContent = fs.readFileSync(inputFilePath, 'utf-8');
  } catch (err) {
    console.error(`❌ Erreur lors de la lecture du fichier: ${err.message}`);
    process.exit(1);
  }

  try {
    jsonData = JSON.parse(fileContent);
  } catch (err) {
    console.error(`❌ Erreur de parsing JSON: La structure du fichier n'est pas un JSON valide. Détails : ${err.message}`);
    process.exit(1);
  }

  const report = validateData(jsonData);

  console.log("📊 --- RAPPORT DE VALIDATION ---");
  console.log(`Sites audités : ${report.totalSites}\n`);

  if (report.errors.length > 0) {
    console.log("❌ ERREURS TROUVÉES (bloquantes) :");
    report.errors.forEach(err => console.log(`  - ${err}`));
  } else {
    console.log("✅ Aucune erreur structurelle trouvée.");
  }

  console.log("");

  if (report.warnings.length > 0) {
    console.log("⚠️  AVERTISSEMENTS (non bloquants) :");
    report.warnings.forEach(warn => console.log(`  - ${warn}`));
  } else {
    console.log("✅ Aucun avertissement identifié.");
  }

  console.log("\n--- Fin du rapport ---\n");

  if (report.errors.length > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

// Support pour module require() et exécution CLI
if (require.main === module) {
  main();
}

module.exports = { validateData };
