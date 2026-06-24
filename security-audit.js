/**
 * Script Assembleur Final : security-audit.js
 * 
 * Ce script orchestre l'ensemble de la chaîne d'audit local.
 * Interface CLI intégrée, gestion d'erreurs et architecture modulaire.
 */

const fs = require('fs');
const path = require('path');

// Chargement des modules depuis lib/
const { validateData } = require('./lib/validate-input');
const { analyzeHeaders } = require('./lib/analyze-headers');
const { parseCookies } = require('./lib/parse-cookies');
const { analyzeCookies } = require('./lib/analyze-cookies');
const { analyzeTls } = require('./lib/analyze-tls');
const { analyzeThirdParties } = require('./lib/analyze-third-parties');
const { analyzeScripts } = require('./lib/analyze-scripts');
const { analyzeTechnologies } = require('./lib/analyze-technologies');
const { calculateScore } = require('./lib/score-site');
const { buildRecommendations } = require('./lib/build-recommendations');
const { buildExecutiveSummary } = require('./lib/build-executive-summary');
const { renderHtmlReport } = require('./lib/render-report');

// Gestion d'erreur homogène
function fatalError(message, details = null) {
    console.error(`\n❌ ERREUR CRITIQUE : ${message}`);
    if (details) {
        console.error(`   Détails: ${details}`);
    }
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Interface de Ligne de Commande (CLI) native (0 dépendance)
// ---------------------------------------------------------------------------

function parseArgs() {
    const args = process.argv.slice(2);
    // Configuration par défaut
    const config = {
        input: path.join(__dirname, 'data', 'input.json'),
        output: path.join(__dirname, 'output', 'rapport-securite-local.html'),
        help: false
    };

    let positionalIndex = 0;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg === '--help' || arg === '-h') {
            config.help = true;
            return config;
        }

        // Support de `--input=chemin` ou `--input chemin`
        if (arg.startsWith('--input=')) {
            config.input = path.resolve(arg.substring(8));
        } else if (arg === '--input') {
            config.input = path.resolve(args[++i]);
        } 
        // Support de `--output=chemin` ou `--output chemin`
        else if (arg.startsWith('--output=')) {
            config.output = path.resolve(arg.substring(9));
        } else if (arg === '--output') {
            config.output = path.resolve(args[++i]);
        } 
        // Support des arguments positionnels (ex: le 1er arg libre est l'input)
        else if (!arg.startsWith('-')) {
            if (positionalIndex === 0) {
                config.input = path.resolve(arg);
                positionalIndex++;
            }
        }
    }

    return config;
}

function displayHelp() {
    console.log(`
🛡️  SECURITY-AUDIT-CLI (Générateur de rapport statique hors-ligne)
===================================================================

Utilisation : 
  node security-audit.js [options] [fichier_entree]

Options :
  -h, --help             Affiche cet écran d'aide.
  --input=<chemin>       Spécifie le fichier JSON source contenant les données de l'audit.
                         (Défaut : ./data/input.json)
  --output=<chemin>      Spécifie le chemin complet du rapport HTML final à générer.
                         (Défaut : ./output/rapport-securite-local.html)

Exemples d'utilisation :
  1. Lancement standard (utilise les valeurs par défaut) :
     $ node security-audit.js

  2. En passant le fichier JSON directement en paramètre positionnel :
     $ node security-audit.js ./data/mon-audit.json

  3. En personnalisant complètement les chemins via les drapeaux dédiés :
     $ node security-audit.js --input=./clients/foo/data.json --output=./rapports/foo.html
`);
    process.exit(0);
}

// ---------------------------------------------------------------------------
// Fonction d'Orchestration Principale
// ---------------------------------------------------------------------------

function main() {
    // Lecture des options CLI
    const config = parseArgs();

    if (config.help) {
        displayHelp();
    }

    console.log("🚀 Démarrage de l'orchestrateur d'audit de sécurité local...");

    // 1. Lecture des données brutes
    if (!fs.existsSync(config.input)) {
        fatalError(`Le fichier d'entrée est introuvable.`, `Chemin cherché : ${config.input}`);
    }

    let rawData;
    let sitesData;
    try {
        rawData = fs.readFileSync(config.input, 'utf8');
        sitesData = JSON.parse(rawData);
    } catch (e) {
        fatalError("Impossible de lire ou parser le fichier JSON.", e.message);
    }

    // 2. Validation du schéma d'entrée
    console.log("🔍 Étape 1 : Validation de la structure des données d'entrée...");
    const validationReport = validateData(sitesData);
    if (validationReport.errors && validationReport.errors.length > 0) {
        fatalError("Des erreurs structurelles bloquantes empêchent l'analyse.", validationReport.errors.join('\n   - '));
    }
    console.log(`✅ Validation réussie (${sitesData.length} sites à traiter)`);

    const finalReports = [];

    // 3. Traitement itératif pour chaque site
    for (const site of sitesData) {
        console.log(`\n⚙️  Étape 2 : Analyse pour : ${site.url || 'URL Inconnue'}`);
        
        try {
            let allFindings = [];

            // a. Analyse des En-têtes (Headers)
            const headersFindings = analyzeHeaders(site.headers);
            allFindings.push(...headersFindings);

            // b. Parsing et Analyse des Cookies
            const parsedCookies = parseCookies(site.setCookies || []);
            const cookiesFindings = analyzeCookies(parsedCookies);
            allFindings.push(...cookiesFindings);

            // c. Analyse du Chiffrement (TLS)
            const auditDate = (site.metadata && site.metadata.auditDate) ? site.metadata.auditDate : new Date();
            const tlsResult = analyzeTls(site.tls, auditDate);
            allFindings.push(...tlsResult.findings);

            // d. Analyse des Tiers (Privacy / RGPD)
            const allThirdPartyStrings = [
                ...(site.thirdPartyDomains || []),
                ...(site.thirdPartyScripts || [])
            ];
            const thirdPartiesFindings = analyzeThirdParties(allThirdPartyStrings);
            allFindings.push(...thirdPartiesFindings);
            
            // Modules contextuels
            const scriptsInventory = analyzeScripts(site.thirdPartyScripts || []);
            const techSummary = analyzeTechnologies(site.technologies || []);

            // e. Notation Globale (Scoring)
            const scoreResult = calculateScore(site, allFindings);

            // f. Synthèse des Remédiations
            const recommendations = buildRecommendations(allFindings);

            // g. Génération du Résumé Exécutif
            const executiveSummaryText = buildExecutiveSummary(site.finalUrl || site.url, scoreResult, allFindings);

            // Assemblage
            finalReports.push({
                siteUrl: site.finalUrl || site.url,
                score: scoreResult.score,
                grade: scoreResult.grade,
                executiveSummary: executiveSummaryText,
                tlsSummary: tlsResult.summary,
                cookies: parsedCookies,
                thirdParties: thirdPartiesFindings,
                recommendations: recommendations,
                techSummary: techSummary,
                scriptsInventory: scriptsInventory
            });
        } catch (e) {
            console.error(`⚠️ Erreur inattendue lors de l'analyse de ${site.url}:`, e.message);
            // Isolation des erreurs : on continue avec le site suivant
        }
    }

    if (finalReports.length === 0) {
        fatalError("Aucun rapport n'a pu être généré. L'analyse de tous les sites a échoué.");
    }

    // 4. Génération du rendu HTML final
    console.log("\n📄 Étape 3 : Génération du rapport HTML autonome...");
    let htmlOutput;
    try {
        htmlOutput = renderHtmlReport(finalReports);
    } catch (e) {
        fatalError("Erreur lors de la compilation du template HTML.", e.message);
    }
    
    // Création récursive du dossier de sortie si inexistant
    const outputDir = path.dirname(config.output);
    if (!fs.existsSync(outputDir)) {
        try {
            fs.mkdirSync(outputDir, { recursive: true });
        } catch (e) {
            fatalError("Impossible de créer le dossier de destination.", e.message);
        }
    }

    try {
        fs.writeFileSync(config.output, htmlOutput, 'utf8');
    } catch (e) {
        fatalError(`Impossible d'écrire le fichier de sortie dans ${config.output}.`, e.message);
    }

    console.log(`\n🎉 TERMINÉ ! Le rapport d'audit est disponible ici :`);
    console.log(`➡️  ${config.output}`);
}

// Lancement automatique si appelé en ligne de commande
if (require.main === module) {
    main();
}
