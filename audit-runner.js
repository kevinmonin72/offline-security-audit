/**
 * audit-runner.js
 * 
 * Pipeline d'audit hors-ligne simplifié en 2 étapes.
 * Ne requiert aucune interaction si appelé avec --input <chemin>.
 * Réutilise tout le moteur d'analyse existant de manière transparente.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Importation du moteur existant (100% réutilisation)
const { importEvidence } = require('./lib/import-evidence');
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

// Utilitaires d'affichage
const colors = {
    reset: "\x1b[0m", bold: "\x1b[1m", red: "\x1b[31m",
    green: "\x1b[32m", yellow: "\x1b[33m", cyan: "\x1b[36m"
};

function printStep(msg) { console.log(`\n${colors.cyan}${colors.bold}▶ ${msg}${colors.reset}`); }
function printSuccess(msg) { console.log(`${colors.green}  ✅ ${msg}${colors.reset}`); }
function printError(msg) { console.log(`${colors.red}  ❌ ${msg}${colors.reset}`); }
function printInfo(msg) { console.log(`  ℹ️  ${msg}`); }

// Fonction d'extraction d'arguments CLI
function getCliArg(flag) {
    const args = process.argv.slice(2);
    for (let i = 0; i < args.length; i++) {
        if (args[i] === flag && args[i+1]) return args[i+1];
        if (args[i].startsWith(`${flag}=`)) return args[i].split('=')[1];
    }
    return null;
}

// Fonction pour demander le fichier de façon interactive si argument manquant
function promptPath(callback) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`${colors.bold}Veuillez indiquer le chemin de votre fichier de preuve locale : ${colors.reset}`, (answer) => {
        rl.close();
        callback(answer.trim());
    });
}

// Cœur de l'exécution
function runAudit(inputPath) {
    const resolvedPath = path.resolve(inputPath);
    if (!fs.existsSync(resolvedPath)) {
        printError(`Le fichier d'entrée est introuvable : ${resolvedPath}`);
        process.exit(1);
    }

    // =========================================================================
    // ÉTAPE 1 — IMPORTER UNE PREUVE
    // =========================================================================
    printStep("ÉTAPE 1 — IMPORTATION ET NORMALISATION DE LA PREUVE");
    let normalizedData;
    
    try {
        normalizedData = importEvidence(resolvedPath);
        printSuccess("Preuve détectée et normalisée avec succès.");
        
        console.log(`\n    ${colors.cyan}--- Résumé de la reconnaissance hors-ligne ---${colors.reset}`);
        console.log(`    📍 Cible identifiée   : ${normalizedData.finalUrl}`);
        console.log(`    📦 En-têtes HTTP      : ${Object.keys(normalizedData.headers).length}`);
        console.log(`    🍪 Cookies détectés   : ${normalizedData.setCookies.length}`);
        console.log(`    🔒 Contexte TLS lu    : ${normalizedData.tls ? 'Oui' : 'Non'}`);
        console.log(`    ${colors.cyan}----------------------------------------------${colors.reset}`);
    } catch (e) {
        printError(`Échec de l'importation de la preuve : ${e.message}`);
        process.exit(1);
    }

    // =========================================================================
    // ÉTAPE 2 — GÉNÉRER L’AUDIT ET LES LIVRABLES
    // =========================================================================
    printStep("ÉTAPE 2 — ANALYSE ET GÉNÉRATION DES RÉSULTATS");
    
    // a. Validation
    printInfo("Validation de la structure interne...");
    const validationReport = validateData([normalizedData]);
    if (validationReport.errors && validationReport.errors.length > 0) {
        printInfo("Les données sont incomplètes, mais l'analyse heuristique continue.");
    } else {
        printSuccess("Schéma de données parfaitement respecté.");
    }

    // b. Analyse complète
    printInfo("Exécution du moteur d'évaluation statique de sécurité...");
    let reportResult;
    try {
        let allFindings = [];
        allFindings.push(...analyzeHeaders(normalizedData.headers));
        
        const parsedCookies = parseCookies(normalizedData.setCookies || []);
        allFindings.push(...analyzeCookies(parsedCookies));

        const auditDate = (normalizedData.metadata && normalizedData.metadata.auditDate) ? new Date(normalizedData.metadata.auditDate) : new Date();
        const tlsResult = analyzeTls(normalizedData.tls, auditDate);
        allFindings.push(...tlsResult.findings);

        const allThirdPartyStrings = [...(normalizedData.thirdPartyDomains || []), ...(normalizedData.thirdPartyScripts || [])];
        allFindings.push(...analyzeThirdParties(allThirdPartyStrings));
        
        const scriptsInventory = analyzeScripts(normalizedData.thirdPartyScripts || []);
        const techSummary = analyzeTechnologies(normalizedData.technologies || []);

        const scoreResult = calculateScore(normalizedData, allFindings);
        const recommendations = buildRecommendations(allFindings);
        const executiveSummaryText = buildExecutiveSummary(normalizedData.finalUrl || normalizedData.url, scoreResult, allFindings);

        reportResult = {
            siteUrl: normalizedData.finalUrl || normalizedData.url,
            score: scoreResult.score,
            grade: scoreResult.grade,
            executiveSummary: executiveSummaryText,
            tlsSummary: tlsResult.summary,
            cookies: parsedCookies,
            thirdParties: analyzeThirdParties(allThirdPartyStrings),
            recommendations: recommendations,
            techSummary: techSummary,
            scriptsInventory: scriptsInventory,
            findings: allFindings
        };
        printSuccess(`L'analyse est terminée (Note Globale : ${reportResult.grade} - ${reportResult.score}/100).`);
    } catch (e) {
        printError(`Erreur fatale de calcul lors de l'analyse : ${e.message}`);
        process.exit(1);
    }

    // c. Création du dossier et génération (Pack Client)
    printInfo("Compilation des livrables finaux...");
    const outputDir = path.join(__dirname, 'output');
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const packDir = path.join(outputDir, `audit-${timestamp}`);
    fs.mkdirSync(packDir);
    
    try {
        // Rendu HTML complet
        const htmlOutput = renderHtmlReport([reportResult]);
        fs.writeFileSync(path.join(packDir, 'rapport-complet.html'), htmlOutput, 'utf8');
        
        // Export JSON sérialisé
        const jsonExport = {
            url: reportResult.siteUrl,
            score: reportResult.score,
            grade: reportResult.grade,
            executiveSummary: reportResult.executiveSummary,
            findings: reportResult.findings,
            recommendations: reportResult.recommendations
        };
        fs.writeFileSync(path.join(packDir, 'export-technique.json'), JSON.stringify(jsonExport, null, 2), 'utf8');
        
        // Résumé exécutif en texte pur
        let txtOutput = `RÉSUMÉ EXÉCUTIF - AUDIT DE SÉCURITÉ OFFLINE\nDate: ${new Date().toLocaleString()}\n\n`;
        txtOutput += `Cible : ${reportResult.siteUrl}\nNote Globale : ${reportResult.grade} (${reportResult.score}/100)\n\n`;
        txtOutput += `Synthèse :\n${reportResult.executiveSummary}\n\n`;
        
        if (reportResult.recommendations['immédiat'] && reportResult.recommendations['immédiat'].length > 0) {
            txtOutput += `!!! ACTIONS URGENTES DÉTECTÉES !!!\n`;
            txtOutput += `Le rapport technique complet contient des remédiations à traiter dans l'immédiat.\n`;
        }
        fs.writeFileSync(path.join(packDir, 'resume-executif.txt'), txtOutput, 'utf8');
        
        printSuccess(`Tous les fichiers ont été générés dans :\n     ${colors.cyan}${packDir}${colors.reset}`);
    } catch(e) {
        printError(`Erreur inattendue lors de l'écriture des fichiers : ${e.message}`);
        process.exit(1);
    }
    
    console.log(`\n🎉 Processus terminé avec succès. Vous pouvez consulter les livrables.\n`);
}

// -----------------------------------------------------------------------------
// Démarrage de l'application
// -----------------------------------------------------------------------------
const inputArg = getCliArg('--input');
if (inputArg) {
    runAudit(inputArg);
} else {
    console.log(`\n${colors.bold}🛡️  AUDIT DE SÉCURITÉ LOCAL (PIPELINE SIMPLIFIÉ)${colors.reset}\n`);
    promptPath((p) => {
        if (!p) {
            printError("Chemin invalide ou annulé.");
            process.exit(1);
        }
        runAudit(p);
    });
}
