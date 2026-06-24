/**
 * lib/bot-actions.js
 * 
 * Contient la logique applicative du bot. 
 */

const fs = require('fs');
const path = require('path');
const ui = require('./bot-ui');
const { state } = require('./bot-session');

const { validateData } = require('./validate-input');
const { analyzeHeaders } = require('./analyze-headers');
const { parseCookies } = require('./parse-cookies');
const { analyzeCookies } = require('./analyze-cookies');
const { analyzeTls } = require('./analyze-tls');
const { analyzeThirdParties } = require('./analyze-third-parties');
const { analyzeScripts } = require('./analyze-scripts');
const { analyzeTechnologies } = require('./analyze-technologies');
const { calculateScore } = require('./score-site');
const { buildRecommendations } = require('./build-recommendations');
const { buildExecutiveSummary } = require('./build-executive-summary');
const { renderHtmlReport } = require('./render-report');
const { importEvidence } = require('./import-evidence');

function _doLoadFile(targetPath) {
    if (!fs.existsSync(targetPath)) {
        ui.printError(`Le fichier n'existe pas ou est inaccessible.`, `Chemin : ${targetPath}`);
        return false;
    }
    try {
        const raw = fs.readFileSync(targetPath, 'utf8');
        const data = JSON.parse(raw);
        state.currentData = data;
        state.currentFilePath = targetPath;
        state.validationPassed = false;
        state.analysisResults = null;
        state.lastAnalysisDate = null;
        ui.printSuccess(`Fichier chargé avec succès (${data.length} sites trouvés).`);
        return true;
    } catch (e) {
        ui.printError(`Impossible de lire ou de parser le JSON.`, e.message);
        return false;
    }
}

function actionLoadFile(callback) {
    const defaultPath = path.join(__dirname, '..', 'data', 'input.json');
    ui.ask(`\nEntrez le chemin du fichier JSON de collecte\n(Laissez vide pour utiliser '${defaultPath}') : `, (answer) => {
        _doLoadFile(answer.trim() || defaultPath);
        ui.promptReturn(callback);
    });
}

function actionImportEvidence(callback) {
    ui.ask(`\nEntrez le chemin du fichier de preuves locales (txt, har, json) : `, (answer) => {
        const targetPath = answer.trim();
        if (!targetPath) {
            ui.printWarning("Chemin vide annulé.");
            return ui.promptReturn(callback);
        }
        try {
            ui.printInfo(`Tentative d'importation depuis : ${targetPath}`);
            const normalizedData = importEvidence(targetPath);
            state.currentData = [normalizedData];
            state.currentFilePath = targetPath;
            state.validationPassed = false;
            state.analysisResults = null;
            state.lastAnalysisDate = null;
            
            ui.printSuccess("Importation et normalisation réussies.");
            console.log(`\n${ui.colors.cyan}--- Résumé de la reconnaissance ---${ui.colors.reset}`);
            console.log(`📍 URL cible estimée : ${normalizedData.finalUrl}`);
            console.log(`📦 En-têtes HTTP détectés : ${Object.keys(normalizedData.headers).length}`);
            console.log(`🍪 Cookies extraits : ${normalizedData.setCookies.length}`);
            console.log(`🔒 Traces TLS reconnues : ${normalizedData.tls ? 'Oui' : 'Non'}`);
            console.log(`${ui.colors.cyan}-----------------------------------${ui.colors.reset}`);
            
            ui.ask(`\nVoulez-vous valider ces données ? (O/n) : `, (ans) => {
                if (ans.trim().toLowerCase() !== 'n') actionValidate(callback);
                else ui.promptReturn(callback);
            });
        } catch (e) {
            ui.printError("Échec de l'importation de la preuve", e.message);
            ui.promptReturn(callback);
        }
    });
}

function actionReloadFile(callback) {
    if (!state.currentFilePath) {
        ui.printWarning("Aucun fichier n'a été chargé précédemment.");
        return ui.promptReturn(callback);
    }
    ui.printInfo(`Rechargement du fichier : ${state.currentFilePath}`);
    _doLoadFile(state.currentFilePath);
    ui.promptReturn(callback);
}

function actionValidate(callback) {
    if (!state.currentData) {
        ui.printWarning("Veuillez d'abord charger ou importer des données.");
        return ui.promptReturn(callback);
    }
    ui.printInfo("Validation structurelle en cours...");
    try {
        const report = validateData(state.currentData);
        if (report.errors && report.errors.length > 0) {
            ui.printError("Des erreurs de structure ont été détectées :");
            report.errors.forEach(e => console.log(`   - ${e}`));
            state.validationPassed = false;
        } else {
            ui.printSuccess("Données validées avec succès.");
            state.validationPassed = true;
        }
    } catch (e) {
        ui.printError("Erreur inattendue", e.message);
        state.validationPassed = false;
    }
    ui.promptReturn(callback);
}

function actionAnalyze(callback, silent = false) {
    if (!state.currentData || !state.validationPassed) {
        if (!silent) ui.printWarning("Veuillez charger ET valider les données avant d'analyser.");
        return silent ? false : ui.promptReturn(callback);
    }

    if (!silent) ui.printInfo("Démarrage du moteur d'analyse hors-ligne...");
    state.analysisResults = [];

    for (const site of state.currentData) {
        if (!silent) console.log(`\n   Analysant le site : ${ui.colors.bold}${site.url || 'URL Inconnue'}${ui.colors.reset} ...`);
        try {
            let allFindings = [];
            allFindings.push(...analyzeHeaders(site.headers));
            
            const parsedCookies = parseCookies(site.setCookies || []);
            allFindings.push(...analyzeCookies(parsedCookies));

            const auditDate = (site.metadata && site.metadata.auditDate) ? new Date(site.metadata.auditDate) : new Date();
            const tlsResult = analyzeTls(site.tls, auditDate);
            allFindings.push(...tlsResult.findings);

            const allThirdPartyStrings = [...(site.thirdPartyDomains || []), ...(site.thirdPartyScripts || [])];
            allFindings.push(...analyzeThirdParties(allThirdPartyStrings));
            
            const scriptsInventory = analyzeScripts(site.thirdPartyScripts || []);
            const techSummary = analyzeTechnologies(site.technologies || []);

            const scoreResult = calculateScore(site, allFindings);
            const recommendations = buildRecommendations(allFindings);
            const executiveSummaryText = buildExecutiveSummary(site.finalUrl || site.url, scoreResult, allFindings);

            state.analysisResults.push({
                siteUrl: site.finalUrl || site.url,
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
            });

            if (!silent) console.log(`     -> ${ui.colors.green}✅ Analyse locale terminée. Score: ${scoreResult.score}/100 (Grade ${scoreResult.grade})${ui.colors.reset}`);
        } catch (e) {
            if (!silent) console.log(`     -> ${ui.colors.red}⚠️ Erreur fatale : ${e.message}${ui.colors.reset}`);
        }
    }

    state.lastAnalysisDate = new Date().toISOString();
    if (!silent) {
        ui.printSuccess("Cycle d'analyse terminé.");
        ui.promptReturn(callback);
    }
    return true;
}

function actionGenerateHtml(callback, silent = false) {
    if (!state.analysisResults) {
        if (!silent) ui.printWarning("Veuillez d'abord lancer l'analyse.");
        return silent ? null : ui.promptReturn(callback);
    }
    
    if (!silent) ui.printInfo("Génération du rapport HTML...");
    try {
        const htmlOutput = renderHtmlReport(state.analysisResults);
        const outputDir = path.join(__dirname, '..', 'output');
        if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
        
        const outputPath = path.join(outputDir, 'rapport-securite-local.html');
        fs.writeFileSync(outputPath, htmlOutput, 'utf8');
        state.lastReportPath = outputPath;
        
        if (!silent) ui.printSuccess(`Rapport HTML généré : ${outputPath}`);
        return silent ? outputPath : ui.promptReturn(callback);
    } catch (e) {
        if (!silent) ui.printError("Erreur HTML", e.message);
        return silent ? null : ui.promptReturn(callback);
    }
}

function actionShowSummary(callback) {
    if (!state.analysisResults) return ui.printWarning("Veuillez lancer l'analyse."), ui.promptReturn(callback);
    ui.printInfo("RÉSUMÉS EXÉCUTIFS");
    for (const report of state.analysisResults) {
        console.log(`\n${ui.colors.cyan}--- ${report.siteUrl} ---${ui.colors.reset}`);
        console.log(`🎯 Score : ${report.score}/100 | Grade : ${report.grade}`);
        console.log(`\n💬 ${report.executiveSummary}`);
    }
    ui.promptReturn(callback);
}

function actionShowRecommendations(callback) {
    if (!state.analysisResults) return ui.printWarning("Veuillez lancer l'analyse."), ui.promptReturn(callback);
    ui.printInfo("RECOMMANDATIONS PRIORITAIRES");
    for (const report of state.analysisResults) {
        console.log(`\n${ui.colors.cyan}--- ${report.siteUrl} ---${ui.colors.reset}`);
        let hasPriorities = false;
        ['immédiat', 'important'].forEach(level => {
            if (report.recommendations[level] && report.recommendations[level].length > 0) {
                console.log(`\n  ${level === 'immédiat' ? ui.colors.red + '🔴' : ui.colors.yellow + '🟠'} [${level.toUpperCase()}]${ui.colors.reset}`);
                report.recommendations[level].forEach(g => {
                    console.log(`    * ${g.theme}`);
                    g.actions.forEach(a => console.log(`      - ${a}`));
                });
                hasPriorities = true;
            }
        });
        if (!hasPriorities) console.log(`  ${ui.colors.green}✅ Aucune alerte prioritaire.${ui.colors.reset}`);
    }
    ui.promptReturn(callback);
}

function actionExportState(callback) {
    ui.printInfo("Export de l'état...");
    const exportData = {
        currentFilePath: state.currentFilePath,
        validationPassed: state.validationPassed,
        lastAnalysisDate: state.lastAnalysisDate,
        lastReportPath: state.lastReportPath,
        siteScores: state.analysisResults ? state.analysisResults.map(r => ({url: r.siteUrl, score: r.score, grade: r.grade})) : []
    };
    const outputDir = path.join(__dirname, '..', 'output');
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    const exportPath = path.join(outputDir, 'session-state.json');
    fs.writeFileSync(exportPath, JSON.stringify(exportData, null, 2), 'utf8');
    ui.printSuccess(`État exporté : ${exportPath}`);
    ui.promptReturn(callback);
}

function actionClientPack(callback) {
    if (!state.analysisResults) {
        ui.printWarning("Veuillez d'abord lancer l'analyse (Option 5).");
        return ui.promptReturn(callback);
    }
    ui.printInfo("Génération du Pack Client...");
    
    const outputDir = path.join(__dirname, '..', 'output');
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const packDir = path.join(outputDir, `client-pack-${timestamp}`);
    fs.mkdirSync(packDir);
    
    try {
        // HTML
        const htmlOutput = renderHtmlReport(state.analysisResults);
        fs.writeFileSync(path.join(packDir, 'rapport-complet.html'), htmlOutput, 'utf8');
        
        // JSON
        const jsonOutput = state.analysisResults.map(r => ({
            url: r.siteUrl,
            score: r.score,
            grade: r.grade,
            executiveSummary: r.executiveSummary,
            findings: r.findings,
            recommendations: r.recommendations
        }));
        fs.writeFileSync(path.join(packDir, 'export-technique.json'), JSON.stringify(jsonOutput, null, 2), 'utf8');
        
        // TXT Summary
        let txtOutput = `RÉSUMÉ EXÉCUTIF - AUDIT DE SÉCURITÉ\nDate: ${new Date().toLocaleString()}\n\n`;
        state.analysisResults.forEach(r => {
            txtOutput += `Cible : ${r.siteUrl}\nNote : ${r.grade} (${r.score}/100)\nRésumé : ${r.executiveSummary}\n\n`;
        });
        fs.writeFileSync(path.join(packDir, 'resume-executif.txt'), txtOutput, 'utf8');
        
        ui.printSuccess(`Pack Client généré avec succès dans :\n${packDir}`);
    } catch (e) {
        ui.printError("Erreur lors de la génération du Pack Client.", e.message);
    }
    
    ui.promptReturn(callback);
}

function actionGuidedMode(callback) {
    console.clear();
    console.log(`${ui.colors.cyan}${ui.colors.bold}🎓 ASSISTANT GUIDÉ (MODE COMPLET)${ui.colors.reset}`);
    console.log("Toutes les opérations restent locales. Rien n'est envoyé sur le réseau.\n");

    ui.ask("1️⃣  Charger un JSON standard (1) ou importer une preuve brute (2) ? [Défaut: 1] : ", (choice) => {
        const isImport = choice.trim() === '2';
        const defaultPath = isImport ? '' : path.join(__dirname, '..', 'data', 'input.json');
        
        ui.ask(`Où se trouve le fichier ? [Défaut : '${defaultPath}'] : `, (answer) => {
            const targetPath = answer.trim() || defaultPath;
            let loaded = false;
            
            console.log("\n⏳ Lecture et normalisation...");
            if (isImport) {
                try {
                    const normalizedData = importEvidence(targetPath);
                    state.currentData = [normalizedData];
                    state.currentFilePath = targetPath;
                    loaded = true;
                    console.log(`✅ Preuve reconnue pour : ${normalizedData.finalUrl}`);
                } catch(e) { ui.printError("Échec de l'import", e.message); }
            } else {
                loaded = _doLoadFile(targetPath);
            }

            if (!loaded) return ui.promptReturn(callback);

            console.log("\n2️⃣  Validation de la structure...");
            try {
                const report = validateData(state.currentData);
                state.validationPassed = (!report.errors || report.errors.length === 0);
                if (state.validationPassed) console.log("✅ Données conformes.");
                else console.log("⚠️ Avertissement : Les données sont partiellement incomplètes.");
            } catch (e) { state.validationPassed = false; }

            console.log("\n3️⃣  Analyse de sécurité...");
            actionAnalyze(null, true);

            console.log("\n4️⃣  Génération du Pack Client...");
            const outputDir = path.join(__dirname, '..', 'output');
            if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
            
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const packDir = path.join(outputDir, `client-pack-${timestamp}`);
            fs.mkdirSync(packDir);
            
            try {
                const htmlOutput = renderHtmlReport(state.analysisResults);
                fs.writeFileSync(path.join(packDir, 'rapport-complet.html'), htmlOutput, 'utf8');
                
                const jsonOutput = state.analysisResults.map(r => ({
                    url: r.siteUrl, score: r.score, grade: r.grade, findings: r.findings
                }));
                fs.writeFileSync(path.join(packDir, 'export-technique.json'), JSON.stringify(jsonOutput, null, 2), 'utf8');
                
                let txtOutput = `RÉSUMÉ EXÉCUTIF\n\n`;
                state.analysisResults.forEach(r => {
                    txtOutput += `Cible : ${r.siteUrl}\nNote : ${r.grade}\nRésumé : ${r.executiveSummary}\n\n`;
                    if (r.recommendations['immédiat'] && r.recommendations['immédiat'].length > 0) {
                        txtOutput += `URGENCES DÉTECTÉES !\n`;
                    }
                });
                fs.writeFileSync(path.join(packDir, 'resume-executif.txt'), txtOutput, 'utf8');
                
                state.lastReportPath = path.join(packDir, 'rapport-complet.html');
                console.log(`✅ Pack complet créé dans : ${packDir}`);
            } catch(e) {
                ui.printError("Erreur Pack Client", e.message);
            }

            console.log("\n🎉 Audit local terminé !");
            ui.promptReturn(callback);
        });
    });
}

module.exports = {
    actionLoadFile, actionImportEvidence, actionReloadFile, actionValidate,
    actionAnalyze, actionGenerateHtml, actionShowSummary, actionShowRecommendations,
    actionExportState, actionClientPack, actionGuidedMode
};
