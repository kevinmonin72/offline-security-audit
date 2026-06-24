/**
 * lib/bot-ui.js
 * 
 * Utilitaire d'interface pour le terminal (UI/UX).
 * Ne dépend d'aucune librairie externe, utilise readline et les codes ANSI natifs
 * pour améliorer la lisibilité des menus, statuts et alertes.
 */

const readline = require('readline');

// Codes de couleurs ANSI standards
const colors = {
    reset: "\x1b[0m",
    bold: "\x1b[1m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    cyan: "\x1b[36m"
};

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function printHeader() {
    console.clear();
    console.log(`${colors.cyan}${colors.bold}============================================================${colors.reset}`);
    console.log(`${colors.cyan}${colors.bold}  🛡️  BOT ORCHESTRATEUR LOCAL D'AUDIT SÉCURITÉ (OFFLINE)  ${colors.reset}`);
    console.log(`${colors.cyan}${colors.bold}============================================================${colors.reset}`);
}

function printMenu(state) {
    printHeader();
    
    // Bloc de statut
    console.log(`\n${colors.bold}📍 ÉTAT DE LA SESSION :${colors.reset}`);
    console.log(` - Fichier chargé   : ${state.currentFilePath ? colors.green + state.currentFilePath + colors.reset : colors.yellow + 'Aucun' + colors.reset}`);
    console.log(` - Validation       : ${state.validationPassed ? colors.green + '✅ Conforme' + colors.reset : colors.red + '❌ Non effectuée / Non conforme' + colors.reset}`);
    console.log(` - Analyse terminée : ${state.analysisResults ? colors.green + '✅ Oui' + colors.reset : colors.yellow + '⏳ Non' + colors.reset}`);
    if (state.lastReportPath) {
        console.log(` - Dernier Rapport  : ${colors.cyan}${state.lastReportPath}${colors.reset}`);
    }
    
    // Bloc d'actions
    console.log(`\n${colors.bold}🛠️  ACTIONS POSSIBLES :${colors.reset}`);
    console.log(`  0. 🎓 Mode Assistant Guidé (Complet)`);
    console.log(`  1. 📂 Charger un fichier JSON structuré`);
    console.log(`  2. 🧩 Importer une preuve brute (TXT, HAR, JSON partiel)`);
    console.log(`  3. 🔄 Recharger le fichier`);
    console.log(`  4. 🔍 Valider les données`);
    console.log(`  5. ⚙️  Lancer l'analyse de sécurité`);
    console.log(`  6. 📄 Générer le rapport HTML`);
    console.log(`  7. 📊 Afficher les résumés exécutifs`);
    console.log(`  8. 🛑 Afficher les recommandations prioritaires`);
    console.log(`  9. 💾 Exporter l'état de la session (Debug)`);
    console.log(` 10. 📦 Générer un Pack Client (HTML + JSON + Résumé TXT)`);
    console.log(` 11. ❌ Quitter`);
    
    console.log(`\n${colors.cyan}============================================================${colors.reset}`);
}

function ask(question, callback) {
    rl.question(`${colors.bold}${question}${colors.reset}`, callback);
}

function printSuccess(msg) {
    console.log(`\n${colors.green}✅ SUCCÈS : ${msg}${colors.reset}`);
}

function printError(msg, err = '') {
    console.log(`\n${colors.red}❌ ERREUR : ${msg}${colors.reset}`);
    if (err) console.log(`${colors.red}   Détails : ${err}${colors.reset}`);
}

function printWarning(msg) {
    console.log(`\n${colors.yellow}⚠️  ATTENTION : ${msg}${colors.reset}`);
}

function printInfo(msg) {
    console.log(`\n${colors.blue}ℹ️  INFO : ${msg}${colors.reset}`);
}

function promptReturn(callback) {
    rl.question(`\n${colors.bold}Appuyez sur 'Entrée' pour continuer...${colors.reset}`, () => {
        callback();
    });
}

function close() {
    rl.close();
}

module.exports = {
    colors,
    printMenu,
    ask,
    printSuccess,
    printError,
    printWarning,
    printInfo,
    promptReturn,
    close
};
