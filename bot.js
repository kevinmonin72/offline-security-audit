/**
 * bot.js
 * 
 * Bot Conversationnel d'Orchestration pour l'Audit Sécurité Offline.
 */

const ui = require('./lib/bot-ui');
const { state } = require('./lib/bot-session');
const actions = require('./lib/bot-actions');

/**
 * Boucle principale de l'interface
 */
function loop() {
    ui.printMenu(state);
    
    ui.ask("\n👉 Votre choix (0-11) : ", (choice) => {
        switch(choice.trim()) {
            case '0': return actions.actionGuidedMode(loop);
            case '1': return actions.actionLoadFile(loop);
            case '2': return actions.actionImportEvidence(loop);
            case '3': return actions.actionReloadFile(loop);
            case '4': return actions.actionValidate(loop);
            case '5': return actions.actionAnalyze(loop);
            case '6': return actions.actionGenerateHtml(loop);
            case '7': return actions.actionShowSummary(loop);
            case '8': return actions.actionShowRecommendations(loop);
            case '9': return actions.actionExportState(loop);
            case '10': return actions.actionClientPack(loop);
            case '11': 
                console.log(`\n👋 Merci d'avoir utilisé le bot d'audit local. À bientôt !\n`);
                ui.close();
                process.exit(0);
                break;
            default:
                ui.printWarning("Choix invalide. Veuillez entrer un nombre entre 0 et 11.");
                ui.promptReturn(loop);
        }
    });
}

console.log("\n🚀 Initialisation du Bot d'Audit de Sécurité Offline...");
loop();
