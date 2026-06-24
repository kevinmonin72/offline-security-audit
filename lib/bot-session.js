/**
 * lib/bot-session.js
 * 
 * Gestion de l'état de la session locale de l'orchestrateur conversationnel.
 * Conserve strictement en mémoire les données du cycle en cours (100% offline).
 */

const state = {
    currentData: null,          // Contenu parsé du fichier JSON
    currentFilePath: null,      // Chemin du fichier d'entrée
    validationPassed: false,    // Indique si le fichier respecte le schéma
    analysisResults: null,      // Résultats complets de l'analyse métier
    lastAnalysisDate: null,     // Horodatage du dernier cycle d'analyse
    lastReportPath: null        // Chemin du dernier rapport HTML généré
};

module.exports = { state };
