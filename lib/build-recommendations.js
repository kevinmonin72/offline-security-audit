/**
 * Module offline de génération des recommandations de remédiation.
 * 
 * Son rôle est d'agréger tous les findings bruts, de les dédupliquer, 
 * de les classer par priorité opérationnelle et de les regrouper par thème pédagogique.
 */

// Définition des niveaux de priorité d'action
const PRIORITIES = {
    IMMEDIATE: 'immédiat',       // Action critique (arrêt de production, faille exploitable directement)
    IMPORTANT: 'important',      // Action majeure (vulnérabilité classique, expiration proche)
    IMPROVEMENT: 'amélioration'  // Action de durcissement (bonne pratique de sécurité en profondeur)
};

/**
 * Traduit une sévérité technique brute en une priorité opérationnelle actionnable.
 */
function determinePriority(severity) {
    if (!severity) return PRIORITIES.IMPROVEMENT;
    
    const sev = severity.toLowerCase();
    
    // Critique = Intervention d'urgence
    if (sev === 'critical') return PRIORITIES.IMMEDIATE;
    
    // High / Medium = Dette technique de sécurité à résorber rapidement
    if (sev === 'high' || sev === 'medium') return PRIORITIES.IMPORTANT;
    
    // Low / Info = Durcissement optionnel mais recommandé
    return PRIORITIES.IMPROVEMENT;
}

/**
 * Normalise et traduit les catégories techniques en thèmes pédagogiques clairs.
 */
function getPedagogicalTheme(finding) {
    let rawTheme = finding.category || finding.type || 'Général';
    
    // Rapprochement des thèmes
    if (rawTheme === 'Security Headers') {
        return 'Durcissement des En-têtes HTTP';
    } 
    if (rawTheme === 'Cookies Security') {
        return 'Sécurisation des Sessions & Cookies';
    } 
    if (rawTheme === 'TLS Security' || rawTheme === 'Cleartext Protocol') {
        return 'Chiffrement et Transport (HTTPS)';
    } 
    if (rawTheme === 'Privacy & Data Flow' || finding.type === 'Publicité' || finding.type === 'Session Replay') {
        return 'Confidentialité et Traceurs Tiers';
    }
    if (finding.tags && finding.tags.includes('dom')) {
        return 'Sécurité Applicative & DOM';
    }

    return rawTheme; // Repli par défaut
}

/**
 * Transforme une liste exhaustive de findings en un plan d'action lisible.
 * 
 * @param {Array<Object>} allFindings - La liste de tous les constats générés.
 * @returns {Object} Le plan d'action découpé par priorités et par thèmes.
 */
function buildRecommendations(allFindings) {
    if (!Array.isArray(allFindings)) {
        return {
            [PRIORITIES.IMMEDIATE]: [],
            [PRIORITIES.IMPORTANT]: [],
            [PRIORITIES.IMPROVEMENT]: []
        };
    }

    // Structure Map temporaire pour garantir la déduplication : 
    // Priorité -> Thème -> Set<Recommandations>
    const grouped = {
        [PRIORITIES.IMMEDIATE]: new Map(),
        [PRIORITIES.IMPORTANT]: new Map(),
        [PRIORITIES.IMPROVEMENT]: new Map()
    };

    for (const finding of allFindings) {
        if (!finding) continue;
        
        // Extraction du texte d'action (nous avons utilisé 'recommendation' ou 'justification' dans nos modules)
        const actionText = finding.recommendation || finding.justification;
        if (!actionText || actionText.trim() === '') continue;

        // Détermination de la priorité et du thème
        const priority = determinePriority(finding.severity || finding.riskLevel);
        const theme = getPedagogicalTheme(finding);

        // Initialisation du Set() pour dédupliquer
        if (!grouped[priority].has(theme)) {
            grouped[priority].set(theme, new Set());
        }

        // Ajout au Set (si une reco est identique pour 5 cookies, elle n'apparaîtra qu'une seule fois)
        grouped[priority].get(theme).add(actionText.trim());
    }

    // Formatage final pour générer un JSON lisible et ordonné
    const results = {
        [PRIORITIES.IMMEDIATE]: [],
        [PRIORITIES.IMPORTANT]: [],
        [PRIORITIES.IMPROVEMENT]: []
    };

    for (const priority of Object.values(PRIORITIES)) {
        for (const [theme, actionsSet] of grouped[priority].entries()) {
            results[priority].push({
                theme: theme,
                actions: Array.from(actionsSet) // Le Set est reconverti en simple Array pour le JSON final
            });
        }
    }

    return results;
}

// Support CLI pour tests unitaires rapides
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const rawFindings = JSON.parse(args[0]);
            const recommendations = buildRecommendations(rawFindings);
            console.log(JSON.stringify(recommendations, null, 2));
        } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit être un JSON contenant un tableau de findings." }, null, 2));
            process.exit(1);
        }
    }
}

module.exports = {
    PRIORITIES,
    buildRecommendations
};
