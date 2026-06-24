/**
 * Module offline de génération de Résumé Exécutif (Executive Summary).
 * 
 * Il rédige automatiquement un paragraphe de 5 à 8 phrases en français,
 * adapté à un public de décideurs (non purement technique).
 * Le ton est factuel, pédagogique et s'appuie sur la compilation de l'audit.
 */

/**
 * Génère le texte du résumé exécutif.
 * 
 * @param {string} siteUrl - L'URL du site audité.
 * @param {Object} scoreData - L'objet de score généré par score-site.js (score, grade, penalties).
 * @param {Array<Object>} allFindings - La liste de tous les constats générés par nos modules.
 * @returns {string} Le paragraphe formaté du résumé exécutif.
 */
function buildExecutiveSummary(siteUrl, scoreData, allFindings) {
    if (!siteUrl || !scoreData || !Array.isArray(allFindings)) {
        return "Données insuffisantes pour générer un résumé exécutif cohérent.";
    }

    const sentences = [];

    // =====================================================================
    // 1. Introduction et posture générale
    // =====================================================================
    sentences.push(`L'audit de sécurité passif de la plateforme ${siteUrl} a permis d'évaluer sa posture globale avec la note de ${scoreData.grade} (score : ${scoreData.score}/100).`);
    
    if (scoreData.score >= 80) {
        sentences.push("Le site démontre un excellent niveau de conformité aux standards de sécurité actuels.");
    } else if (scoreData.score >= 50) {
        sentences.push("La configuration est acceptable dans son ensemble, bien qu'elle nécessite des ajustements techniques de renforcement.");
    } else {
        sentences.push("L'architecture présente des lacunes structurelles nécessitant une intervention technique prioritaire.");
    }

    // --- Analyse rapide des données pour contextualiser les phrases suivantes ---
    let tlsCritical = false;
    let tlsWarning = false;
    let headersCritical = false;
    let cookiesCritical = false;
    let thirdPartiesRisky = false;

    // Détection de l'absence fondamentale de HTTPS
    const noHttpsPenalty = scoreData.penalties && scoreData.penalties.some(p => p.findingId === 'NO_HTTPS_PROTOCOL');
    if (noHttpsPenalty) {
        tlsCritical = true;
    }

    for (const f of allFindings) {
        if (!f) continue;
        
        if (f.category === 'TLS Security' || f.category === 'Cleartext Protocol') {
            if (f.severity === 'Critical' || f.severity === 'High') tlsCritical = true;
            else if (f.severity === 'Medium') tlsWarning = true;
        }
        
        if (f.category === 'Security Headers') {
            // HSTS manquant ou CSP manquant sont des marqueurs d'absence de défense périmétrique de base
            if (f.id === 'HSTS_MISSING' || f.id === 'CSP_MISSING') headersCritical = true;
        }
        
        if (f.category === 'Cookies Security') {
            // Un cookie de session non sécurisé est critique
            if (f.severity === 'Critical') cookiesCritical = true;
        }
        
        // Modules tiers, on regarde le type ou le risque
        if (f.type === 'Publicité' || f.type === 'Session Replay' || f.riskLevel === 'High') {
            thirdPartiesRisky = true;
        }
    }

    // =====================================================================
    // 2. Transport et Chiffrement (TLS)
    // =====================================================================
    if (tlsCritical) {
        sentences.push("Sur le plan du transport des données, la sécurisation par chiffrement est absente ou techniquement défaillante, exposant le trafic à des interceptions.");
    } else if (tlsWarning) {
        sentences.push("Le trafic est chiffré de manière adéquate, mais le mécanisme de renouvellement du certificat technique approche de son échéance.");
    } else {
        sentences.push("Concernant le transport des données, le chiffrement des échanges est correctement configuré et assure efficacement la confidentialité des communications.");
    }

    // =====================================================================
    // 3. En-têtes (Headers)
    // =====================================================================
    if (headersCritical) {
        sentences.push("Les mécanismes de défense du navigateur (en-têtes HTTP) sont largement incomplets, ce qui limite la résilience de l'application face aux vecteurs d'attaques standards.");
    } else {
        sentences.push("Les directives de défense périmétriques sont globalement en place pour protéger l'intégrité de la navigation des utilisateurs.");
    }

    // =====================================================================
    // 4. Sessions (Cookies)
    // =====================================================================
    if (cookiesCritical) {
        sentences.push("La gestion des sessions de connexion omet certaines protections fondamentales, rendant potentiellement possible l'usurpation de comptes en cas d'attaque ciblée.");
    } else {
        sentences.push("La gestion des sessions et de l'authentification s'appuie sur des pratiques robustes garantissant l'étanchéité des connexions de vos visiteurs.");
    }

    // =====================================================================
    // 5. Écosystème Tiers
    // =====================================================================
    if (thirdPartiesRisky) {
        sentences.push("Enfin, l'analyse de l'écosystème révèle la présence de traceurs externes nécessitant une vigilance particulière sur le plan de la vie privée et du recueil de consentement.");
    } else {
        sentences.push("Enfin, l'intégration de services tiers semble mesurée, limitant nativement les risques de fuite de données vers des acteurs de tracking externes.");
    }

    // =====================================================================
    // 6. Conclusion
    // =====================================================================
    if (scoreData.score < 80) {
        sentences.push("Il est conseillé de confier les actions classées comme immédiates ou importantes à l'équipe de développement afin de consolider durablement cette posture.");
    } else {
        sentences.push("L'objectif est désormais de maintenir ce haut niveau d'exigence au fil des futures évolutions de la plateforme.");
    }

    // Génération du texte final (7 phrases)
    return sentences.join(' ');
}

// Support pour tests CLI
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 2) {
        try {
            const url = args[0];
            const scoreData = JSON.parse(args[1]);
            const findings = JSON.parse(args[2]);
            const summary = buildExecutiveSummary(url, scoreData, findings);
            console.log(summary);
        } catch (e) {
            console.error("Arguments invalides. Usage : node build-executive-summary.js '<url>' '<scoreDataJson>' '<findingsArrayJson>'");
            process.exit(1);
        }
    }
}

module.exports = {
    buildExecutiveSummary
};
