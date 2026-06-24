/**
 * Module offline d'analyse de la configuration TLS/SSL.
 * 
 * Il n'ouvre aucune socket réseau et se contente d'évaluer 
 * la posture TLS d'après les données d'audit JSON existantes.
 */

/**
 * Analyse les détails du certificat TLS et retourne un résumé
 * accompagné d'éventuelles vulnérabilités ou alertes (findings).
 * 
 * @param {Object} tlsObj - L'objet contenant les infos TLS (issuer, validTo, protocol, etc.)
 * @param {string|Date} [referenceDate] - Date de référence pour le calcul (optionnelle, utile pour relire un vieil audit). Par défaut : date actuelle.
 * @returns {Object} Un objet contenant un 'summary' et une liste de 'findings'.
 */
function analyzeTls(tlsObj, referenceDate = new Date()) {
    // Structure de retour
    const result = {
        summary: null,
        findings: []
    };

    if (!tlsObj || typeof tlsObj !== 'object') {
        return result;
    }

    // Préparation du résumé (summary)
    result.summary = {
        subject: tlsObj.subject || 'Inconnu',
        issuer: tlsObj.issuer || 'Inconnu',
        protocol: tlsObj.protocol || 'Inconnu',
        cipher: tlsObj.cipher || 'Inconnu',
        daysRemaining: null,
        isExpired: false,
        isAuthorized: tlsObj.authorized === true
    };

    // =====================================================================
    // 1. Chaîne de confiance et validité de l'autorité (Authorized)
    // =====================================================================
    if (tlsObj.authorized === false) {
        result.findings.push({
            id: 'TLS_NOT_AUTHORIZED',
            category: 'TLS Security',
            severity: 'High',
            title: 'Certificat TLS non autorisé (Chaîne de confiance invalide)',
            description: `Le certificat présenté n'est pas reconnu par les autorités de certification (CA) publiques. Le motif remonté est : "${tlsObj.authorizationError || 'Inconnu'}". Les navigateurs afficheront un avertissement bloquant de type "Connexion non sécurisée".`,
            evidence: `authorized: false | erreur: ${tlsObj.authorizationError || 'N/A'}`,
            recommendation: "Installez un certificat valide émis par une autorité publique reconnue (ex: Let's Encrypt) et assurez-vous de servir la chaîne intermédiaire complète."
        });
    }

    // =====================================================================
    // 2. Calcul des dates et des expirations
    // =====================================================================
    if (tlsObj.validTo) {
        const toDate = new Date(tlsObj.validTo);
        const refDate = new Date(referenceDate);

        // Calcul de la différence en jours francs
        const diffTime = toDate.getTime() - refDate.getTime();
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        
        result.summary.daysRemaining = diffDays;

        if (diffDays < 0) {
            // Le certificat est déjà expiré
            result.summary.isExpired = true;
            result.findings.push({
                id: 'TLS_CERT_EXPIRED',
                category: 'TLS Security',
                severity: 'Critical',
                title: 'Certificat TLS expiré',
                description: `Le certificat est périmé depuis ${Math.abs(diffDays)} jours (Date d'expiration : ${tlsObj.validTo}). L'accès au site est vraisemblablement bloqué par tous les navigateurs.`,
                evidence: `validTo: ${tlsObj.validTo}`,
                recommendation: "Renouvelez le certificat TLS de toute urgence."
            });
        } else if (diffDays <= 30) {
            // Expiration critique (< 30 jours)
            result.findings.push({
                id: 'TLS_CERT_EXPIRING_SOON_30',
                category: 'TLS Security',
                severity: 'High',
                title: `Expiration imminente du certificat TLS (${diffDays} jours restants)`,
                description: `Le certificat arrive à expiration dans moins de 30 jours. S'il n'est pas renouvelé à temps, le site subira une interruption de service.`,
                evidence: `validTo: ${tlsObj.validTo} (Reste ${diffDays} jours)`,
                recommendation: "Procédez au renouvellement immédiat de ce certificat."
            });
        } else if (diffDays <= 60) {
            // Expiration d'attention (< 60 jours)
            result.findings.push({
                id: 'TLS_CERT_EXPIRING_SOON_60',
                category: 'TLS Security',
                severity: 'Medium',
                title: `Certificat TLS expirant prochainement (${diffDays} jours restants)`,
                description: `Le certificat expirera d'ici environ deux mois. C'est le moment habituel pour vérifier que les mécanismes de renouvellement automatique (comme certbot) fonctionnent correctement.`,
                evidence: `validTo: ${tlsObj.validTo} (Reste ${diffDays} jours)`,
                recommendation: "Assurez-vous que l'automatisation de renouvellement est planifiée, ou préparez un renouvellement manuel dans les semaines à venir."
            });
        }
    }

    return result;
}

// Support pour une utilisation directe en ligne de commande (CLI)
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const raw = JSON.parse(args[0]);
            // On peut optionnellement passer une date de référence en 2ème argument
            const refDate = args[1] ? new Date(args[1]) : new Date();
            const results = analyzeTls(raw, refDate);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit être un objet JSON valide contenant les propriétés TLS." }, null, 2));
            process.exit(1);
        }
    }
}

module.exports = {
    analyzeTls
};
