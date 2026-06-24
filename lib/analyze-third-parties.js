/**
 * Module offline d'analyse des domaines tiers.
 * 
 * Il s'appuie sur une liste configurable de signatures (patterns) pour
 * identifier la nature probable des services tiers appelés par l'application
 * et émettre un diagnostic orienté "Privacy / Conformité".
 */

// Définition des catégories majeures
const CATEGORIES = {
    ANALYTICS: 'Analytics',
    ADVERTISING: 'Publicité',
    MARKETING: 'Marketing Automation',
    SESSION_REPLAY: 'Session Replay',
    TAG_MANAGER: 'Tag Manager'
};

// Niveaux de risque liés à la vie privée et à l'exfiltration de données
const RISK_LEVELS = {
    LOW: 'Low',       // Risque faible, transfert de données commun (nécessitant toutefois un consentement)
    MEDIUM: 'Medium', // Transfert important, croisement de données ou injection de code dynamique
    HIGH: 'High'      // Risque élevé d'enregistrement intégral de l'activité ou de fuite PII (données personnelles)
};

// Dictionnaire de signatures par défaut (configurable en argument)
const DEFAULT_PATTERNS = [
    // --- Tag Managers ---
    {
        service: 'Google Tag Manager',
        type: CATEGORIES.TAG_MANAGER,
        match: /googletagmanager\.com/i,
        riskLevel: RISK_LEVELS.MEDIUM,
        justification: "Permet l'injection dynamique et non auditable de scripts tiers directement par les équipes marketing. Exige un contrôle strict des accès."
    },
    // --- Analytics ---
    {
        service: 'Google Analytics',
        type: CATEGORIES.ANALYTICS,
        match: /google-analytics\.com|analytics\.js/i,
        riskLevel: RISK_LEVELS.LOW,
        justification: "Outil de mesure d'audience standard. Sauf configuration d'anonymisation très stricte, il requiert généralement un consentement RGPD explicite."
    },
    {
        service: 'Matomo / Piwik',
        type: CATEGORIES.ANALYTICS,
        match: /matomo|piwik/i,
        riskLevel: RISK_LEVELS.LOW,
        justification: "Mesure d'audience. Le risque de vie privée dépend fortement de son mode d'hébergement (Cloud vs On-Premise) et de l'anonymisation des IPs."
    },
    // --- Publicité (Advertising) ---
    {
        service: 'Google Ads / DoubleClick',
        type: CATEGORIES.ADVERTISING,
        match: /doubleclick\.net|googleadservices\.com/i,
        riskLevel: RISK_LEVELS.MEDIUM,
        justification: "Réseau publicitaire favorisant le suivi inter-sites (cross-site tracking) des utilisateurs. Impose un recueil strict du consentement."
    },
    {
        service: 'Facebook Pixel',
        type: CATEGORIES.ADVERTISING,
        match: /connect\.facebook\.net/i,
        riskLevel: RISK_LEVELS.MEDIUM,
        justification: "Traceur social transmettant les événements de navigation pour du reciblage, pouvant lier un visiteur à son profil Facebook."
    },
    {
        service: 'Criteo',
        type: CATEGORIES.ADVERTISING,
        match: /criteo\.com/i,
        riskLevel: RISK_LEVELS.MEDIUM,
        justification: "Spécialiste mondial du reciblage (retargeting) basé sur l'historique de navigation produit."
    },
    // --- Marketing Automation ---
    {
        service: 'HubSpot',
        type: CATEGORIES.MARKETING,
        match: /hubspot\.com|hs-scripts\.com/i,
        riskLevel: RISK_LEVELS.MEDIUM,
        justification: "Outil CRM pouvant lier l'historique de navigation anonyme à un profil utilisateur formellement identifié (après remplissage d'un formulaire)."
    },
    {
        service: 'Marketo',
        type: CATEGORIES.MARKETING,
        match: /marketo\.com/i,
        riskLevel: RISK_LEVELS.MEDIUM,
        justification: "Plateforme de marketing automation d'entreprise collectant le comportement de navigation pour du scoring (B2B/B2C)."
    },
    // --- Session Replay (Fort Enjeu) ---
    {
        service: 'Hotjar',
        type: CATEGORIES.SESSION_REPLAY,
        match: /hotjar\.com/i,
        riskLevel: RISK_LEVELS.HIGH,
        justification: "Outil reproduisant visuellement la session (clics, scrolls). S'il est mal configuré, il peut capturer involontairement les saisies clavier contenant des données sensibles (mots de passe, numéros de carte)."
    },
    {
        service: 'FullStory',
        type: CATEGORIES.SESSION_REPLAY,
        match: /fullstory\.com/i,
        riskLevel: RISK_LEVELS.HIGH,
        justification: "Enregistrement profond du DOM utilisateur. Le risque de captation accidentelle de données à caractère personnel (PII) est extrêmement élevé sans masque (masking) proactif."
    }
];

/**
 * Extrait le nom de domaine propre à partir d'une chaîne (qui peut être une URL complète ou juste un domaine).
 * @param {string} input 
 * @returns {string} Le domaine extrait.
 */
function extractHostname(input) {
    if (!input || typeof input !== 'string') return '';
    try {
        // Ajout d'un schéma fictif si manquant pour forcer le parsing de l'URL
        const urlStr = input.startsWith('http') ? input : `http://${input}`;
        return new URL(urlStr).hostname;
    } catch (e) {
        return input;
    }
}

/**
 * Analyse une liste de domaines tiers pour y détecter des services connus.
 * 
 * @param {Array<string>} domainsList - Tableau contenant des domaines ou des URLs (ex: thirdPartyDomains et/ou thirdPartyScripts).
 * @param {Array<Object>} [customPatterns] - Liste optionnelle de règles pour écraser ou étendre les comportements par défaut.
 * @returns {Array<Object>} Un tableau structuré de constats sur les tiers détectés.
 */
function analyzeThirdParties(domainsList, customPatterns = null) {
    if (!Array.isArray(domainsList)) {
        return [];
    }

    const rules = (customPatterns && Array.isArray(customPatterns)) ? customPatterns : DEFAULT_PATTERNS;
    const detectedServices = new Set();
    const results = [];

    for (const rawEntry of domainsList) {
        if (typeof rawEntry !== 'string') continue;

        const hostname = extractHostname(rawEntry);

        for (const rule of rules) {
            // Vérification de la signature regex
            if (rule.match.test(hostname) || rule.match.test(rawEntry)) {
                
                // On évite les doublons : si le service a déjà été signalé, on ignore les occurences suivantes
                if (!detectedServices.has(rule.service)) {
                    detectedServices.add(rule.service);

                    // On respecte la structure demandée avec une approche prudente
                    results.push({
                        service: rule.service,
                        type: rule.type,
                        riskLevel: rule.riskLevel,
                        justification: rule.justification,
                        evidence: `Correspondance avec l'entrée : ${rawEntry}`
                    });
                }
            }
        }
    }

    return results;
}

// Support pour une utilisation directe en ligne de commande (CLI)
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const raw = JSON.parse(args[0]);
            // raw est censé être un tableau de chaînes, par exemple les thirdPartyDomains
            const results = analyzeThirdParties(raw);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            // Repli : on tente d'analyser l'argument comme un seul domaine en chaîne de caractères
            const results = analyzeThirdParties([args[0]]);
            console.log(JSON.stringify(results, null, 2));
        }
    }
}

module.exports = {
    CATEGORIES,
    RISK_LEVELS,
    DEFAULT_PATTERNS,
    analyzeThirdParties
};
