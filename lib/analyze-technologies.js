/**
 * Module offline de classification des technologies détectées.
 * 
 * Ce module a pour unique but de structurer l'inventaire technique pour fournir
 * un contexte lisible lors de la restitution d'un audit. 
 * Note de sécurité : La simple présence d'une technologie n'implique pas de vulnérabilité.
 */

// Catégories formelles de classification
const CATEGORIES = {
    CMS: 'CMS',
    JS_FRAMEWORK: 'Framework JS',
    ANALYTICS: 'Analytics',
    CDN: 'CDN',
    MARKETING: 'Marketing',
    PAYMENT: 'Paiement',
    SECURITY: 'Sécurité',
    OTHER: 'Autre'
};

// Dictionnaire de rapprochement (basé sur des Regex simples)
const TECH_DICTIONARY = [
    // --- CMS / E-commerce ---
    { regex: /wordpress/i, category: CATEGORIES.CMS },
    { regex: /drupal/i, category: CATEGORIES.CMS },
    { regex: /joomla/i, category: CATEGORIES.CMS },
    { regex: /magento/i, category: CATEGORIES.CMS },
    { regex: /shopify/i, category: CATEGORIES.CMS },
    { regex: /prestashop/i, category: CATEGORIES.CMS },
    { regex: /wix/i, category: CATEGORIES.CMS },

    // --- Frameworks JavaScript ---
    { regex: /react/i, category: CATEGORIES.JS_FRAMEWORK },
    { regex: /vue\.?js/i, category: CATEGORIES.JS_FRAMEWORK },
    { regex: /angular/i, category: CATEGORIES.JS_FRAMEWORK },
    { regex: /svelte/i, category: CATEGORIES.JS_FRAMEWORK },
    { regex: /next\.?js/i, category: CATEGORIES.JS_FRAMEWORK },
    { regex: /nuxt\.?js/i, category: CATEGORIES.JS_FRAMEWORK },
    { regex: /jquery/i, category: CATEGORIES.JS_FRAMEWORK },

    // --- Analytics ---
    { regex: /google analytics/i, category: CATEGORIES.ANALYTICS },
    { regex: /matomo|piwik/i, category: CATEGORIES.ANALYTICS },
    { regex: /plausible/i, category: CATEGORIES.ANALYTICS },
    { regex: /datadog|new relic/i, category: CATEGORIES.ANALYTICS },

    // --- CDN ---
    { regex: /cloudflare/i, category: CATEGORIES.CDN },
    { regex: /akamai/i, category: CATEGORIES.CDN },
    { regex: /fastly/i, category: CATEGORIES.CDN },
    { regex: /amazon cloudfront|aws cloudfront/i, category: CATEGORIES.CDN },

    // --- Marketing ---
    { regex: /hubspot/i, category: CATEGORIES.MARKETING },
    { regex: /mailchimp/i, category: CATEGORIES.MARKETING },
    { regex: /marketo/i, category: CATEGORIES.MARKETING },
    { regex: /salesforce/i, category: CATEGORIES.MARKETING },

    // --- Paiement ---
    { regex: /stripe/i, category: CATEGORIES.PAYMENT },
    { regex: /paypal/i, category: CATEGORIES.PAYMENT },
    { regex: /adyen/i, category: CATEGORIES.PAYMENT },
    { regex: /braintree/i, category: CATEGORIES.PAYMENT },

    // --- Sécurité & Anti-bot ---
    { regex: /recaptcha/i, category: CATEGORIES.SECURITY },
    { regex: /hcaptcha/i, category: CATEGORIES.SECURITY },
    { regex: /auth0/i, category: CATEGORIES.SECURITY },
    { regex: /okta/i, category: CATEGORIES.SECURITY },
    { regex: /datadome/i, category: CATEGORIES.SECURITY }
];

/**
 * Analyse une liste de technologies (chaînes ou objets) et les regroupe par catégorie.
 * 
 * @param {Array<string|Object>} techList - La liste des technologies brutes provenant de l'audit.
 * @returns {Object} Un objet regroupant les technologies par catégorie.
 */
function analyzeTechnologies(techList) {
    if (!Array.isArray(techList)) {
        return {};
    }

    // Initialisation d'une structure complète (on nettoiera les catégories vides à la fin)
    const summary = {};
    for (const cat of Object.values(CATEGORIES)) {
        summary[cat] = [];
    }

    for (const item of techList) {
        if (!item) continue;

        // Tolérance : extraction du nom de la techno qu'il s'agisse d'une chaîne ou d'un objet (Wappalyzer renvoie souvent des objets)
        let techName = '';
        if (typeof item === 'string') {
            techName = item;
        } else if (typeof item === 'object') {
            // Si c'est un objet, on cherche un champ 'name' en priorité, sinon on stringifie
            techName = item.name || Object.values(item).join(' ');
        }

        if (!techName.trim()) continue;

        let matchedCategory = CATEGORIES.OTHER;

        // Rapprochement catégoriel
        for (const rule of TECH_DICTIONARY) {
            if (rule.regex.test(techName)) {
                matchedCategory = rule.category;
                break; // On s'arrête à la première correspondance valide
            }
        }

        summary[matchedCategory].push(techName.trim());
    }

    // Nettoyage : on supprime les catégories ne contenant aucune technologie détectée
    // et on dé-doublonne les technologies au sein de chaque catégorie restante.
    const cleanSummary = {};
    for (const [category, items] of Object.entries(summary)) {
        if (items.length > 0) {
            cleanSummary[category] = Array.from(new Set(items));
        }
    }

    return cleanSummary;
}

// Support pour une utilisation directe en ligne de commande (CLI)
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const raw = JSON.parse(args[0]);
            const results = analyzeTechnologies(raw);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit être un JSON contenant une liste de technologies." }, null, 2));
            process.exit(1);
        }
    }
}

module.exports = {
    CATEGORIES,
    TECH_DICTIONARY,
    analyzeTechnologies
};
