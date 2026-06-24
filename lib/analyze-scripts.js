/**
 * Module offline d'inventaire et d'analyse des scripts tiers.
 * 
 * Ce module normalise une liste d'URLs de scripts, en extrait les hôtes (hostnames),
 * et regroupe ces scripts sous de grandes familles connues pour une lecture simplifiée.
 */

// Liste des familles de scripts demandées avec leurs signatures (URL ou Hostname)
const SCRIPT_FAMILIES = [
    { 
        name: 'Google Analytics', 
        // Identifie les scripts historiques (analytics.js, ga.js) et les modernes via gtag
        regex: /google-analytics\.com|googletagmanager\.com\/gtag/i 
    },
    { 
        name: 'Google Tag Manager', 
        // Identifie spécifiquement le conteneur GTM (gtm.js)
        regex: /googletagmanager\.com\/gtm/i 
    },
    { 
        name: 'DoubleClick', 
        regex: /doubleclick\.net|googleadservices\.com/i 
    },
    { 
        name: 'Facebook Pixel', 
        regex: /connect\.facebook\.net/i 
    },
    { 
        name: 'Hotjar', 
        regex: /hotjar\.com/i 
    },
    { 
        name: 'HubSpot', 
        regex: /hs-scripts\.com|hubspot\.com|js\.hs-analytics\.net/i 
    },
    { 
        name: 'Segment', 
        regex: /cdn\.segment\.com/i 
    },
    { 
        name: 'LinkedIn Insight', 
        regex: /snap\.licdn\.com/i 
    },
    { 
        name: 'TikTok Pixel', 
        regex: /analytics\.tiktok\.com/i 
    },
    { 
        name: 'Criteo', 
        regex: /criteo\.com|criteo\.net/i 
    }
];

/**
 * Analyse, normalise et classe une liste d'URLs de scripts tiers.
 * 
 * @param {Array<string>} scriptsList - La liste des URLs brutes des scripts collectés.
 * @returns {Array<Object>} Un inventaire propre et dédupliqué, regroupé par famille.
 */
function analyzeScripts(scriptsList) {
    if (!Array.isArray(scriptsList)) {
        return [];
    }

    // Utilisation d'une Map pour faciliter le regroupement (déduplication) par famille
    const inventory = new Map();

    for (const rawUrl of scriptsList) {
        if (typeof rawUrl !== 'string' || !rawUrl.trim()) continue;

        let urlObj;
        try {
            // Normalisation de base via l'API URL intégrée de Node.js
            urlObj = new URL(rawUrl.trim());
        } catch (e) {
            // Si l'URL n'a pas de protocole (ex: "//www.google-analytics.com/analytics.js")
            try {
                const prefixedUrl = rawUrl.trim().startsWith('//') ? `https:${rawUrl.trim()}` : `http://${rawUrl.trim()}`;
                urlObj = new URL(prefixedUrl);
            } catch (err) {
                // Si ce n'est définitivement pas parsable comme URL, on ignore
                continue; 
            }
        }

        const hostname = urlObj.hostname;
        const normalizedUrl = urlObj.href;

        let detectedFamily = 'Autre (Non reconnu)';

        // Rapprochement avec les familles connues
        for (const family of SCRIPT_FAMILIES) {
            // La vérification se fait sur l'URL normalisée entière, car certains services
            // (comme GTM et Analytics) partagent le même domaine mais ont des chemins différents.
            if (family.regex.test(normalizedUrl)) {
                detectedFamily = family.name;
                break;
            }
        }

        // Initialisation de la famille dans l'inventaire si elle n'existe pas encore
        if (!inventory.has(detectedFamily)) {
            inventory.set(detectedFamily, {
                family: detectedFamily,
                hosts: new Set(),
                scripts: new Set()
            });
        }

        // Ajout des informations (les Sets garantissent la déduplication au sein de la famille)
        const familyEntry = inventory.get(detectedFamily);
        familyEntry.hosts.add(hostname);
        familyEntry.scripts.add(normalizedUrl);
    }

    // Transformation de la Map et de ses Sets en un tableau JSON propre et simple
    const results = [];
    for (const [familyName, data] of inventory.entries()) {
        results.push({
            family: familyName,
            hosts: Array.from(data.hosts),
            scripts: Array.from(data.scripts)
        });
    }

    // On trie le résultat de façon à avoir les familles reconnues en premier, puis "Autre" à la fin
    results.sort((a, b) => {
        if (a.family === 'Autre (Non reconnu)') return 1;
        if (b.family === 'Autre (Non reconnu)') return -1;
        return a.family.localeCompare(b.family);
    });

    return results;
}

// Support pour une utilisation directe en ligne de commande (CLI)
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const raw = JSON.parse(args[0]);
            const results = analyzeScripts(raw);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            // En cas d'échec de parse JSON, on tente d'analyser l'argument comme une URL unique
            const results = analyzeScripts([args[0]]);
            console.log(JSON.stringify(results, null, 2));
        }
    }
}

module.exports = {
    SCRIPT_FAMILIES,
    analyzeScripts
};
