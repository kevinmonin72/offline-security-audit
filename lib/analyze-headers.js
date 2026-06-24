/**
 * Module offline d'analyse des en-têtes HTTP.
 * 
 * Analyse heuristique prudente pour repérer les défauts de configuration.
 */

/**
 * Normalise les clés d'un objet d'en-têtes HTTP en minuscules.
 * @param {Object} rawHeaders 
 * @returns {Object}
 */
function normalizeHeaders(rawHeaders) {
    if (!rawHeaders || typeof rawHeaders !== 'object') {
        return {};
    }
    const normalized = {};
    for (const [key, value] of Object.entries(rawHeaders)) {
        const stringValue = Array.isArray(value) ? value.join(', ') : String(value);
        normalized[key.toLowerCase()] = stringValue;
    }
    return normalized;
}

/**
 * Analyse les en-têtes de sécurité avec des heuristiques fines.
 * @param {Object} rawHeaders 
 * @returns {Array<Object>}
 */
function analyzeHeaders(rawHeaders) {
    const headers = normalizeHeaders(rawHeaders);
    const findings = [];

    // =====================================================================
    // 1. Strict-Transport-Security (HSTS)
    // =====================================================================
    const hsts = headers['strict-transport-security'];
    if (!hsts) {
        findings.push({
            id: 'HSTS_MISSING',
            category: 'Security Headers',
            severity: 'High',
            title: 'Absence de Strict-Transport-Security (HSTS)',
            description: "L'en-tête HSTS n'est pas configuré. Sans cette instruction, les connexions initiales ou les liens explicites en 'http://' ne sont pas automatiquement convertis en HTTPS par le navigateur, laissant une fenêtre d'opportunité pour une interception réseau.",
            evidence: 'En-tête manquant',
            recommendation: "Ajoutez l'en-tête 'Strict-Transport-Security: max-age=31536000; includeSubDomains' si l'ensemble de votre domaine et de vos sous-domaines supportent HTTPS de manière stable."
        });
    } else {
        const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
        if (!maxAgeMatch) {
            findings.push({
                id: 'HSTS_MALFORMED',
                category: 'Security Headers',
                severity: 'Medium',
                title: 'Directive max-age introuvable dans HSTS',
                description: "L'en-tête HSTS est présent mais la directive obligatoire 'max-age' semble absente ou mal formatée. Le navigateur pourrait ignorer l'en-tête.",
                evidence: `strict-transport-security: ${hsts}`,
                recommendation: "Assurez-vous que la valeur inclut 'max-age=DUREE_EN_SECONDES'."
            });
        } else {
            const maxAge = parseInt(maxAgeMatch[1], 10);
            if (maxAge < 31536000) { // < 1 an
                findings.push({
                    id: 'HSTS_WEAK_MAX_AGE',
                    category: 'Security Headers',
                    severity: 'Low',
                    title: 'Durée de rétention HSTS (max-age) relativement courte',
                    description: "La durée spécifiée par 'max-age' est inférieure à 1 an (31536000 secondes). Bien que fonctionnelle, une durée plus longue est souvent recommandée pour une protection persistante.",
                    evidence: `max-age=${maxAge}`,
                    recommendation: "Envisagez d'augmenter le 'max-age' à au moins 31536000 une fois le déploiement HTTPS stabilisé."
                });
            }
        }
        
        if (!/includeSubDomains/i.test(hsts)) {
            findings.push({
                id: 'HSTS_NO_SUBDOMAINS',
                category: 'Security Headers',
                severity: 'Info',
                title: 'Absence de la directive includeSubDomains dans HSTS',
                description: "La directive 'includeSubDomains' n'est pas présente. La politique HSTS ne s'appliquera donc pas aux sous-domaines, ce qui pourrait les exposer s'ils ne définissent pas eux-mêmes cette politique.",
                evidence: `strict-transport-security: ${hsts}`,
                recommendation: "Si l'architecture le permet, ajoutez '; includeSubDomains' à la configuration HSTS."
            });
        }
    }

    // =====================================================================
    // 2. Content-Security-Policy (CSP)
    // =====================================================================
    const csp = headers['content-security-policy'];
    if (!csp) {
        findings.push({
            id: 'CSP_MISSING',
            category: 'Security Headers',
            severity: 'Medium',
            title: 'Absence de Content-Security-Policy (CSP)',
            description: "L'en-tête CSP n'est pas défini. Une politique de sécurité de contenu permet de restreindre l'origine des ressources autorisées (scripts, styles, images) et de réduire considérablement l'impact de certaines attaques d'injection, comme le XSS.",
            evidence: 'En-tête manquant',
            recommendation: "Définissez une politique CSP prudente, par exemple en démarrant avec 'default-src 'self'' pour n'autoriser par défaut que les ressources de l'origine courante."
        });
    } else {
        const cspLower = csp.toLowerCase();
        
        if (!cspLower.includes('default-src') && !cspLower.includes('script-src') && !cspLower.includes('object-src')) {
            findings.push({
                id: 'CSP_NO_BASE_DIRECTIVES',
                category: 'Security Headers',
                severity: 'Medium',
                title: 'Directives de base manquantes dans le CSP',
                description: "Le CSP défini ne semble pas inclure 'default-src', 'script-src' ni 'object-src'. Sans ces directives fondamentales, la politique peut ne pas bloquer efficacement l'exécution de scripts tiers indésirables.",
                evidence: `content-security-policy: ${csp}`,
                recommendation: "Ajoutez au moins une directive de repli comme 'default-src 'none'' ou 'default-src 'self''."
            });
        }
        
        if (cspLower.includes("'unsafe-inline'")) {
            findings.push({
                id: 'CSP_UNSAFE_INLINE',
                category: 'Security Headers',
                severity: 'Low',
                title: 'Directive permissive unsafe-inline dans le CSP',
                description: "La présence de 'unsafe-inline' autorise l'exécution de scripts ou de styles directement intégrés dans le code HTML. Cela limite fortement la capacité du CSP à prévenir certaines attaques XSS.",
                evidence: "Présence de 'unsafe-inline'",
                recommendation: "Si possible, extrayez les scripts inline vers des fichiers externes ou utilisez des nonces cryptographiques / empreintes (hashes)."
            });
        }
        
        if (csp.includes("*")) {
            findings.push({
                id: 'CSP_WILDCARD',
                category: 'Security Headers',
                severity: 'Info',
                title: 'Utilisation de joker (*) dans le CSP',
                description: "Le caractère joker '*' est présent dans la politique. S'il est utilisé dans des contextes sensibles comme 'script-src *', il autorise le chargement de code depuis n'importe quel domaine, affaiblissant ainsi la posture de défense.",
                evidence: "Présence de '*'",
                recommendation: "Vérifiez que le joker n'est pas utilisé pour des directives permettant l'exécution de code. Préférez lister explicitement les domaines de confiance."
            });
        }
    }

    // =====================================================================
    // 3. X-Frame-Options
    // =====================================================================
    const xfo = headers['x-frame-options'];
    if (!xfo) {
        const hasFrameAncestors = csp && csp.toLowerCase().includes('frame-ancestors');
        if (!hasFrameAncestors) {
            findings.push({
                id: 'X_FRAME_OPTIONS_MISSING',
                category: 'Security Headers',
                severity: 'Medium',
                title: 'Absence de protection anti-Clickjacking',
                description: "Ni l'en-tête X-Frame-Options, ni la directive CSP 'frame-ancestors' ne sont présents. L'application pourrait être intégrée dans une iframe tierce malveillante (Clickjacking).",
                evidence: 'En-tête manquant et absence de frame-ancestors',
                recommendation: "Ajoutez l'en-tête 'X-Frame-Options: SAMEORIGIN' ou la directive CSP correspondante."
            });
        }
    } else {
        const xfoVal = xfo.trim().toUpperCase();
        if (xfoVal !== 'DENY' && xfoVal !== 'SAMEORIGIN') {
            if (xfoVal.includes('ALLOW-FROM')) {
                findings.push({
                    id: 'X_FRAME_OPTIONS_DEPRECATED',
                    category: 'Security Headers',
                    severity: 'Low',
                    title: 'Utilisation obsolète de X-Frame-Options: ALLOW-FROM',
                    description: "La directive 'ALLOW-FROM' n'est plus supportée de manière fiable par les navigateurs modernes, qui l'ignoreront souvent complètement.",
                    evidence: `x-frame-options: ${xfo}`,
                    recommendation: "Utilisez 'SAMEORIGIN' ou migrez vers la directive CSP moderne 'frame-ancestors'."
                });
            } else {
                findings.push({
                    id: 'X_FRAME_OPTIONS_INVALID',
                    category: 'Security Headers',
                    severity: 'Medium',
                    title: 'Valeur incohérente pour X-Frame-Options',
                    description: "La valeur fournie n'est ni DENY, ni SAMEORIGIN. Si l'en-tête est défini plusieurs fois ou contient des valeurs séparées par des virgules, il sera souvent ignoré.",
                    evidence: `x-frame-options: ${xfo}`,
                    recommendation: "Assurez-vous qu'une seule valeur stricte et valide (DENY ou SAMEORIGIN) soit définie."
                });
            }
        }
    }

    // =====================================================================
    // 4. X-Content-Type-Options
    // =====================================================================
    const xcto = headers['x-content-type-options'];
    if (!xcto) {
        findings.push({
            id: 'X_CONTENT_TYPE_OPTIONS_MISSING',
            category: 'Security Headers',
            severity: 'Low',
            title: 'Absence de X-Content-Type-Options',
            description: "Sans cet en-tête, les navigateurs peuvent tenter de déduire le type MIME d'un fichier en l'analysant (sniffing), ce qui peut mener à l'exécution de scripts s'ils sont maquillés sous d'autres extensions (ex: image).",
            evidence: 'En-tête manquant',
            recommendation: "Ajoutez systématiquement 'X-Content-Type-Options: nosniff'."
        });
    } else if (xcto.trim().toLowerCase() !== 'nosniff') {
        findings.push({
            id: 'X_CONTENT_TYPE_OPTIONS_INVALID',
            category: 'Security Headers',
            severity: 'Low',
            title: 'Valeur invalide pour X-Content-Type-Options',
            description: "La seule valeur valide et documentée pour cet en-tête est 'nosniff'. Toute autre valeur (y compris avec des fautes de frappe) risque d'être ignorée par le navigateur.",
            evidence: `x-content-type-options: ${xcto}`,
            recommendation: "Corrigez la valeur pour utiliser exactement 'nosniff'."
        });
    }

    // =====================================================================
    // 5. Referrer-Policy
    // =====================================================================
    const rp = headers['referrer-policy'];
    if (!rp) {
        findings.push({
            id: 'REFERRER_POLICY_MISSING',
            category: 'Security Headers',
            severity: 'Low',
            title: 'Absence de Referrer-Policy',
            description: "L'en-tête Referrer-Policy n'est pas défini. Les navigateurs récents appliquent une politique prudente par défaut, mais il reste conseillé de définir explicitement le comportement souhaité pour éviter des fuites accidentelles d'URL.",
            evidence: 'En-tête manquant',
            recommendation: "Utilisez 'strict-origin-when-cross-origin' pour ne partager l'URL complète que vers des origines équivalentes (HTTPS vers HTTPS de même domaine)."
        });
    } else if (rp.toLowerCase().includes('unsafe-url')) {
        findings.push({
            id: 'REFERRER_POLICY_UNSAFE',
            category: 'Security Headers',
            severity: 'Low',
            title: 'Politique permissive Referrer-Policy: unsafe-url',
            description: "La valeur 'unsafe-url' instruit le navigateur d'envoyer l'URL complète vers n'importe quelle destination (même HTTP). Cela peut faire fuiter des données si l'URL contient des paramètres sensibles.",
            evidence: `referrer-policy: ${rp}`,
            recommendation: "Si l'architecture le permet, remplacez par 'strict-origin-when-cross-origin'."
        });
    }

    // =====================================================================
    // 6. Permissions-Policy
    // =====================================================================
    const pp = headers['permissions-policy'];
    if (!pp) {
        findings.push({
            id: 'PERMISSIONS_POLICY_MISSING',
            category: 'Security Headers',
            severity: 'Info',
            title: 'Absence de Permissions-Policy',
            description: "Cet en-tête permet de restreindre explicitement l'accès à certaines fonctionnalités sensibles du navigateur (géolocalisation, caméra, etc.) pour limiter la surface d'attaque.",
            evidence: 'En-tête manquant',
            recommendation: "Pour une approche de défense en profondeur, déclarez cet en-tête pour bloquer les fonctionnalités que votre site n'utilise pas."
        });
    }

    // =====================================================================
    // 7. X-XSS-Protection
    // =====================================================================
    const xxss = headers['x-xss-protection'];
    if (xxss && xxss !== '0') {
        findings.push({
            id: 'X_XSS_PROTECTION_ENABLED',
            category: 'Security Headers',
            severity: 'Info',
            title: 'En-tête historique X-XSS-Protection non désactivé',
            description: "L'en-tête X-XSS-Protection activé (valeur différente de '0') est considéré comme obsolète. Les filtres intégrés des anciens navigateurs peuvent parfois être abusés pour créer de nouvelles failles (side-channel).",
            evidence: `x-xss-protection: ${xxss}`,
            recommendation: "Il est aujourd'hui recommandé de le désactiver explicitement ('X-XSS-Protection: 0') et de se fier uniquement à une politique CSP robuste."
        });
    }

    return findings;
}

// Support pour une utilisation directe en ligne de commande (CLI)
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const raw = JSON.parse(args[0]);
            const results = analyzeHeaders(raw);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit être un JSON valide d'en-têtes HTTP." }, null, 2));
            process.exit(1);
        }
    }
}

module.exports = {
    normalizeHeaders,
    analyzeHeaders
};
