/**
 * Module offline d'analyse de sécurité des cookies.
 * 
 * Prend en entrée un tableau de cookies (généré par parse-cookies.js)
 * et retourne une liste de findings structurés selon des règles de sécurité.
 */

/**
 * Analyse un tableau de cookies et génère des constats de sécurité (findings).
 * 
 * @param {Array<Object>} parsedCookies - Le tableau d'objets cookies normalisés.
 * @returns {Array<Object>} Un tableau structuré de findings détaillant les erreurs.
 */
function analyzeCookies(parsedCookies) {
    if (!Array.isArray(parsedCookies)) {
        return [];
    }

    const findings = [];

    for (const cookie of parsedCookies) {
        // Ignorer les éventuels objets mal formés
        if (!cookie || !cookie.name) continue;

        const cookieName = cookie.name;
        const isSession = cookie.isSession === true;
        
        // La preuve (evidence) sert à identifier facilement la source de l'anomalie
        const evidence = `Cookie: ${cookieName}`;

        if (isSession) {
            // =====================================================================
            // RÈGLES POUR LES COOKIES DE SESSION
            // Un cookie de session a des enjeux de sécurité très élevés.
            // =====================================================================

            // Règle : Cookie de session sans Secure -> Critique
            if (!cookie.secure) {
                findings.push({
                    id: 'SESSION_COOKIE_MISSING_SECURE',
                    category: 'Cookies Security',
                    severity: 'Critical',
                    title: `Cookie de session vulnérable à l'interception en clair (Secure manquant)`,
                    description: `Le cookie de session '${cookieName}' ne possède pas le flag 'Secure'. Il sera transmis en clair sur le réseau si l'utilisateur navigue accidentellement sur une URL HTTP non chiffrée. Cela permet à un attaquant positionné sur le réseau (ex: Wi-Fi public) d'intercepter le cookie et d'usurper la session de l'utilisateur.`,
                    evidence: evidence,
                    recommendation: `Ajoutez impérativement l'attribut 'Secure' au cookie '${cookieName}' pour exiger qu'il ne soit transmis que via des connexions chiffrées (HTTPS).`
                });
            }

            // Règle : Cookie de session sans HttpOnly -> Critique
            if (!cookie.httpOnly) {
                findings.push({
                    id: 'SESSION_COOKIE_MISSING_HTTPONLY',
                    category: 'Cookies Security',
                    severity: 'Critical',
                    title: `Cookie de session exposé au JavaScript (HttpOnly manquant)`,
                    description: `Le flag 'HttpOnly' est absent sur le cookie de session '${cookieName}'. Le cookie est donc accessible via le code JavaScript du navigateur (ex: document.cookie). C'est la cible principale lors de l'exploitation d'une vulnérabilité Cross-Site Scripting (XSS), permettant le vol de session.`,
                    evidence: evidence,
                    recommendation: `Ajoutez impérativement l'attribut 'HttpOnly' au cookie '${cookieName}' pour interdire sa lecture par les scripts côté client.`
                });
            }

            // Règle : Cookie de session sans SameSite -> Warning (Medium)
            if (!cookie.sameSite) {
                findings.push({
                    id: 'SESSION_COOKIE_MISSING_SAMESITE',
                    category: 'Cookies Security',
                    severity: 'Medium',
                    title: `Avertissement : Cookie de session sans protection explicite SameSite`,
                    description: `Le cookie de session '${cookieName}' ne définit pas d'attribut 'SameSite'. Même si les navigateurs récents appliquent un comportement 'Lax' par défaut, cette absence d'explicitation laisse l'application à la merci des comportements hétérogènes des navigateurs et augmente les risques d'attaques par Cross-Site Request Forgery (CSRF).`,
                    evidence: evidence,
                    recommendation: `Définissez explicitement l'attribut 'SameSite' à 'Strict' (idéal) ou 'Lax' (si la navigation multi-site légitime l'exige) sur le cookie '${cookieName}'.`
                });
            }

        } else {
            // =====================================================================
            // RÈGLES POUR LES COOKIES STANDARDS (NON SESSION)
            // L'enjeu est moindre, on remonte des avertissements (Warning).
            // =====================================================================

            // Règle : Cookie non session sans Secure -> Warning (Low)
            if (!cookie.secure) {
                findings.push({
                    id: 'COOKIE_MISSING_SECURE',
                    category: 'Cookies Security',
                    severity: 'Low',
                    title: `Avertissement : Cookie classique sans flag Secure`,
                    description: `Le cookie '${cookieName}' n'a pas le flag 'Secure'. Bien qu'il ne s'agisse pas d'un identifiant de session, ce cookie pourrait fuiter des informations sur le comportement de l'utilisateur ou ses préférences lors d'une connexion HTTP en clair.`,
                    evidence: evidence,
                    recommendation: `Dans un environnement HTTPS, il est recommandé d'ajouter l'attribut 'Secure' à tous les cookies, sans exception, pour éviter toute fuite réseau.`
                });
            }

            // Règle : Cookie non session sans HttpOnly -> Warning (Low)
            if (!cookie.httpOnly) {
                findings.push({
                    id: 'COOKIE_MISSING_HTTPONLY',
                    category: 'Cookies Security',
                    severity: 'Low',
                    title: `Avertissement : Cookie classique accessible via JavaScript`,
                    description: `Le cookie '${cookieName}' est lisible par le code JavaScript car il lui manque le flag 'HttpOnly'. Laisser un cookie accessible au front-end est une mauvaise pratique à moins que le code client (ex: React, Vue) n'ait techniquement besoin de le lire.`,
                    evidence: evidence,
                    recommendation: `Sauf si le cookie '${cookieName}' doit strictement être manipulé par le JavaScript côté client, ajoutez-y l'attribut 'HttpOnly' par principe de moindre privilège.`
                });
            }
        }
    }

    return findings;
}

// Support pour une utilisation directe en ligne de commande (CLI)
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        try {
            const raw = JSON.parse(args[0]);
            const results = analyzeCookies(raw);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit être un JSON contenant un tableau de cookies normalisés." }, null, 2));
            process.exit(1);
        }
    }
}

module.exports = {
    analyzeCookies
};
