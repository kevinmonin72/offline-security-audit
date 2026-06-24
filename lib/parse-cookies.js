/**
 * Module offline de parsing et normalisation des cookies (Set-Cookie).
 * 
 * Il est capable de traiter :
 * - des chaînes de caractères brutes ('Set-Cookie: session=123; Secure')
 * - des objets de cookies déjà partiellement ou totalement parsés (comme dans input.json)
 */

/**
 * Parse une chaîne de caractères brute issue d'un en-tête Set-Cookie.
 * @param {string} cookieStr - La chaîne représentant le cookie.
 * @returns {Object|null} L'objet cookie structuré.
 */
function parseSingleCookieString(cookieStr) {
    if (typeof cookieStr !== 'string' || cookieStr.trim() === '') {
        return null;
    }

    // Séparer les différentes directives par le point-virgule
    const parts = cookieStr.split(';');
    
    // Le premier élément est toujours nom=valeur
    const nameValue = parts.shift().trim();
    const splitIndex = nameValue.indexOf('=');
    
    let name = '';
    let value = '';
    
    if (splitIndex === -1) {
        name = nameValue;
    } else {
        name = nameValue.substring(0, splitIndex).trim();
        value = nameValue.substring(splitIndex + 1).trim();
    }

    const cookieObj = {
        name: name,
        value: value,
        domain: null,
        path: null,
        expires: null,
        maxAge: null,
        secure: false,
        httpOnly: false,
        sameSite: null,
        isSession: false
    };

    // Analyse des directives optionnelles
    parts.forEach(part => {
        const p = part.trim();
        if (!p) return;

        const eqIdx = p.indexOf('=');
        let key = p;
        let val = null;

        if (eqIdx !== -1) {
            key = p.substring(0, eqIdx).trim();
            val = p.substring(eqIdx + 1).trim();
        }

        const lowerKey = key.toLowerCase();

        switch (lowerKey) {
            case 'domain':
                cookieObj.domain = val;
                break;
            case 'path':
                cookieObj.path = val;
                break;
            case 'expires':
                cookieObj.expires = val;
                break;
            case 'max-age':
                cookieObj.maxAge = parseInt(val, 10);
                if (isNaN(cookieObj.maxAge)) cookieObj.maxAge = null;
                break;
            case 'secure':
                cookieObj.secure = true;
                break;
            case 'httponly':
                cookieObj.httpOnly = true;
                break;
            case 'samesite':
                cookieObj.sameSite = val;
                break;
        }
    });

    return applyHeuristics(cookieObj);
}

/**
 * Normalise un cookie déjà présenté sous forme d'objet JSON.
 * @param {Object} obj - L'objet cookie.
 * @returns {Object|null} L'objet cookie structuré et normalisé.
 */
function normalizeCookieObject(obj) {
    if (!obj || typeof obj !== 'object') {
        return null;
    }

    const maxAgeVal = obj.maxAge !== undefined ? obj.maxAge : obj['max-age'];

    const cookieObj = {
        name: obj.name || '',
        value: obj.value || '',
        domain: obj.domain || null,
        path: obj.path || null,
        expires: obj.expires || null,
        maxAge: typeof maxAgeVal === 'number' ? maxAgeVal : (parseInt(maxAgeVal, 10) || null),
        secure: obj.secure === true || String(obj.secure).toLowerCase() === 'true',
        httpOnly: obj.httpOnly === true || obj.httponly === true || String(obj.httpOnly).toLowerCase() === 'true',
        sameSite: obj.sameSite || obj.samesite || null,
        isSession: false
    };

    return applyHeuristics(cookieObj);
}

/**
 * Applique l'heuristique de détection de session sur un objet cookie.
 * @param {Object} cookieObj - L'objet cookie structuré.
 * @returns {Object} L'objet avec le flag isSession mis à jour.
 */
function applyHeuristics(cookieObj) {
    if (!cookieObj || !cookieObj.name) return cookieObj;

    const lowerName = cookieObj.name.toLowerCase();
    
    // Heuristique: recherche de mots-clés typiques de session
    if (
        lowerName.includes('session') || 
        lowerName.includes('sess') || 
        lowerName.includes('sid')
    ) {
        cookieObj.isSession = true;
    }

    return cookieObj;
}

/**
 * Fonction principale du module. Prend en entrée un tableau de cookies (chaînes ou objets)
 * et retourne un tableau d'objets de cookies normalisés et analysés.
 * 
 * @param {Array<string|Object>} cookiesInput - Les cookies à analyser.
 * @returns {Array<Object>} Le tableau de cookies normalisés.
 */
function parseCookies(cookiesInput) {
    if (!cookiesInput) return [];
    
    // Tolérance : si on passe un seul cookie au lieu d'un tableau
    if (!Array.isArray(cookiesInput)) {
        cookiesInput = [cookiesInput];
    }

    const result = [];

    for (const item of cookiesInput) {
        let parsed = null;

        if (typeof item === 'string') {
            parsed = parseSingleCookieString(item);
        } else if (typeof item === 'object' && item !== null) {
            parsed = normalizeCookieObject(item);
        }

        if (parsed) {
            result.push(parsed);
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
            const results = parseCookies(raw);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            // Tentative de parsing en tant que chaîne brute simple si JSON échoue
            const result = parseCookies([args[0]]);
            console.log(JSON.stringify(result, null, 2));
        }
    }
}

module.exports = {
    parseSingleCookieString,
    normalizeCookieObject,
    parseCookies
};
