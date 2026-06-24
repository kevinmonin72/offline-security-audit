/**
 * lib/import-evidence.js
 * 
 * Module hors-ligne d'importation et de normalisation de preuves de sécurité.
 * Gère plusieurs formats : JSON structuré, texte brut (curl), HAR simplifié.
 */

const fs = require('fs');

function importEvidence(filePath) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`IMPORT ERROR : Le fichier d'évidence est introuvable (${filePath}).`);
    }

    const content = fs.readFileSync(filePath, 'utf8').trim();
    if (!content) throw new Error(`IMPORT ERROR : Le fichier est vide.`);

    // 1. Détection HAR (HTTP Archive)
    if (content.includes('"log"') && content.includes('"entries"')) {
        try {
            const parsed = JSON.parse(content);
            if (parsed.log && parsed.log.entries) {
                return _normalizeFromHar(parsed);
            }
        } catch(e) {}
    }

    // 2. Détection JSON Générique
    if (content.startsWith('{') || content.startsWith('[')) {
        try {
            const parsed = JSON.parse(content);
            return _normalizeFromJson(parsed);
        } catch (e) {}
    }

    // 3. Détection Texte Brut
    if (content.toLowerCase().includes('http/') || content.includes(':')) {
        return _normalizeFromRawText(content);
    }

    throw new Error("Format non reconnu. Utilisez du JSON, du HAR ou du texte brut (curl -I).");
}

function _normalizeFromHar(har) {
    const normalized = {
        url: 'http://imported-from-har.local',
        finalUrl: 'http://imported-from-har.local',
        headers: {},
        setCookies: [],
        tls: null,
        thirdPartyDomains: [],
        thirdPartyScripts: [],
        technologies: []
    };

    // On cherche l'entrée principale (la première réponse avec des headers)
    const mainEntry = har.log.entries.find(e => e.response && e.response.headers && e.response.headers.length > 0);
    
    if (mainEntry) {
        normalized.url = mainEntry.request.url || normalized.url;
        normalized.finalUrl = normalized.url;

        // Headers
        mainEntry.response.headers.forEach(h => {
            if (h.name && h.value) {
                normalized.headers[h.name.toLowerCase()] = String(h.value);
            }
        });

        // Cookies
        if (mainEntry.response.cookies) {
            normalized.setCookies = mainEntry.response.cookies.map(c => {
                let str = `${c.name}=${c.value}`;
                if (c.secure) str += '; Secure';
                if (c.httpOnly) str += '; HttpOnly';
                if (c.sameSite) str += `; SameSite=${c.sameSite}`;
                return str;
            });
        }

        // Tiers : on extrait les domaines de toutes les requêtes du HAR
        const domains = new Set();
        har.log.entries.forEach(e => {
            try {
                const u = new URL(e.request.url);
                domains.add(u.hostname);
            } catch(err) {}
        });
        normalized.thirdPartyDomains = Array.from(domains);
    }

    return normalized;
}

function _normalizeFromJson(data) {
    const source = Array.isArray(data) ? data[0] : data;
    const normalized = {
        url: source.url || source.target || source.site || 'http://imported-target.local',
        finalUrl: source.finalUrl || source.url || source.target || 'http://imported-target.local',
        headers: {},
        setCookies: [],
        tls: null,
        thirdPartyDomains: source.thirdPartyDomains || [],
        thirdPartyScripts: source.thirdPartyScripts || [],
        technologies: source.technologies || []
    };

    const sourceHeaders = source.headers || source.responseHeaders;
    if (sourceHeaders) {
        if (Array.isArray(sourceHeaders)) {
            sourceHeaders.forEach(h => {
                if (h.name && h.value) normalized.headers[h.name.toLowerCase()] = String(h.value);
            });
        } else if (typeof sourceHeaders === 'object') {
            for (const [k, v] of Object.entries(sourceHeaders)) {
                normalized.headers[k.toLowerCase()] = String(v);
            }
        }
    }

    const rawCookies = source.cookies || source.setCookies;
    if (rawCookies && Array.isArray(rawCookies)) {
        normalized.setCookies = rawCookies.map(c => {
            if (typeof c === 'string') return c;
            if (c.raw) return c.raw;
            return `${c.name}=${c.value}`;
        });
    } else if (normalized.headers['set-cookie']) {
        const sc = normalized.headers['set-cookie'];
        normalized.setCookies = Array.isArray(sc) ? sc : [sc];
    }

    const cert = source.tls || source.certificate || source.ssl;
    if (cert) {
        normalized.tls = {
            validTo: cert.validTo || cert.notAfter || cert.expires || null,
            authorized: cert.authorized !== undefined ? cert.authorized : true,
            protocol: cert.protocol || cert.version || null,
            issuer: cert.issuer ? (typeof cert.issuer === 'string' ? cert.issuer : cert.issuer.O || cert.issuer.CN) : null
        };
    }

    if (source.technologies && Array.isArray(source.technologies)) {
        normalized.technologies = source.technologies.map(t => typeof t === 'string' ? t : t.name);
    }
    
    return normalized;
}

function _normalizeFromRawText(text) {
    const normalized = {
        url: 'http://imported-from-text.local',
        finalUrl: 'http://imported-from-text.local',
        headers: {},
        setCookies: [],
        tls: null,
        thirdPartyDomains: [],
        thirdPartyScripts: [],
        technologies: []
    };

    const lines = text.split('\n');
    for (const line of lines) {
        if (line.trim().toUpperCase().startsWith('HTTP/')) continue;
        const idx = line.indexOf(':');
        if (idx > 0) {
            const key = line.substring(0, idx).trim().toLowerCase();
            const value = line.substring(idx + 1).trim();
            if (key === 'set-cookie') {
                normalized.setCookies.push(value);
            } else {
                normalized.headers[key] = value;
            }
        }
    }
    return normalized;
}

module.exports = { importEvidence };
