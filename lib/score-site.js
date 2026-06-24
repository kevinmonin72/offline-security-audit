/**
 * Module offline de calcul du score de sécurité (Security Posture).
 * 
 * Il agrège les findings remontés par les modules spécialisés (en-têtes, cookies, TLS, tiers)
 * et applique un barème de pénalités pour calculer une note sur 100 et un grade lettré (A à F).
 */

const GRADE_THRESHOLDS = [
    { min: 90, grade: 'A' },
    { min: 70, grade: 'B' },
    { min: 50, grade: 'C' },
    { min: 30, grade: 'D' },
    { min: 0,  grade: 'F' }
];

/**
 * Calcule le score global d'un site à partir de ses données de base et des findings générés.
 * 
 * @param {Object} siteData - L'objet du site (provient de input.json, pour vérifier finalUrl).
 * @param {Array<Object>} allFindings - Le tableau contenant la fusion de TOUS les findings générés par nos modules.
 * @returns {Object} Un objet contenant le score numérique, le grade, et le détail des pénalités.
 */
function calculateScore(siteData, allFindings) {
    let score = 100;
    const appliedPenalties = [];

    /**
     * Applique une pénalité au score et la trace.
     */
    function applyPenalty(points, reason, findingId = null) {
        score -= points;
        appliedPenalties.push({
            points: -points, // Stocké en négatif pour plus de lisibilité
            reason: reason,
            findingId: findingId || 'N/A'
        });
    }

    // =====================================================================
    // 1. Vérification globale du protocole (Absence de HTTPS) -> -30
    // =====================================================================
    if (siteData && siteData.finalUrl && siteData.finalUrl.trim().toLowerCase().startsWith('http://')) {
        applyPenalty(30, "Absence de HTTPS : Le site est servi en clair (HTTP).", 'NO_HTTPS_PROTOCOL');
    }

    // =====================================================================
    // 2. Évaluation des Findings (En-têtes, Cookies, TLS, Tiers)
    // =====================================================================
    if (Array.isArray(allFindings)) {
        for (const finding of allFindings) {
            
            // --- EN-TÊTES DE SÉCURITÉ ---
            if (finding.category === 'Security Headers') {
                if (finding.id && finding.id.includes('MISSING')) {
                    applyPenalty(10, `En-tête de sécurité manquant`, finding.id);
                } 
                else if (finding.id && (
                    finding.id.includes('WEAK') || 
                    finding.id.includes('INVALID') || 
                    finding.id.includes('UNSAFE') || 
                    finding.id.includes('MALFORMED') || 
                    finding.id.includes('DEPRECATED') ||
                    finding.id.includes('NO_BASE_DIRECTIVES')
                )) {
                    applyPenalty(5, `En-tête de sécurité faible ou obsolète`, finding.id);
                }
            }

            // --- SÉCURITÉ DES COOKIES ---
            else if (finding.category === 'Cookies Security') {
                if (finding.id === 'SESSION_COOKIE_MISSING_SECURE' || finding.id === 'SESSION_COOKIE_MISSING_HTTPONLY') {
                    // La règle métier : "cookie session sans Secure ou HttpOnly : -20"
                    applyPenalty(20, `Cookie de session critique non protégé (${finding.id.includes('SECURE') ? 'Secure' : 'HttpOnly'} manquant)`, finding.id);
                } 
                else if (finding.id === 'SESSION_COOKIE_MISSING_SAMESITE') {
                    // La règle métier : "cookie session sans SameSite : -10"
                    applyPenalty(10, `Cookie de session sans attribut SameSite`, finding.id);
                }
            }

            // --- SÉCURITÉ TLS ---
            else if (finding.category === 'TLS Security') {
                if (finding.id === 'TLS_CERT_EXPIRED') {
                    applyPenalty(30, "Certificat TLS expiré", finding.id);
                } 
                else if (finding.id === 'TLS_CERT_EXPIRING_SOON_30') {
                    applyPenalty(25, "Certificat TLS expirant dans moins de 30 jours", finding.id);
                } 
                else if (finding.id === 'TLS_CERT_EXPIRING_SOON_60') {
                    applyPenalty(10, "Certificat TLS expirant dans moins de 60 jours", finding.id);
                }
            }

            // --- DOMAINES TIERS ---
            // Les modules "third-parties" renvoient souvent une clé 'type' valant 'Publicité'
            else if (finding.type === 'Publicité') {
                applyPenalty(15, `Tracker publicitaire ou reciblage détecté (${finding.service})`, `THIRDPARTY_ADS_${finding.service}`);
            }

            // --- VULNÉRABILITÉS MANUELLES (issues de input.json brut) ---
            else if (finding.type === 'Cleartext Protocol' && (!siteData || !siteData.finalUrl || !siteData.finalUrl.startsWith('http://'))) {
                // Au cas où une vulnérabilité HTTP a été signalée manuellement mais non captée par finalUrl
                applyPenalty(30, "Protocole en clair (HTTP) détecté manuellement", 'MANUAL_HTTP_CLEARTEXT');
            }
        }
    }

    // =====================================================================
    // 3. Calcul Final
    // =====================================================================
    
    // Le score final doit être borné strictement entre 0 et 100
    const finalScore = Math.max(0, Math.min(100, score));

    // Attribution du Grade lettré
    let finalGrade = 'F';
    for (const threshold of GRADE_THRESHOLDS) {
        if (finalScore >= threshold.min) {
            finalGrade = threshold.grade;
            break;
        }
    }

    return {
        score: finalScore,
        grade: finalGrade,
        penalties: appliedPenalties
    };
}

// Support CLI direct
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 1) {
        try {
            const siteData = JSON.parse(args[0]);
            const findings = JSON.parse(args[1]);
            const results = calculateScore(siteData, findings);
            console.log(JSON.stringify(results, null, 2));
        } catch (e) {
            console.error(JSON.stringify({ error: "Arguments invalides. Usage : node score-site.js '<siteData>' '<findingsArray>'" }, null, 2));
            process.exit(1);
        }
    }
}

module.exports = {
    calculateScore
};
