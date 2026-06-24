/**
 * Suite de tests unitaires locaux sans dépendance.
 * 
 * Ce script valide le bon fonctionnement de nos principaux modules
 * d'analyse hors-ligne en utilisant uniquement le module 'assert' natif de Node.js.
 */

const assert = require('assert');

// Importation des modules internes
const { analyzeHeaders } = require('./lib/analyze-headers');
const { parseCookies } = require('./lib/parse-cookies');
const { analyzeCookies } = require('./lib/analyze-cookies');
const { analyzeTls } = require('./lib/analyze-tls');
const { calculateScore } = require('./lib/score-site');

let passedTests = 0;
let failedTests = 0;

/**
 * Enveloppe d'exécution pour structurer proprement l'affichage.
 */
function runTest(testName, testFn) {
    try {
        testFn();
        console.log(`✅ PASS : ${testName}`);
        passedTests++;
    } catch (e) {
        console.error(`❌ FAIL : ${testName}`);
        
        // Extraction du message d'erreur spécifique ou de la différence d'assertion
        if (e.code === 'ERR_ASSERTION') {
            console.error(`   -> Attendu : ${e.expected} | Reçu : ${e.actual}`);
            console.error(`   -> Message : ${e.message}`);
        } else {
            console.error(`   -> Exception : ${e.message}`);
        }
        failedTests++;
    }
}

console.log("\n🧪 Démarrage de la suite de tests locaux...\n");

// =====================================================================
// 1. TESTS : En-têtes HTTP (Headers)
// =====================================================================
runTest("Headers : Détection stricte de l'absence de HSTS", () => {
    const findings = analyzeHeaders({});
    const hstsFinding = findings.find(f => f.id === 'HSTS_MISSING');
    assert.ok(hstsFinding, "Le finding HSTS_MISSING devrait être présent.");
    assert.strictEqual(hstsFinding.severity, 'High', "L'absence de HSTS doit être de sévérité High.");
});

runTest("Headers : Détection d'un HSTS avec durée faible", () => {
    const findings = analyzeHeaders({ 'strict-transport-security': 'max-age=3600' });
    const hstsFinding = findings.find(f => f.id === 'HSTS_WEAK_MAX_AGE');
    assert.ok(hstsFinding, "Le finding HSTS_WEAK_MAX_AGE devrait être présent car la durée est < 1 an.");
});

// =====================================================================
// 2. TESTS : Cookies & Sessions
// =====================================================================
runTest("Cookies : Détection heuristique d'un cookie de session vulnérable", () => {
    const parsed = parseCookies(["session_id=1234; Path=/"]);
    assert.strictEqual(parsed.length, 1);
    assert.strictEqual(parsed[0].isSession, true, "L'heuristique doit détecter 'session_id' comme cookie de session");
    
    const findings = analyzeCookies(parsed);
    const missingSecure = findings.find(f => f.id === 'SESSION_COOKIE_MISSING_SECURE');
    const missingHttpOnly = findings.find(f => f.id === 'SESSION_COOKIE_MISSING_HTTPONLY');
    
    assert.ok(missingSecure, "Doit alerter de manière critique sur l'absence de Secure");
    assert.ok(missingHttpOnly, "Doit alerter de manière critique sur l'absence de HttpOnly");
});

runTest("Cookies : Tolérance pour un cookie standard parfaitement configuré", () => {
    const parsed = parseCookies(["theme=dark; Secure; HttpOnly; SameSite=Lax"]);
    assert.strictEqual(parsed[0].isSession, false, "Le cookie 'theme' n'est pas un identifiant de session.");
    
    const findings = analyzeCookies(parsed);
    assert.strictEqual(findings.length, 0, "Un cookie parfaitement configuré ne doit générer aucune alerte.");
});

// =====================================================================
// 3. TESTS : Transport et Chiffrement (TLS)
// =====================================================================
runTest("TLS : Validation d'un certificat TLS expiré", () => {
    const tlsObj = { validTo: '2000-01-01T00:00:00Z', authorized: true };
    // On passe une date de référence très ultérieure pour être certain du hors-ligne
    const result = analyzeTls(tlsObj, new Date('2024-01-01T00:00:00Z'));
    
    assert.strictEqual(result.summary.isExpired, true, "Le statut doit être flaggé 'isExpired'");
    const expiredFinding = result.findings.find(f => f.id === 'TLS_CERT_EXPIRED');
    assert.ok(expiredFinding, "Le finding d'expiration absolue doit être remonté.");
});

runTest("TLS : Détection d'une chaîne de confiance invalide (auto-signé)", () => {
    // Certificat valide dans le futur, mais l'autorité l'a refusé
    const tlsObj = { validTo: '2099-01-01T00:00:00Z', authorized: false };
    const result = analyzeTls(tlsObj);
    
    const notAuthFinding = result.findings.find(f => f.id === 'TLS_NOT_AUTHORIZED');
    assert.ok(notAuthFinding, "L'absence d'autorité racine publique doit être alertée en High.");
});

// =====================================================================
// 4. TESTS : Système de Scoring
// =====================================================================
runTest("Scoring : Un site exempt de faille conserve son score de 100 (Grade A)", () => {
    const siteObj = { finalUrl: "https://example.com" };
    const findings = []; // Aucun finding remonté
    const result = calculateScore(siteObj, findings);
    
    assert.strictEqual(result.score, 100);
    assert.strictEqual(result.grade, 'A');
});

runTest("Scoring : Un site en clair (HTTP pur) subit une pénalité maximale (-30)", () => {
    const siteObj = { finalUrl: "http://example.com" };
    const findings = []; // Pas d'autres findings
    const result = calculateScore(siteObj, findings);
    
    assert.strictEqual(result.score, 70); // 100 - 30 = 70
    assert.strictEqual(result.penalties[0].findingId, 'NO_HTTPS_PROTOCOL');
});

// =====================================================================
// BILAN FINAL
// =====================================================================
console.log("\n📊 Bilan de la suite de tests :");
console.log(`✅ Réussis : ${passedTests}`);
console.log(`❌ Échoués : ${failedTests}\n`);

if (failedTests > 0) {
    process.exit(1);
} else {
    process.exit(0);
}
