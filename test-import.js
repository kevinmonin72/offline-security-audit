/**
 * test-import.js
 * 
 * Batterie de tests locaux pour le module import-evidence.js.
 * Utilise l'environnement de fichiers temporaires pour émuler des données externes.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { importEvidence } = require('./lib/import-evidence');

const TEMP_DIR = path.join(__dirname, 'test-temp');

function setup() {
    if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);
}

function teardown() {
    if (fs.existsSync(TEMP_DIR)) fs.rmSync(TEMP_DIR, { recursive: true, force: true });
}

function runTest(name, fn) {
    try {
        fn();
        console.log(`✅ PASS : ${name}`);
    } catch (e) {
        console.error(`❌ FAIL : ${name}`);
        console.error(`   -> ${e.message}`);
        process.exitCode = 1;
    }
}

console.log("\n🧪 Tests du module import-evidence (100% offline)...\n");
setup();

// 1. Test sur un JSON brut non standard
runTest("Normalisation d'un JSON avec clés exotiques", () => {
    const filePath = path.join(TEMP_DIR, 'raw-data.json');
    const rawData = {
        target: "https://my-target.com",
        responseHeaders: {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff"
        },
        ssl: { expires: "2030-01-01T00:00:00Z" }
    };
    fs.writeFileSync(filePath, JSON.stringify(rawData));

    const result = importEvidence(filePath);
    
    // Assertions de normalisation
    assert.strictEqual(result.url, "https://my-target.com", "L'URL doit être récupérée depuis 'target'");
    assert.strictEqual(result.headers['content-security-policy'], "default-src 'self'", "Les en-têtes doivent être normalisés et en minuscules");
    assert.strictEqual(result.tls.validTo, "2030-01-01T00:00:00Z", "La date TLS doit être traduite de ssl.expires à tls.validTo");
});

// 2. Test sur un export texte pur (ex: curl)
runTest("Normalisation d'un dump HTTP (Texte Brut)", () => {
    const filePath = path.join(TEMP_DIR, 'curl-output.txt');
    const rawText = `HTTP/2 200
Server: nginx
Set-Cookie: auth_token=xyz; Secure; HttpOnly
Strict-Transport-Security: max-age=31536000
Set-Cookie: theme=dark`;
    
    fs.writeFileSync(filePath, rawText);

    const result = importEvidence(filePath);
    
    assert.strictEqual(result.headers['server'], "nginx");
    assert.strictEqual(result.headers['strict-transport-security'], "max-age=31536000");
    // Doit avoir combiné les deux set-cookie dans un tableau
    assert.strictEqual(result.setCookies.length, 2);
    assert.strictEqual(result.setCookies[0], "auth_token=xyz; Secure; HttpOnly");
});

// 3. Test de gestion d'erreur (Fichier inexistant)
runTest("Rejet gracieux d'un fichier inexistant", () => {
    assert.throws(
        () => importEvidence(path.join(TEMP_DIR, 'ghost.json')),
        /Le fichier d'évidence est introuvable/
    );
});

teardown();
console.log("\nFin des tests d'importation.");
