const http = require('http');
const fs = require('fs');
const path = require('path');
const { importEvidence } = require('./lib/import-evidence');
const { validateData } = require('./lib/validate-input');
const { analyzeHeaders } = require('./lib/analyze-headers');
const { parseCookies } = require('./lib/parse-cookies');
const { analyzeCookies } = require('./lib/analyze-cookies');
const { analyzeTls } = require('./lib/analyze-tls');
const { analyzeThirdParties } = require('./lib/analyze-third-parties');
const { analyzeScripts } = require('./lib/analyze-scripts');
const { analyzeTechnologies } = require('./lib/analyze-technologies');
const { calculateScore } = require('./lib/score-site');
const { buildRecommendations } = require('./lib/build-recommendations');
const { buildExecutiveSummary } = require('./lib/build-executive-summary');
const { renderHtmlReport } = require('./lib/render-report');

const PORT = 3000;

const server = http.createServer((req, res) => {
    // Fichiers statiques
    if (req.method === 'GET') {
        let filePath = path.join(__dirname, 'public', req.url === '/' ? 'index.html' : req.url);
        if (fs.existsSync(filePath)) {
            let ext = path.extname(filePath);
            let contentType = 'text/html';
            if (ext === '.css') contentType = 'text/css';
            if (ext === '.js') contentType = 'text/javascript';
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(fs.readFileSync(filePath));
        } else {
            res.writeHead(404);
            res.end('Not Found');
        }
        return;
    }

    // API d'Analyse 100% Locale
    if (req.method === 'POST' && req.url === '/api/audit') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const payload = JSON.parse(body);
                // Utilisation d'un fichier temporaire local car notre module actuel attend un chemin
                const tempPath = path.join(__dirname, `temp_${Date.now()}.txt`);
                fs.writeFileSync(tempPath, payload.content);

                // Exécution du moteur
                const normalizedData = importEvidence(tempPath);
                let allFindings = [];
                allFindings.push(...analyzeHeaders(normalizedData.headers));
                const parsedCookies = parseCookies(normalizedData.setCookies || []);
                allFindings.push(...analyzeCookies(parsedCookies));
                const auditDate = new Date();
                const tlsResult = analyzeTls(normalizedData.tls, auditDate);
                allFindings.push(...tlsResult.findings);
                const allThirdPartyStrings = [...(normalizedData.thirdPartyDomains || []), ...(normalizedData.thirdPartyScripts || [])];
                allFindings.push(...analyzeThirdParties(allThirdPartyStrings));
                const scriptsInventory = analyzeScripts(normalizedData.thirdPartyScripts || []);
                const techSummary = analyzeTechnologies(normalizedData.technologies || []);

                const scoreResult = calculateScore(normalizedData, allFindings);
                const recommendations = buildRecommendations(allFindings);
                const executiveSummaryText = buildExecutiveSummary(normalizedData.finalUrl || normalizedData.url, scoreResult, allFindings);

                const reportResult = {
                    siteUrl: normalizedData.finalUrl || normalizedData.url,
                    score: scoreResult.score,
                    grade: scoreResult.grade,
                    executiveSummary: executiveSummaryText,
                    tlsSummary: tlsResult.summary,
                    cookies: parsedCookies,
                    thirdParties: analyzeThirdParties(allThirdPartyStrings),
                    recommendations: recommendations,
                    techSummary: techSummary,
                    scriptsInventory: scriptsInventory,
                    findings: allFindings
                };

                const htmlOutput = renderHtmlReport([reportResult]);
                fs.unlinkSync(tempPath); // Nettoyage

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    html: htmlOutput, 
                    summary: executiveSummaryText, 
                    grade: reportResult.grade, 
                    score: reportResult.score 
                }));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
        });
    }
});

server.listen(PORT, () => {
    console.log(`🚀 Interface d'audit local lancée sur : http://localhost:${PORT}`);
    console.log(`(Pressez Ctrl+C pour arrêter le serveur)`);
});
