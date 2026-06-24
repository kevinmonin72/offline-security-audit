const { importEvidenceString } = require('../lib/import-evidence-browser');
const { analyzeHeaders } = require('../lib/analyze-headers');
const { parseCookies } = require('../lib/parse-cookies');
const { analyzeCookies } = require('../lib/analyze-cookies');
const { analyzeTls } = require('../lib/analyze-tls');
const { analyzeThirdParties } = require('../lib/analyze-third-parties');
const { analyzeScripts } = require('../lib/analyze-scripts');
const { analyzeTechnologies } = require('../lib/analyze-technologies');
const { calculateScore } = require('../lib/score-site');
const { buildRecommendations } = require('../lib/build-recommendations');
const { buildExecutiveSummary } = require('../lib/build-executive-summary');
const { renderHtmlReport } = require('../lib/render-report');

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const loading = document.getElementById('loading');
const resultCard = document.getElementById('result-card');
const errorCard = document.getElementById('error-card');
const scoreBadge = document.getElementById('score-badge');
const resultSummary = document.getElementById('result-summary');
const downloadBtn = document.getElementById('download-btn');
const restartBtn = document.getElementById('restart-btn');
const errorMessage = document.getElementById('error-message');

let currentHtmlReport = null;

// Drag & Drop
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) handleFile(e.target.files[0]);
});

function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        runAnalysisLocally(e.target.result);
    };
    reader.readAsText(file);
}

function runAnalysisLocally(content) {
    dropZone.classList.add('hidden');
    errorCard.classList.add('hidden');
    resultCard.classList.add('hidden');
    loading.classList.remove('hidden');

    setTimeout(() => {
        try {
            const normalizedData = importEvidenceString(content);
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

            loading.classList.add('hidden');
            
            scoreBadge.textContent = reportResult.grade;
            let color = '#3b82f6';
            if (reportResult.grade === 'A') color = '#22c55e';
            else if (reportResult.grade === 'B') color = '#eab308';
            else if (reportResult.grade === 'C') color = '#f97316';
            else color = '#ef4444';
            scoreBadge.style.backgroundColor = color;
            scoreBadge.style.boxShadow = `0 0 20px ${color}80`;

            resultSummary.textContent = executiveSummaryText;
            currentHtmlReport = htmlOutput;
            resultCard.classList.remove('hidden');

        } catch (e) {
            loading.classList.add('hidden');
            showError(e.message);
        }
    }, 500); // Slight delay for UI transition
}

function showError(msg) {
    errorMessage.textContent = msg;
    errorCard.classList.remove('hidden');
    dropZone.classList.remove('hidden');
}

downloadBtn.addEventListener('click', () => {
    if (!currentHtmlReport) return;
    const blob = new Blob([currentHtmlReport], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

restartBtn.addEventListener('click', () => {
    resultCard.classList.add('hidden');
    errorCard.classList.add('hidden');
    dropZone.classList.remove('hidden');
    fileInput.value = '';
    currentHtmlReport = null;
});
