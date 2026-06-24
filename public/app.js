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

// --- Écoute des événements venant de l'extension Chrome ---
window.addEventListener('ShowLocalsecEmail', (e) => {
    // Si on est dans un autre onglet, on bascule sur l'onglet principal pour l'affichage
    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.add('hidden'));
    const auditTabBtn = document.querySelector('[data-tab="audit-tab"]');
    if (auditTabBtn) auditTabBtn.classList.add('active');
    document.getElementById('audit-tab').classList.remove('hidden');

    dropZone.classList.add('hidden');
    errorCard.classList.add('hidden');
    
    renderSalesEmailView(e.detail);
});

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
            let parsedContent;
            try { parsedContent = JSON.parse(content); } catch(e){}
            
            if (parsedContent && parsedContent.isLocalsecAudit) {
                renderSalesEmailView(parsedContent);
                return;
            }

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

function renderSalesEmailView(data) {
    loading.classList.add('hidden');
    resultCard.classList.remove('hidden');
    
    // Hide default download button for email view
    downloadBtn.style.display = 'none';

    let color = '#3b82f6';
    if (data.grade === 'A') color = '#22c55e';
    else if (data.grade === 'B') color = '#eab308';
    else if (data.grade === 'C') color = '#f97316';
    else color = '#ef4444';

    scoreBadge.textContent = data.grade;
    scoreBadge.style.backgroundColor = color;
    scoreBadge.style.boxShadow = `0 0 20px ${color}80`;

    // Génération du pitch email
    const criticals = data.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    const hasSeo = data.findings.some(f => f.tags && f.tags.includes('seo'));
    const hasPrivacy = data.findings.some(f => f.category === 'Cookies Security' && f.severity === 'high');

    let painPoints = "";
    if (criticals.length > 0) {
        painPoints += `<li>⚠️ **Vulnérabilités critiques détectées** (${criticals.length} problème(s) identifié(s) pouvant compromettre vos données)</li>`;
    }
    if (hasSeo) {
        painPoints += `<li>📉 **Pénalité SEO potentielle** (Pratiques de référencement détectées pouvant vous faire bannir de Google)</li>`;
    }
    if (hasPrivacy) {
        painPoints += `<li>⚖️ **Risque RGPD** (Vos cookies exposent les données de vos utilisateurs)</li>`;
    }
    if (painPoints === "") {
        painPoints = `<li>🔍 **Améliorations de durcissement requises** pour correspondre aux standards 2026.</li>`;
    }

    const emailTemplate = `
Objet : Faille de sécurité et risque de pénalité détectés sur ${new URL(data.siteUrl).hostname}

Bonjour,

En naviguant sur votre site internet (${new URL(data.siteUrl).hostname}), j'ai remarqué quelques problèmes techniques qui exposent actuellement vos utilisateurs et votre activité.

J'ai fait tourner un rapide audit de sécurité externe et votre site obtient la note de **${data.score}/100 (Grade ${data.grade})**.

Voici les risques principaux actuellement visibles publiquement sur votre code :
<ul>
${painPoints}
</ul>

Ces problèmes peuvent non seulement faire fuiter les données de vos clients, mais aussi impacter lourdement votre référencement naturel.

Nous accompagnons les entreprises dans la sécurisation et la mise aux normes de leur architecture web. Seriez-vous disponible mardi prochain pour un échange de 10 minutes afin que je vous montre les détails techniques ?

Cordialement,

*Généré par LocalSec Audit*
    `;

    resultSummary.innerHTML = `
        <h3 style="color: #2c3e50; margin-bottom: 20px;">📧 Modèle d'Email de Prospection</h3>
        <div style="background: #f8f9fa; border: 1px solid #dfe6e9; border-radius: 8px; padding: 25px; font-family: 'Arial', sans-serif; font-size: 14px; line-height: 1.6;">
            ${emailTemplate}
        </div>
        <button id="copy-email-btn" class="btn primary" style="margin-top: 15px; width: 100%;">📋 Copier l'email</button>
    `;

    document.getElementById('copy-email-btn').addEventListener('click', () => {
        // Strip HTML tags for clipboard (keeping formatting where possible)
        const textToCopy = document.createElement('div');
        textToCopy.innerHTML = emailTemplate;
        navigator.clipboard.writeText(textToCopy.innerText).then(() => {
            document.getElementById('copy-email-btn').textContent = "✅ Copié !";
            setTimeout(() => { document.getElementById('copy-email-btn').textContent = "📋 Copier l'email"; }, 2000);
        });
    });
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
    downloadBtn.style.display = 'inline-block';
});

// --- Tab Logic ---
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        // Remove active class from all
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.add('hidden'));
        
        // Add active to clicked
        btn.classList.add('active');
        const targetId = btn.getAttribute('data-tab');
        document.getElementById(targetId).classList.remove('hidden');

        // If URLs tab, load data
        if (targetId === 'urls-tab') {
            loadUrls();
        }
    });
});

const refreshUrlsBtn = document.getElementById('refresh-urls-btn');
const urlListContainer = document.getElementById('url-list-container');

refreshUrlsBtn.addEventListener('click', loadUrls);

async function loadUrls() {
    urlListContainer.innerHTML = '<div class="spinner"></div><p>Chargement des URLs depuis le Cloud...</p>';
    try {
        const res = await fetch('urls-trouvees.txt?v=' + new Date().getTime());
        if (!res.ok) throw new Error('Fichier introuvable. Le bot n\'a peut-être pas encore généré la liste.');
        
        const text = await res.text();
        const urls = text.split('\n').map(u => u.trim()).filter(u => u);

        if (urls.length === 0) {
            urlListContainer.textContent = "Le fichier est vide.";
            return;
        }

        urlListContainer.innerHTML = '';
        
        const fragment = document.createDocumentFragment();
        const savedState = JSON.parse(localStorage.getItem('auditedUrls') || '{}');

        urls.forEach((url, index) => {
            const div = document.createElement('div');
            div.className = 'url-item';
            
            const isChecked = savedState[url] === true;
            if (isChecked) div.classList.add('checked');

            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = isChecked;
            cb.title = "Marquer comme audité";
            
            cb.addEventListener('change', (e) => {
                const state = JSON.parse(localStorage.getItem('auditedUrls') || '{}');
                state[url] = e.target.checked;
                localStorage.setItem('auditedUrls', JSON.stringify(state));
                if (e.target.checked) div.classList.add('checked');
                else div.classList.remove('checked');
            });

            const link = document.createElement('a');
            link.href = url;
            link.target = '_blank';
            link.textContent = url;

            div.appendChild(cb);
            div.appendChild(link);
            fragment.appendChild(div);
        });

        urlListContainer.appendChild(fragment);

    } catch (e) {
        urlListContainer.innerHTML = `<p style="color: #ef4444;">Erreur : ${e.message}</p>`;
    }
}
