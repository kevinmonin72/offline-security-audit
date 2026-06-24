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
        sendForAnalysis(e.target.result);
    };
    reader.readAsText(file);
}

async function sendForAnalysis(content) {
    dropZone.classList.add('hidden');
    errorCard.classList.add('hidden');
    resultCard.classList.add('hidden');
    loading.classList.remove('hidden');

    try {
        const res = await fetch('/api/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        const data = await res.json();

        loading.classList.add('hidden');

        if (data.success) {
            scoreBadge.textContent = data.grade;
            // set colors based on grade
            let color = '#3b82f6';
            if (data.grade === 'A') color = '#22c55e';
            else if (data.grade === 'B') color = '#eab308';
            else if (data.grade === 'C') color = '#f97316';
            else color = '#ef4444';
            scoreBadge.style.backgroundColor = color;
            scoreBadge.style.boxShadow = `0 0 20px ${color}80`;

            resultSummary.textContent = data.summary;
            currentHtmlReport = data.html;
            resultCard.classList.remove('hidden');
        } else {
            showError(data.error);
        }
    } catch (e) {
        loading.classList.add('hidden');
        showError("Impossible de contacter le serveur local.");
    }
}

function showError(msg) {
    errorMessage.textContent = msg;
    errorCard.classList.remove('hidden');
    dropZone.classList.remove('hidden'); // allow retry
}

downloadBtn.addEventListener('click', () => {
    if (!currentHtmlReport) return;
    const blob = new Blob([currentHtmlReport], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    // a.download = `audit-local-${new Date().getTime()}.html`; // Optionnel si on veut forcer le dl
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
