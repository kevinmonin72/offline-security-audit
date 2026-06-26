/**
 * Logique partagée de vulgarisation et de rendu du tableau des failles.
 * Utilisée à la fois par le rapport téléchargeable (render-report.js) et par
 * l'aperçu à l'écran (public/app.js) afin que les deux soient identiques.
 *
 * Le tableau utilise uniquement des styles inline : aucune dépendance à une
 * feuille de style externe, il s'affiche donc à l'identique partout.
 */

const SEV_COLORS = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#94a3b8' };

/** Échappe le HTML pour neutraliser toute donnée auditée injectable. */
function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

/**
 * Métadonnées d'affichage de la sévérité. Les "Moyennes" retenues par le
 * filtre sont des menaces proches d'une "Élevée" : on les distingue (⬆).
 */
function sevMeta(severity, borderline) {
    if (borderline) return { label: 'Moyenne ⬆', note: 'proche élevée', color: '#f59e0b' };
    switch (severity) {
        case 'Critical': return { label: 'Critique', note: '', color: '#ef4444' };
        case 'High':     return { label: 'Élevée',   note: '', color: '#f97316' };
        case 'Medium':   return { label: 'Moyenne',  note: '', color: '#eab308' };
        default:         return { label: severity || 'Info', note: '', color: '#94a3b8' };
    }
}

/** Déduit le "critère" (catégorie lisible) d'une faille. */
function deriveCategory(f) {
    const cat = String(f.category || '').toLowerCase();
    const id = String(f.id || '').toUpperCase();
    const tit = String(f.title || '').toLowerCase();
    const tags = (f.tags || []).map((t) => String(t).toLowerCase());

    if (tags.includes('api-key') || tags.includes('source-code')) return 'Fuite de secrets';
    if (cat.includes('header') || id.includes('HSTS') || id.includes('CSP') || id.includes('X_FRAME') || id.includes('REFERRER') || id.includes('PERMISSIONS') || id.includes('CONTENT_TYPE') || id.includes('XSS_PROTECTION')) return 'En-têtes de sécurité';
    if (cat.includes('cookie') || id.includes('COOKIE') || id.includes('SESSION')) return 'Cookies & Sessions';
    if (cat.includes('tls') || cat.includes('ssl') || cat.includes('cleartext') || tags.includes('mixed-content') || tags.includes('password')) return 'Chiffrement HTTPS';
    if (tags.includes('seo') || tags.includes('black-hat')) return 'SEO / Réputation';
    if (tags.includes('localstorage') || tags.includes('tokens')) return 'Gestion des jetons';
    if (tags.includes('email') || tags.includes('privacy') || tit.includes('traceur') || tit.includes('pixel') || tit.includes('cookie')) return 'Confidentialité / RGPD';
    return f.category || f.type || 'Autre';
}

/**
 * Traduit une faille technique en une phrase claire pour un non-technicien
 * (coeur du lead magnet). Du plus spécifique au plus général.
 */
function vulgarize(f) {
    const id = String(f.id || '').toUpperCase();
    const title = String(f.title || '').toLowerCase();
    const tags = (f.tags || []).map((t) => String(t).toLowerCase());

    if (id.includes('API') || tags.includes('api-key')) return "Une clé secrète est visible directement dans le code du site. N'importe qui peut la copier et s'en servir à vos frais.";
    if (tags.includes('password') || title.includes('mot de passe')) return "Les mots de passe circulent en clair sur le réseau : une personne mal intentionnée peut les intercepter.";
    if (title.includes('pixel') || title.includes('traceur') || title.includes('hotjar') || title.includes('criteo') || title.includes('hubspot') || title.includes('tag manager')) return "Un traceur publicitaire collecte les données de vos visiteurs. Sans consentement clair, c'est un risque RGPD/CNIL.";
    if (id.includes('HSTS') || tags.includes('mixed-content') || title.includes('http ')) return "La connexion peut basculer en non-chiffré : un pirate sur le même Wi-Fi pourrait espionner les échanges.";
    if (id.includes('CSP')) return "Protection insuffisante contre l'injection de code piégé (vol de données, fausses publicités).";
    if (id.includes('X_FRAME') || id.includes('FRAME')) return "Votre site peut être affiché dans une fausse page pour tromper vos visiteurs (clickjacking).";
    if (id.includes('CONTENT_TYPE')) return "Le navigateur pourrait exécuter un fichier malveillant déguisé en simple image.";
    if (id.includes('REFERRER')) return "L'adresse de vos pages, parfois sensible, peut fuiter vers d'autres sites.";
    if (id.includes('PERMISSIONS')) return "Caméra, micro et géolocalisation ne sont pas explicitement bloqués pour les scripts.";
    if (id.includes('XSS_PROTECTION')) return "Une ancienne protection du navigateur, aujourd'hui obsolète et risquée, est restée active.";
    if (id.includes('HTTPONLY')) return "Un script malveillant peut lire ce cookie et voler la session de l'utilisateur.";
    if (id.includes('SECURE')) return "L'identifiant de connexion peut circuler en clair et être intercepté.";
    if (id.includes('SAMESITE') || id.includes('SESSION')) return "Le site est plus exposé aux actions forcées à l'insu de l'utilisateur (attaque CSRF).";
    if (tags.includes('seo') || tags.includes('black-hat')) return "Des liens cachés polluent votre référencement Google — souvent le signe d'un piratage.";
    if (tags.includes('email')) return "Vos adresses e-mail sont visibles et peuvent être aspirées par des robots spammeurs.";
    if (tags.includes('comments')) return "Des notes internes de développeurs traînent dans le code source, lisibles par tous.";
    if (tags.includes('localstorage') || tags.includes('tokens')) return "Des jetons de sécurité sont stockés d'une façon vulnérable au vol par un script.";

    return f.description || "Écart de sécurité à corriger pour durcir votre site.";
}

/** Correctif technique brut (court, sans explication). */
function techFix(f) {
    const id = String(f.id || '').toUpperCase();
    const cat = String(f.category || '');
    if (cat.includes('Headers') || cat.includes('Security Headers') || id.includes('HSTS') || id.includes('CSP') || id.includes('X_FRAME') || id.includes('CONTENT_TYPE') || id.includes('REFERRER') || id.includes('PERMISSIONS') || id.includes('XSS_PROTECTION')) {
        return "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'  •  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
    }
    if (cat.includes('Cookies') || id.includes('COOKIE') || id.includes('SESSION')) {
        return "Set-Cookie: __Host-SESSIONID=<val>; SameSite=Strict; Secure; HttpOnly; Partitioned";
    }
    return f.recommendation || 'Appliquer les directives de durcissement ANSSI.';
}

const TH = 'background:#0b1220;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;font-size:0.72rem;font-weight:800;text-align:left;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.1);';
const TD = 'padding:16px;border-bottom:1px solid rgba(255,255,255,0.06);vertical-align:top;color:#cbd5e1;';

/**
 * Construit le tableau large des failles (HTML inline-stylé).
 * @param {Array} findings - failles déjà filtrées et triées (Critical>High>Medium)
 * @param {Array} [eliminated] - faux positifs rejetés (optionnel)
 */
function buildFindingsTable(findings, eliminated) {
    if (!findings || findings.length === 0) {
        return `<div style="padding:26px;background:rgba(34,197,94,0.1);border:1px solid #22c55e;border-radius:14px;color:#22c55e;font-weight:600;text-align:center;">✅ Architecture conforme. Aucune faille critique, élevée ou moyenne-haute détectée.</div>`;
    }

    let rows = '';
    findings.forEach((f) => {
        const sev = f.severity || f.riskLevel || 'Info';
        const borderline = sev === 'Medium';
        const m = sevMeta(sev, borderline);
        const category = deriveCategory(f);
        const plain = vulgarize(f);
        const fix = techFix(f);
        const rowBg = borderline ? 'background:rgba(245,158,11,0.06);' : '';
        const dash = borderline ? 'dashed' : 'solid';

        rows += `
            <tr style="border-left:5px ${dash} ${m.color};${rowBg}">
                <td style="${TD}width:120px;white-space:nowrap;">
                    <span style="display:inline-block;padding:4px 10px;border-radius:20px;font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.4px;border:1px solid ${m.color}66;background:${m.color}1f;color:${m.color};">${escapeHtml(m.label)}</span>
                    ${m.note ? `<span style="display:block;margin-top:5px;font-size:0.68rem;color:#f59e0b;font-style:italic;">${escapeHtml(m.note)}</span>` : ''}
                </td>
                <td style="${TD}width:150px;"><span style="display:inline-block;background:rgba(56,189,248,0.12);color:#38bdf8;padding:4px 10px;border-radius:8px;font-size:0.76rem;font-weight:600;">${escapeHtml(category)}</span></td>
                <td style="${TD}width:200px;color:#fff;font-weight:600;">${escapeHtml(f.title || 'Vulnérabilité détectée')}</td>
                <td style="${TD}color:#e2e8f0;line-height:1.5;">${escapeHtml(plain)}</td>
                <td style="${TD}min-width:230px;"><code style="font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:0.78rem;color:#38bdf8;word-break:break-word;white-space:normal;display:block;background:#0f172a;padding:10px;border-radius:8px;border:1px solid #334155;">${escapeHtml(fix)}</code></td>
            </tr>`;
    });

    let html = `
        <div style="width:100%;overflow-x:auto;border-radius:16px;border:1px solid rgba(255,255,255,0.08);box-shadow:0 10px 25px rgba(0,0,0,0.3);margin-bottom:18px;">
            <table style="width:100%;min-width:760px;border-collapse:collapse;background:#1e293b;font-size:0.9rem;">
                <thead>
                    <tr>
                        <th style="${TH}">Criticité</th>
                        <th style="${TH}">Critère</th>
                        <th style="${TH}">Faille</th>
                        <th style="${TH}">Ce que ça signifie pour vous</th>
                        <th style="${TH}">Correctif technique</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:18px;font-size:0.8rem;color:#94a3b8;margin-bottom:30px;padding:4px 2px;">
            <span style="display:inline-flex;align-items:center;gap:7px;"><span style="width:12px;height:12px;border-radius:3px;display:inline-block;background:#ef4444;"></span>Critique</span>
            <span style="display:inline-flex;align-items:center;gap:7px;"><span style="width:12px;height:12px;border-radius:3px;display:inline-block;background:#f97316;"></span>Élevée</span>
            <span style="display:inline-flex;align-items:center;gap:7px;"><span style="width:12px;height:12px;border-radius:3px;display:inline-block;background:#f59e0b;border:1px dashed #fbbf24;"></span>Moyenne ⬆ (proche d'une élevée)</span>
        </div>`;

    if (eliminated && eliminated.length > 0) {
        let elimRows = '';
        eliminated.forEach((fp) => {
            elimRows += `
                <tr style="border-left:5px solid #64748b;opacity:0.75;">
                    <td style="${TD}width:120px;"><span style="display:inline-block;padding:4px 10px;border-radius:20px;font-size:0.7rem;font-weight:800;background:#64748b30;color:#cbd5e1;">REJETÉ</span></td>
                    <td style="${TD}color:#94a3b8;text-decoration:line-through;" colspan="2">${escapeHtml(fp.finding && fp.finding.title ? fp.finding.title : 'Anomalie réconciliée')}</td>
                    <td style="${TD}color:#4ade80;" colspan="2">🛡️ ${escapeHtml(fp.reason || 'Invalidé lors du contrôle.')}</td>
                </tr>`;
        });
        html += `
        <div style="margin:10px 0 8px 0;font-size:1rem;font-weight:700;color:#94a3b8;">🗑️ Faux positifs écartés (${eliminated.length})</div>
        <div style="width:100%;overflow-x:auto;border-radius:14px;border:1px solid rgba(255,255,255,0.06);margin-bottom:20px;">
            <table style="width:100%;min-width:600px;border-collapse:collapse;background:#0f172a;font-size:0.85rem;">
                <tbody>${elimRows}</tbody>
            </table>
        </div>`;
    }

    return html;
}

module.exports = {
    SEV_COLORS,
    escapeHtml,
    sevMeta,
    deriveCategory,
    vulgarize,
    techFix,
    buildFindingsTable
};
