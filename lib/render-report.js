/**
 * Module offline de rendu du rapport final au format HTML autonome.
 * 
 * Il génère une page HTML (sans aucune dépendance CSS externe) présentant
 * la synthèse des scores et les détails spécifiques de l'audit pour chaque site.
 */

/**
 * Associe un grade à une couleur de charte visuelle.
 */
function getGradeColor(grade) {
    switch (grade) {
        case 'A': return '#2ecc71'; // Vert
        case 'B': return '#3498db'; // Bleu
        case 'C': return '#f1c40f'; // Jaune
        case 'D': return '#e67e22'; // Orange
        case 'F': return '#e74c3c'; // Rouge
        default: return '#95a5a6';  // Gris
    }
}

/**
 * Génère le code HTML complet du rapport.
 * 
 * @param {Array<Object>} reportsArray - Le tableau contenant les résultats consolidés par site.
 * @returns {string} Le code source HTML du rapport.
 */
function renderHtmlReport(reportsArray) {
    if (!Array.isArray(reportsArray) || reportsArray.length === 0) {
        return "<!DOCTYPE html><html lang='fr'><body><h1>Aucune donnée d'audit disponible.</h1></body></html>";
    }

    // Début de l'injection HTML et style Vanilla CSS
    let html = `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit Sécurité Passif</title>
    <style>
        :root {
            --font-main: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            --bg-body: #f4f6f8;
            --color-text: #2c3e50;
            --color-border: #dfe6e9;
        }
        body {
            font-family: var(--font-main);
            background-color: var(--bg-body);
            color: var(--color-text);
            line-height: 1.6;
            margin: 0;
            padding: 40px 20px;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        h1 {
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 50px;
            color: #34495e;
        }
        
        /* Tableau Récapitulatif */
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 60px;
        }
        .summary-table th, .summary-table td {
            padding: 16px 24px;
            text-align: left;
            border-bottom: 1px solid var(--color-border);
        }
        .summary-table th {
            background-color: #2c3e50;
            color: white;
            font-weight: 600;
        }
        .summary-table a {
            color: #2980b9;
            text-decoration: none;
            font-weight: bold;
        }
        .summary-table a:hover {
            text-decoration: underline;
        }

        /* Badge pour la note */
        .badge {
            display: inline-block;
            color: white;
            font-weight: bold;
            padding: 6px 16px;
            border-radius: 20px;
            text-align: center;
            min-width: 30px;
        }

        /* Cartes de Sites */
        .site-card {
            background: white;
            border-radius: 10px;
            padding: 40px;
            margin-bottom: 50px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            border-top: 6px solid #bdc3c7;
        }
        .site-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            border-bottom: 2px solid var(--color-border);
            padding-bottom: 15px;
        }
        .site-title {
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
            margin: 0;
        }
        .executive-summary {
            font-size: 1.15em;
            background: #f8f9fa;
            padding: 20px 25px;
            border-left: 5px solid #34495e;
            border-radius: 0 8px 8px 0;
            margin-bottom: 35px;
            color: #4a5568;
            font-style: italic;
        }

        /* Sections d'information internes */
        .section-title {
            color: #2980b9;
            margin-top: 40px;
            margin-bottom: 15px;
            font-size: 1.3em;
            border-bottom: 1px solid #ecf0f1;
            padding-bottom: 8px;
        }
        
        .info-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .info-list li {
            background: #fdfdfd;
            border: 1px solid #ecf0f1;
            padding: 12px 15px;
            margin-bottom: 8px;
            border-radius: 6px;
        }

        .tag {
            display: inline-block;
            background: #ecf0f1;
            color: #34495e;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            margin-right: 5px;
            font-weight: 600;
        }
        .tag-session {
            background: #f39c12;
            color: white;
        }

        /* Recommandations */
        .reco-block {
            margin-bottom: 25px;
            padding: 20px;
            border-radius: 8px;
            background: #fff;
        }
        .reco-immédiat { border-left: 5px solid #e74c3c; background: #fdf3f2; }
        .reco-important { border-left: 5px solid #e67e22; background: #fef7f1; }
        .reco-amélioration { border-left: 5px solid #3498db; background: #f4f9fd; }
        
        .reco-block h4 { margin-top: 0; font-size: 1.2em; margin-bottom: 15px; }
        .reco-theme { font-weight: bold; color: #2c3e50; margin-top: 15px; margin-bottom: 10px; }
        .reco-ul { margin-top: 5px; padding-left: 20px; }
        .reco-ul li { margin-bottom: 8px; }

    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'Audit de Sécurité</h1>

        <!-- SECTION : TABLEAU RÉCAPITULATIF -->
        <h2>Récapitulatif Global</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Domaine Audité</th>
                    <th>Score de Sécurité</th>
                    <th>Grade</th>
                </tr>
            </thead>
            <tbody>`;

    for (const report of reportsArray) {
        html += `
                <tr>
                    <td><a href="#site-${report.siteUrl}">${report.siteUrl}</a></td>
                    <td><strong>${report.score} / 100</strong></td>
                    <td><span class="badge" style="background-color: ${getGradeColor(report.grade)}">${report.grade}</span></td>
                </tr>`;
    }

    html += `
            </tbody>
        </table>

        <!-- SECTION : DÉTAIL PAR SITE -->
        <h2>Détails par Site</h2>`;

    for (const report of reportsArray) {
        html += `
        <div class="site-card" id="site-${report.siteUrl}" style="border-top-color: ${getGradeColor(report.grade)}">
            <div class="site-header">
                <h3 class="site-title">${report.siteUrl}</h3>
                <div class="badge" style="background-color: ${getGradeColor(report.grade)}; font-size: 1.4em; padding: 8px 24px;">
                    Grade ${report.grade} (${report.score})
                </div>
            </div>
            
            <div class="executive-summary">
                ${report.executiveSummary || 'Résumé exécutif non disponible.'}
            </div>`;

        // --- SECTION : TLS ---
        if (report.tlsSummary) {
            html += `<h4 class="section-title">🔒 Chiffrement des Transports (TLS)</h4>`;
            html += `<ul class="info-list">`;
            html += `<li><strong>Protocole configuré :</strong> ${report.tlsSummary.protocol || 'Non détecté'}</li>`;
            html += `<li><strong>Autorité émettrice :</strong> ${report.tlsSummary.issuer || 'Inconnue'}</li>`;
            
            if (report.tlsSummary.daysRemaining !== null && report.tlsSummary.daysRemaining !== undefined) {
                const days = report.tlsSummary.daysRemaining;
                const statusColor = days < 0 ? '#e74c3c' : (days < 30 ? '#e67e22' : '#27ae60');
                const statusText = days < 0 ? `Expiré depuis ${Math.abs(days)} jours` : `Valide (${days} jours restants)`;
                html += `<li><strong>Statut d'expiration :</strong> <span style="color: ${statusColor}; font-weight: bold;">${statusText}</span></li>`;
            }
            html += `</ul>`;
        }

        // --- SECTION : COOKIES ---
        html += `<h4 class="section-title">🍪 Politiques des Cookies & Sessions</h4>`;
        if (report.cookies && report.cookies.length > 0) {
            html += `<ul class="info-list">`;
            for (const cookie of report.cookies) {
                const flags = [];
                if (cookie.secure) flags.push('<span class="tag">Secure</span>');
                if (cookie.httpOnly) flags.push('<span class="tag">HttpOnly</span>');
                if (cookie.sameSite) flags.push(`<span class="tag">SameSite=${cookie.sameSite}</span>`);
                if (cookie.isSession) flags.push('<span class="tag tag-session">Session</span>');
                
                html += `<li><strong>${cookie.name}</strong> &nbsp; ${flags.length > 0 ? flags.join('') : '<em>Aucune protection (ni Secure, ni HttpOnly)</em>'}</li>`;
            }
            html += `</ul>`;
        } else {
            html += `<p>Aucun cookie détecté par l'audit passif sur cette page.</p>`;
        }

        // --- SECTION : FORMULAIRES, DOM & SEO ---
        html += `<h4 class="section-title">🕵️‍♂️ Sécurité Applicative, DOM & SEO</h4>`;
        const domFindings = report.findings ? report.findings.filter(f => f.tags && f.tags.includes('dom')) : [];
        if (domFindings.length > 0) {
            html += `<ul class="info-list">`;
            for (const f of domFindings) {
                const riskColor = f.severity === 'critical' ? '#e74c3c' : (f.severity === 'high' ? '#e67e22' : '#f1c40f');
                html += `<li>
                            <strong style="color: ${riskColor}">${f.title}</strong> 
                            <div style="margin-top: 5px; color: #7f8c8d; font-size: 0.95em;">${f.description}</div>
                         </li>`;
            }
            html += `</ul>`;
        } else {
            html += `<p>Aucune faille passive détectée au niveau du DOM (Formulaires, SEO, Mixed Content).</p>`;
        }

        // --- SECTION : TIERS ---
        html += `<h4 class="section-title">🌐 Écosystème Tiers & Fuite de données</h4>`;
        if (report.thirdParties && report.thirdParties.length > 0) {
            html += `<ul class="info-list">`;
            for (const tp of report.thirdParties) {
                const riskColor = tp.riskLevel === 'High' ? '#e74c3c' : (tp.riskLevel === 'Medium' ? '#e67e22' : '#27ae60');
                html += `<li>
                            <strong>${tp.service}</strong> <span class="tag">${tp.type}</span> 
                            | Risque RGPD : <strong style="color: ${riskColor}">${tp.riskLevel}</strong>
                            <div style="margin-top: 5px; color: #7f8c8d; font-size: 0.95em;">${tp.justification}</div>
                         </li>`;
            }
            html += `</ul>`;
        } else {
            html += `<p>Aucun domaine de tracking tiers significatif n'a été détecté.</p>`;
        }

        // --- SECTION : RECOMMANDATIONS ---
        if (report.recommendations) {
            html += `<h4 class="section-title">📋 Plan d'Action (Remédiations)</h4>`;
            
            const renderPriorityBox = (prioKey, title, cssClass) => {
                if (report.recommendations[prioKey] && report.recommendations[prioKey].length > 0) {
                    html += `<div class="reco-block ${cssClass}">
                                <h4 style="color: ${cssClass.includes('immédiat') ? '#c0392b' : (cssClass.includes('important') ? '#d35400' : '#2980b9')}">${title}</h4>`;
                    
                    for (const group of report.recommendations[prioKey]) {
                        html += `<div class="reco-theme">${group.theme} :</div><ul class="reco-ul">`;
                        for (const action of group.actions) {
                            html += `<li>${action}</li>`;
                        }
                        html += `</ul>`;
                    }
                    html += `</div>`;
                }
            };

            renderPriorityBox('immédiat', '🛑 Actions Immédiates', 'reco-immédiat');
            renderPriorityBox('important', '⚠️ Actions Importantes', 'reco-important');
            renderPriorityBox('amélioration', '💡 Améliorations de Durcissement', 'reco-amélioration');
            
            if (!report.recommendations['immédiat']?.length && !report.recommendations['important']?.length && !report.recommendations['amélioration']?.length) {
                html += `<p>Aucune recommandation technique à formuler. La posture est excellente.</p>`;
            }
        }

        html += `</div>`; // Fin de la .site-card
    }

    html += `
    </div>
</body>
</html>`;

    return html;
}

// Export du module
module.exports = {
    renderHtmlReport
};
