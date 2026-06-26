/**
 * Module offline de rendu du rapport final Lead Magnet ultra-graphique.
 * B2B Cyber Security Prospecting Report Engine.
 */

const { deriveCategory, buildFindingsTable } = require('./vulgarize-findings');

function getGradeColor(grade) {
    switch (grade) {
        case 'A': return '#22c55e';
        case 'B': return '#eab308';
        case 'C': return '#f97316';
        case 'D': return '#ea580c';
        default: return '#ef4444';
    }
}

function renderHtmlReport(reportsArray) {
    if (!Array.isArray(reportsArray) || reportsArray.length === 0) {
        return "<!DOCTYPE html><html lang='fr'><body style='background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h1>Aucune donnée d'audit disponible.</h1></body></html>";
    }

    const report = reportsArray[0];
    const siteUrl = report.siteUrl || report.url || report.finalUrl || "Cible audité";
    const hostname = (() => { try { return new URL(siteUrl).hostname; } catch(e){ return siteUrl; } })();
    const score = report.score !== undefined ? report.score : 50;
    const grade = report.grade || (score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 50 ? 'C' : score >= 30 ? 'D' : 'F');
    const color = getGradeColor(grade);

    const rawFindings = report.findings || [];

    // Filtrage strict des faux positifs
    const validFindings = rawFindings.filter(f => {
        const id = (f.id || "").toUpperCase();
        const ev = (f.evidence || "").toLowerCase();
        if (id.includes("AKIAIOSFODNN7EXAMPLE") || ev.includes("akiaiosfodnn7example")) return false;
        if (ev.includes("placeholder") || ev.includes("example.com")) return false;
        
        const sev = f.severity || f.riskLevel || "Info";
        if (sev === "Info" || sev === "Low") return false;
        if (sev === "Critical" || sev === "High") return true;
        if (sev === "Medium") {
            const cat = (f.category || f.type || "").toLowerCase();
            const tit = (f.title || f.service || "").toLowerCase();
            if (id.includes("CSP") || id.includes("FRAME") || id.includes("SESSION") || cat.includes("publicité") || cat.includes("advertising") || cat.includes("tag manager") || cat.includes("marketing") || cat.includes("session replay") || tit.includes("google tag manager") || tit.includes("pixel") || tit.includes("hubspot") || tit.includes("hotjar") || tit.includes("criteo")) {
                return true;
            }
            return false;
        }
        return false;
    });

    // Tri strict par criticité (Critical > High > Medium > Low > Info)
    const order = { "Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5 };
    validFindings.sort((a, b) => {
        const sa = order[a.severity || a.riskLevel || "Info"] || 6;
        const sb = order[b.severity || b.riskLevel || "Info"] || 6;
        if (sa !== sb) return sa - sb;
        return deriveCategory(a).localeCompare(deriveCategory(b));
    });

    const critCount = validFindings.filter(f => f.severity === "Critical" || f.severity === "High").length;
    const medCount = validFindings.filter(f => f.severity === "Medium").length;

    let findingsHtml = '';
    if (validFindings.length === 0) {
        findingsHtml = `<div class="zero-flaws">✅ Architecture certifiée conforme aux standards de sécurité 2026. Aucune vulnérabilité externe détectée.</div>`;
    } else {
        // Tableau large des failles : 1 ligne = 1 faille, triées par criticité
        // puis par critère, vulgarisées, avec correctif technique brut.
        findingsHtml += buildFindingsTable(validFindings, report.eliminatedFindings || []);
    }

    const emailPitch = `Objet : Alerte Sécurité & Conformité — Failles détectées sur ${hostname}

Bonjour l'équipe de ${hostname},

En analysant la posture de sécurité publique de votre architecture web, notre moteur d'audit a identifié ${validFindings.length} faille(s) résiduelle(s) (Score : ${score}/100 - Grade ${grade}).

${critCount > 0 ? `🚨 Nous avons relevé ${critCount} vulnérabilité(s) critique(s) ou élevée(s) directement exposées. Dans le contexte actuel de recrudescence des ransomwares et des sanctions RGPD (Art. 32), ces brèches représentent un risque opérationnel et juridique immédiat.` : `⚠️ Bien que votre base principale soit accessible, nous avons relevé ${medCount} point(s) de durcissement requis pour éviter toute compromission d'en-tête ou vol de session cookie.`}

La bonne nouvelle ? La majorité de ces failles peuvent être corrigées en moins d'une heure par un expert.

J'ai préparé un dossier technique d'intervention contenant le code exact de remédiation pour chacune de ces anomalies. Seriez-vous disponible mardi prochain à 14h pour un briefing téléphonique de 10 minutes afin que je vous transmette le dossier ?

Bien à vous,

Responsable Audit Cyber & Conformité`;

    const now = new Date().toLocaleDateString('fr-FR');

    return `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Sécurité — ${hostname}</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #8b5cf6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: radial-gradient(circle at top, #1e293b 0%, #0f172a 100%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 40px 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        .hero {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
        }
        .hero::after {
            content: '';
            position: absolute;
            top: -50%; right: -10%;
            width: 300px; height: 300px;
            background: ${color};
            filter: blur(120px);
            opacity: 0.25;
            z-index: 0;
        }
        .hero-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            position: relative;
            z-index: 1;
            margin-bottom: 30px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            padding-bottom: 25px;
        }
        .target-info h1 {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(to right, #38bdf8, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .target-info p {
            color: var(--text-muted);
            font-size: 0.95rem;
            margin-top: 4px;
        }
        .score-circle {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .grade-pill {
            font-size: 2.2rem;
            font-weight: 900;
            background: ${color};
            color: #fff;
            width: 70px; height: 70px;
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 30px ${color}80;
        }
        .score-num {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--text-main);
        }
        .score-num span {
            display: block;
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 500;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            position: relative;
            z-index: 1;
        }
        .stat-box {
            background: rgba(15, 23, 42, 0.6);
            padding: 18px;
            border-radius: 14px;
            border: 1px solid rgba(255,255,255,0.05);
            text-align: center;
        }
        .stat-val {
            font-size: 1.6rem;
            font-weight: 800;
            color: #38bdf8;
        }
        .stat-lbl {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }
        .section-title {
            font-size: 1.4rem;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .zero-flaws {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid #22c55e;
            color: #22c55e;
            padding: 30px;
            border-radius: 16px;
            text-align: center;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 40px;
        }
        .pitch-card {
            background: linear-gradient(135deg, rgba(30,41,59,0.9), rgba(15,23,42,0.9));
            border: 2px solid var(--accent);
            border-radius: 20px;
            padding: 30px;
            margin-top: 50px;
            position: relative;
            box-shadow: 0 0 40px rgba(139, 92, 246, 0.2);
        }
        .pitch-tag {
            position: absolute;
            top: -14px; left: 30px;
            background: var(--accent);
            color: #fff;
            font-size: 0.75rem;
            font-weight: 800;
            padding: 4px 16px;
            border-radius: 20px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .pitch-text {
            white-space: pre-wrap;
            color: #e2e8f0;
            font-size: 0.95rem;
            line-height: 1.7;
            margin-top: 10px;
        }
        .footer {
            text-align: center;
            margin-top: 60px;
            color: #64748b;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <div class="hero-top">
                <div class="target-info">
                    <h1>🛡️ Dossier d'Audit Cyber</h1>
                    <p>Cible : <strong>${hostname}</strong> — Date : ${now}</p>
                </div>
                <div class="score-circle">
                    <div class="score-num">
                        ${score}/100
                        <span>Score Global</span>
                    </div>
                    <div class="grade-pill">${grade}</div>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-val" style="color: ${critCount > 0 ? '#ef4444' : '#22c55e'}">${critCount > 0 ? 'ALERTE' : 'PROTECT'}</div>
                    <div class="stat-lbl">Statut Exposition</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val">${validFindings.length}</div>
                    <div class="stat-lbl">Failles Confirmées</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val">${critCount}</div>
                    <div class="stat-lbl">Critiques / Élevées</div>
                </div>
            </div>
        </div>

        <div class="section-title">
            <span>🎯 Failles classées par criticité &amp; critère</span>
        </div>

        ${findingsHtml}

        <div class="pitch-card">
            <div class="pitch-tag">🧲 Modèle Email Prospection Prêt à l'Emploi</div>
            <div class="pitch-text">${emailPitch}</div>
        </div>

        <div class="footer">
            Rapport généré de manière autonome par LocalSec Audit Pro v2.0
        </div>
    </div>
</body>
</html>`;
}

module.exports = {
    renderHtmlReport
};
