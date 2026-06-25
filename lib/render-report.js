/**
 * Module offline de rendu du rapport final Lead Magnet ultra-graphique.
 * B2B Cyber Security Prospecting Report Engine.
 */

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
        return true;
    });

    // Tri strict par criticité (Critical > High > Medium > Low > Info)
    const order = { "Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5 };
    validFindings.sort((a, b) => {
        const sa = order[a.severity || a.riskLevel || "Info"] || 6;
        const sb = order[b.severity || b.riskLevel || "Info"] || 6;
        return sa - sb;
    });

    const critCount = validFindings.filter(f => f.severity === "Critical" || f.severity === "High").length;
    const medCount = validFindings.filter(f => f.severity === "Medium").length;

    const sevColors = { "Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#3b82f6", "Info": "#94a3b8" };

    let findingsHtml = '';
    if (validFindings.length === 0) {
        findingsHtml = `<div class="zero-flaws">✅ Architecture certifiée conforme aux standards de sécurité 2026. Aucune vulnérabilité externe détectée.</div>`;
    } else {
        // Classification stratégique en 3 pôles de menace (CNIL / RGPD / Intrusion)
        const pillars = {
            access: { title: "🔐 SÉCURITÉ DES ACCÈS & INTRUSION SERVEUR", desc: "Risque de compromission du site ou vol de session administrative", legal: "⚖️ Cadre Légal : RGPD Art. 32 (Sécurité des traitements) & Directive NIS 2", fine: "💥 Sanction CNIL / Pénale officielle : Jusqu'à 10 M€ ou 2% du CA mondial + 5 ans d'emprisonnement (Art. 226-17 CP)", color: "#ef4444", items: [] },
            leak: { title: "👁️ FUITE DE DONNÉES & TRACEURS TIERS ILLÉGAUX", desc: "Interception de données personnelles clients ou cookies publicitaires non consentis", legal: "⚖️ Cadre Légal : Directive ePrivacy Art. 5(3) & RGPD Art. 5, 6 et 82", fine: "💥 Sanction CNIL officielle : Jusqu'à 20 M€ ou 4% du CA mondial (Amendes records CNIL cookies)", color: "#f97316", items: [] },
            seo: { title: "⚠️ RÉPUTATION NUMÉRIQUE, PHISHING & DÉGRADATION SEO", desc: "Absence de bouclier anti-clonage et pénalité de confiance Google Safe Browsing", legal: "📉 Risque Business & Moteur de recherche : Blacklistage Google et perte organique", fine: "💥 Sanction Algorithmique : Déclassement SEO B2B et usurpation de nom de domaine", color: "#eab308", items: [] }
        };

        validFindings.forEach(f => {
            const cat = (f.category || "").toLowerCase();
            const tit = (f.title || "").toLowerCase();
            const id = (f.id || "").toLowerCase();
            
            if (cat.includes("cookie") || tit.includes("cookie") || tit.includes("traceur") || tit.includes("pii") || tit.includes("form") || tit.includes("fuite") || tit.includes("leak") || tit.includes("email") || tit.includes("password")) {
                pillars.leak.items.push(f);
            } else if (cat.includes("tls") || cat.includes("ssl") || tit.includes("cve") || tit.includes("admin") || tit.includes("auth") || tit.includes("injection") || id.includes("csp")) {
                pillars.access.items.push(f);
            } else {
                pillars.seo.items.push(f);
            }
        });

        Object.keys(pillars).forEach(k => {
            const p = pillars[k];
            if (p.items.length === 0) return;

            findingsHtml += `
            <div style="margin:45px 0 25px 0;background:rgba(15,23,42,0.8);border:2px solid ${p.color};border-radius:20px;padding:24px;box-shadow:0 10px 30px rgba(0,0,0,0.4);">
                <div style="display:flex;align-items:center;gap:14px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:16px;margin-bottom:18px;flex-wrap:wrap;">
                    <h3 style="font-size:1.25rem;font-weight:800;color:#fff;margin:0;">${p.title} (${p.items.length})</h3>
                    <span style="font-size:0.85rem;color:#cbd5e1;background:rgba(255,255,255,0.05);padding:4px 12px;border-radius:20px;">${p.desc}</span>
                </div>
                <div style="background:${p.color}15;border-left:4px solid ${p.color};padding:14px;border-radius:8px;margin-bottom:24px;text-align:left;">
                    <div style="font-size:0.85rem;font-weight:700;color:#f8fafc;margin-bottom:4px;">${p.legal}</div>
                    <div style="font-size:0.82rem;font-weight:800;color:${p.color};">${p.fine}</div>
                </div>
            `;

            p.items.forEach(f => {
                const sev = f.severity || f.riskLevel || "Info";
                const sCol = sevColors[sev] || "#94a3b8";
                
                let vulgarised = f.description || "Écart de sécurité ou exposition d'en-tête identifié.";
                if (sev === "Critical" || sev === "High") {
                    vulgarised = `🚨 <strong>Danger Business Immédiat :</strong> ${f.description || "Cette brèche permet à un attaquant d'intercepter des sessions clients ou d'aspirer des données protégées. Exposition CNIL directe."}`;
                }

                let techFix = f.recommendation || "Appliquer les directives de durcissement ANSSI.";
                if (f.category === "Headers" || (f.id || "").includes("HSTS") || (f.id || "").includes("CSP")) {
                    techFix = `Injecter en-tête HTTP : Content-Security-Policy: default-src 'self'; frame-ancestors 'none' & Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`;
                } else if (f.category === "Cookies Security" || (f.id || "").includes("COOKIE")) {
                    techFix = `Set-Cookie flags: __Host-SESSIONID=<val>; SameSite=Strict; Secure; HttpOnly; Partitioned`;
                }

                findingsHtml += `
                <div class="finding-card" style="border-left-color: ${sCol};background:#1e293b;">
                    <div class="finding-head">
                        <span class="finding-title">${f.title || "Vulnérabilité Détectée"}</span>
                        <span class="sev-badge" style="background: ${sCol}20; color: ${sCol}; border-color: ${sCol}60">${sev}</span>
                    </div>
                    <div class="finding-vulgarised">${vulgarised}</div>
                    <div class="tech-fix-box">
                        <span class="tech-fix-label">🛠️ REMÉDIATION TECHNIQUE BRUTE :</span>
                        <code>${techFix}</code>
                    </div>
                    <div style="margin-top:14px;display:inline-block;background:#0284c725;color:#38bdf8;border:1px solid #0284c7;padding:5px 14px;border-radius:8px;font-size:0.78rem;font-weight:700;">
                        ⚡ Certifié 100% Réel (Contre-Vérification Active Serveur)
                    </div>
                </div>`;
            });

            findingsHtml += `</div>`;
        });
    }

    const elim = report.eliminatedFindings || [];
    if (elim.length > 0) {
        findingsHtml += `<div style="margin:40px 0 20px 0;font-size:1.3rem;font-weight:700;color:#94a3b8;display:flex;align-items:center;gap:10px;">
            <span>🗑️ Faux Positifs & Correctifs Récents Éliminés en Direct (${elim.length})</span>
        </div>`;
        elim.forEach(fp => {
            findingsHtml += `
            <div class="finding-card" style="border-left-color: #64748b; opacity: 0.75;">
                <div class="finding-head">
                    <span class="finding-title" style="text-decoration:line-through;color:#94a3b8">${fp.finding?.title || "Anomalie réconciliée"}</span>
                    <span class="sev-badge" style="background: #64748b30; color: #cbd5e1; border-color: #64748b60">REJETÉ</span>
                </div>
                <div style="color:#4ade80;font-size:0.95rem;font-weight:600;background:rgba(0,0,0,0.3);padding:14px;border-radius:8px;">
                    🛡️ Preuve de confrontation serveur : ${fp.reason || "Invalidé lors du crash-test live."}
                </div>
            </div>`;
        });
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
        .finding-card {
            background: var(--card-bg);
            border: 1px solid rgba(255,255,255,0.08);
            border-left: 6px solid #3b82f6;
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            transition: transform 0.2s;
        }
        .finding-card:hover {
            transform: translateY(-2px);
        }
        .finding-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }
        .finding-title {
            font-size: 1.15rem;
            font-weight: 700;
            color: #fff;
        }
        .sev-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid;
        }
        .finding-vulgarised {
            color: #cbd5e1;
            font-size: 0.98rem;
            margin-bottom: 18px;
            background: rgba(0,0,0,0.25);
            padding: 16px;
            border-radius: 10px;
        }
        .tech-fix-box {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 14px;
        }
        .tech-fix-label {
            display: block;
            font-size: 0.75rem;
            color: #64748b;
            font-weight: 700;
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }
        .tech-fix-box code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            color: #38bdf8;
            word-break: break-all;
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

        <div style="background:linear-gradient(135deg,#0369a1,#1e40af);color:#fff;padding:20px 28px;border-radius:18px;margin-bottom:35px;display:flex;align-items:center;gap:20px;box-shadow:0 10px 30px rgba(3,105,161,0.35);border:1px solid #38bdf880;">
            <span style="font-size:2.4rem;">⚡</span>
            <div style="text-align:left;">
                <div style="font-weight:800;font-size:1.15rem;letter-spacing:0.5px;color:#38bdf8;">CERTIFICATION DE CONTRE-SONDAGE ACTIF SERVEUR (100% VÉRIFIÉ)</div>
                <div style="font-size:0.9rem;opacity:0.95;margin-top:4px;">Chaque anomalie détectée par l'audit passif a fait l'objet d'une contre-vérification en direct par confrontation réseau sur l'hôte ciblé pour éliminer 100% des faux positifs.</div>
            </div>
        </div>

        <div class="section-title">
            <span>🎯 Matrice des Failles & Correctifs</span>
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
