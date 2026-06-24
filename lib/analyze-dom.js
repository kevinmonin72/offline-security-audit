function analyzeDom(domData, pageUrl) {
    const findings = [];
    if (!domData) return findings;

    // Mixed Content Forms
    if (pageUrl && pageUrl.startsWith('https:')) {
        domData.forms.forEach(form => {
            if (!form.isActionHttps) {
                findings.push({
                    title: "Formulaire sur protocole HTTP non sécurisé",
                    description: `Le formulaire pointant vers "${form.action}" transmet des données via HTTP en clair depuis une page HTTPS (Mixed Content).`,
                    severity: "critical",
                    tags: ["dom", "mixed-content", "privacy"]
                });
            }
        });
    }

    // Mots de passe
    const hasFormsWithPassword = domData.forms.some(f => f.hasPasswordField);
    if (hasFormsWithPassword && pageUrl && !pageUrl.startsWith('https:')) {
        findings.push({
            title: "Mot de passe saisi sur HTTP (En clair)",
            description: "Un champ de mot de passe est présent sur une page non-sécurisée (HTTP). Les identifiants peuvent être interceptés.",
            severity: "critical",
            tags: ["dom", "password", "privacy"]
        });
    }

    // Referer / Sensitive URL
    if (domData.sensitiveUrl) {
        findings.push({
            title: "Fuite potentielle de données dans l'URL",
            description: "L'URL de la page contient des mots-clés sensibles (token=, key=, password=). Ces données peuvent fuiter via l'en-tête Referer vers des sites tiers.",
            severity: "high",
            tags: ["dom", "privacy", "referer"]
        });
    }

    // Hidden Inputs
    const suspectHidden = domData.hiddenInputs.filter(i => {
        const name = i.name.toLowerCase();
        return name.includes('token') || name.includes('key') || name.includes('secret') || name.includes('pwd');
    });

    if (suspectHidden.length > 0) {
        findings.push({
            title: "Présence de tokens/clés dans les champs cachés",
            description: `Les champs cachés suivants semblent contenir des données sensibles ou des jetons : ${suspectHidden.map(i => i.name).join(', ')}.`,
            severity: "low",
            tags: ["dom", "tokens"]
        });
    }

    return findings;
}

module.exports = { analyzeDom };
