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
                    recommendation: `Modifiez l'attribut action du formulaire pour pointer vers une URL HTTPS (${form.action.replace('http:', 'https:')}).`,
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
            recommendation: "Migrez immédiatement la page de connexion sous HTTPS et forcez la redirection (HSTS).",
            severity: "critical",
            tags: ["dom", "password", "privacy"]
        });
    }

    // Referer / Sensitive URL
    if (domData.sensitiveUrl) {
        findings.push({
            title: "Fuite potentielle de données dans l'URL",
            description: "L'URL de la page contient des mots-clés sensibles (token=, key=, password=). Ces données peuvent fuiter via l'en-tête Referer vers des sites tiers.",
            recommendation: "Utilisez la méthode POST pour la transmission de jetons ou mots de passe, et évitez de les passer dans l'URL (GET).",
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
            recommendation: "Vérifiez que ces tokens (CSRF ou autres) sont correctement générés par session de manière imprédictible et vérifiés côté serveur.",
            severity: "low",
            tags: ["dom", "tokens"]
        });
    }

    // Black Hat SEO (Hidden Links)
    if (domData.hiddenLinks && domData.hiddenLinks.length > 0) {
        findings.push({
            title: "Pratique Black Hat SEO (Liens cachés détectés)",
            description: `Le site contient ${domData.hiddenLinks.length} lien(s) rendu(s) invisible(s) à l'utilisateur (display:none, opacité à 0, hors de l'écran). C'est souvent utilisé pour manipuler le référencement (Dark links) ou injecté par des malwares.`,
            recommendation: "Vérifiez le code source de votre CMS pour supprimer ces liens s'ils ont été injectés à votre insu. Privilégiez des liens visibles et pertinents.",
            severity: "medium",
            tags: ["dom", "seo", "black-hat"]
        });
    }

    // Code Source - Clés API
    if (domData.potentialApiKeys && domData.potentialApiKeys.length > 0) {
        findings.push({
            title: "Fuite de clés d'API dans le code source",
            description: `Le code source de la page (ou un script en ligne) contient des chaînes de caractères ressemblant à des clés d'API (Stripe, Google, AWS) : ${domData.potentialApiKeys.join(', ')}`,
            recommendation: "Révoquez ces clés immédiatement. Le code front-end ne doit jamais contenir de clés secrètes. Utilisez un backend pour faire vos appels d'API.",
            severity: "critical",
            tags: ["dom", "source-code", "api-key"]
        });
    }

    // Code Source - Commentaires HTML suspects
    if (domData.htmlComments && domData.htmlComments.length > 0) {
        const suspectComments = domData.htmlComments.filter(c => {
            const low = c.toLowerCase();
            return low.includes('password') || low.includes('pwd') || low.includes('secret') || low.includes('todo') || low.includes('fixme') || low.includes('admin') || low.includes('test');
        });

        if (suspectComments.length > 0) {
            findings.push({
                title: "Informations sensibles dans les commentaires HTML",
                description: `Des commentaires HTML (<!-- ... -->) laissés par les développeurs contiennent des mots-clés suspects (TODO, password, admin, etc.), révélant des informations sur l'architecture.`,
                recommendation: "Nettoyez vos templates HTML en production pour supprimer les commentaires de développement et les instructions internes.",
                severity: "low",
                tags: ["dom", "source-code", "comments"]
            });
        }
    }

    // NOUVEAU : Emails exposés
    if (domData.exposedEmails && domData.exposedEmails.length > 0) {
        findings.push({
            title: "Adresses e-mail exposées publiquement",
            description: `Le code source de la page contient ${domData.exposedEmails.length} adresse(s) e-mail en clair (ex: ${domData.exposedEmails[0]}). Elles peuvent être aspirées par des robots spammeurs.`,
            recommendation: "Masquez les adresses e-mail (ex: en utilisant des formulaires de contact) ou obfusquez-les techniquement pour éviter le scraping par des bots.",
            severity: "low",
            tags: ["dom", "privacy", "email"]
        });
    }

    // NOUVEAU : LocalStorage et SessionStorage
    if (domData.storageKeys) {
        const suspectStorage = [...(domData.storageKeys.local || []), ...(domData.storageKeys.session || [])].filter(k => {
            const low = k.toLowerCase();
            return low.includes('token') || low.includes('jwt') || low.includes('auth') || low.includes('session');
        });

        if (suspectStorage.length > 0) {
            findings.push({
                title: "Stockage potentiel de tokens dans Local/Session Storage",
                description: `Des clés suspectes (jetons d'authentification) ont été détectées dans le stockage local du navigateur : ${suspectStorage.join(', ')}.`,
                recommendation: "Le LocalStorage est vulnérable aux attaques XSS. Il est fortement recommandé d'utiliser des cookies HttpOnly pour stocker les jetons de session (JWT, Auth).",
                severity: "medium",
                tags: ["dom", "privacy", "localstorage"]
            });
        }
    }

    return findings;
}

module.exports = { analyzeDom };
