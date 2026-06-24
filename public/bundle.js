(() => {
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
    get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
  }) : x)(function(x) {
    if (typeof require !== "undefined") return require.apply(this, arguments);
    throw Error('Dynamic require of "' + x + '" is not supported');
  });
  var __commonJS = (cb, mod) => function __require2() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };

  // lib/import-evidence-browser.js
  var require_import_evidence_browser = __commonJS({
    "lib/import-evidence-browser.js"(exports, module) {
      function importEvidenceString2(content) {
        content = content.trim();
        if (!content) throw new Error(`Le fichier est vide.`);
        if (content.includes('"log"') && content.includes('"entries"')) {
          try {
            const parsed = JSON.parse(content);
            if (parsed.log && parsed.log.entries) {
              return _normalizeFromHar(parsed);
            }
          } catch (e) {
          }
        }
        if (content.startsWith("{") || content.startsWith("[")) {
          try {
            const parsed = JSON.parse(content);
            return _normalizeFromJson(parsed);
          } catch (e) {
          }
        }
        if (content.toLowerCase().includes("http/") || content.includes(":")) {
          return _normalizeFromRawText(content);
        }
        throw new Error("Format non reconnu. Utilisez du JSON, du HAR ou du texte brut (curl -I).");
      }
      function _normalizeFromHar(har) {
        const normalized = {
          url: "http://imported-from-har.local",
          finalUrl: "http://imported-from-har.local",
          headers: {},
          setCookies: [],
          tls: null,
          thirdPartyDomains: [],
          thirdPartyScripts: [],
          technologies: []
        };
        const mainEntry = har.log.entries.find((e) => e.response && e.response.headers && e.response.headers.length > 0);
        if (mainEntry) {
          normalized.url = mainEntry.request.url || normalized.url;
          normalized.finalUrl = normalized.url;
          mainEntry.response.headers.forEach((h) => {
            if (h.name && h.value) normalized.headers[h.name.toLowerCase()] = String(h.value);
          });
          if (mainEntry.response.cookies) {
            normalized.setCookies = mainEntry.response.cookies.map((c) => {
              let str = `${c.name}=${c.value}`;
              if (c.secure) str += "; Secure";
              if (c.httpOnly) str += "; HttpOnly";
              if (c.sameSite) str += `; SameSite=${c.sameSite}`;
              return str;
            });
          }
          const domains = /* @__PURE__ */ new Set();
          har.log.entries.forEach((e) => {
            try {
              domains.add(new URL(e.request.url).hostname);
            } catch (err) {
            }
          });
          normalized.thirdPartyDomains = Array.from(domains);
        }
        return normalized;
      }
      function _normalizeFromJson(data) {
        const source = Array.isArray(data) ? data[0] : data;
        const normalized = {
          url: source.url || source.target || source.site || "http://imported-target.local",
          finalUrl: source.finalUrl || source.url || source.target || "http://imported-target.local",
          headers: {},
          setCookies: [],
          tls: null,
          thirdPartyDomains: source.thirdPartyDomains || [],
          thirdPartyScripts: source.thirdPartyScripts || [],
          technologies: source.technologies || []
        };
        const sourceHeaders = source.headers || source.responseHeaders;
        if (sourceHeaders) {
          if (Array.isArray(sourceHeaders)) {
            sourceHeaders.forEach((h) => {
              if (h.name && h.value) normalized.headers[h.name.toLowerCase()] = String(h.value);
            });
          } else if (typeof sourceHeaders === "object") {
            for (const [k, v] of Object.entries(sourceHeaders)) {
              normalized.headers[k.toLowerCase()] = String(v);
            }
          }
        }
        const rawCookies = source.cookies || source.setCookies;
        if (rawCookies && Array.isArray(rawCookies)) {
          normalized.setCookies = rawCookies.map((c) => {
            if (typeof c === "string") return c;
            if (c.raw) return c.raw;
            return `${c.name}=${c.value}`;
          });
        } else if (normalized.headers["set-cookie"]) {
          const sc = normalized.headers["set-cookie"];
          normalized.setCookies = Array.isArray(sc) ? sc : [sc];
        }
        const cert = source.tls || source.certificate || source.ssl;
        if (cert) {
          normalized.tls = {
            validTo: cert.validTo || cert.notAfter || cert.expires || null,
            authorized: cert.authorized !== void 0 ? cert.authorized : true,
            protocol: cert.protocol || cert.version || null,
            issuer: cert.issuer ? typeof cert.issuer === "string" ? cert.issuer : cert.issuer.O || cert.issuer.CN : null
          };
        }
        if (source.technologies && Array.isArray(source.technologies)) {
          normalized.technologies = source.technologies.map((t) => typeof t === "string" ? t : t.name);
        }
        return normalized;
      }
      function _normalizeFromRawText(text) {
        const normalized = {
          url: "http://imported-from-text.local",
          finalUrl: "http://imported-from-text.local",
          headers: {},
          setCookies: [],
          tls: null,
          thirdPartyDomains: [],
          thirdPartyScripts: [],
          technologies: []
        };
        const lines = text.split("\n");
        for (const line of lines) {
          if (line.trim().toUpperCase().startsWith("HTTP/")) continue;
          const idx = line.indexOf(":");
          if (idx > 0) {
            const key = line.substring(0, idx).trim().toLowerCase();
            const value = line.substring(idx + 1).trim();
            if (key === "set-cookie") normalized.setCookies.push(value);
            else normalized.headers[key] = value;
          }
        }
        return normalized;
      }
      module.exports = { importEvidenceString: importEvidenceString2 };
    }
  });

  // lib/analyze-headers.js
  var require_analyze_headers = __commonJS({
    "lib/analyze-headers.js"(exports, module) {
      function normalizeHeaders(rawHeaders) {
        if (!rawHeaders || typeof rawHeaders !== "object") {
          return {};
        }
        const normalized = {};
        for (const [key, value] of Object.entries(rawHeaders)) {
          const stringValue = Array.isArray(value) ? value.join(", ") : String(value);
          normalized[key.toLowerCase()] = stringValue;
        }
        return normalized;
      }
      function analyzeHeaders2(rawHeaders) {
        const headers = normalizeHeaders(rawHeaders);
        const findings = [];
        const hsts = headers["strict-transport-security"];
        if (!hsts) {
          findings.push({
            id: "HSTS_MISSING",
            category: "Security Headers",
            severity: "High",
            title: "Absence de Strict-Transport-Security (HSTS)",
            description: "L'en-t\xEAte HSTS n'est pas configur\xE9. Sans cette instruction, les connexions initiales ou les liens explicites en 'http://' ne sont pas automatiquement convertis en HTTPS par le navigateur, laissant une fen\xEAtre d'opportunit\xE9 pour une interception r\xE9seau.",
            evidence: "En-t\xEAte manquant",
            recommendation: "Ajoutez l'en-t\xEAte 'Strict-Transport-Security: max-age=31536000; includeSubDomains' si l'ensemble de votre domaine et de vos sous-domaines supportent HTTPS de mani\xE8re stable."
          });
        } else {
          const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
          if (!maxAgeMatch) {
            findings.push({
              id: "HSTS_MALFORMED",
              category: "Security Headers",
              severity: "Medium",
              title: "Directive max-age introuvable dans HSTS",
              description: "L'en-t\xEAte HSTS est pr\xE9sent mais la directive obligatoire 'max-age' semble absente ou mal format\xE9e. Le navigateur pourrait ignorer l'en-t\xEAte.",
              evidence: `strict-transport-security: ${hsts}`,
              recommendation: "Assurez-vous que la valeur inclut 'max-age=DUREE_EN_SECONDES'."
            });
          } else {
            const maxAge = parseInt(maxAgeMatch[1], 10);
            if (maxAge < 31536e3) {
              findings.push({
                id: "HSTS_WEAK_MAX_AGE",
                category: "Security Headers",
                severity: "Low",
                title: "Dur\xE9e de r\xE9tention HSTS (max-age) relativement courte",
                description: "La dur\xE9e sp\xE9cifi\xE9e par 'max-age' est inf\xE9rieure \xE0 1 an (31536000 secondes). Bien que fonctionnelle, une dur\xE9e plus longue est souvent recommand\xE9e pour une protection persistante.",
                evidence: `max-age=${maxAge}`,
                recommendation: "Envisagez d'augmenter le 'max-age' \xE0 au moins 31536000 une fois le d\xE9ploiement HTTPS stabilis\xE9."
              });
            }
          }
          if (!/includeSubDomains/i.test(hsts)) {
            findings.push({
              id: "HSTS_NO_SUBDOMAINS",
              category: "Security Headers",
              severity: "Info",
              title: "Absence de la directive includeSubDomains dans HSTS",
              description: "La directive 'includeSubDomains' n'est pas pr\xE9sente. La politique HSTS ne s'appliquera donc pas aux sous-domaines, ce qui pourrait les exposer s'ils ne d\xE9finissent pas eux-m\xEAmes cette politique.",
              evidence: `strict-transport-security: ${hsts}`,
              recommendation: "Si l'architecture le permet, ajoutez '; includeSubDomains' \xE0 la configuration HSTS."
            });
          }
        }
        const csp = headers["content-security-policy"];
        if (!csp) {
          findings.push({
            id: "CSP_MISSING",
            category: "Security Headers",
            severity: "Medium",
            title: "Absence de Content-Security-Policy (CSP)",
            description: "L'en-t\xEAte CSP n'est pas d\xE9fini. Une politique de s\xE9curit\xE9 de contenu permet de restreindre l'origine des ressources autoris\xE9es (scripts, styles, images) et de r\xE9duire consid\xE9rablement l'impact de certaines attaques d'injection, comme le XSS.",
            evidence: "En-t\xEAte manquant",
            recommendation: "D\xE9finissez une politique CSP prudente, par exemple en d\xE9marrant avec 'default-src 'self'' pour n'autoriser par d\xE9faut que les ressources de l'origine courante."
          });
        } else {
          const cspLower = csp.toLowerCase();
          if (!cspLower.includes("default-src") && !cspLower.includes("script-src") && !cspLower.includes("object-src")) {
            findings.push({
              id: "CSP_NO_BASE_DIRECTIVES",
              category: "Security Headers",
              severity: "Medium",
              title: "Directives de base manquantes dans le CSP",
              description: "Le CSP d\xE9fini ne semble pas inclure 'default-src', 'script-src' ni 'object-src'. Sans ces directives fondamentales, la politique peut ne pas bloquer efficacement l'ex\xE9cution de scripts tiers ind\xE9sirables.",
              evidence: `content-security-policy: ${csp}`,
              recommendation: "Ajoutez au moins une directive de repli comme 'default-src 'none'' ou 'default-src 'self''."
            });
          }
          if (cspLower.includes("'unsafe-inline'")) {
            findings.push({
              id: "CSP_UNSAFE_INLINE",
              category: "Security Headers",
              severity: "Low",
              title: "Directive permissive unsafe-inline dans le CSP",
              description: "La pr\xE9sence de 'unsafe-inline' autorise l'ex\xE9cution de scripts ou de styles directement int\xE9gr\xE9s dans le code HTML. Cela limite fortement la capacit\xE9 du CSP \xE0 pr\xE9venir certaines attaques XSS.",
              evidence: "Pr\xE9sence de 'unsafe-inline'",
              recommendation: "Si possible, extrayez les scripts inline vers des fichiers externes ou utilisez des nonces cryptographiques / empreintes (hashes)."
            });
          }
          if (csp.includes("*")) {
            findings.push({
              id: "CSP_WILDCARD",
              category: "Security Headers",
              severity: "Info",
              title: "Utilisation de joker (*) dans le CSP",
              description: "Le caract\xE8re joker '*' est pr\xE9sent dans la politique. S'il est utilis\xE9 dans des contextes sensibles comme 'script-src *', il autorise le chargement de code depuis n'importe quel domaine, affaiblissant ainsi la posture de d\xE9fense.",
              evidence: "Pr\xE9sence de '*'",
              recommendation: "V\xE9rifiez que le joker n'est pas utilis\xE9 pour des directives permettant l'ex\xE9cution de code. Pr\xE9f\xE9rez lister explicitement les domaines de confiance."
            });
          }
        }
        const xfo = headers["x-frame-options"];
        if (!xfo) {
          const hasFrameAncestors = csp && csp.toLowerCase().includes("frame-ancestors");
          if (!hasFrameAncestors) {
            findings.push({
              id: "X_FRAME_OPTIONS_MISSING",
              category: "Security Headers",
              severity: "Medium",
              title: "Absence de protection anti-Clickjacking",
              description: "Ni l'en-t\xEAte X-Frame-Options, ni la directive CSP 'frame-ancestors' ne sont pr\xE9sents. L'application pourrait \xEAtre int\xE9gr\xE9e dans une iframe tierce malveillante (Clickjacking).",
              evidence: "En-t\xEAte manquant et absence de frame-ancestors",
              recommendation: "Ajoutez l'en-t\xEAte 'X-Frame-Options: SAMEORIGIN' ou la directive CSP correspondante."
            });
          }
        } else {
          const xfoVal = xfo.trim().toUpperCase();
          if (xfoVal !== "DENY" && xfoVal !== "SAMEORIGIN") {
            if (xfoVal.includes("ALLOW-FROM")) {
              findings.push({
                id: "X_FRAME_OPTIONS_DEPRECATED",
                category: "Security Headers",
                severity: "Low",
                title: "Utilisation obsol\xE8te de X-Frame-Options: ALLOW-FROM",
                description: "La directive 'ALLOW-FROM' n'est plus support\xE9e de mani\xE8re fiable par les navigateurs modernes, qui l'ignoreront souvent compl\xE8tement.",
                evidence: `x-frame-options: ${xfo}`,
                recommendation: "Utilisez 'SAMEORIGIN' ou migrez vers la directive CSP moderne 'frame-ancestors'."
              });
            } else {
              findings.push({
                id: "X_FRAME_OPTIONS_INVALID",
                category: "Security Headers",
                severity: "Medium",
                title: "Valeur incoh\xE9rente pour X-Frame-Options",
                description: "La valeur fournie n'est ni DENY, ni SAMEORIGIN. Si l'en-t\xEAte est d\xE9fini plusieurs fois ou contient des valeurs s\xE9par\xE9es par des virgules, il sera souvent ignor\xE9.",
                evidence: `x-frame-options: ${xfo}`,
                recommendation: "Assurez-vous qu'une seule valeur stricte et valide (DENY ou SAMEORIGIN) soit d\xE9finie."
              });
            }
          }
        }
        const xcto = headers["x-content-type-options"];
        if (!xcto) {
          findings.push({
            id: "X_CONTENT_TYPE_OPTIONS_MISSING",
            category: "Security Headers",
            severity: "Low",
            title: "Absence de X-Content-Type-Options",
            description: "Sans cet en-t\xEAte, les navigateurs peuvent tenter de d\xE9duire le type MIME d'un fichier en l'analysant (sniffing), ce qui peut mener \xE0 l'ex\xE9cution de scripts s'ils sont maquill\xE9s sous d'autres extensions (ex: image).",
            evidence: "En-t\xEAte manquant",
            recommendation: "Ajoutez syst\xE9matiquement 'X-Content-Type-Options: nosniff'."
          });
        } else if (xcto.trim().toLowerCase() !== "nosniff") {
          findings.push({
            id: "X_CONTENT_TYPE_OPTIONS_INVALID",
            category: "Security Headers",
            severity: "Low",
            title: "Valeur invalide pour X-Content-Type-Options",
            description: "La seule valeur valide et document\xE9e pour cet en-t\xEAte est 'nosniff'. Toute autre valeur (y compris avec des fautes de frappe) risque d'\xEAtre ignor\xE9e par le navigateur.",
            evidence: `x-content-type-options: ${xcto}`,
            recommendation: "Corrigez la valeur pour utiliser exactement 'nosniff'."
          });
        }
        const rp = headers["referrer-policy"];
        if (!rp) {
          findings.push({
            id: "REFERRER_POLICY_MISSING",
            category: "Security Headers",
            severity: "Low",
            title: "Absence de Referrer-Policy",
            description: "L'en-t\xEAte Referrer-Policy n'est pas d\xE9fini. Les navigateurs r\xE9cents appliquent une politique prudente par d\xE9faut, mais il reste conseill\xE9 de d\xE9finir explicitement le comportement souhait\xE9 pour \xE9viter des fuites accidentelles d'URL.",
            evidence: "En-t\xEAte manquant",
            recommendation: "Utilisez 'strict-origin-when-cross-origin' pour ne partager l'URL compl\xE8te que vers des origines \xE9quivalentes (HTTPS vers HTTPS de m\xEAme domaine)."
          });
        } else if (rp.toLowerCase().includes("unsafe-url")) {
          findings.push({
            id: "REFERRER_POLICY_UNSAFE",
            category: "Security Headers",
            severity: "Low",
            title: "Politique permissive Referrer-Policy: unsafe-url",
            description: "La valeur 'unsafe-url' instruit le navigateur d'envoyer l'URL compl\xE8te vers n'importe quelle destination (m\xEAme HTTP). Cela peut faire fuiter des donn\xE9es si l'URL contient des param\xE8tres sensibles.",
            evidence: `referrer-policy: ${rp}`,
            recommendation: "Si l'architecture le permet, remplacez par 'strict-origin-when-cross-origin'."
          });
        }
        const pp = headers["permissions-policy"];
        if (!pp) {
          findings.push({
            id: "PERMISSIONS_POLICY_MISSING",
            category: "Security Headers",
            severity: "Info",
            title: "Absence de Permissions-Policy",
            description: "Cet en-t\xEAte permet de restreindre explicitement l'acc\xE8s \xE0 certaines fonctionnalit\xE9s sensibles du navigateur (g\xE9olocalisation, cam\xE9ra, etc.) pour limiter la surface d'attaque.",
            evidence: "En-t\xEAte manquant",
            recommendation: "Pour une approche de d\xE9fense en profondeur, d\xE9clarez cet en-t\xEAte pour bloquer les fonctionnalit\xE9s que votre site n'utilise pas."
          });
        }
        const xxss = headers["x-xss-protection"];
        if (xxss && xxss !== "0") {
          findings.push({
            id: "X_XSS_PROTECTION_ENABLED",
            category: "Security Headers",
            severity: "Info",
            title: "En-t\xEAte historique X-XSS-Protection non d\xE9sactiv\xE9",
            description: "L'en-t\xEAte X-XSS-Protection activ\xE9 (valeur diff\xE9rente de '0') est consid\xE9r\xE9 comme obsol\xE8te. Les filtres int\xE9gr\xE9s des anciens navigateurs peuvent parfois \xEAtre abus\xE9s pour cr\xE9er de nouvelles failles (side-channel).",
            evidence: `x-xss-protection: ${xxss}`,
            recommendation: "Il est aujourd'hui recommand\xE9 de le d\xE9sactiver explicitement ('X-XSS-Protection: 0') et de se fier uniquement \xE0 une politique CSP robuste."
          });
        }
        return findings;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const results = analyzeHeaders2(raw);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit \xEAtre un JSON valide d'en-t\xEAtes HTTP." }, null, 2));
            process.exit(1);
          }
        }
      }
      module.exports = {
        normalizeHeaders,
        analyzeHeaders: analyzeHeaders2
      };
    }
  });

  // lib/parse-cookies.js
  var require_parse_cookies = __commonJS({
    "lib/parse-cookies.js"(exports, module) {
      function parseSingleCookieString(cookieStr) {
        if (typeof cookieStr !== "string" || cookieStr.trim() === "") {
          return null;
        }
        const parts = cookieStr.split(";");
        const nameValue = parts.shift().trim();
        const splitIndex = nameValue.indexOf("=");
        let name = "";
        let value = "";
        if (splitIndex === -1) {
          name = nameValue;
        } else {
          name = nameValue.substring(0, splitIndex).trim();
          value = nameValue.substring(splitIndex + 1).trim();
        }
        const cookieObj = {
          name,
          value,
          domain: null,
          path: null,
          expires: null,
          maxAge: null,
          secure: false,
          httpOnly: false,
          sameSite: null,
          isSession: false
        };
        parts.forEach((part) => {
          const p = part.trim();
          if (!p) return;
          const eqIdx = p.indexOf("=");
          let key = p;
          let val = null;
          if (eqIdx !== -1) {
            key = p.substring(0, eqIdx).trim();
            val = p.substring(eqIdx + 1).trim();
          }
          const lowerKey = key.toLowerCase();
          switch (lowerKey) {
            case "domain":
              cookieObj.domain = val;
              break;
            case "path":
              cookieObj.path = val;
              break;
            case "expires":
              cookieObj.expires = val;
              break;
            case "max-age":
              cookieObj.maxAge = parseInt(val, 10);
              if (isNaN(cookieObj.maxAge)) cookieObj.maxAge = null;
              break;
            case "secure":
              cookieObj.secure = true;
              break;
            case "httponly":
              cookieObj.httpOnly = true;
              break;
            case "samesite":
              cookieObj.sameSite = val;
              break;
          }
        });
        return applyHeuristics(cookieObj);
      }
      function normalizeCookieObject(obj) {
        if (!obj || typeof obj !== "object") {
          return null;
        }
        const maxAgeVal = obj.maxAge !== void 0 ? obj.maxAge : obj["max-age"];
        const cookieObj = {
          name: obj.name || "",
          value: obj.value || "",
          domain: obj.domain || null,
          path: obj.path || null,
          expires: obj.expires || null,
          maxAge: typeof maxAgeVal === "number" ? maxAgeVal : parseInt(maxAgeVal, 10) || null,
          secure: obj.secure === true || String(obj.secure).toLowerCase() === "true",
          httpOnly: obj.httpOnly === true || obj.httponly === true || String(obj.httpOnly).toLowerCase() === "true",
          sameSite: obj.sameSite || obj.samesite || null,
          isSession: false
        };
        return applyHeuristics(cookieObj);
      }
      function applyHeuristics(cookieObj) {
        if (!cookieObj || !cookieObj.name) return cookieObj;
        const lowerName = cookieObj.name.toLowerCase();
        if (lowerName.includes("session") || lowerName.includes("sess") || lowerName.includes("sid")) {
          cookieObj.isSession = true;
        }
        return cookieObj;
      }
      function parseCookies2(cookiesInput) {
        if (!cookiesInput) return [];
        if (!Array.isArray(cookiesInput)) {
          cookiesInput = [cookiesInput];
        }
        const result = [];
        for (const item of cookiesInput) {
          let parsed = null;
          if (typeof item === "string") {
            parsed = parseSingleCookieString(item);
          } else if (typeof item === "object" && item !== null) {
            parsed = normalizeCookieObject(item);
          }
          if (parsed) {
            result.push(parsed);
          }
        }
        return result;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const results = parseCookies2(raw);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            const result = parseCookies2([args[0]]);
            console.log(JSON.stringify(result, null, 2));
          }
        }
      }
      module.exports = {
        parseSingleCookieString,
        normalizeCookieObject,
        parseCookies: parseCookies2
      };
    }
  });

  // lib/analyze-cookies.js
  var require_analyze_cookies = __commonJS({
    "lib/analyze-cookies.js"(exports, module) {
      function analyzeCookies2(parsedCookies) {
        if (!Array.isArray(parsedCookies)) {
          return [];
        }
        const findings = [];
        for (const cookie of parsedCookies) {
          if (!cookie || !cookie.name) continue;
          const cookieName = cookie.name;
          const isSession = cookie.isSession === true;
          const evidence = `Cookie: ${cookieName}`;
          if (isSession) {
            if (!cookie.secure) {
              findings.push({
                id: "SESSION_COOKIE_MISSING_SECURE",
                category: "Cookies Security",
                severity: "Critical",
                title: `Cookie de session vuln\xE9rable \xE0 l'interception en clair (Secure manquant)`,
                description: `Le cookie de session '${cookieName}' ne poss\xE8de pas le flag 'Secure'. Il sera transmis en clair sur le r\xE9seau si l'utilisateur navigue accidentellement sur une URL HTTP non chiffr\xE9e. Cela permet \xE0 un attaquant positionn\xE9 sur le r\xE9seau (ex: Wi-Fi public) d'intercepter le cookie et d'usurper la session de l'utilisateur.`,
                evidence,
                recommendation: `Ajoutez imp\xE9rativement l'attribut 'Secure' au cookie '${cookieName}' pour exiger qu'il ne soit transmis que via des connexions chiffr\xE9es (HTTPS).`
              });
            }
            if (!cookie.httpOnly) {
              findings.push({
                id: "SESSION_COOKIE_MISSING_HTTPONLY",
                category: "Cookies Security",
                severity: "Critical",
                title: `Cookie de session expos\xE9 au JavaScript (HttpOnly manquant)`,
                description: `Le flag 'HttpOnly' est absent sur le cookie de session '${cookieName}'. Le cookie est donc accessible via le code JavaScript du navigateur (ex: document.cookie). C'est la cible principale lors de l'exploitation d'une vuln\xE9rabilit\xE9 Cross-Site Scripting (XSS), permettant le vol de session.`,
                evidence,
                recommendation: `Ajoutez imp\xE9rativement l'attribut 'HttpOnly' au cookie '${cookieName}' pour interdire sa lecture par les scripts c\xF4t\xE9 client.`
              });
            }
            if (!cookie.sameSite) {
              findings.push({
                id: "SESSION_COOKIE_MISSING_SAMESITE",
                category: "Cookies Security",
                severity: "Medium",
                title: `Avertissement : Cookie de session sans protection explicite SameSite`,
                description: `Le cookie de session '${cookieName}' ne d\xE9finit pas d'attribut 'SameSite'. M\xEAme si les navigateurs r\xE9cents appliquent un comportement 'Lax' par d\xE9faut, cette absence d'explicitation laisse l'application \xE0 la merci des comportements h\xE9t\xE9rog\xE8nes des navigateurs et augmente les risques d'attaques par Cross-Site Request Forgery (CSRF).`,
                evidence,
                recommendation: `D\xE9finissez explicitement l'attribut 'SameSite' \xE0 'Strict' (id\xE9al) ou 'Lax' (si la navigation multi-site l\xE9gitime l'exige) sur le cookie '${cookieName}'.`
              });
            }
          } else {
            if (!cookie.secure) {
              findings.push({
                id: "COOKIE_MISSING_SECURE",
                category: "Cookies Security",
                severity: "Low",
                title: `Avertissement : Cookie classique sans flag Secure`,
                description: `Le cookie '${cookieName}' n'a pas le flag 'Secure'. Bien qu'il ne s'agisse pas d'un identifiant de session, ce cookie pourrait fuiter des informations sur le comportement de l'utilisateur ou ses pr\xE9f\xE9rences lors d'une connexion HTTP en clair.`,
                evidence,
                recommendation: `Dans un environnement HTTPS, il est recommand\xE9 d'ajouter l'attribut 'Secure' \xE0 tous les cookies, sans exception, pour \xE9viter toute fuite r\xE9seau.`
              });
            }
            if (!cookie.httpOnly) {
              findings.push({
                id: "COOKIE_MISSING_HTTPONLY",
                category: "Cookies Security",
                severity: "Low",
                title: `Avertissement : Cookie classique accessible via JavaScript`,
                description: `Le cookie '${cookieName}' est lisible par le code JavaScript car il lui manque le flag 'HttpOnly'. Laisser un cookie accessible au front-end est une mauvaise pratique \xE0 moins que le code client (ex: React, Vue) n'ait techniquement besoin de le lire.`,
                evidence,
                recommendation: `Sauf si le cookie '${cookieName}' doit strictement \xEAtre manipul\xE9 par le JavaScript c\xF4t\xE9 client, ajoutez-y l'attribut 'HttpOnly' par principe de moindre privil\xE8ge.`
              });
            }
          }
        }
        return findings;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const results = analyzeCookies2(raw);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit \xEAtre un JSON contenant un tableau de cookies normalis\xE9s." }, null, 2));
            process.exit(1);
          }
        }
      }
      module.exports = {
        analyzeCookies: analyzeCookies2
      };
    }
  });

  // lib/analyze-tls.js
  var require_analyze_tls = __commonJS({
    "lib/analyze-tls.js"(exports, module) {
      function analyzeTls2(tlsObj, referenceDate = /* @__PURE__ */ new Date()) {
        const result = {
          summary: null,
          findings: []
        };
        if (!tlsObj || typeof tlsObj !== "object") {
          return result;
        }
        result.summary = {
          subject: tlsObj.subject || "Inconnu",
          issuer: tlsObj.issuer || "Inconnu",
          protocol: tlsObj.protocol || "Inconnu",
          cipher: tlsObj.cipher || "Inconnu",
          daysRemaining: null,
          isExpired: false,
          isAuthorized: tlsObj.authorized === true
        };
        if (tlsObj.authorized === false) {
          result.findings.push({
            id: "TLS_NOT_AUTHORIZED",
            category: "TLS Security",
            severity: "High",
            title: "Certificat TLS non autoris\xE9 (Cha\xEEne de confiance invalide)",
            description: `Le certificat pr\xE9sent\xE9 n'est pas reconnu par les autorit\xE9s de certification (CA) publiques. Le motif remont\xE9 est : "${tlsObj.authorizationError || "Inconnu"}". Les navigateurs afficheront un avertissement bloquant de type "Connexion non s\xE9curis\xE9e".`,
            evidence: `authorized: false | erreur: ${tlsObj.authorizationError || "N/A"}`,
            recommendation: "Installez un certificat valide \xE9mis par une autorit\xE9 publique reconnue (ex: Let's Encrypt) et assurez-vous de servir la cha\xEEne interm\xE9diaire compl\xE8te."
          });
        }
        if (tlsObj.validTo) {
          const toDate = new Date(tlsObj.validTo);
          const refDate = new Date(referenceDate);
          const diffTime = toDate.getTime() - refDate.getTime();
          const diffDays = Math.ceil(diffTime / (1e3 * 60 * 60 * 24));
          result.summary.daysRemaining = diffDays;
          if (diffDays < 0) {
            result.summary.isExpired = true;
            result.findings.push({
              id: "TLS_CERT_EXPIRED",
              category: "TLS Security",
              severity: "Critical",
              title: "Certificat TLS expir\xE9",
              description: `Le certificat est p\xE9rim\xE9 depuis ${Math.abs(diffDays)} jours (Date d'expiration : ${tlsObj.validTo}). L'acc\xE8s au site est vraisemblablement bloqu\xE9 par tous les navigateurs.`,
              evidence: `validTo: ${tlsObj.validTo}`,
              recommendation: "Renouvelez le certificat TLS de toute urgence."
            });
          } else if (diffDays <= 30) {
            result.findings.push({
              id: "TLS_CERT_EXPIRING_SOON_30",
              category: "TLS Security",
              severity: "High",
              title: `Expiration imminente du certificat TLS (${diffDays} jours restants)`,
              description: `Le certificat arrive \xE0 expiration dans moins de 30 jours. S'il n'est pas renouvel\xE9 \xE0 temps, le site subira une interruption de service.`,
              evidence: `validTo: ${tlsObj.validTo} (Reste ${diffDays} jours)`,
              recommendation: "Proc\xE9dez au renouvellement imm\xE9diat de ce certificat."
            });
          } else if (diffDays <= 60) {
            result.findings.push({
              id: "TLS_CERT_EXPIRING_SOON_60",
              category: "TLS Security",
              severity: "Medium",
              title: `Certificat TLS expirant prochainement (${diffDays} jours restants)`,
              description: `Le certificat expirera d'ici environ deux mois. C'est le moment habituel pour v\xE9rifier que les m\xE9canismes de renouvellement automatique (comme certbot) fonctionnent correctement.`,
              evidence: `validTo: ${tlsObj.validTo} (Reste ${diffDays} jours)`,
              recommendation: "Assurez-vous que l'automatisation de renouvellement est planifi\xE9e, ou pr\xE9parez un renouvellement manuel dans les semaines \xE0 venir."
            });
          }
        }
        return result;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const refDate = args[1] ? new Date(args[1]) : /* @__PURE__ */ new Date();
            const results = analyzeTls2(raw, refDate);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit \xEAtre un objet JSON valide contenant les propri\xE9t\xE9s TLS." }, null, 2));
            process.exit(1);
          }
        }
      }
      module.exports = {
        analyzeTls: analyzeTls2
      };
    }
  });

  // lib/analyze-third-parties.js
  var require_analyze_third_parties = __commonJS({
    "lib/analyze-third-parties.js"(exports, module) {
      var CATEGORIES = {
        ANALYTICS: "Analytics",
        ADVERTISING: "Publicit\xE9",
        MARKETING: "Marketing Automation",
        SESSION_REPLAY: "Session Replay",
        TAG_MANAGER: "Tag Manager"
      };
      var RISK_LEVELS = {
        LOW: "Low",
        // Risque faible, transfert de données commun (nécessitant toutefois un consentement)
        MEDIUM: "Medium",
        // Transfert important, croisement de données ou injection de code dynamique
        HIGH: "High"
        // Risque élevé d'enregistrement intégral de l'activité ou de fuite PII (données personnelles)
      };
      var DEFAULT_PATTERNS = [
        // --- Tag Managers ---
        {
          service: "Google Tag Manager",
          type: CATEGORIES.TAG_MANAGER,
          match: /googletagmanager\.com/i,
          riskLevel: RISK_LEVELS.MEDIUM,
          justification: "Permet l'injection dynamique et non auditable de scripts tiers directement par les \xE9quipes marketing. Exige un contr\xF4le strict des acc\xE8s."
        },
        // --- Analytics ---
        {
          service: "Google Analytics",
          type: CATEGORIES.ANALYTICS,
          match: /google-analytics\.com|analytics\.js/i,
          riskLevel: RISK_LEVELS.LOW,
          justification: "Outil de mesure d'audience standard. Sauf configuration d'anonymisation tr\xE8s stricte, il requiert g\xE9n\xE9ralement un consentement RGPD explicite."
        },
        {
          service: "Matomo / Piwik",
          type: CATEGORIES.ANALYTICS,
          match: /matomo|piwik/i,
          riskLevel: RISK_LEVELS.LOW,
          justification: "Mesure d'audience. Le risque de vie priv\xE9e d\xE9pend fortement de son mode d'h\xE9bergement (Cloud vs On-Premise) et de l'anonymisation des IPs."
        },
        // --- Publicité (Advertising) ---
        {
          service: "Google Ads / DoubleClick",
          type: CATEGORIES.ADVERTISING,
          match: /doubleclick\.net|googleadservices\.com/i,
          riskLevel: RISK_LEVELS.MEDIUM,
          justification: "R\xE9seau publicitaire favorisant le suivi inter-sites (cross-site tracking) des utilisateurs. Impose un recueil strict du consentement."
        },
        {
          service: "Facebook Pixel",
          type: CATEGORIES.ADVERTISING,
          match: /connect\.facebook\.net/i,
          riskLevel: RISK_LEVELS.MEDIUM,
          justification: "Traceur social transmettant les \xE9v\xE9nements de navigation pour du reciblage, pouvant lier un visiteur \xE0 son profil Facebook."
        },
        {
          service: "Criteo",
          type: CATEGORIES.ADVERTISING,
          match: /criteo\.com/i,
          riskLevel: RISK_LEVELS.MEDIUM,
          justification: "Sp\xE9cialiste mondial du reciblage (retargeting) bas\xE9 sur l'historique de navigation produit."
        },
        // --- Marketing Automation ---
        {
          service: "HubSpot",
          type: CATEGORIES.MARKETING,
          match: /hubspot\.com|hs-scripts\.com/i,
          riskLevel: RISK_LEVELS.MEDIUM,
          justification: "Outil CRM pouvant lier l'historique de navigation anonyme \xE0 un profil utilisateur formellement identifi\xE9 (apr\xE8s remplissage d'un formulaire)."
        },
        {
          service: "Marketo",
          type: CATEGORIES.MARKETING,
          match: /marketo\.com/i,
          riskLevel: RISK_LEVELS.MEDIUM,
          justification: "Plateforme de marketing automation d'entreprise collectant le comportement de navigation pour du scoring (B2B/B2C)."
        },
        // --- Session Replay (Fort Enjeu) ---
        {
          service: "Hotjar",
          type: CATEGORIES.SESSION_REPLAY,
          match: /hotjar\.com/i,
          riskLevel: RISK_LEVELS.HIGH,
          justification: "Outil reproduisant visuellement la session (clics, scrolls). S'il est mal configur\xE9, il peut capturer involontairement les saisies clavier contenant des donn\xE9es sensibles (mots de passe, num\xE9ros de carte)."
        },
        {
          service: "FullStory",
          type: CATEGORIES.SESSION_REPLAY,
          match: /fullstory\.com/i,
          riskLevel: RISK_LEVELS.HIGH,
          justification: "Enregistrement profond du DOM utilisateur. Le risque de captation accidentelle de donn\xE9es \xE0 caract\xE8re personnel (PII) est extr\xEAmement \xE9lev\xE9 sans masque (masking) proactif."
        }
      ];
      function extractHostname(input) {
        if (!input || typeof input !== "string") return "";
        try {
          const urlStr = input.startsWith("http") ? input : `http://${input}`;
          return new URL(urlStr).hostname;
        } catch (e) {
          return input;
        }
      }
      function analyzeThirdParties2(domainsList, customPatterns = null) {
        if (!Array.isArray(domainsList)) {
          return [];
        }
        const rules = customPatterns && Array.isArray(customPatterns) ? customPatterns : DEFAULT_PATTERNS;
        const detectedServices = /* @__PURE__ */ new Set();
        const results = [];
        for (const rawEntry of domainsList) {
          if (typeof rawEntry !== "string") continue;
          const hostname = extractHostname(rawEntry);
          for (const rule of rules) {
            if (rule.match.test(hostname) || rule.match.test(rawEntry)) {
              if (!detectedServices.has(rule.service)) {
                detectedServices.add(rule.service);
                results.push({
                  service: rule.service,
                  type: rule.type,
                  riskLevel: rule.riskLevel,
                  justification: rule.justification,
                  evidence: `Correspondance avec l'entr\xE9e : ${rawEntry}`
                });
              }
            }
          }
        }
        return results;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const results = analyzeThirdParties2(raw);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            const results = analyzeThirdParties2([args[0]]);
            console.log(JSON.stringify(results, null, 2));
          }
        }
      }
      module.exports = {
        CATEGORIES,
        RISK_LEVELS,
        DEFAULT_PATTERNS,
        analyzeThirdParties: analyzeThirdParties2
      };
    }
  });

  // lib/analyze-scripts.js
  var require_analyze_scripts = __commonJS({
    "lib/analyze-scripts.js"(exports, module) {
      var SCRIPT_FAMILIES = [
        {
          name: "Google Analytics",
          // Identifie les scripts historiques (analytics.js, ga.js) et les modernes via gtag
          regex: /google-analytics\.com|googletagmanager\.com\/gtag/i
        },
        {
          name: "Google Tag Manager",
          // Identifie spécifiquement le conteneur GTM (gtm.js)
          regex: /googletagmanager\.com\/gtm/i
        },
        {
          name: "DoubleClick",
          regex: /doubleclick\.net|googleadservices\.com/i
        },
        {
          name: "Facebook Pixel",
          regex: /connect\.facebook\.net/i
        },
        {
          name: "Hotjar",
          regex: /hotjar\.com/i
        },
        {
          name: "HubSpot",
          regex: /hs-scripts\.com|hubspot\.com|js\.hs-analytics\.net/i
        },
        {
          name: "Segment",
          regex: /cdn\.segment\.com/i
        },
        {
          name: "LinkedIn Insight",
          regex: /snap\.licdn\.com/i
        },
        {
          name: "TikTok Pixel",
          regex: /analytics\.tiktok\.com/i
        },
        {
          name: "Criteo",
          regex: /criteo\.com|criteo\.net/i
        }
      ];
      function analyzeScripts2(scriptsList) {
        if (!Array.isArray(scriptsList)) {
          return [];
        }
        const inventory = /* @__PURE__ */ new Map();
        for (const rawUrl of scriptsList) {
          if (typeof rawUrl !== "string" || !rawUrl.trim()) continue;
          let urlObj;
          try {
            urlObj = new URL(rawUrl.trim());
          } catch (e) {
            try {
              const prefixedUrl = rawUrl.trim().startsWith("//") ? `https:${rawUrl.trim()}` : `http://${rawUrl.trim()}`;
              urlObj = new URL(prefixedUrl);
            } catch (err) {
              continue;
            }
          }
          const hostname = urlObj.hostname;
          const normalizedUrl = urlObj.href;
          let detectedFamily = "Autre (Non reconnu)";
          for (const family of SCRIPT_FAMILIES) {
            if (family.regex.test(normalizedUrl)) {
              detectedFamily = family.name;
              break;
            }
          }
          if (!inventory.has(detectedFamily)) {
            inventory.set(detectedFamily, {
              family: detectedFamily,
              hosts: /* @__PURE__ */ new Set(),
              scripts: /* @__PURE__ */ new Set()
            });
          }
          const familyEntry = inventory.get(detectedFamily);
          familyEntry.hosts.add(hostname);
          familyEntry.scripts.add(normalizedUrl);
        }
        const results = [];
        for (const [familyName, data] of inventory.entries()) {
          results.push({
            family: familyName,
            hosts: Array.from(data.hosts),
            scripts: Array.from(data.scripts)
          });
        }
        results.sort((a, b) => {
          if (a.family === "Autre (Non reconnu)") return 1;
          if (b.family === "Autre (Non reconnu)") return -1;
          return a.family.localeCompare(b.family);
        });
        return results;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const results = analyzeScripts2(raw);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            const results = analyzeScripts2([args[0]]);
            console.log(JSON.stringify(results, null, 2));
          }
        }
      }
      module.exports = {
        SCRIPT_FAMILIES,
        analyzeScripts: analyzeScripts2
      };
    }
  });

  // lib/analyze-technologies.js
  var require_analyze_technologies = __commonJS({
    "lib/analyze-technologies.js"(exports, module) {
      var CATEGORIES = {
        CMS: "CMS",
        JS_FRAMEWORK: "Framework JS",
        ANALYTICS: "Analytics",
        CDN: "CDN",
        MARKETING: "Marketing",
        PAYMENT: "Paiement",
        SECURITY: "S\xE9curit\xE9",
        OTHER: "Autre"
      };
      var TECH_DICTIONARY = [
        // --- CMS / E-commerce ---
        { regex: /wordpress/i, category: CATEGORIES.CMS },
        { regex: /drupal/i, category: CATEGORIES.CMS },
        { regex: /joomla/i, category: CATEGORIES.CMS },
        { regex: /magento/i, category: CATEGORIES.CMS },
        { regex: /shopify/i, category: CATEGORIES.CMS },
        { regex: /prestashop/i, category: CATEGORIES.CMS },
        { regex: /wix/i, category: CATEGORIES.CMS },
        // --- Frameworks JavaScript ---
        { regex: /react/i, category: CATEGORIES.JS_FRAMEWORK },
        { regex: /vue\.?js/i, category: CATEGORIES.JS_FRAMEWORK },
        { regex: /angular/i, category: CATEGORIES.JS_FRAMEWORK },
        { regex: /svelte/i, category: CATEGORIES.JS_FRAMEWORK },
        { regex: /next\.?js/i, category: CATEGORIES.JS_FRAMEWORK },
        { regex: /nuxt\.?js/i, category: CATEGORIES.JS_FRAMEWORK },
        { regex: /jquery/i, category: CATEGORIES.JS_FRAMEWORK },
        // --- Analytics ---
        { regex: /google analytics/i, category: CATEGORIES.ANALYTICS },
        { regex: /matomo|piwik/i, category: CATEGORIES.ANALYTICS },
        { regex: /plausible/i, category: CATEGORIES.ANALYTICS },
        { regex: /datadog|new relic/i, category: CATEGORIES.ANALYTICS },
        // --- CDN ---
        { regex: /cloudflare/i, category: CATEGORIES.CDN },
        { regex: /akamai/i, category: CATEGORIES.CDN },
        { regex: /fastly/i, category: CATEGORIES.CDN },
        { regex: /amazon cloudfront|aws cloudfront/i, category: CATEGORIES.CDN },
        // --- Marketing ---
        { regex: /hubspot/i, category: CATEGORIES.MARKETING },
        { regex: /mailchimp/i, category: CATEGORIES.MARKETING },
        { regex: /marketo/i, category: CATEGORIES.MARKETING },
        { regex: /salesforce/i, category: CATEGORIES.MARKETING },
        // --- Paiement ---
        { regex: /stripe/i, category: CATEGORIES.PAYMENT },
        { regex: /paypal/i, category: CATEGORIES.PAYMENT },
        { regex: /adyen/i, category: CATEGORIES.PAYMENT },
        { regex: /braintree/i, category: CATEGORIES.PAYMENT },
        // --- Sécurité & Anti-bot ---
        { regex: /recaptcha/i, category: CATEGORIES.SECURITY },
        { regex: /hcaptcha/i, category: CATEGORIES.SECURITY },
        { regex: /auth0/i, category: CATEGORIES.SECURITY },
        { regex: /okta/i, category: CATEGORIES.SECURITY },
        { regex: /datadome/i, category: CATEGORIES.SECURITY }
      ];
      function analyzeTechnologies2(techList) {
        if (!Array.isArray(techList)) {
          return {};
        }
        const summary = {};
        for (const cat of Object.values(CATEGORIES)) {
          summary[cat] = [];
        }
        for (const item of techList) {
          if (!item) continue;
          let techName = "";
          if (typeof item === "string") {
            techName = item;
          } else if (typeof item === "object") {
            techName = item.name || Object.values(item).join(" ");
          }
          if (!techName.trim()) continue;
          let matchedCategory = CATEGORIES.OTHER;
          for (const rule of TECH_DICTIONARY) {
            if (rule.regex.test(techName)) {
              matchedCategory = rule.category;
              break;
            }
          }
          summary[matchedCategory].push(techName.trim());
        }
        const cleanSummary = {};
        for (const [category, items] of Object.entries(summary)) {
          if (items.length > 0) {
            cleanSummary[category] = Array.from(new Set(items));
          }
        }
        return cleanSummary;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const raw = JSON.parse(args[0]);
            const results = analyzeTechnologies2(raw);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit \xEAtre un JSON contenant une liste de technologies." }, null, 2));
            process.exit(1);
          }
        }
      }
      module.exports = {
        CATEGORIES,
        TECH_DICTIONARY,
        analyzeTechnologies: analyzeTechnologies2
      };
    }
  });

  // lib/score-site.js
  var require_score_site = __commonJS({
    "lib/score-site.js"(exports, module) {
      var GRADE_THRESHOLDS = [
        { min: 90, grade: "A" },
        { min: 70, grade: "B" },
        { min: 50, grade: "C" },
        { min: 30, grade: "D" },
        { min: 0, grade: "F" }
      ];
      function calculateScore2(siteData, allFindings) {
        let score = 100;
        const appliedPenalties = [];
        function applyPenalty(points, reason, findingId = null) {
          score -= points;
          appliedPenalties.push({
            points: -points,
            // Stocké en négatif pour plus de lisibilité
            reason,
            findingId: findingId || "N/A"
          });
        }
        if (siteData && siteData.finalUrl && siteData.finalUrl.trim().toLowerCase().startsWith("http://")) {
          applyPenalty(30, "Absence de HTTPS : Le site est servi en clair (HTTP).", "NO_HTTPS_PROTOCOL");
        }
        if (Array.isArray(allFindings)) {
          for (const finding of allFindings) {
            if (finding.category === "Security Headers") {
              if (finding.id && finding.id.includes("MISSING")) {
                applyPenalty(10, `En-t\xEAte de s\xE9curit\xE9 manquant`, finding.id);
              } else if (finding.id && (finding.id.includes("WEAK") || finding.id.includes("INVALID") || finding.id.includes("UNSAFE") || finding.id.includes("MALFORMED") || finding.id.includes("DEPRECATED") || finding.id.includes("NO_BASE_DIRECTIVES"))) {
                applyPenalty(5, `En-t\xEAte de s\xE9curit\xE9 faible ou obsol\xE8te`, finding.id);
              }
            } else if (finding.category === "Cookies Security") {
              if (finding.id === "SESSION_COOKIE_MISSING_SECURE" || finding.id === "SESSION_COOKIE_MISSING_HTTPONLY") {
                applyPenalty(20, `Cookie de session critique non prot\xE9g\xE9 (${finding.id.includes("SECURE") ? "Secure" : "HttpOnly"} manquant)`, finding.id);
              } else if (finding.id === "SESSION_COOKIE_MISSING_SAMESITE") {
                applyPenalty(10, `Cookie de session sans attribut SameSite`, finding.id);
              }
            } else if (finding.category === "TLS Security") {
              if (finding.id === "TLS_CERT_EXPIRED") {
                applyPenalty(30, "Certificat TLS expir\xE9", finding.id);
              } else if (finding.id === "TLS_CERT_EXPIRING_SOON_30") {
                applyPenalty(25, "Certificat TLS expirant dans moins de 30 jours", finding.id);
              } else if (finding.id === "TLS_CERT_EXPIRING_SOON_60") {
                applyPenalty(10, "Certificat TLS expirant dans moins de 60 jours", finding.id);
              }
            } else if (finding.type === "Publicit\xE9") {
              applyPenalty(15, `Tracker publicitaire ou reciblage d\xE9tect\xE9 (${finding.service})`, `THIRDPARTY_ADS_${finding.service}`);
            } else if (finding.type === "Cleartext Protocol" && (!siteData || !siteData.finalUrl || !siteData.finalUrl.startsWith("http://"))) {
              applyPenalty(30, "Protocole en clair (HTTP) d\xE9tect\xE9 manuellement", "MANUAL_HTTP_CLEARTEXT");
            }
          }
        }
        const finalScore = Math.max(0, Math.min(100, score));
        let finalGrade = "F";
        for (const threshold of GRADE_THRESHOLDS) {
          if (finalScore >= threshold.min) {
            finalGrade = threshold.grade;
            break;
          }
        }
        return {
          score: finalScore,
          grade: finalGrade,
          penalties: appliedPenalties
        };
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 1) {
          try {
            const siteData = JSON.parse(args[0]);
            const findings = JSON.parse(args[1]);
            const results = calculateScore2(siteData, findings);
            console.log(JSON.stringify(results, null, 2));
          } catch (e) {
            console.error(JSON.stringify({ error: "Arguments invalides. Usage : node score-site.js '<siteData>' '<findingsArray>'" }, null, 2));
            process.exit(1);
          }
        }
      }
      module.exports = {
        calculateScore: calculateScore2
      };
    }
  });

  // lib/build-recommendations.js
  var require_build_recommendations = __commonJS({
    "lib/build-recommendations.js"(exports, module) {
      var PRIORITIES = {
        IMMEDIATE: "imm\xE9diat",
        // Action critique (arrêt de production, faille exploitable directement)
        IMPORTANT: "important",
        // Action majeure (vulnérabilité classique, expiration proche)
        IMPROVEMENT: "am\xE9lioration"
        // Action de durcissement (bonne pratique de sécurité en profondeur)
      };
      function determinePriority(severity) {
        if (!severity) return PRIORITIES.IMPROVEMENT;
        const sev = severity.toLowerCase();
        if (sev === "critical") return PRIORITIES.IMMEDIATE;
        if (sev === "high" || sev === "medium") return PRIORITIES.IMPORTANT;
        return PRIORITIES.IMPROVEMENT;
      }
      function getPedagogicalTheme(finding) {
        let rawTheme = finding.category || finding.type || "G\xE9n\xE9ral";
        if (rawTheme === "Security Headers") {
          return "Durcissement des En-t\xEAtes HTTP";
        }
        if (rawTheme === "Cookies Security") {
          return "S\xE9curisation des Sessions & Cookies";
        }
        if (rawTheme === "TLS Security" || rawTheme === "Cleartext Protocol") {
          return "Chiffrement et Transport (HTTPS)";
        }
        if (rawTheme === "Privacy & Data Flow" || finding.type === "Publicit\xE9" || finding.type === "Session Replay") {
          return "Confidentialit\xE9 et Traceurs Tiers";
        }
        return rawTheme;
      }
      function buildRecommendations2(allFindings) {
        if (!Array.isArray(allFindings)) {
          return {
            [PRIORITIES.IMMEDIATE]: [],
            [PRIORITIES.IMPORTANT]: [],
            [PRIORITIES.IMPROVEMENT]: []
          };
        }
        const grouped = {
          [PRIORITIES.IMMEDIATE]: /* @__PURE__ */ new Map(),
          [PRIORITIES.IMPORTANT]: /* @__PURE__ */ new Map(),
          [PRIORITIES.IMPROVEMENT]: /* @__PURE__ */ new Map()
        };
        for (const finding of allFindings) {
          if (!finding) continue;
          const actionText = finding.recommendation || finding.justification;
          if (!actionText || actionText.trim() === "") continue;
          const priority = determinePriority(finding.severity || finding.riskLevel);
          const theme = getPedagogicalTheme(finding);
          if (!grouped[priority].has(theme)) {
            grouped[priority].set(theme, /* @__PURE__ */ new Set());
          }
          grouped[priority].get(theme).add(actionText.trim());
        }
        const results = {
          [PRIORITIES.IMMEDIATE]: [],
          [PRIORITIES.IMPORTANT]: [],
          [PRIORITIES.IMPROVEMENT]: []
        };
        for (const priority of Object.values(PRIORITIES)) {
          for (const [theme, actionsSet] of grouped[priority].entries()) {
            results[priority].push({
              theme,
              actions: Array.from(actionsSet)
              // Le Set est reconverti en simple Array pour le JSON final
            });
          }
        }
        return results;
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 0) {
          try {
            const rawFindings = JSON.parse(args[0]);
            const recommendations = buildRecommendations2(rawFindings);
            console.log(JSON.stringify(recommendations, null, 2));
          } catch (e) {
            console.error(JSON.stringify({ error: "L'argument doit \xEAtre un JSON contenant un tableau de findings." }, null, 2));
            process.exit(1);
          }
        }
      }
      module.exports = {
        PRIORITIES,
        buildRecommendations: buildRecommendations2
      };
    }
  });

  // lib/build-executive-summary.js
  var require_build_executive_summary = __commonJS({
    "lib/build-executive-summary.js"(exports, module) {
      function buildExecutiveSummary2(siteUrl, scoreData, allFindings) {
        if (!siteUrl || !scoreData || !Array.isArray(allFindings)) {
          return "Donn\xE9es insuffisantes pour g\xE9n\xE9rer un r\xE9sum\xE9 ex\xE9cutif coh\xE9rent.";
        }
        const sentences = [];
        sentences.push(`L'audit de s\xE9curit\xE9 passif de la plateforme ${siteUrl} a permis d'\xE9valuer sa posture globale avec la note de ${scoreData.grade} (score : ${scoreData.score}/100).`);
        if (scoreData.score >= 80) {
          sentences.push("Le site d\xE9montre un excellent niveau de conformit\xE9 aux standards de s\xE9curit\xE9 actuels.");
        } else if (scoreData.score >= 50) {
          sentences.push("La configuration est acceptable dans son ensemble, bien qu'elle n\xE9cessite des ajustements techniques de renforcement.");
        } else {
          sentences.push("L'architecture pr\xE9sente des lacunes structurelles n\xE9cessitant une intervention technique prioritaire.");
        }
        let tlsCritical = false;
        let tlsWarning = false;
        let headersCritical = false;
        let cookiesCritical = false;
        let thirdPartiesRisky = false;
        const noHttpsPenalty = scoreData.penalties && scoreData.penalties.some((p) => p.findingId === "NO_HTTPS_PROTOCOL");
        if (noHttpsPenalty) {
          tlsCritical = true;
        }
        for (const f of allFindings) {
          if (!f) continue;
          if (f.category === "TLS Security" || f.category === "Cleartext Protocol") {
            if (f.severity === "Critical" || f.severity === "High") tlsCritical = true;
            else if (f.severity === "Medium") tlsWarning = true;
          }
          if (f.category === "Security Headers") {
            if (f.id === "HSTS_MISSING" || f.id === "CSP_MISSING") headersCritical = true;
          }
          if (f.category === "Cookies Security") {
            if (f.severity === "Critical") cookiesCritical = true;
          }
          if (f.type === "Publicit\xE9" || f.type === "Session Replay" || f.riskLevel === "High") {
            thirdPartiesRisky = true;
          }
        }
        if (tlsCritical) {
          sentences.push("Sur le plan du transport des donn\xE9es, la s\xE9curisation par chiffrement est absente ou techniquement d\xE9faillante, exposant le trafic \xE0 des interceptions.");
        } else if (tlsWarning) {
          sentences.push("Le trafic est chiffr\xE9 de mani\xE8re ad\xE9quate, mais le m\xE9canisme de renouvellement du certificat technique approche de son \xE9ch\xE9ance.");
        } else {
          sentences.push("Concernant le transport des donn\xE9es, le chiffrement des \xE9changes est correctement configur\xE9 et assure efficacement la confidentialit\xE9 des communications.");
        }
        if (headersCritical) {
          sentences.push("Les m\xE9canismes de d\xE9fense du navigateur (en-t\xEAtes HTTP) sont largement incomplets, ce qui limite la r\xE9silience de l'application face aux vecteurs d'attaques standards.");
        } else {
          sentences.push("Les directives de d\xE9fense p\xE9rim\xE9triques sont globalement en place pour prot\xE9ger l'int\xE9grit\xE9 de la navigation des utilisateurs.");
        }
        if (cookiesCritical) {
          sentences.push("La gestion des sessions de connexion omet certaines protections fondamentales, rendant potentiellement possible l'usurpation de comptes en cas d'attaque cibl\xE9e.");
        } else {
          sentences.push("La gestion des sessions et de l'authentification s'appuie sur des pratiques robustes garantissant l'\xE9tanch\xE9it\xE9 des connexions de vos visiteurs.");
        }
        if (thirdPartiesRisky) {
          sentences.push("Enfin, l'analyse de l'\xE9cosyst\xE8me r\xE9v\xE8le la pr\xE9sence de traceurs externes n\xE9cessitant une vigilance particuli\xE8re sur le plan de la vie priv\xE9e et du recueil de consentement.");
        } else {
          sentences.push("Enfin, l'int\xE9gration de services tiers semble mesur\xE9e, limitant nativement les risques de fuite de donn\xE9es vers des acteurs de tracking externes.");
        }
        if (scoreData.score < 80) {
          sentences.push("Il est conseill\xE9 de confier les actions class\xE9es comme imm\xE9diates ou importantes \xE0 l'\xE9quipe de d\xE9veloppement afin de consolider durablement cette posture.");
        } else {
          sentences.push("L'objectif est d\xE9sormais de maintenir ce haut niveau d'exigence au fil des futures \xE9volutions de la plateforme.");
        }
        return sentences.join(" ");
      }
      if (__require.main === module) {
        const args = process.argv.slice(2);
        if (args.length > 2) {
          try {
            const url = args[0];
            const scoreData = JSON.parse(args[1]);
            const findings = JSON.parse(args[2]);
            const summary = buildExecutiveSummary2(url, scoreData, findings);
            console.log(summary);
          } catch (e) {
            console.error("Arguments invalides. Usage : node build-executive-summary.js '<url>' '<scoreDataJson>' '<findingsArrayJson>'");
            process.exit(1);
          }
        }
      }
      module.exports = {
        buildExecutiveSummary: buildExecutiveSummary2
      };
    }
  });

  // lib/render-report.js
  var require_render_report = __commonJS({
    "lib/render-report.js"(exports, module) {
      function getGradeColor(grade) {
        switch (grade) {
          case "A":
            return "#2ecc71";
          // Vert
          case "B":
            return "#3498db";
          // Bleu
          case "C":
            return "#f1c40f";
          // Jaune
          case "D":
            return "#e67e22";
          // Orange
          case "F":
            return "#e74c3c";
          // Rouge
          default:
            return "#95a5a6";
        }
      }
      function renderHtmlReport2(reportsArray) {
        if (!Array.isArray(reportsArray) || reportsArray.length === 0) {
          return "<!DOCTYPE html><html lang='fr'><body><h1>Aucune donn\xE9e d'audit disponible.</h1></body></html>";
        }
        let html = `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit S\xE9curit\xE9 Passif</title>
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
        
        /* Tableau R\xE9capitulatif */
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
        .reco-imm\xE9diat { border-left: 5px solid #e74c3c; background: #fdf3f2; }
        .reco-important { border-left: 5px solid #e67e22; background: #fef7f1; }
        .reco-am\xE9lioration { border-left: 5px solid #3498db; background: #f4f9fd; }
        
        .reco-block h4 { margin-top: 0; font-size: 1.2em; margin-bottom: 15px; }
        .reco-theme { font-weight: bold; color: #2c3e50; margin-top: 15px; margin-bottom: 10px; }
        .reco-ul { margin-top: 5px; padding-left: 20px; }
        .reco-ul li { margin-bottom: 8px; }

    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'Audit de S\xE9curit\xE9</h1>

        <!-- SECTION : TABLEAU R\xC9CAPITULATIF -->
        <h2>R\xE9capitulatif Global</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Domaine Audit\xE9</th>
                    <th>Score de S\xE9curit\xE9</th>
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

        <!-- SECTION : D\xC9TAIL PAR SITE -->
        <h2>D\xE9tails par Site</h2>`;
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
                ${report.executiveSummary || "R\xE9sum\xE9 ex\xE9cutif non disponible."}
            </div>`;
          if (report.tlsSummary) {
            html += `<h4 class="section-title">\u{1F512} Chiffrement des Transports (TLS)</h4>`;
            html += `<ul class="info-list">`;
            html += `<li><strong>Protocole configur\xE9 :</strong> ${report.tlsSummary.protocol || "Non d\xE9tect\xE9"}</li>`;
            html += `<li><strong>Autorit\xE9 \xE9mettrice :</strong> ${report.tlsSummary.issuer || "Inconnue"}</li>`;
            if (report.tlsSummary.daysRemaining !== null && report.tlsSummary.daysRemaining !== void 0) {
              const days = report.tlsSummary.daysRemaining;
              const statusColor = days < 0 ? "#e74c3c" : days < 30 ? "#e67e22" : "#27ae60";
              const statusText = days < 0 ? `Expir\xE9 depuis ${Math.abs(days)} jours` : `Valide (${days} jours restants)`;
              html += `<li><strong>Statut d'expiration :</strong> <span style="color: ${statusColor}; font-weight: bold;">${statusText}</span></li>`;
            }
            html += `</ul>`;
          }
          html += `<h4 class="section-title">\u{1F36A} Politiques des Cookies & Sessions</h4>`;
          if (report.cookies && report.cookies.length > 0) {
            html += `<ul class="info-list">`;
            for (const cookie of report.cookies) {
              const flags = [];
              if (cookie.secure) flags.push('<span class="tag">Secure</span>');
              if (cookie.httpOnly) flags.push('<span class="tag">HttpOnly</span>');
              if (cookie.sameSite) flags.push(`<span class="tag">SameSite=${cookie.sameSite}</span>`);
              if (cookie.isSession) flags.push('<span class="tag tag-session">Session</span>');
              html += `<li><strong>${cookie.name}</strong> &nbsp; ${flags.length > 0 ? flags.join("") : "<em>Aucune protection (ni Secure, ni HttpOnly)</em>"}</li>`;
            }
            html += `</ul>`;
          } else {
            html += `<p>Aucun cookie d\xE9tect\xE9 par l'audit passif sur cette page.</p>`;
          }
          html += `<h4 class="section-title">\u{1F310} \xC9cosyst\xE8me Tiers & Fuite de donn\xE9es</h4>`;
          if (report.thirdParties && report.thirdParties.length > 0) {
            html += `<ul class="info-list">`;
            for (const tp of report.thirdParties) {
              const riskColor = tp.riskLevel === "High" ? "#e74c3c" : tp.riskLevel === "Medium" ? "#e67e22" : "#27ae60";
              html += `<li>
                            <strong>${tp.service}</strong> <span class="tag">${tp.type}</span> 
                            | Risque RGPD : <strong style="color: ${riskColor}">${tp.riskLevel}</strong>
                            <div style="margin-top: 5px; color: #7f8c8d; font-size: 0.95em;">${tp.justification}</div>
                         </li>`;
            }
            html += `</ul>`;
          } else {
            html += `<p>Aucun domaine de tracking tiers significatif n'a \xE9t\xE9 d\xE9tect\xE9.</p>`;
          }
          if (report.recommendations) {
            html += `<h4 class="section-title">\u{1F4CB} Plan d'Action (Rem\xE9diations)</h4>`;
            const renderPriorityBox = (prioKey, title, cssClass) => {
              if (report.recommendations[prioKey] && report.recommendations[prioKey].length > 0) {
                html += `<div class="reco-block ${cssClass}">
                                <h4 style="color: ${cssClass.includes("imm\xE9diat") ? "#c0392b" : cssClass.includes("important") ? "#d35400" : "#2980b9"}">${title}</h4>`;
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
            renderPriorityBox("imm\xE9diat", "\u{1F6D1} Actions Imm\xE9diates", "reco-imm\xE9diat");
            renderPriorityBox("important", "\u26A0\uFE0F Actions Importantes", "reco-important");
            renderPriorityBox("am\xE9lioration", "\u{1F4A1} Am\xE9liorations de Durcissement", "reco-am\xE9lioration");
            if (!report.recommendations["imm\xE9diat"]?.length && !report.recommendations["important"]?.length && !report.recommendations["am\xE9lioration"]?.length) {
              html += `<p>Aucune recommandation technique \xE0 formuler. La posture est excellente.</p>`;
            }
          }
          html += `</div>`;
        }
        html += `
    </div>
</body>
</html>`;
        return html;
      }
      module.exports = {
        renderHtmlReport: renderHtmlReport2
      };
    }
  });

  // public/app.js
  var { importEvidenceString } = require_import_evidence_browser();
  var { analyzeHeaders } = require_analyze_headers();
  var { parseCookies } = require_parse_cookies();
  var { analyzeCookies } = require_analyze_cookies();
  var { analyzeTls } = require_analyze_tls();
  var { analyzeThirdParties } = require_analyze_third_parties();
  var { analyzeScripts } = require_analyze_scripts();
  var { analyzeTechnologies } = require_analyze_technologies();
  var { calculateScore } = require_score_site();
  var { buildRecommendations } = require_build_recommendations();
  var { buildExecutiveSummary } = require_build_executive_summary();
  var { renderHtmlReport } = require_render_report();
  var dropZone = document.getElementById("drop-zone");
  var fileInput = document.getElementById("file-input");
  var loading = document.getElementById("loading");
  var resultCard = document.getElementById("result-card");
  var errorCard = document.getElementById("error-card");
  var scoreBadge = document.getElementById("score-badge");
  var resultSummary = document.getElementById("result-summary");
  var downloadBtn = document.getElementById("download-btn");
  var restartBtn = document.getElementById("restart-btn");
  var errorMessage = document.getElementById("error-message");
  var currentHtmlReport = null;
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", (e) => {
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
    dropZone.classList.add("hidden");
    errorCard.classList.add("hidden");
    resultCard.classList.add("hidden");
    loading.classList.remove("hidden");
    setTimeout(() => {
      try {
        const normalizedData = importEvidenceString(content);
        let allFindings = [];
        allFindings.push(...analyzeHeaders(normalizedData.headers));
        const parsedCookies = parseCookies(normalizedData.setCookies || []);
        allFindings.push(...analyzeCookies(parsedCookies));
        const auditDate = /* @__PURE__ */ new Date();
        const tlsResult = analyzeTls(normalizedData.tls, auditDate);
        allFindings.push(...tlsResult.findings);
        const allThirdPartyStrings = [...normalizedData.thirdPartyDomains || [], ...normalizedData.thirdPartyScripts || []];
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
          recommendations,
          techSummary,
          scriptsInventory,
          findings: allFindings
        };
        const htmlOutput = renderHtmlReport([reportResult]);
        loading.classList.add("hidden");
        scoreBadge.textContent = reportResult.grade;
        let color = "#3b82f6";
        if (reportResult.grade === "A") color = "#22c55e";
        else if (reportResult.grade === "B") color = "#eab308";
        else if (reportResult.grade === "C") color = "#f97316";
        else color = "#ef4444";
        scoreBadge.style.backgroundColor = color;
        scoreBadge.style.boxShadow = `0 0 20px ${color}80`;
        resultSummary.textContent = executiveSummaryText;
        currentHtmlReport = htmlOutput;
        resultCard.classList.remove("hidden");
      } catch (e) {
        loading.classList.add("hidden");
        showError(e.message);
      }
    }, 500);
  }
  function showError(msg) {
    errorMessage.textContent = msg;
    errorCard.classList.remove("hidden");
    dropZone.classList.remove("hidden");
  }
  downloadBtn.addEventListener("click", () => {
    if (!currentHtmlReport) return;
    const blob = new Blob([currentHtmlReport], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1e3);
  });
  restartBtn.addEventListener("click", () => {
    resultCard.classList.add("hidden");
    errorCard.classList.add("hidden");
    dropZone.classList.remove("hidden");
    fileInput.value = "";
    currentHtmlReport = null;
  });
  var tabBtns = document.querySelectorAll(".tab-btn");
  var tabContents = document.querySelectorAll(".tab-content");
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      tabContents.forEach((c) => c.classList.add("hidden"));
      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).classList.remove("hidden");
      if (targetId === "urls-tab") {
        loadUrls();
      }
    });
  });
  var refreshUrlsBtn = document.getElementById("refresh-urls-btn");
  var urlListContainer = document.getElementById("url-list-container");
  refreshUrlsBtn.addEventListener("click", loadUrls);
  async function loadUrls() {
    urlListContainer.innerHTML = '<div class="spinner"></div><p>Chargement des URLs depuis le Cloud...</p>';
    try {
      const res = await fetch("urls-trouvees.txt?v=" + (/* @__PURE__ */ new Date()).getTime());
      if (!res.ok) {
        throw new Error("Fichier introuvable. Le bot n'a peut-\xEAtre pas encore g\xE9n\xE9r\xE9 la liste.");
      }
      const text = await res.text();
      if (!text.trim()) {
        urlListContainer.textContent = "Le fichier est vide.";
      } else {
        urlListContainer.textContent = text;
      }
    } catch (e) {
      urlListContainer.innerHTML = `<p style="color: #ef4444;">Erreur : ${e.message}</p>`;
    }
  }
})();
