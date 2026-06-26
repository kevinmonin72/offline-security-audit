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
        if (content.toLowerCase().includes("<html") || content.includes("#report-data") || content.includes("#audit-data") || content.includes("localsec")) {
          const match = content.match(/<script[^>]*id=["']?(?:report-data|audit-data)["']?[^>]*>([\s\S]*?)<\/script>/i);
          if (match && match[1]) {
            try {
              const parsed = JSON.parse(match[1].trim());
              const reportObj = Array.isArray(parsed) ? parsed[0] : parsed;
              reportObj.isLocalsecAudit = true;
              return reportObj;
            } catch (e) {
            }
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
            } else if (finding.tags && finding.tags.includes("dom")) {
              if (finding.severity === "critical") {
                applyPenalty(25, finding.title, "DOM_CRITICAL");
              } else if (finding.severity === "high") {
                applyPenalty(15, finding.title, "DOM_HIGH");
              } else if (finding.severity === "medium") {
                applyPenalty(10, finding.title, "DOM_MEDIUM");
              } else {
                applyPenalty(5, finding.title, "DOM_LOW");
              }
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
        if (finding.tags && finding.tags.includes("dom")) {
          return "S\xE9curit\xE9 Applicative & DOM";
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

  // lib/vulgarize-findings.js
  var require_vulgarize_findings = __commonJS({
    "lib/vulgarize-findings.js"(exports, module) {
      var SEV_COLORS = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#3b82f6", Info: "#94a3b8" };
      function escapeHtml(value) {
        return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;"
        })[c]);
      }
      function sevMeta(severity, borderline) {
        if (borderline) return { label: "Moyenne \u2B06", note: "proche \xE9lev\xE9e", color: "#f59e0b" };
        switch (severity) {
          case "Critical":
            return { label: "Critique", note: "", color: "#ef4444" };
          case "High":
            return { label: "\xC9lev\xE9e", note: "", color: "#f97316" };
          case "Medium":
            return { label: "Moyenne", note: "", color: "#eab308" };
          default:
            return { label: severity || "Info", note: "", color: "#94a3b8" };
        }
      }
      function deriveCategory(f) {
        const cat = String(f.category || "").toLowerCase();
        const id = String(f.id || "").toUpperCase();
        const tit = String(f.title || "").toLowerCase();
        const tags = (f.tags || []).map((t) => String(t).toLowerCase());
        if (tags.includes("api-key") || tags.includes("source-code")) return "Fuite de secrets";
        if (cat.includes("header") || id.includes("HSTS") || id.includes("CSP") || id.includes("X_FRAME") || id.includes("REFERRER") || id.includes("PERMISSIONS") || id.includes("CONTENT_TYPE") || id.includes("XSS_PROTECTION")) return "En-t\xEAtes de s\xE9curit\xE9";
        if (cat.includes("cookie") || id.includes("COOKIE") || id.includes("SESSION")) return "Cookies & Sessions";
        if (cat.includes("tls") || cat.includes("ssl") || cat.includes("cleartext") || tags.includes("mixed-content") || tags.includes("password")) return "Chiffrement HTTPS";
        if (tags.includes("seo") || tags.includes("black-hat")) return "SEO / R\xE9putation";
        if (tags.includes("localstorage") || tags.includes("tokens")) return "Gestion des jetons";
        if (tags.includes("email") || tags.includes("privacy") || tit.includes("traceur") || tit.includes("pixel") || tit.includes("cookie")) return "Confidentialit\xE9 / RGPD";
        return f.category || f.type || "Autre";
      }
      function vulgarize(f) {
        const id = String(f.id || "").toUpperCase();
        const title = String(f.title || "").toLowerCase();
        const tags = (f.tags || []).map((t) => String(t).toLowerCase());
        if (id.includes("API") || tags.includes("api-key")) return "Une cl\xE9 secr\xE8te est visible directement dans le code du site. N'importe qui peut la copier et s'en servir \xE0 vos frais.";
        if (tags.includes("password") || title.includes("mot de passe")) return "Les mots de passe circulent en clair sur le r\xE9seau : une personne mal intentionn\xE9e peut les intercepter.";
        if (title.includes("pixel") || title.includes("traceur") || title.includes("hotjar") || title.includes("criteo") || title.includes("hubspot") || title.includes("tag manager")) return "Un traceur publicitaire collecte les donn\xE9es de vos visiteurs. Sans consentement clair, c'est un risque RGPD/CNIL.";
        if (id.includes("HSTS") || tags.includes("mixed-content") || title.includes("http ")) return "La connexion peut basculer en non-chiffr\xE9 : un pirate sur le m\xEAme Wi-Fi pourrait espionner les \xE9changes.";
        if (id.includes("CSP")) return "Protection insuffisante contre l'injection de code pi\xE9g\xE9 (vol de donn\xE9es, fausses publicit\xE9s).";
        if (id.includes("X_FRAME") || id.includes("FRAME")) return "Votre site peut \xEAtre affich\xE9 dans une fausse page pour tromper vos visiteurs (clickjacking).";
        if (id.includes("CONTENT_TYPE")) return "Le navigateur pourrait ex\xE9cuter un fichier malveillant d\xE9guis\xE9 en simple image.";
        if (id.includes("REFERRER")) return "L'adresse de vos pages, parfois sensible, peut fuiter vers d'autres sites.";
        if (id.includes("PERMISSIONS")) return "Cam\xE9ra, micro et g\xE9olocalisation ne sont pas explicitement bloqu\xE9s pour les scripts.";
        if (id.includes("XSS_PROTECTION")) return "Une ancienne protection du navigateur, aujourd'hui obsol\xE8te et risqu\xE9e, est rest\xE9e active.";
        if (id.includes("HTTPONLY")) return "Un script malveillant peut lire ce cookie et voler la session de l'utilisateur.";
        if (id.includes("SECURE")) return "L'identifiant de connexion peut circuler en clair et \xEAtre intercept\xE9.";
        if (id.includes("SAMESITE") || id.includes("SESSION")) return "Le site est plus expos\xE9 aux actions forc\xE9es \xE0 l'insu de l'utilisateur (attaque CSRF).";
        if (tags.includes("seo") || tags.includes("black-hat")) return "Des liens cach\xE9s polluent votre r\xE9f\xE9rencement Google \u2014 souvent le signe d'un piratage.";
        if (tags.includes("email")) return "Vos adresses e-mail sont visibles et peuvent \xEAtre aspir\xE9es par des robots spammeurs.";
        if (tags.includes("comments")) return "Des notes internes de d\xE9veloppeurs tra\xEEnent dans le code source, lisibles par tous.";
        if (tags.includes("localstorage") || tags.includes("tokens")) return "Des jetons de s\xE9curit\xE9 sont stock\xE9s d'une fa\xE7on vuln\xE9rable au vol par un script.";
        return f.description || "\xC9cart de s\xE9curit\xE9 \xE0 corriger pour durcir votre site.";
      }
      function techFix(f) {
        const id = String(f.id || "").toUpperCase();
        const cat = String(f.category || "");
        if (cat.includes("Headers") || cat.includes("Security Headers") || id.includes("HSTS") || id.includes("CSP") || id.includes("X_FRAME") || id.includes("CONTENT_TYPE") || id.includes("REFERRER") || id.includes("PERMISSIONS") || id.includes("XSS_PROTECTION")) {
          return "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'  \u2022  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
        }
        if (cat.includes("Cookies") || id.includes("COOKIE") || id.includes("SESSION")) {
          return "Set-Cookie: __Host-SESSIONID=<val>; SameSite=Strict; Secure; HttpOnly; Partitioned";
        }
        return f.recommendation || "Appliquer les directives de durcissement ANSSI.";
      }
      var TH = "background:#0b1220;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;font-size:0.72rem;font-weight:800;text-align:left;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.1);";
      var TD = "padding:16px;border-bottom:1px solid rgba(255,255,255,0.06);vertical-align:top;color:#cbd5e1;";
      function buildFindingsTable2(findings, eliminated) {
        if (!findings || findings.length === 0) {
          return `<div style="padding:26px;background:rgba(34,197,94,0.1);border:1px solid #22c55e;border-radius:14px;color:#22c55e;font-weight:600;text-align:center;">\u2705 Architecture conforme. Aucune faille critique, \xE9lev\xE9e ou moyenne-haute d\xE9tect\xE9e.</div>`;
        }
        let rows = "";
        findings.forEach((f) => {
          const sev = f.severity || f.riskLevel || "Info";
          const borderline = sev === "Medium";
          const m = sevMeta(sev, borderline);
          const category = deriveCategory(f);
          const plain = vulgarize(f);
          const fix = techFix(f);
          const rowBg = borderline ? "background:rgba(245,158,11,0.06);" : "";
          const dash = borderline ? "dashed" : "solid";
          rows += `
            <tr style="border-left:5px ${dash} ${m.color};${rowBg}">
                <td style="${TD}width:120px;white-space:nowrap;">
                    <span style="display:inline-block;padding:4px 10px;border-radius:20px;font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.4px;border:1px solid ${m.color}66;background:${m.color}1f;color:${m.color};">${escapeHtml(m.label)}</span>
                    ${m.note ? `<span style="display:block;margin-top:5px;font-size:0.68rem;color:#f59e0b;font-style:italic;">${escapeHtml(m.note)}</span>` : ""}
                </td>
                <td style="${TD}width:150px;"><span style="display:inline-block;background:rgba(56,189,248,0.12);color:#38bdf8;padding:4px 10px;border-radius:8px;font-size:0.76rem;font-weight:600;">${escapeHtml(category)}</span></td>
                <td style="${TD}width:200px;color:#fff;font-weight:600;">${escapeHtml(f.title || "Vuln\xE9rabilit\xE9 d\xE9tect\xE9e")}</td>
                <td style="${TD}color:#e2e8f0;line-height:1.5;">${escapeHtml(plain)}</td>
                <td style="${TD}min-width:230px;"><code style="font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:0.78rem;color:#38bdf8;word-break:break-word;white-space:normal;display:block;background:#0f172a;padding:10px;border-radius:8px;border:1px solid #334155;">${escapeHtml(fix)}</code></td>
            </tr>`;
        });
        let html = `
        <div style="width:100%;overflow-x:auto;border-radius:16px;border:1px solid rgba(255,255,255,0.08);box-shadow:0 10px 25px rgba(0,0,0,0.3);margin-bottom:18px;">
            <table style="width:100%;min-width:760px;border-collapse:collapse;background:#1e293b;font-size:0.9rem;">
                <thead>
                    <tr>
                        <th style="${TH}">Criticit\xE9</th>
                        <th style="${TH}">Crit\xE8re</th>
                        <th style="${TH}">Faille</th>
                        <th style="${TH}">Ce que \xE7a signifie pour vous</th>
                        <th style="${TH}">Correctif technique</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:18px;font-size:0.8rem;color:#94a3b8;margin-bottom:30px;padding:4px 2px;">
            <span style="display:inline-flex;align-items:center;gap:7px;"><span style="width:12px;height:12px;border-radius:3px;display:inline-block;background:#ef4444;"></span>Critique</span>
            <span style="display:inline-flex;align-items:center;gap:7px;"><span style="width:12px;height:12px;border-radius:3px;display:inline-block;background:#f97316;"></span>\xC9lev\xE9e</span>
            <span style="display:inline-flex;align-items:center;gap:7px;"><span style="width:12px;height:12px;border-radius:3px;display:inline-block;background:#f59e0b;border:1px dashed #fbbf24;"></span>Moyenne \u2B06 (proche d'une \xE9lev\xE9e)</span>
        </div>`;
        if (eliminated && eliminated.length > 0) {
          let elimRows = "";
          eliminated.forEach((fp) => {
            elimRows += `
                <tr style="border-left:5px solid #64748b;opacity:0.75;">
                    <td style="${TD}width:120px;"><span style="display:inline-block;padding:4px 10px;border-radius:20px;font-size:0.7rem;font-weight:800;background:#64748b30;color:#cbd5e1;">REJET\xC9</span></td>
                    <td style="${TD}color:#94a3b8;text-decoration:line-through;" colspan="2">${escapeHtml(fp.finding && fp.finding.title ? fp.finding.title : "Anomalie r\xE9concili\xE9e")}</td>
                    <td style="${TD}color:#4ade80;" colspan="2">\u{1F6E1}\uFE0F ${escapeHtml(fp.reason || "Invalid\xE9 lors du contr\xF4le.")}</td>
                </tr>`;
          });
          html += `
        <div style="margin:10px 0 8px 0;font-size:1rem;font-weight:700;color:#94a3b8;">\u{1F5D1}\uFE0F Faux positifs \xE9cart\xE9s (${eliminated.length})</div>
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
        buildFindingsTable: buildFindingsTable2
      };
    }
  });

  // lib/render-report.js
  var require_render_report = __commonJS({
    "lib/render-report.js"(exports, module) {
      var { deriveCategory, buildFindingsTable: buildFindingsTable2 } = require_vulgarize_findings();
      function getGradeColor(grade) {
        switch (grade) {
          case "A":
            return "#22c55e";
          case "B":
            return "#eab308";
          case "C":
            return "#f97316";
          case "D":
            return "#ea580c";
          default:
            return "#ef4444";
        }
      }
      function renderHtmlReport2(reportsArray) {
        if (!Array.isArray(reportsArray) || reportsArray.length === 0) {
          return "<!DOCTYPE html><html lang='fr'><body style='background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h1>Aucune donn\xE9e d'audit disponible.</h1></body></html>";
        }
        const report = reportsArray[0];
        const siteUrl = report.siteUrl || report.url || report.finalUrl || "Cible audit\xE9";
        const hostname = (() => {
          try {
            return new URL(siteUrl).hostname;
          } catch (e) {
            return siteUrl;
          }
        })();
        const score = report.score !== void 0 ? report.score : 50;
        const grade = report.grade || (score >= 90 ? "A" : score >= 75 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F");
        const color = getGradeColor(grade);
        const rawFindings = report.findings || [];
        const validFindings = rawFindings.filter((f) => {
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
            if (id.includes("CSP") || id.includes("FRAME") || id.includes("SESSION") || cat.includes("publicit\xE9") || cat.includes("advertising") || cat.includes("tag manager") || cat.includes("marketing") || cat.includes("session replay") || tit.includes("google tag manager") || tit.includes("pixel") || tit.includes("hubspot") || tit.includes("hotjar") || tit.includes("criteo")) {
              return true;
            }
            return false;
          }
          return false;
        });
        const order = { "Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5 };
        validFindings.sort((a, b) => {
          const sa = order[a.severity || a.riskLevel || "Info"] || 6;
          const sb = order[b.severity || b.riskLevel || "Info"] || 6;
          if (sa !== sb) return sa - sb;
          return deriveCategory(a).localeCompare(deriveCategory(b));
        });
        const critCount = validFindings.filter((f) => f.severity === "Critical" || f.severity === "High").length;
        const medCount = validFindings.filter((f) => f.severity === "Medium").length;
        let findingsHtml = "";
        if (validFindings.length === 0) {
          findingsHtml = `<div class="zero-flaws">\u2705 Architecture certifi\xE9e conforme aux standards de s\xE9curit\xE9 2026. Aucune vuln\xE9rabilit\xE9 externe d\xE9tect\xE9e.</div>`;
        } else {
          findingsHtml += buildFindingsTable2(validFindings, report.eliminatedFindings || []);
        }
        const emailPitch = `Objet : Alerte S\xE9curit\xE9 & Conformit\xE9 \u2014 Failles d\xE9tect\xE9es sur ${hostname}

Bonjour l'\xE9quipe de ${hostname},

En analysant la posture de s\xE9curit\xE9 publique de votre architecture web, notre moteur d'audit a identifi\xE9 ${validFindings.length} faille(s) r\xE9siduelle(s) (Score : ${score}/100 - Grade ${grade}).

${critCount > 0 ? `\u{1F6A8} Nous avons relev\xE9 ${critCount} vuln\xE9rabilit\xE9(s) critique(s) ou \xE9lev\xE9e(s) directement expos\xE9es. Dans le contexte actuel de recrudescence des ransomwares et des sanctions RGPD (Art. 32), ces br\xE8ches repr\xE9sentent un risque op\xE9rationnel et juridique imm\xE9diat.` : `\u26A0\uFE0F Bien que votre base principale soit accessible, nous avons relev\xE9 ${medCount} point(s) de durcissement requis pour \xE9viter toute compromission d'en-t\xEAte ou vol de session cookie.`}

La bonne nouvelle ? La majorit\xE9 de ces failles peuvent \xEAtre corrig\xE9es en moins d'une heure par un expert.

J'ai pr\xE9par\xE9 un dossier technique d'intervention contenant le code exact de rem\xE9diation pour chacune de ces anomalies. Seriez-vous disponible mardi prochain \xE0 14h pour un briefing t\xE9l\xE9phonique de 10 minutes afin que je vous transmette le dossier ?

Bien \xE0 vous,

Responsable Audit Cyber & Conformit\xE9`;
        const now = (/* @__PURE__ */ new Date()).toLocaleDateString("fr-FR");
        return `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit S\xE9curit\xE9 \u2014 ${hostname}</title>
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
                    <h1>\u{1F6E1}\uFE0F Dossier d'Audit Cyber</h1>
                    <p>Cible : <strong>${hostname}</strong> \u2014 Date : ${now}</p>
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
                    <div class="stat-val" style="color: ${critCount > 0 ? "#ef4444" : "#22c55e"}">${critCount > 0 ? "ALERTE" : "PROTECT"}</div>
                    <div class="stat-lbl">Statut Exposition</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val">${validFindings.length}</div>
                    <div class="stat-lbl">Failles Confirm\xE9es</div>
                </div>
                <div class="stat-box">
                    <div class="stat-val">${critCount}</div>
                    <div class="stat-lbl">Critiques / \xC9lev\xE9es</div>
                </div>
            </div>
        </div>

        <div class="section-title">
            <span>\u{1F3AF} Failles class\xE9es par criticit\xE9 &amp; crit\xE8re</span>
        </div>

        ${findingsHtml}

        <div class="pitch-card">
            <div class="pitch-tag">\u{1F9F2} Mod\xE8le Email Prospection Pr\xEAt \xE0 l'Emploi</div>
            <div class="pitch-text">${emailPitch}</div>
        </div>

        <div class="footer">
            Rapport g\xE9n\xE9r\xE9 de mani\xE8re autonome par LocalSec Audit Pro v2.0
        </div>
    </div>
</body>
</html>`;
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
  var { buildFindingsTable } = require_vulgarize_findings();
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
  window.addEventListener("ShowLocalsecEmail", (e) => {
    tabBtns.forEach((b) => b.classList.remove("active"));
    tabContents.forEach((c) => c.classList.add("hidden"));
    const auditTabBtn = document.querySelector('[data-tab="audit-tab"]');
    if (auditTabBtn) auditTabBtn.classList.add("active");
    document.getElementById("audit-tab").classList.remove("hidden");
    dropZone.classList.add("hidden");
    errorCard.classList.add("hidden");
    renderSalesEmailView(e.detail);
  });
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
        let parsedContent;
        try {
          parsedContent = JSON.parse(content);
        } catch (e) {
        }
        if (parsedContent && parsedContent.isLocalsecAudit) {
          renderSalesEmailView(parsedContent);
          return;
        }
        const normalizedData = importEvidenceString(content);
        if (normalizedData && normalizedData.isLocalsecAudit) {
          renderSalesEmailView(normalizedData);
          return;
        }
        let allFindings = [];
        allFindings.push(...analyzeHeaders(normalizedData.headers));
        const parsedCookies = parseCookies(normalizedData.setCookies || []);
        allFindings.push(...analyzeCookies(parsedCookies));
        const auditDate = /* @__PURE__ */ new Date();
        const tlsResult = analyzeTls(normalizedData.tls, auditDate);
        allFindings.push(...tlsResult.findings);
        const allThirdPartyStrings = [...normalizedData.thirdPartyDomains || [], ...normalizedData.thirdPartyScripts || []];
        const thirdPartiesResult = analyzeThirdParties(allThirdPartyStrings);
        allFindings.push(...thirdPartiesResult);
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
          thirdParties: thirdPartiesResult,
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
  function renderSalesEmailView(data) {
    loading.classList.add("hidden");
    resultCard.classList.remove("hidden");
    downloadBtn.style.display = "inline-block";
    downloadBtn.textContent = "\u{1F4BE} T\xE9l\xE9charger le Lead Magnet HTML";
    currentHtmlReport = renderHtmlReport([data]);
    const findings = data.findings || [];
    const validFindings = findings.filter((f) => {
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
        if (id.includes("CSP") || id.includes("FRAME") || id.includes("SESSION") || cat.includes("publicit\xE9") || cat.includes("advertising") || cat.includes("tag manager") || cat.includes("marketing") || cat.includes("session replay") || tit.includes("google tag manager") || tit.includes("pixel") || tit.includes("hubspot") || tit.includes("hotjar") || tit.includes("criteo")) {
          return true;
        }
        return false;
      }
      return false;
    });
    const order = { "Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5 };
    validFindings.sort((a, b) => {
      const sa = order[a.severity || a.riskLevel || "Info"] || 6;
      const sb = order[b.severity || b.riskLevel || "Info"] || 6;
      return sa - sb;
    });
    const grade = data.grade || "C";
    const score = data.score || 50;
    let color = "#3b82f6";
    if (grade === "A") color = "#22c55e";
    else if (grade === "B") color = "#eab308";
    else if (grade === "C") color = "#f97316";
    else color = "#ef4444";
    scoreBadge.textContent = grade;
    scoreBadge.style.backgroundColor = color;
    scoreBadge.style.boxShadow = `0 0 25px ${color}`;
    const findingsHtml = buildFindingsTable(validFindings, []);
    const hostname = (() => {
      try {
        return new URL(data.siteUrl).hostname;
      } catch (e) {
        return data.siteUrl || "votre site";
      }
    })();
    const critCount = validFindings.filter((f) => f.severity === "Critical" || f.severity === "High").length;
    const medCount = validFindings.filter((f) => f.severity === "Medium").length;
    const emailPitch = `Objet : Alerte S\xE9curit\xE9 & Conformit\xE9 \u2014 Failles d\xE9tect\xE9es sur ${hostname}

Bonjour l'\xE9quipe de ${hostname},

En analysant la posture de s\xE9curit\xE9 publique de votre architecture web, notre moteur d'audit a identifi\xE9 ${validFindings.length} faille(s) r\xE9siduelle(s) (Score : ${score}/100 - Grade ${grade}).

${critCount > 0 ? `\u{1F6A8} Nous avons relev\xE9 **${critCount} vuln\xE9rabilit\xE9(s) critique(s) ou \xE9lev\xE9e(s)** directement expos\xE9es. Dans le contexte actuel de recrudescence des ransomwares et des sanctions RGPD (Art. 32), ces br\xE8ches repr\xE9sentent un risque op\xE9rationnel et juridique imm\xE9diat.` : `\u26A0\uFE0F Bien que votre base principale soit sible, nous avons relev\xE9 **${medCount} point(s) de durcissement requis** pour \xE9viter toute compromission d'en-t\xEAte ou vol de session cookie.`}

La bonne nouvelle ? La majorit\xE9 de ces failles peuvent \xEAtre corrig\xE9es en moins d'une heure par un expert.

J'ai pr\xE9par\xE9 un rapport technique d'intervention contenant le code exact de rem\xE9diation pour chacune de ces anomalies. Seriez-vous disponible mardi prochain \xE0 14h pour un briefing t\xE9l\xE9phonique de 10 minutes afin que je vous transmette le dossier ?

Bien \xE0 vous,

*Responsable Audit Offensif & D\xE9fensif*`;
    resultSummary.innerHTML = `
        <div style="margin-bottom:30px;background:linear-gradient(135deg,rgba(30,41,59,0.9),rgba(15,23,42,0.9));padding:25px;border-radius:16px;border:1px solid rgba(255,255,255,0.1);box-shadow:0 10px 30px rgba(0,0,0,0.4);">
            <div style="display:flex;justify-content:space-around;align-items:center;margin-bottom:25px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:20px;">
                <div style="text-align:center;">
                    <div style="font-size:0.85em;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Cible Audit\xE9</div>
                    <div style="font-size:1.3em;font-weight:700;color:#38bdf8;">${hostname}</div>
                </div>
                <div style="text-align:center;">
                    <div style="font-size:0.85em;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Indice de Menace</div>
                    <div style="font-size:1.3em;font-weight:700;color:${critCount > 0 ? "#ef4444" : "#22c55e"};">${critCount > 0 ? "CRITIQUE" : "MA\xCETRIS\xC9"}</div>
                </div>
                <div style="text-align:center;">
                    <div style="font-size:0.85em;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Failles confirm\xE9es</div>
                    <div style="font-size:1.3em;font-weight:700;color:#f8fafc;">${validFindings.length}</div>
                </div>
            </div>

            <h3 style="color:#f8fafc;font-size:1.3em;margin-bottom:20px;display:flex;align-items:center;gap:10px;">
                <span>\u{1F3AF} Failles class\xE9es par criticit\xE9 &amp; crit\xE8re</span>
            </h3>
            <div style="max-height:480px;overflow-y:auto;padding-right:8px;margin-bottom:30px;">
                ${findingsHtml}
            </div>

            <div style="background:#0f172a;border:2px solid #8b5cf6;border-radius:12px;padding:22px;text-align:left;position:relative;">
                <div style="position:absolute;top:-12px;left:20px;background:#8b5cf6;color:#fff;font-size:0.75em;font-weight:800;padding:3px 12px;border-radius:12px;text-transform:uppercase;letter-spacing:1px;">\u{1F9F2} Lead Magnet \u2014 Email de Prospection</div>
                <div style="font-family:'Inter',sans-serif;font-size:0.95em;color:#e2e8f0;white-space:pre-wrap;line-height:1.6;margin-top:8px;">${emailPitch}</div>
                <button id="copy-email-btn" style="margin-top:20px;width:100%;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;border:none;padding:14px;border-radius:8px;font-weight:700;font-size:1em;cursor:pointer;transition:transform 0.2s,box-shadow 0.2s;box-shadow:0 4px 20px rgba(139,92,246,0.4);">\u{1F4CB} Copier le pitch cold-email pr\xEAt \xE0 envoyer</button>
            </div>
        </div>
    `;
    setTimeout(async () => {
      let liveReconciled = [...validFindings];
      let falsePositivesEliminated = [];
      try {
        const probeUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(data.siteUrl || "http://" + hostname)}`;
        const res = await fetch(probeUrl);
        if (res.ok) {
          const json = await res.json();
          const liveHtml = (json.contents || "").toLowerCase();
          const doc = new DOMParser().parseFromString(json.contents || "", "text/html");
          liveReconciled = validFindings.filter((f) => {
            const id = (f.id || "").toUpperCase();
            const title = (f.title || "").toLowerCase();
            const cat = (f.category || "").toLowerCase();
            if (id.includes("VIEWPORT") || title.includes("viewport")) {
              if (doc.querySelector('meta[name="viewport"]')) {
                falsePositivesEliminated.push({ finding: f, reason: "Balise <meta name='viewport'> confirm\xE9e active et pr\xE9sente sur le DOM en direct." });
                return false;
              }
            }
            if (id.includes("TITLE") || title.includes("title")) {
              const t = doc.querySelector("title");
              if (t && t.textContent && t.textContent.trim().length > 2) {
                falsePositivesEliminated.push({ finding: f, reason: "Balise <title> confirm\xE9e non vide en direct (" + t.textContent.trim().substring(0, 25) + "...)." });
                return false;
              }
            }
            if (id.includes("WORDPRESS") || title.includes("wordpress") || cat.includes("wordpress")) {
              const hasWpMeta = doc.querySelector('meta[name="generator"][content*="WordPress"]');
              const hasWpLink = liveHtml.includes("wp-content") || liveHtml.includes("wp-includes");
              if (!hasWpMeta && !hasWpLink) {
                falsePositivesEliminated.push({ finding: f, reason: "Signature WordPress introuvable lors du sondage actif HTML en direct." });
                return false;
              }
            }
            return true;
          });
        }
      } catch (e) {
      }
      if (falsePositivesEliminated.length > 0 || liveReconciled.length !== validFindings.length) {
        const container = document.querySelector('div[style*="max-height:480px"]');
        if (container) {
          container.innerHTML = buildFindingsTable(liveReconciled, falsePositivesEliminated);
        }
        const countBoxes = document.querySelectorAll('div[style*="font-size:1.3em;font-weight:700"]');
        if (countBoxes.length >= 3) {
          countBoxes[2].textContent = liveReconciled.length;
        }
        const updatedData = { ...data, findings: liveReconciled, eliminatedFindings: falsePositivesEliminated };
        currentHtmlReport = renderHtmlReport([updatedData]);
      }
    }, 700);
    document.getElementById("copy-email-btn").addEventListener("click", () => {
      navigator.clipboard.writeText(emailPitch).then(() => {
        const b = document.getElementById("copy-email-btn");
        b.textContent = "\u2705 Pitch copi\xE9 avec succ\xE8s !";
        b.style.background = "#22c55e";
        setTimeout(() => {
          b.textContent = "\u{1F4CB} Copier le pitch cold-email pr\xEAt \xE0 envoyer";
          b.style.background = "linear-gradient(135deg,#3b82f6,#8b5cf6)";
        }, 3e3);
      });
    });
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
    downloadBtn.style.display = "inline-block";
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
  var urlListContainer = document.getElementById("url-list-container");
  var refreshUrlsBtn = document.getElementById("refresh-urls-btn");
  var urlSearchInput = document.getElementById("url-search");
  var urlCountEl = document.getElementById("url-count");
  var allLoadedUrls = [];
  if (refreshUrlsBtn) refreshUrlsBtn.addEventListener("click", loadUrls);
  if (urlSearchInput) urlSearchInput.addEventListener("input", () => renderUrlList(allLoadedUrls, urlSearchInput.value.trim().toLowerCase()));
  function renderUrlList(urls, filter = "") {
    const filtered = filter ? urls.filter((u) => u.toLowerCase().includes(filter)) : urls;
    urlListContainer.innerHTML = "";
    if (filtered.length === 0) {
      urlListContainer.innerHTML = '<p style="color: var(--text-muted); padding: 12px;">Aucune URL ne correspond.</p>';
      if (urlCountEl) urlCountEl.textContent = `0 / ${urls.length}`;
      return;
    }
    const fragment = document.createDocumentFragment();
    const savedState = JSON.parse(localStorage.getItem("auditedUrls") || "{}");
    let auditedCount = 0;
    filtered.forEach((url) => {
      const div = document.createElement("div");
      div.className = "url-item";
      const isChecked = savedState[url] === true;
      if (isChecked) {
        div.classList.add("checked");
        auditedCount++;
      }
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = isChecked;
      cb.title = "Marquer comme audit\xE9";
      cb.addEventListener("change", (e) => {
        const state = JSON.parse(localStorage.getItem("auditedUrls") || "{}");
        state[url] = e.target.checked;
        localStorage.setItem("auditedUrls", JSON.stringify(state));
        if (e.target.checked) div.classList.add("checked");
        else div.classList.remove("checked");
        updateCount();
      });
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = url;
      div.appendChild(cb);
      div.appendChild(link);
      fragment.appendChild(div);
    });
    urlListContainer.appendChild(fragment);
    if (urlCountEl) urlCountEl.textContent = `${filtered.length} affich\xE9es / ${urls.length} totales \u2014 ${auditedCount} audit\xE9es`;
  }
  function updateCount() {
    if (!urlCountEl) return;
    const savedState = JSON.parse(localStorage.getItem("auditedUrls") || "{}");
    const auditedCount = allLoadedUrls.filter((u) => savedState[u]).length;
    urlCountEl.textContent = `${allLoadedUrls.length} URLs \u2014 ${auditedCount} audit\xE9es`;
  }
  async function loadUrls() {
    urlListContainer.innerHTML = '<div class="spinner"></div><p>Chargement des URLs depuis le Cloud...</p>';
    if (urlCountEl) urlCountEl.textContent = "\u2014";
    try {
      const res = await fetch("urls-trouvees.txt?v=" + Date.now());
      if (!res.ok) throw new Error("Fichier introuvable. Le bot n'a peut-\xEAtre pas encore g\xE9n\xE9r\xE9 la liste.");
      const text = await res.text();
      allLoadedUrls = [...new Set(text.split("\n").map((u) => u.trim()).filter(Boolean))].sort();
      if (allLoadedUrls.length === 0) {
        urlListContainer.innerHTML = '<p style="color: var(--text-muted);">Le fichier est vide.</p>';
        return;
      }
      renderUrlList(allLoadedUrls, urlSearchInput ? urlSearchInput.value.trim().toLowerCase() : "");
    } catch (e) {
      urlListContainer.innerHTML = `<p style="color: #ef4444;">Erreur : ${e.message}</p>`;
      if (urlCountEl) urlCountEl.textContent = "\u2014";
    }
  }
})();
