# Schéma JSON d'Audit Web Passif

Ce document décrit précisément la structure attendue d'un fichier JSON contenant les résultats d'un audit web passif, ayant été collecté manuellement.

## Spécification des champs

Voici la description de chaque champ du schéma, incluant son type et s'il est requis ou optionnel.

| Champ | Type | Statut | Description |
| :--- | :--- | :--- | :--- |
| `url` | `string` | **Requis** | L'URL initiale ciblée par l'audit. |
| `finalUrl` | `string` | **Requis** | L'URL finale après avoir suivi les éventuelles redirections HTTP. |
| `status` | `integer` | **Requis** | Le code de statut HTTP de la réponse finale (ex: `200`, `404`, `500`). |
| `headers` | `object` | Optionnel | Un objet contenant les en-têtes HTTP de la réponse sous forme de paires clé-valeur. |
| `setCookies` | `array` | Optionnel | Une liste d'objets décrivant les cookies définis par le serveur via l'en-tête `Set-Cookie`. Peut inclure les attributs du cookie (nom, valeur, domaine, chemin, `Secure`, `HttpOnly`, etc.). |
| `tls` | `object` | Optionnel | Les informations relatives au certificat TLS/SSL du serveur (ex: émetteur, validité, version du protocole). |
| `thirdPartyDomains`| `array` | Optionnel | Une liste de chaînes de caractères représentant les domaines tiers contactés lors du chargement de la page. |
| `thirdPartyScripts`| `array` | Optionnel | Une liste d'URLs (chaînes de caractères) pointant vers les scripts tiers inclus dans la page. |
| `technologies` | `array` | Optionnel | Une liste d'objets ou de chaînes de caractères identifiant les technologies détectées sur le site (ex: CMS, serveurs web, frameworks JS, outils d'analyse). |
| `findings` | `array` | Optionnel | Une liste d'objets décrivant les constatations, anomalies ou potentielles vulnérabilités identifiées (ex: absence d'en-têtes de sécurité, exposition de données). |
| `metadata` | `object` | Optionnel | Des méta-données contextuelles concernant l'audit lui-même (ex: date et heure de la collecte, identifiant de l'analyste, notes éventuelles). |

## Exemple JSON Minimal

Voici un exemple de fichier JSON respectant ce schéma de données :

```json
{
  "url": "http://example.com",
  "finalUrl": "https://www.example.com",
  "status": 200,
  "headers": {
    "server": "nginx/1.18.0",
    "content-type": "text/html; charset=UTF-8",
    "x-frame-options": "SAMEORIGIN"
  },
  "setCookies": [
    {
      "name": "session_id",
      "value": "a1b2c3d4e5f6",
      "domain": ".example.com",
      "path": "/",
      "secure": true,
      "httpOnly": true
    }
  ],
  "tls": {
    "protocol": "TLSv1.3",
    "issuer": "Let's Encrypt Authority X3",
    "validFrom": "2026-05-01T00:00:00Z",
    "validTo": "2026-08-01T00:00:00Z"
  },
  "thirdPartyDomains": [
    "fonts.googleapis.com",
    "www.google-analytics.com"
  ],
  "thirdPartyScripts": [
    "https://www.google-analytics.com/analytics.js"
  ],
  "technologies": [
    "WordPress 6.2",
    "PHP 8.1"
  ],
  "findings": [
    {
      "type": "Missing Header",
      "severity": "Low",
      "description": "L'en-tête Strict-Transport-Security n'est pas configuré."
    }
  ],
  "metadata": {
    "auditDate": "2026-06-24T21:05:06+02:00",
    "auditor": "Analyste Sécurité"
  }
}
```
