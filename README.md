# LocalSec Audit & URL Bot 🛡️

Ce projet contient deux éléments distincts qui fonctionnent ensemble :
1. **Un outil d'audit de sécurité Web (SaaS Hors-Ligne)**
2. **Un Bot GitHub Actions (Spider) pour recenser des URLs**

## 1. Moteur d'Audit SaaS (Hors-ligne)

Le moteur principal est hébergé de manière statique via GitHub Pages. Tout l'algorithme s'exécute localement dans votre navigateur sans faire appel à des serveurs tiers.

👉 **[Accéder à l'interface Web](https://kevinmonin72.github.io/offline-security-audit/)**

### Comment l'utiliser avec un fichier `.har` ?
1. Rendez-vous sur le site cible avec Google Chrome.
2. Ouvrez les outils de développement (Clic droit > Inspecter > onglet **Réseau/Network**).
3. Rafraîchissez la page pour capturer le trafic.
4. Cliquez sur l'icône de téléchargement "Exporter HAR".
5. Glissez-déposez le fichier `.har` téléchargé dans l'interface de LocalSec Audit.
6. Cliquez sur "Ouvrir le rapport HTML".

---

## 2. Bot de Recensement d'URLs

Ce dépôt intègre un spider automatisé (`url-scraper.js`) déclenché par GitHub Actions (`.github/workflows/url-bot.yml`). Il visite un site, extrait les liens, et pousse la liste générée vers un autre dépôt : l'extension Chrome.

### Configuration du Workflow (Important)
Pour que l'automatisation ait le droit de pousser la liste `urls-trouvees.txt` vers le dépôt `localsec-extension`, vous devez configurer un secret :
1. Allez dans les paramètres de ce dépôt : **Settings > Secrets and variables > Actions**.
2. Créez un **New repository secret** nommé `GH_PAT`.
3. Mettez-y en valeur votre Jeton d'accès personnel GitHub (Token classique avec la permission `repo`).

### Modifier la cible du Bot
Pour changer le site que le bot scanne 2 fois par jour, éditez le fichier `.github/workflows/url-bot.yml` à la ligne 24 :
```yaml
run: node url-scraper.js "https://nouveau-site.com"
```

## 🛠️ Développement en local

Si vous souhaitez modifier le design (`style.css`), l'algorithme (`lib/`) ou l'interface (`app.js`), vous devez recompiler le front-end avant de déployer :

1. Installez les dépendances :
   ```bash
   npm install
   ```
2. Modifiez les fichiers dans le dossier `public/` ou `lib/`.
3. Compilez :
   ```bash
   npm run build
   ```
4. Poussez sur GitHub (le déploiement vers GitHub Pages est automatique).

*(Note : vous pouvez aussi démarrer le serveur local `npm start` pour tester sans pousser sur GitHub).*
