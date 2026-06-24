# 🛡️ Audit de Posture Sécurité Web (Bot Offline)

## 🎯 Objectif du projet

Ce projet est un **assistant conversationnel en ligne de commande (CLI)** permettant de générer automatiquement un rapport d'audit de sécurité web à partir de données brutes **déjà collectées localement**. 

Son rôle exclusif est d'**agréger, classifier et évaluer** techniquement des données hétérogènes (En-têtes HTTP, Cookies, configuration TLS, Domaines tiers) pour en déduire un **score de posture de sécurité (A à F)**, des constats précis et un plan d'action vulgarisé (Résumé exécutif). Le rendu final est une page HTML autonome et visuelle de qualité professionnelle.

## ⚠️ Avertissement & Éthique

**CE PROJET N'EFFECTUE AUCUN SCAN RÉSEAU ACTIF.**
Il n'émet aucune requête, n'exploite aucune vulnérabilité et fonctionne **strictement hors-ligne** (offline). 
Il s'agit d'un pur *outil de traitement et de normalisation de données*. Il est conçu pour analyser et interpréter des preuves brutes qui ont *déjà été collectées* par l'utilisateur (via curl, Wappalyzer, Postman, etc.) de manière légale et autorisée.

## 🛑 Limites du projet

1. **Aucune découverte automatique** : L'outil ne découvre aucune cible et ne résout aucun domaine de lui-même.
2. **Aucune validation dynamique** : Le score reflète uniquement les données injectées localement dans les fichiers (JSON ou textes bruts). Si le fichier contient des informations partielles, le rapport sera partiel.
3. **Ne remplace pas un pentest** : L'outil s'attarde sur l'hygiène de surface et les anomalies de configuration (Headers, TLS, protections RGPD, Cookies). Il ne détectera jamais les failles applicatives profondes (SQLi, CSRF, failles logiques).
4. **Approche par heuristiques** : Les détections (par ex. pour les trackers ou les cookies de session) sont basées sur des dictionnaires locaux et des heuristiques définies dans le code source.

## 📁 Architecture du Projet

Le projet suit une architecture MVC (Modèle-Vue-Contrôleur) locale Node.js pure, volontairement sans dépendance externe au registre NPM.

```text
.
├── data/                      # Données de référence
│   ├── input.json             # Fichier JSON de collecte standard (si utilisé)
│   └── input.schema.md        # Schéma de données attendu en interne
├── lib/                       # Noyau métier et logique du Bot
│   ├── bot-session.js         # Gestionnaire d'état de la session locale (MVC: Modèle)
│   ├── bot-ui.js              # Interface Terminal interactive, Couleurs ANSI (MVC: Vue)
│   ├── bot-actions.js         # Logique des commandes du bot (MVC: Contrôleur)
│   ├── import-evidence.js     # Module d'import et de normalisation de preuves brutes
│   ├── analyze-*.js           # Différents modules d'analyse (Headers, TLS, Tiers...)
│   ├── build-*.js             # Moteurs de rédaction (Recommandations, Résumé Exécutif)
│   ├── score-site.js          # Moteur de calcul de note
│   ├── validate-input.js      # Assurances de schémas des données brutes
│   └── render-report.js       # Template engine HTML vanilla
├── output/                    # Dossier généré contenant les rapports (ex: .html, session.json)
├── security-audit.js          # Orchestrateur "One-Shot" (Ancienne interface CLI non-interactive)
├── bot.js                     # 🚀 Point d'entrée de l'Assistant Interactif (Recommandé)
├── test.js                    # Tests unitaires du noyau d'analyse
├── test-import.js             # Tests unitaires du module d'import de preuves
├── package.json               # Index du projet et alias de scripts locaux
└── README.md                  # Ce fichier
```

## 🛠️ Commandes NPM disponibles

Le projet intègre maintenant des raccourcis de démarrage rapides via npm :

### Lancer l'Assistant Interactif (Bot)
Ouvre le menu interactif proposant le Mode Guidé (0), l'import de preuves (2) et la génération.
```bash
npm run bot
```

### Lancer un Audit "One-Shot" (Pipeline Automatique)
Récupère directement `./data/input.json` et génère `./output/rapport-securite-local.html` sans interface utilisateur.
```bash
npm run audit
```

### Lancer la suite de Tests
Lance toutes les assertions locales pour vérifier que l'analyse et l'import de preuves ne comportent aucune régression.
```bash
npm run test
```

## 🔄 Exemple de Workflow : Import de preuves locales

1. **Collecte externe (hors-périmètre de cet outil)** : 
   Vous requétez un serveur de manière autorisée. Vous sauvegardez les en-têtes dans un fichier texte brut `preuve-headers.txt`.
   *(Ex: `curl -I https://cible.com > preuve-headers.txt`)*
2. **Démarrage de l'Assistant** : 
   Vous lancez la commande `npm run bot`.
3. **Importation** : 
   Dans le menu principal, vous choisissez l'**Option 2** (Importer des preuves locales brutes) et fournissez le chemin `./preuve-headers.txt`. Le module interne `import-evidence.js` traduit automatiquement ces données brutes dans le format strict du projet.
4. **Analyse & Rapport** : 
   Vous lancez l'**Option 4** (Validation), puis l'**Option 5** (Analyse) et enfin l'**Option 6** (Générer le rapport HTML).
5. **Résultat** : 
   Le fichier autonome `output/rapport-securite-local.html` est créé, offrant un diagnostic pointu de vos preuves brutes sans que rien n'ait jamais transité par internet.

---
*Conçu avec rigueur pour simplifier l'exploitation de données brutes via un assistant 100% hors-ligne.*
