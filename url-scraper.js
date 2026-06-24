const https = require('https');
const http = require('http');
const fs = require('fs');

const urlToScrape = process.argv[2];

if (!urlToScrape) {
    console.error("Utilisation : node url-scraper.js <URL>");
    process.exit(1);
}

// Choix du module selon le protocole
const client = urlToScrape.startsWith('https') ? https : http;

client.get(urlToScrape, {
    headers: { 
        // Toujours s'identifier proprement lors du scraping
        'User-Agent': 'LocalSec-URL-Bot/1.0 (Bot éducatif respectueux)' 
    }
}, (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    
    res.on('end', () => {
        // Extraction basique des liens via regex (href="http...")
        const urlRegex = /href="(https?:\/\/[^"]+)"/g;
        let match;
        const urls = new Set();
        
        while ((match = urlRegex.exec(data)) !== null) {
            urls.add(match[1]);
        }
        
        const result = Array.from(urls).join('\n');
        fs.writeFileSync('urls-trouvees.txt', result);
        console.log(`✅ ${urls.size} URLs uniques trouvées et sauvegardées dans urls-trouvees.txt.`);
    });
}).on('error', (e) => {
    console.error("❌ Erreur de requête :", e.message);
});
