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
        // Extraction des liens via regex (href="http...")
        const urlRegex = /href="(https?:\/\/[^"]+)"/g;
        let match;
        const rootUrls = new Set();
        
        let baseHost = "";
        try {
            baseHost = new URL(urlToScrape).hostname;
        } catch(e) {}
        
        while ((match = urlRegex.exec(data)) !== null) {
            try {
                const parsedUrl = new URL(match[1]);
                // Ne garder que l'origine (ex: https://example.com) 
                // et exclure les liens internes au site scanné
                if (parsedUrl.hostname !== baseHost && !parsedUrl.hostname.includes(baseHost)) {
                    rootUrls.add(parsedUrl.origin);
                }
            } catch (e) {
                // Ignore silentieusement si l'URL est mal formée
            }
        }
        
        const result = Array.from(rootUrls).join('\n');
        fs.writeFileSync('urls-trouvees.txt', result);
        console.log(`✅ ${rootUrls.size} sites externes distincts trouvés et sauvegardés dans urls-trouvees.txt.`);
    });
}).on('error', (e) => {
    console.error("❌ Erreur de requête :", e.message);
});
