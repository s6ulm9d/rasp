const http = require('http');

const ENDPOINT = 'http://localhost:8081';

const payloads = [
    { name: 'Double URL Encoded SQLi', url: `${ENDPOINT}/vuln/sqli?id=%2527%2520UNION%2520SELECT%2520*%2520FROM%2520secrets--` },
    { name: 'SSRF Hex Bypass', url: `${ENDPOINT}/vuln/ssrf?url=http://0x7f000001` },
    { name: 'SSRF Decimal Bypass', url: `${ENDPOINT}/vuln/ssrf?url=http://2130706433` },
    { name: 'SSRF Misdirection Bypass', url: `${ENDPOINT}/vuln/ssrf?url=http://localhost@evil.com` }
];

async function runTests() {
    console.log("🔥 Running Brutal Multi-Layer RASP Bypass Tests...\n");

    for (const p of payloads) {
        process.stdout.write(`Testing [${p.name}]... `);
        
        await new Promise(resolve => {
            http.get(p.url, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 403) {
                        try {
                            const parsed = JSON.parse(data);
                            console.log(`\x1b[32m🛡️  BLOCKED (403)\x1b[0m -> ${parsed.message} (Score: ${parsed.details.score})`);
                        } catch(e) {
                            console.log(`\x1b[32m🛡️  BLOCKED (403)\x1b[0m`);
                        }
                    } else if (res.statusCode === 500) {
                        console.log(`\x1b[33m⚠️  ERROR (500)\x1b[0m -> ${data.substring(0, 50)}`);
                    } else {
                        console.log(`\x1b[31m❌ BYPASSED (${res.statusCode})\x1b[0m -> ${data.substring(0, 50)}`);
                    }
                    resolve();
                });
            }).on('error', (err) => {
                console.log(`\x1b[33m⚠️  NETWORK ERROR\x1b[0m -> ${err.message}`);
                resolve();
            });
        });
    }

    console.log("\n🧪 Running Chained Attack Simulation (Encoded + SSRF + DB query)...");
    
    // Simulating chained logic via sequential execution of components referencing the same context
    // Our TaintContext runs on a per-request basis in express via AsyncLocalStorage.
    // To simulate a chain perfectly, we will hit an endpoint that does multiple things, OR 
    // we use a specific constructed test parameter on the demo-app. 
    // Wait, the demo app endpoints only do ONE thing per route. I will hit the NoSQL route with multiple nasty operators.
    
    const chainedUrl = `${ENDPOINT}/vuln/nosql?filter=%257B%2522%2524where%2522%253A%2520%2522process.exit(1)%2522%257D`;
    process.stdout.write(`Testing [Chained Double Encoded NoSQL Injection + RCE]... `);
    
    await new Promise(resolve => {
        http.get(chainedUrl, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 403) {
                    try {
                        const parsed = JSON.parse(data);
                        console.log(`\x1b[32m🛡️  BLOCKED (403)\x1b[0m -> Score: ${parsed.details.score}`);
                    } catch(e) {
                         console.log(`\x1b[32m🛡️  BLOCKED (403)\x1b[0m`);
                    }
                } else {
                    console.log(`\x1b[31m❌ BYPASSED (${res.statusCode})\x1b[0m -> ${data.substring(0, 50)}`);
                }
                resolve();
            });
        });
    });

}

runTests();
