const http = require('http');

async function testCanaryMemoryScrape() {
    console.log(`\n\x1b[36m[Test 1] Memory Canary Scrape Attack (Behavioral Anomaly)\x1b[0m`);
    return new Promise(resolve => {
        // Send a request carrying the strict global memory trap code 
        // Emulating an attacker trying to blindly search memory pages
        const payload = `data={"id": "CAFEBABE_9f8a7b_MEMORY_SCRAPE_TRAP"}`;
        
        const req = http.request({
            hostname: 'localhost',
            port: 8081,
            path: '/vuln/prototype',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, (res) => {
            let body = '';
            res.on('data', d => body += d);
            res.on('end', () => resolve({ code: res.statusCode, body }));
        });
        req.write(payload);
        req.end();
    });
}

function testTaintGraphAggregation() {
    console.log(`\n\x1b[36m[Test 2] Weighted Taint Graph (Small fragments mutating & combining)\x1b[0m`);
    // Testing the node-propagation engine using sub-strings in SQL
    // Payload uses sub-queries. The TaintContext parses relationships.
    return new Promise(resolve => {
        http.get("http://localhost:8081/vuln/sqli?id=1'%20OR%20(SELECT%20sleep(5))--", res => {
            let body = '';
            res.on('data', d => body += d);
            res.on('end', () => resolve({ code: res.statusCode, body }));
        });
    });
}

async function run() {
    console.log("🔥 Starting Advanced Behavioral & Context Engine Tests 🔥");
    
    const r1 = await testCanaryMemoryScrape();
    if(r1.code === 403 && r1.body.includes('ShieldRASP Security Engine')) {
        console.log(`\x1b[32m🛡️  Canary Defense Passed (403 Blocked Memory Scrape)\x1b[0m`);
    } else {
        console.log(`\x1b[31m❌ Bypass detected (Responded ${r1.code})\x1b[0m`);
    }

    const r2 = await testTaintGraphAggregation();
    if(r2.code === 403 && r2.body.includes('ShieldRASP')) {
        console.log(`\x1b[32m🛡️  Taint Graph Evaluation Passed (403 Blocked Deep SQLi)\x1b[0m`);
    } else {
        console.log(`\x1b[31m❌ Taint Bypass detected (Responded ${r2.code})\x1b[0m`);
    }
}

run();
