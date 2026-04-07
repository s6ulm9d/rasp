const http = require('http');

const TARGET = { host: 'localhost', port: 8081 };
const RESULTS = { bypassed: [], blocked: [], errors: [] };

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function sendRequest(path, method = 'GET', body = null, headers = {}) {
    const start = Date.now();
    return new Promise((resolve) => {
        const fullUrl = new URL(path, `http://${TARGET.host}:${TARGET.port}`);
        const req = http.request({
            hostname: TARGET.host,
            port: TARGET.port,
            path: fullUrl.pathname + fullUrl.search,
            method,
            headers: { 
                'Content-Type': 'application/json',
                ...headers, 
                'Connection': 'keep-alive' 
            }
        }, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => resolve({ status: res.statusCode, data, latency: Date.now() - start }));
        });
        req.on('error', (e) => resolve({ status: e.code || 'ERROR', data: e.message, latency: Date.now() - start }));
        if (body) req.write(typeof body === 'object' ? JSON.stringify(body) : body);
        req.end();
    });
}

async function aptSimulation() {
    console.log("==========================================");
    console.log("🕵️ SHIELDRASP APT SILENT STRIKE 🕵️");
    console.log("==========================================");

    // --- PHASE 1: RECON ---
    console.log("\n[*] PHASE 1: STEALTH RECON");
    for(let i=0; i<5; i++) {
        await sendRequest('/health');
        await sleep(1000); // 1s delay
    }
    console.log("[+] Baseline established.");

    // --- PHASE 2: LOW-SIGNAL MAPPING ---
    console.log("\n[*] PHASE 2: LOW-SIGNAL MAPPING");
    const signals = ["obj", "key", "val", "data"];
    for (const s of signals) {
        const res = await sendRequest(`/vuln/sqli?id=${s}`);
        console.log(`[ ] Probe '${s}': ${res.status}`);
        await sleep(2000);
    }

    // --- PHASE 3: PROTOTYPE POLLUTION (Stealth) ---
    // Instead of "__proto__", use "constructor.prototype" which might be less watched.
    // Use encoding for the keys.
    console.log("\n[*] PHASE 3: INVISIBLE PROTOTYPE POISONING");
    const polluteBody = {
        "constructor": {
            "prototype": {
                "admin": true,
                "shell_hook": "calc.exe"
            }
        }
    };
    // Send it slowly, wrapped in benign data
    const res3 = await sendRequest('/vuln/prototype', 'POST', {
        user: "guest",
        preferences: polluteBody,
        timestamp: Date.now()
    });
    
    if (res3.status === 200) {
        console.log("[💥 BYPASS] Prototype poisoned via constructor.prototype!");
    } else {
        console.log(`[🛡️ BLOCKED] Phase 3: ${res3.status}`);
    }

    // --- PHASE 4: SIGNAL MUTATION (Polyglot) ---
    console.log("\n[*] PHASE 4: SIGNAL MUTATION (Polyglot)");
    // Try a payload that looks like a normal JSON but is malicious
    const polyglotSQL = "1' OR (SELECT CHAR(101))='e'--";
    const res4 = await sendRequest(`/vuln/sqli?id=${encodeURIComponent(polyglotSQL)}`);
    console.log(`[ ] Polyglot result: ${res4.status}`);

    // --- PHASE 5: BEHAVIORAL BYPASS ---
    console.log("\n[*] PHASE 5: BEHAVIORAL COOL-DOWN");
    for(let i=0; i<10; i++) {
        await sendRequest('/health');
        await sleep(500);
    }

    // --- PHASE 6: INDIRECT SINK TRIGGER ---
    console.log("\n[*] PHASE 6: INDIRECT SINK TRIGGER");
    // Attempting to trigger the polluted prototype in a sink
    // If the app uses a default object that now has 'shell_hook'
    const res6 = await sendRequest('/vuln/cmd', 'POST', { 
        injected: "127.0.0.1" // "Benign" input
    });
    console.log(`[ ] Sink trigger result: ${res6.status}`);

    console.log("\n==========================================");
    console.log("🏁 APT SIMULATION COMPLETE");
    console.log("==========================================");
}

aptSimulation().catch(console.error);
