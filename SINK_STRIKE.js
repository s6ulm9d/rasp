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

function logResult(phase, payload, status, latency) {
    const isSuccess = status === 200;
    if (isSuccess) {
        RESULTS.bypassed.push({ phase, payload });
        console.log(`[💥 BYPASS] ${phase} | ${status} | ${payload}`);
    } else {
        RESULTS.blocked.push({ phase, payload });
        console.log(`[🛡️ BLOCKED] ${phase} | ${status} | ${latency}ms`);
    }
}

async function sinkAssault() {
    console.log("==========================================");
    console.log("🎯 SHIELDRASP SINK STRIKE 🎯");
    console.log("==========================================");

    // --- STRATEGY 1: TAINT FRAGMENTATION ---
    // We send payload fragments that are benign alone but malicious in a sink.
    // Assuming the demo-app concatenates 'q1' and 'q2' into a command.
    console.log("\n[*] STRATEGY 1: TAINT FRAGMENTATION");
    const res1 = await sendRequest('/vuln/cmd', 'POST', { 
        cmd: 'who', // Benign fragment
        suffix: 'ami' // Benign fragment
    });
    logResult('Fragmentation', 'who + ami', res1.status, res1.latency);

    // --- STRATEGY 2: INDIRECT SINK TRIGGER ---
    // Using objects that resolve to malicious strings when stringified at the sink.
    console.log("\n[*] STRATEGY 2: INDIRECT SINK TRIGGER");
    const res2 = await sendRequest('/vuln/rce', 'POST', { 
        code: { toString: () => "process.exit(1)" } 
    });
    logResult('Indirect Sink', 'toString object', res2.status, res2.latency);

    // --- STRATEGY 3: PROTOTYPE POLLUTION TO SINK ---
    // Pollute properties that are used inside sinks.
    console.log("\n[*] STRATEGY 3: PROTOTYPE POLLUTION");
    const res3 = await sendRequest('/vuln/proto', 'POST', { 
        "constructor": { "prototype": { "polluted": "cat /etc/passwd" } } 
    });
    logResult('Proto Pollution', 'constructor.prototype', res3.status, res3.latency);

    // --- STRATEGY 4: BASE64 WRAPPING OF SINK-MALICIOUS DATA ---
    console.log("\n[*] STRATEGY 4: SINK-SPECIFIC OBFUSCATION");
    const res4 = await sendRequest('/vuln/sqli', 'POST', { 
        id: Buffer.from("1' OR '1'='1").toString('base64') 
    });
    logResult('Sink Obfuscation', 'B64 SQLi', res4.status, res4.latency);

    // --- STRATEGY 5: ENVIRONMENT POISONING ---
    console.log("\n[*] STRATEGY 5: ENVIRONMENT POISONING (via headers)");
    const res5 = await sendRequest('/api/health', 'GET', null, {
        'NODE_OPTIONS': '--inspect=0.0.0.0:9229',
        'LD_PRELOAD': '/tmp/evil.so'
    });
    logResult('Env Poisoning', 'Critical Headers', res5.status, res5.latency);

    console.log("\n==========================================");
    console.log(`📊 FINAL RESULTS: ${RESULTS.bypassed.length} BYPASSES`);
    console.log("==========================================");
}

sinkAssault().catch(console.error);
