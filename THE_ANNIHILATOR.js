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
    const isBlocked = status === 403 || status === 'ECONNRESET';
    
    if (isSuccess) {
        RESULTS.bypassed.push({ phase, payload });
        console.log(`[💥 BYPASS] ${phase} | ${status} | ${payload.substring(0, 80)}`);
    } else if (isBlocked) {
        RESULTS.blocked.push({ phase, payload });
        console.log(`[🛡️ BLOCKED] ${phase} | ${status} | ${latency}ms`);
    } else {
        RESULTS.errors.push({ phase, payload, status });
        console.log(`[⚠️ ERROR] ${phase} | ${status} | ${latency}ms`);
    }
}

async function startAssault() {
    console.log("==========================================");
    console.log("⚡ SHIELDRASP ADVERSARIAL ANNIHILATION ⚡");
    console.log("==========================================");

    // --- PHASE 1: RECON & LATENCY FINGERPRINTING ---
    console.log("\n[*] PHASE 1: RECON (Latency Fingerprinting)");
    for(let i=0; i<10; i++) await sendRequest('/api/health'); // Warm up
    
    // --- PHASE 2: NORMALIZATION DEPTH EXHAUSTION ---
    // The engine normalizes up to 5 levels. Let's send 7 levels of Base64.
    console.log("\n[*] PHASE 2: NORMALIZATION DEPTH EXHAUSTION");
    let payload = "1' OR 1=1--";
    for(let i=0; i<7; i++) payload = Buffer.from(payload).toString('base64');
    const res2 = await sendRequest(`/vuln/sqli?id=${payload}`);
    logResult('Depth Exhaustion', payload, res2.status, res2.latency);

    // --- PHASE 3: SEMANTIC EVASION (Constructor Bypass) ---
    // It blocks "constructorconstructor". Let's try Unicode escapes and concatenation.
    console.log("\n[*] PHASE 3: SEMANTIC EVASION (Constructor Bypass)");
    const semanticPayloads = [
        "this['const' + 'ructor']",
        "this['\\u0063onstructor']",
        "Object.getPrototypeOf(this).constructor",
        "this.constructor?.constructor('return process')()"
    ];
    for (const p of semanticPayloads) {
        const res = await sendRequest('/vuln/rce', 'POST', { code: p });
        logResult('Semantic Evasion', p, res.status, res.latency);
    }

    // --- PHASE 4: JSON KEY INJECTION ---
    // Does it scan the keys of the JSON object?
    console.log("\n[*] PHASE 4: JSON KEY INJECTION");
    const res4 = await sendRequest('/vuln/proto', 'POST', '{"__proto__": {"polluted": true}}');
    logResult('Key Injection', '__proto__', res4.status, res4.latency);

    // --- PHASE 5: MULTI-STEP FRAGMENTATION (Stateful) ---
    // If the engine reconstructs body but maybe doesn't handle fragments across multiple POSTs?
    console.log("\n[*] PHASE 5: MULTI-STEP FRAGMENTATION");
    // This requires backend persistence which might not be in demo-app, but let's try to confuse the reconstructor
    const res5 = await sendRequest('/vuln/cmd', 'POST', { cmd: 'cat ', junk: 'A'.repeat(100) });
    const res5b = await sendRequest('/vuln/cmd', 'POST', { cmd: '/etc/passwd', junk: 'B'.repeat(100) });
    logResult('Fragmentation', 'Split cmd', res5b.status, res5b.latency);

    // --- PHASE 6: UNICODE NORMALIZATION BYPASS ---
    console.log("\n[*] PHASE 6: UNICODE NORMALIZATION BYPASS");
    const unicodePayloads = [
        "1\\u0027 OR 1=1--",
        "<s\\u0063ript>alert(1)</script>",
        "\\u0065val('id')"
    ];
    for (const p of unicodePayloads) {
        const res = await sendRequest(`/vuln/sqli?q=${p}`);
        logResult('Unicode Bypass', p, res.status, res.latency);
    }

    // --- PHASE 7: COMMENT MUTATION EXHAUSTION ---
    console.log("\n[*] PHASE 7: COMMENT MUTATION EXHAUSTION");
    const commentPayloads = [
        "1'/**/OR/**/1=1--",
        "1'/* anything */OR/* multi */1=1--",
        "1'/*!50000OR*/1=1--"
    ];
    for (const p of commentPayloads) {
        const res = await sendRequest(`/vuln/sqli?id=${encodeURIComponent(p)}`);
        logResult('Comment Mutation', p, res.status, res.latency);
    }

    // --- PHASE 8: BEHAVIORAL SCORE RESET (Traffic Blending) ---
    console.log("\n[*] PHASE 8: TRAFFIC BLENDING (Behavioral Reset)");
    for(let i=0; i<30; i++) await sendRequest('/api/health'); // Blend
    const res8 = await sendRequest('/vuln/cmd', 'POST', { cmd: 'sleep 1' });
    logResult('Blending', 'Delayed Attack', res8.status, res8.latency);

    // --- PHASE 9: SEMANTIC RECON (Sink probing) ---
    console.log("\n[*] PHASE 9: SINK PROBING");
    const sinks = [
        "process.env",
        "require('fs')",
        "global.process"
    ];
    for (const s of sinks) {
        const res = await sendRequest('/vuln/rce', 'POST', { code: `console.log(${s})` });
        logResult('Sink Probe', s, res.status, res.latency);
    }

    // --- PHASE 10: THE ULTRA CHAIN (Polymorphic JSON + UTF8 Bomb) ---
    console.log("\n[*] PHASE 10: THE ULTRA-CHAIN");
    let ultra = "constructor.constructor('return process')()";
    // Encode parts differently
    let chain = {
        meta: Buffer.from("benign").toString('base64'),
        data: ultra.substring(0, 10),
        payload: {
            sub: ultra.substring(10)
        },
        trailers: "\\u0000" // Null byte attempt
    };
    const res10 = await sendRequest('/vuln/rce', 'POST', chain);
    logResult('Ultra Chain', 'Fragmented Semantic', res10.status, res10.latency);

    console.log("\n==========================================");
    console.log("📊 ASSAULT REPORT");
    console.log("==========================================");
    console.log(`⚡ Total Tests:  ${RESULTS.blocked.length + RESULTS.bypassed.length + RESULTS.errors.length}`);
    console.log(`🛡️  Blocked:      ${RESULTS.blocked.length}`);
    console.log(`💥 Bypassed:     ${RESULTS.bypassed.length}`);
    console.log(`⚠️  Errors:       ${RESULTS.errors.length}`);
    
    if (RESULTS.bypassed.length > 0) {
        console.log("\n🔥 CRITICAL: SYSTEM COMPROMISED 🔥");
    } else {
        console.log("\n🛡️  SYSTEM HELD (For now...) 🛡️");
    }
}

startAssault().catch(console.error);
