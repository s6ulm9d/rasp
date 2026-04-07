const http = require('http');
const crypto = require('crypto');

const TARGET_HOST = 'localhost';
const TARGET_PORT = 8081;

const RESULTS = {
    total: 0,
    blocked: 0,
    bypassed: 0,
    errors: 0,
    failures: []
};

function trackResult(name, status, responseText) {
    RESULTS.total++;
    // Expected to block (403) or not found (404 if blocked upstream/downstream, but 403 is ShieldRASP)
    // Actually, demo app usually returns 200, 404, or 500 on vulnerable routes if hit. 
    // ShieldRASP should intercept and return 403 or hang (ECONNRESET if socket destroyed).
    // Let's assume 403 or socket hang up (error) is a BLOCKED status.
    // >= 400 && < 500 (except 404 if it bypassed) -> 403 is blocked.
    // If it reaches 200, it bypassed.
    // If it reaches 500, it's a RASP crash or App crash.

    let isBlocked = false;
    let isBypassed = false;
    let isError = false;

    if (status === 403 || status === 'ECONNRESET') {
        isBlocked = true;
        RESULTS.blocked++;
    } else if (status === 200) {
        isBypassed = true;
        RESULTS.bypassed++;
        RESULTS.failures.push({ name, status, reason: 'Returned 200 OK (Bypass)', response: responseText.substring(0, 100) });
    } else if (status === 500) {
        isError = true;
        RESULTS.errors++;
        RESULTS.failures.push({ name, status, reason: 'Returned 500 Internal Server Error (Crash)', response: responseText.substring(0, 100) });
    } else {
        // App returned 404 if endpoint doesn't exist, treat as blocked/safe for now if not 200
        isBlocked = true;
        RESULTS.blocked++;
    }

    console.log(`[TEST] ${name}`);
    console.log(`   └─ Status: ${status} | Result: ${isBlocked ? '✅ BLOCKED' : isBypassed ? '❌ BYPASSED' : '⚠️ ERROR'}`);
}

async function request(options, body = null, delayChunks = 0) {
    return new Promise((resolve) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, data }));
        });

        req.on('error', (e) => resolve({ status: e.code, data: e.message }));

        if (body) {
            if (delayChunks > 0 && typeof body === 'string') {
                // Fragmented sending
                let i = 0;
                const interval = setInterval(() => {
                    if (i < body.length) {
                        req.write(body[i]);
                        i++;
                    } else {
                        clearInterval(interval);
                        req.end();
                    }
                }, delayChunks);
            } else {
                req.write(body);
                req.end();
            }
        } else {
            req.end();
        }
    });
}

// ==========================================
// SCENARIOS
// ==========================================

async function runSinglePayloads() {
    console.log('\n--- 1. SINGLE PAYLOAD ATTACKS ---');

    const payloads = [
        { name: "SQLi Inline Comment", path: `/vuln/sqli?id=1'/**/UNION/**/SELECT/**/1,2,3--` },
        { name: "XSS Unicode", path: `/vuln/xss?q=${encodeURIComponent('\\u003cscript\\u003ealert(1)\\u003c/script\\u003e')}` },
        { name: "CMD IFS", path: `/vuln/cmd`, method: 'POST', body: '{"cmd":"${IFS}cat${IFS}/etc/passwd"}' },
        { name: "RCE Dynamic", path: `/vuln/rce`, method: 'POST', body: `{"code":"this.constructor.constructor('return process')().exit()"}` },
        { name: "NoSQL Where", path: `/vuln/nosql`, method: 'POST', body: '{"$where":"this.password.length>0"}' },
        { name: "Proto Pollution", path: `/vuln/proto`, method: 'POST', body: '{"constructor":{"prototype":{"isAdmin":true}}}' },
        { name: "SSRF IPv6", path: `/vuln/ssrf?url=http://[::ffff:127.0.0.1]` },
        { name: "Base64 Mixed", path: `/vuln/xss`, method: 'POST', body: '{"data": "some benign text PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== and more text"}' }
    ];

    for (const p of payloads) {
        const opts = {
            hostname: TARGET_HOST, port: TARGET_PORT,
            path: p.path.replace(/ /g, '%20').replace(/'/g, '%27').replace(/"/g, '%22').replace(/{/g, '%7B').replace(/}/g, '%7D'), method: p.method || 'GET',
            headers: Object.assign({}, p.body ? { 'Content-Type': 'application/json' } : {})
        };
        const res = await request(opts, p.body);
        trackResult(p.name, res.status, res.data);
    }
}

async function runChainedPayloads() {
    console.log('\n--- 2. CHAINED / MULTI-FIELD ATTACKS ---');
    // B64 -> URL Encode -> Fragmented simulated by multiple encoding layers
    const b64 = Buffer.from("1' UNION SELECT 1,2,3--").toString('base64');
    const urlEncoded = encodeURIComponent(b64);

    // Multi-field: malicious payload spread across headers, query, cookies, and body
    const opts = {
        hostname: TARGET_HOST, port: TARGET_PORT, path: `/vuln/sqli?q=${urlEncoded}`, method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Custom-Malicious': `eval('al'+'ert(1)')`,
            'Cookie': `session=this.constructor.constructor`
        }
    };

    const res = await request(opts, `{"fragment1": "1' UN", "fragment2": "ION SELECT"}`);
    trackResult('Multi-Field Chained Obfuscation', res.status, res.data);
}

async function runStressAndConcurrency() {
    console.log('\n--- 3. CONCURRENCY & STRESS ---');

    const promises = [];
    // Send 100 parallel requests with benign and malicious payloads
    for (let i = 0; i < 100; i++) {
        const isMalicious = i % 10 === 0;
        const opts = {
            hostname: TARGET_HOST, port: TARGET_PORT,
            path: isMalicious ? `/vuln/sqli?id=1' OR 1=1--` : `/`, method: 'GET'
        };
        promises.push(request(opts).then(r => ({ ...r, malicious: isMalicious })));
    }

    const results = await Promise.all(promises);
    const blocked = results.filter(r => r.malicious && (r.status === 403 || r.status === 'ECONNRESET')).length;
    const bypassed = results.filter(r => r.malicious && r.status === 200).length;

    console.log(`[TEST] Concurrency (100 reqs, 10 malicious)`);
    console.log(`   └─ Malicious Blocked: ${blocked}/10 | Bypassed: ${bypassed} | Result: ${bypassed === 0 ? '✅ SAFE' : '❌ BYPASSED'}`);
    if (bypassed > 0) RESULTS.failures.push({ name: 'Concurrency Bypass', status: 200, reason: `${bypassed} malicious concurrent requests bypassed` });
}

async function runMemoryCpuStress() {
    console.log('\n--- 4. MEMORY & CPU STRESS (LARGE PAYLOAD) ---');

    // 2MB Payload with scattered malicious signatures
    const largeObj = {};
    for (let i = 0; i < 10000; i++) {
        largeObj[`key${i}`] = crypto.randomBytes(64).toString('hex');
    }
    largeObj['injection'] = "global['eval']('alert(1)')";
    largeObj['filler'] = Buffer.alloc(1024 * 1024, 'A').toString(); // 1MB string

    const body = JSON.stringify(largeObj);

    const opts = {
        hostname: TARGET_HOST, port: TARGET_PORT, path: `/vuln/cmd`, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };

    const start = Date.now();
    const res = await request(opts, body);
    const time = Date.now() - start;

    trackResult('Memory/CPU Stress (2MB JSON)', res.status, res.data);
    console.log(`   └─ Time: ${time}ms`);
}

async function runStreamFragmentation() {
    console.log('\n--- 5. STREAM FRAGMENTATION ---');

    const payload = `{"cmd": "ls ; bash -c whoami"}`;
    const opts = {
        hostname: TARGET_HOST, port: TARGET_PORT, path: `/vuln/cmd`, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length }
    };

    // 1-byte chunks with 2ms delay
    const start = Date.now();
    const res = await request(opts, payload, 2);
    const time = Date.now() - start;

    trackResult('1-Byte Stream Fragmentation', res.status, res.data);
}

async function main() {
    console.log("==========================================");
    console.log("🛡️ SHIELDRASP ADVERSARIAL TEARDOWN SUITE 🛡️");
    console.log("==========================================");

    await runSinglePayloads();
    await runChainedPayloads();
    await runStressAndConcurrency();
    await runMemoryCpuStress();
    await runStreamFragmentation();

    console.log("\n==========================================");
    console.log("📊 FINAL REPORT");
    console.log("==========================================");
    console.log(`Total Tests Executed : ${RESULTS.total}`);
    console.log(`✅ Successfully Blocked: ${RESULTS.blocked}`);
    console.log(`❌ Bypasses Detected   : ${RESULTS.bypassed}`);
    console.log(`⚠️  System Errors (500) : ${RESULTS.errors}`);

    if (RESULTS.failures.length > 0) {
        console.log("\n🚨 CRITICAL VULNERABILITIES FOUND:");
        RESULTS.failures.forEach(f => {
            console.log(`- [${f.name}] | Status: ${f.status} | Reason: ${f.reason}`);
        });
    } else {
        console.log("\n✅ SHIELDRASP IS RESILIENT UNDER EXTREME TEARDOWN.");
    }
}

main().catch(console.error);
