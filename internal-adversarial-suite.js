const http = require('http');

async function test(name, path, method = 'GET', body = null, headers = {}) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost',
            port: 8081,
            path,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, data }));
        });
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function runSuite() {
    console.log("==========================================");
    console.log("🚀 ARCHITECTURAL VALIDATION SUITE (V2)");
    console.log("==========================================");

    // 1. Non-string Execution (Prototype Pollution -> Sink)
    console.log("\n[1] Testing Prototype Pollution -> Sink Chain...");
    const p1 = await test('ProtoPollution', '/vuln/prototype', 'POST', {
        "__proto__": { "polluted": "true" }
    });
    console.log(`Result: ${p1.status === 403 ? '🛡️ BLOCKED' : '❌ BYPASSED (' + p1.status + ')'}`);

    // 2. High-Risk AST Pattern in Sink
    console.log("\n[2] Testing Malicious AST Pattern in Sink...");
    // Passing tainted code through query parameter
    const code = "require('child_process').exec('id')";
    const p2 = await test('ASTPattern', `/vuln/rce?code=${encodeURIComponent(code)}`, 'GET');
    console.log(`Result: ${p2.status === 403 ? '🛡️ BLOCKED' : '❌ BYPASSED (' + p2.status + ')'}`);

    // 3. Fragmentation Resistance (Taint Fragmentation)
    console.log("\n[3] Testing Taint Fragmentation...");
    const p3 = await test('Fragmentation', '/vuln/cmd', 'POST', { "injected": "id" });
    console.log(`Result: ${p3.status === 403 ? '🛡️ BLOCKED' : '❌ BYPASSED (' + p3.status + ')'}`);

    console.log("\n==========================================");
}

runSuite();
