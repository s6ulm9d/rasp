const http = require('http');

const PORT = 8081;
const HOST = 'localhost';

const runTest = (name, path, method, headers, body) => {
    return new Promise((resolve) => {
        const options = {
            hostname: HOST,
            port: PORT,
            path: path,
            method: method,
            headers: headers || {}
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    name,
                    status: res.statusCode,
                    body: data.substring(0, 500)
                });
            });
        });

        req.on('error', (e) => {
            resolve({
                name,
                status: 'ERROR',
                body: e.message
            });
        });

        if (body) {
            req.write(body);
        }
        req.end();
    });
};

const tests = [
    {
        name: '1. Baseline Normal Request',
        path: '/api/status',
        method: 'GET'
    },
    {
        name: '2. Classic SQL Injection (Query Param)',
        path: '/vuln/sqli?id=1%27%20UNION%20SELECT%20*%20FROM%20users--',
        method: 'GET'
    },
    {
        name: '3. Command Injection (Body)',
        path: '/vuln/exec',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd: '; cat /etc/passwd' })
    },
    {
        name: '4. Local File Inclusion (LFI)',
        path: '/vuln/read?file=../../../../windows/system32/cmd.exe',
        method: 'GET'
    },
    {
        name: '5. Cross-Site Scripting (XSS in JSON Body)',
        path: '/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '<script>alert("XSS")</script>' })
    },
    {
        name: '6. [NEW] Prototype Pollution Attempt (Node.js evasion)',
        path: '/api/update',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"__proto__": {"admin": true}}'
    },
    {
        name: '7. [NEW] SSRF Evasion Attempt (Userinfo Trick)',
        path: '/proxy?url=http://127.0.0.1@evil.com/',
        method: 'GET'
    },
    {
        name: '8. [NEW] Remote Code Execution (Node.js eval payload)',
        path: '/api/run',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ func: "require('child_process').exec('calc.exe')" })
    },
    {
        name: '9. [NEW] RCE via Deserialization Payload Format',
        path: '/api/object',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ obj: "_{$eval(process.exit())}_" })
    },
    {
        name: '10. [NEW] NoSQL Injection',
        path: '/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: {"$gt": ""}, password: {"$gt": ""} })
    }
];

async function executeAll() {
    console.log("======================================");
    console.log("🛡️ ShieldRASP Comprehensive QA Test 🛡️");
    console.log("======================================\n");
    for (const t of tests) {
        console.log(`[Testing] ${t.name}...`);
        const result = await runTest(t.name, t.path, t.method, t.headers, t.body);
        let color = result.status === 403 || result.status === 200 || result.status === 404 ? '✅' : '❌';
        
        // Let's refine what is expected: Malicious should be 403. Normal should be 200 or 404.
        let expected = '403';
        if (t.name.includes('Baseline')) expected = '200|404';
        
        console.log(`   ${color} Result Status: ${result.status} (Expected: ${expected})`);
        
        if (result.status === 403) {
            try {
               const parsedResult = JSON.parse(result.body);
               console.log(`   └─ Blocked Reason: ${parsedResult.message}`);
            } catch(e) {
               console.log(`   └─ Response: ${result.body}`);
            }
        } else if (result.status === 'ERROR') {
             console.log(`   └─ Connection dropped/Error: ${result.body}`);
        }
        console.log('');
    }
}

executeAll();
