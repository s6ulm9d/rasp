const http = require('http');

const PORT = 8081;
const HOST = 'localhost';

const runTest = (name, path, method, headers, chunks) => {
    return new Promise((resolve) => {
        const options = { hostname: HOST, port: PORT, path: path, method: method, headers: headers || {} };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ name, status: res.statusCode, body: data.substring(0, 200) }));
        });
        req.on('error', (e) => resolve({ name, status: 'BLOCKED (ECONNRESET)', body: e.message }));
        
        const delay = (ms) => new Promise(r => setTimeout(r, ms));
        
        (async () => {
             for (const chunk of chunks) {
                 req.write(chunk);
                 await delay(5);
             }
             req.end();
        })();
    });
};

const payloads = [
    // SQL INJECTION
    { name: "SQLi 1", body: "1' OR 1=1--" },
    { name: "SQLi 2", body: "1' UNION SELECT NULL,NULL,NULL--" },
    { name: "SQLi 3", body: "1'/**/UNION/**/SELECT/**/1,2,3--" },
    { name: "SQLi 4", body: "1' UNI%4F%4E SELECT 1,2,3--" },
    
    // COMMAND INJECTION
    { name: "CMD 1", body: "; cat /etc/passwd" },
    { name: "CMD 2", body: "&& whoami" },
    { name: "CMD 3", body: "| powershell.exe calc.exe" },
    { name: "CMD 4", body: "`id`" },
    { name: "CMD 5", body: "${IFS}cat${IFS}/etc/passwd" },

    // XSS
    { name: "XSS 1", body: "<script>alert(1)</script>" },
    { name: "XSS 2", body: "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" },
    { name: "XSS 3", body: "<img src=x onerror=alert(1)>" },
    { name: "XSS 4", body: "<svg/onload=alert(1)>" },
    { name: "XSS 5", body: "%3Cscript%3Ealert(1)%3C/script%3E" },

    // NOSQL
    { name: "NoSQL 1", body: '{"username":{"$ne":null},"password":{"$ne":null}}', path: '/vuln/nosql' },
    { name: "NoSQL 2", body: '{"$where":"this.password.length > 0"}', path: '/vuln/nosql' },
    { name: "NoSQL 3", body: '{"username":{"$gt":""}}', path: '/vuln/nosql' },

    // PROTOTYPE POLLUTION
    { name: "Proto 1", body: '{"__proto__":{"admin":true}}', path: '/vuln/prototype' },
    { name: "Proto 2", body: '{"constructor":{"prototype":{"isAdmin":true}}}', path: '/vuln/prototype' },

    // RCE
    { name: "RCE 1", body: "require('child_process').exec('calc.exe')", path: '/vuln/rce' },
    { name: "RCE 2", body: "process.mainModule.require('child_process').execSync('whoami')", path: '/vuln/rce' },
    { name: "RCE 3", body: "_{$eval(process.exit())}_", path: '/vuln/rce' },
    { name: "RCE 4", body: "this.constructor.constructor('return process')().exit()", path: '/vuln/rce' },

    // ENCODING
    { name: "Enc 1 Base64", body: "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", path: '/vuln/cmd' },
    { name: "Enc 2 Double", body: "%253Cscript%253Ealert(1)%253C/script%253E", path: '/vuln/cmd' },
    { name: "Enc 3 Mixed", body: "<scr%69pt>alert(1)</scr%69pt>", path: '/vuln/cmd' }
];

async function run() {
    console.log("==========================================");
    console.log("🛡️ ShieldRASP Offensive Matrix Teardown 🛡️");
    console.log("==========================================\n");

    for (const p of payloads) {
        // Format the testing payload correctly to pass express JSON middleware checks, triggering the 500 fixes we just made.
        const stringified = JSON.stringify({ injected: p.body });
        const targetPath = p.path || '/vuln/cmd';
        
        // Run Normal
        const resN = await runTest(`${p.name} (Normal)`, targetPath, 'POST', { 'Content-Type': 'application/json' }, [stringified]);
        
        // Run Chunked/Fragmented
        const parts = [stringified.substring(0, 3), stringified.substring(3)];
        const resF = await runTest(`${p.name} (Fragmented)`, targetPath, 'POST', { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' }, parts);
        
        console.log(`[${p.name}]`);
        console.log(` ├─ Normal:     ${resN.status}`);
        console.log(` └─ Fragmented: ${resF.status}`);
    }
}
run();
