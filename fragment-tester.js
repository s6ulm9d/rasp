const http = require('http');

const PORT = 8081;
const HOST = 'localhost';

const runTest = (name, path, method, headers, chunkParts) => {
    return new Promise((resolve) => {
        const options = { hostname: HOST, port: PORT, path: path, method: method, headers: headers || {} };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ name, status: res.statusCode, body: data.substring(0, 300) }));
        });
        req.on('error', (e) => resolve({ name, status: 'ERROR', body: e.message }));
        
        const delay = (ms) => new Promise(r => setTimeout(r, ms));
        
        (async () => {
             for (const chunk of chunkParts) {
                 req.write(chunk);
                 await delay(20);
             }
             req.end();
        })();
    });
};

const payloads = [
    { name: "Fragmented SQLi", parts: ["1' UN", "ION SEL", "ECT * FROM users--"] },
    { name: "Fragmented XSS", parts: ["<scr", "ipt>alert(1)</script>"] },
    { name: "Fragmented RCE", parts: ["requ", "ire('child_process')"] }
];

async function run() {
    for (const p of payloads) {
        const res = await runTest(p.name, '/test', 'POST', { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' }, p.parts);
        console.log(`[${p.name}] Status: ${res.status}`);
    }
}
run();
