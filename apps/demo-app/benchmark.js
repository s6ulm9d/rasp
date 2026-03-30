const http = require('http');
const { spawn } = require('child_process');

console.log('🚀 Starting ShieldRASP Native Benchmark...');

function startServer(withRASP) {
    return new Promise((resolve, reject) => {
        const env = Object.assign({}, process.env);
        if (withRASP) {
            env.NODE_OPTIONS = '--require ' + require('path').resolve(__dirname, '../../packages/agent');
        } else {
            env.NODE_OPTIONS = '';
        }

        const server = spawn('node', ['index.js'], { cwd: __dirname, env });

        server.stdout.on('data', (data) => {
            if (data.toString().includes('listening on port 8081')) {
                resolve(server);
            }
        });

        server.stderr.on('data', (data) => {
            console.error(`[Server stderr] ${data}`);
        });

        server.on('error', (err) => reject(err));
    });
}

function sendRequest() {
    return new Promise((resolve) => {
        const start = performance.now();
        http.get('http://localhost:8081/health', (res) => {
            res.on('data', () => { }); // Consume body
            res.on('end', () => {
                resolve(performance.now() - start);
            });
        }).on('error', () => resolve(null));
    });
}

async function runBenchmark(title, durationSeconds = 5) {
    console.log(`\n--- Running: ${title} ---`);
    const endTime = Date.now() + (durationSeconds * 1000);
    let count = 0;
    let latencies = [];

    // Simple connection pool logic
    const concurrency = 50;

    await new Promise((resolve) => {
        let active = 0;

        const tick = async () => {
            if (Date.now() >= endTime) {
                if (active === 0) resolve();
                return;
            }
            active++;
            const t = await sendRequest();
            if (t !== null) {
                count++;
                latencies.push(t);
            }
            active--;
            tick();
        };

        for (let i = 0; i < concurrency; i++) tick();
    });

    latencies.sort((a, b) => a - b);
    const p99 = latencies[Math.floor(latencies.length * 0.99)] || 0;
    const rps = count / durationSeconds;

    console.log(`Latency p99: ${p99.toFixed(2)} ms`);
    console.log(`Requests/sec: ${rps.toFixed(2)}`);

    return { rps, p99 };
}

async function run() {
    console.log('\n[1/2] Baseline (NO RASP)...');
    let srv = await startServer(false);
    const baseline = await runBenchmark('Baseline (Without RASP)', 5);
    srv.kill();
    await new Promise(r => setTimeout(r, 2000));

    console.log('\n[2/2] ShieldRASP Enabled...');
    srv = await startServer(true);
    const rasp = await runBenchmark('ShieldRASP Enabled', 5);
    srv.kill();

    const overhead = ((baseline.rps - rasp.rps) / baseline.rps) * 100;
    const latencyIncrease = rasp.p99 - baseline.p99;

    console.log(`\n================================`);
    console.log(`🛡️  ShieldRASP Overhead Results  🛡️`);
    console.log(`================================`);
    console.log(`Throughput Penalty: ${overhead.toFixed(2)}% (${Math.round(rasp.rps)} vs ${Math.round(baseline.rps)} req/s)`);
    console.log(`p99 Latency Delta: ${latencyIncrease > 0 ? '+' : ''}${latencyIncrease.toFixed(2)} ms`);

    if (overhead < 10) {
        console.log(`\n✅ PERFORMANCE TARGET MET: Overhead is < 10%`);
    } else {
        console.log(`\n⚠️ PERFORMANCE WARNING: Overhead is > 10%`);
    }
}

run().catch(console.error);
