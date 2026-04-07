const net = require('net');
const http = require('http');

// Pre-load RASP
require('../src/index');

const targetServer = http.createServer((req, res) => {
   res.end('SUCCESS_STRESS_TEST');
});

const PORT = 5001;
targetServer.listen(PORT, async () => {
   console.log(`[Chaos-Test] Stress server listening on ${PORT}`);
   await runChaosTests();
   targetServer.close();
   process.exit(0);
});

async function runChaosTests() {
   console.log('\n--- ShieldRASP v2 PROTOCOL HARDENING SUITE ---');

   // 1. Invalid HTTP Method (Raw Socket)
   await sendRawRequest('1. Invalid HTTP Method (HACK_EXPLOIT)', 
      "HACK_EXPLOIT / HTTP/1.1\r\nHost: localhost\r\n\r\n");

   // 2. Header Injection (Raw Socket)
   await sendRawRequest('2. Header Injection (CRLF in value)', 
      "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: \r\nInjected-Header: evil\r\n\r\n");

   // 3. Fragmentation Attack (Single-byte writes)
   await sendFragmentedPayload('3. Byte-Fragmentation XSS');

   console.log('\n--- CHAOS TESTING COMPLETED ---');
}

function sendRawRequest(name, data) {
   return new Promise((resolve) => {
      const client = net.connect(PORT, '127.0.0.1', () => {
         client.write(data);
      });
      client.on('data', (d) => {
         console.log(`[${name}] Response: ${d.toString().split('\r\n')[0]}`);
         client.destroy();
      });
      client.on('end', () => resolve());
      client.on('error', () => {
         console.log(`[${name}] Connection Severed (PASS)`);
         resolve();
      });
      setTimeout(() => { client.destroy(); resolve(); }, 1000);
   });
}

function sendFragmentedPayload(name) {
   return new Promise((resolve) => {
      const payload = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 25\r\n\r\n<script>alert(1)</script>";
      const client = net.connect(PORT, '127.0.0.1', () => {
         // Send byte by byte with small delay to test adaptive window
         let i = 0;
         const interval = setInterval(() => {
            if (i >= payload.length) {
               clearInterval(interval);
               return;
            }
            client.write(payload[i++]);
         }, 1);
      });
      client.on('data', (d) => {
         console.log(`[${name}] Response: ${d.toString().split('\r\n')[0]}`);
         client.destroy();
         resolve();
      });
      client.on('end', () => resolve());
      client.on('error', () => resolve());
      setTimeout(() => { client.destroy(); resolve(); }, 2000);
   });
}
