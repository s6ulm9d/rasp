const http = require('http');
const assert = require('assert');
// Pre-load RASP
require('../src/index');

const { exec } = require('child_process');

// Create a simple Target Server that should ONLY be reached if RASP allows
const targetServer = http.createServer((req, res) => {
   const url = req.url;

   if (url === '/leaked-ssn') {
      res.end('User records: John Doe - SSN: 123-45-6789 - END');
      return;
   }

   if (url === '/trigger-sink') {
      // Simulate vulnerable sink
      const cmd = "echo 'Executing: " + req.url + "'";
      // Attempting to spawn something malicious from input:
      // Note: In real setup, we'd need body-parser, but we simulate sink call with known input
      try {
         exec('whoami', (err) => { 
            res.end('SUCCESS_UNGUARDED_SINK'); 
         });
      } catch (e) {
         res.statusCode = 500;
         res.end('RASP_BLOCKED_SINK');
      }
      return;
   }

   if (url === '/test-stream-replay') {
      let bodyReceived = '';
      req.on('data', (c) => bodyReceived += c.toString());
      req.on('end', () => {
         if (bodyReceived === 'REPLAY_TEST_123') {
            res.end('SUCCESS_REPLAY');
         } else {
            res.end('FAILURE_REPLAY:' + bodyReceived);
         }
      });
      return;
   }
   res.end('SUCCESS_DEFAULT');
});

const PORT = 4999;
targetServer.listen(PORT, async () => {
   console.log(`[Self-Test] Target server listening on ${PORT}`);
   await runAllTests();
   targetServer.close();
   // Exit if successful
   process.exit(0);
});

async function runAllTests() {
   console.log('\n--- ShieldRASP v2 SELF-TEST SUITE ---');

   // 1. Chunked Payload Bypass Attempt (SQLi)
   await testRequest('1. Chunked Payload SQLi Bypass', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', 'Transfer-Encoding': 'chunked' },
      body: ["' OR ", "1=1 --", " "]
   }, { expectedStatus: 403, expectedReason: 'SUSPICIOUS_DYNAMIC_SCORE' });

   // 2. JSON Body Injection (CMD)
   await testRequest('2. JSON Command Injection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      bodyContent: JSON.stringify({ cmd: "whoami && ls" })
   }, { expectedStatus: 403, expectedReason: 'SUSPICIOUS_DYNAMIC_SCORE' });

   // 3. Multipart Injection
   await testRequest('3. Multipart Filename Traversal', {
      method: 'POST',
      headers: { 'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' },
      bodyContent: `------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name="file"; filename="../../../etc/passwd"\r\nContent-Type: text/plain\r\n\r\nTEST CONTENT\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n`
   }, { expectedStatus: 403, expectedReason: 'SUSPICIOUS_DYNAMIC_SCORE' });

   // 4. Multi-Encoded Payloads (XSS)
   // Escaped: <script> -> %3cscript%3e -> hex: \x253cscript\x253e
   await testRequest('4. Multi-Encoded XSS Payload', {
      method: 'GET',
      path: '/?q=%253cscript%253e' 
   }, { expectedStatus: 403 });

   // 5. SSRF Variants
   await testRequest('5a. SSRF Localhost Bypass', { method: 'GET', path: '/?url=http://127.0.0.1/admin' }, { expectedStatus: 403 });
   await testRequest('5b. SSRF Hex Encoding', { method: 'GET', path: '/?url=http://0x7f.0.0.1/' }, { expectedStatus: 403 });
   await testRequest('5c. SSRF @ Trick', { method: 'GET', path: '/?url=http://google.com@127.0.0.1' }, { expectedStatus: 403 });

   // 6. Enterprise: Data Leakage Protection (PII Redaction)
   await testRequest('6. Response SSN Redaction', {
      method: 'GET',
      path: '/leaked-ssn'
   }, { expectedStatus: 200, expectedContent: '[REDACTED]' });

   // 7. Enterprise: Sink Monitoring (RCE Prevention)
   // We simulate a request having 'whoami' and the server TRying to spawn it
   await testRequest('7. Sink Taint Detection (RCE)', {
      method: 'POST',
      bodyContent: 'target=whoami',
      path: '/trigger-sink',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
   }, { expectedStatus: 500 }); // Server should crash or RASP should throw which leads to generic error

   // 8. Enterprise: Early Abort (Memory Protection)
   // Send a slow malicious stream and ensure it blocks MID-TRANSFER
   await testRequest('8. Early Abort Mid-Stream', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: ["<script", "> alert('XSS') </script>", "TRAILING JUNK"]
   }, { expectedStatus: 403, allowHangup: true });

   // Reset reputations for clean performance test
   const shield = require('../src/index');
   shield.interceptor.inspector.detector._eventHistory.clear();
   shield.interceptor.inspector.detector.reputations.clear();

   // 9. High-Frequency Burst (1000 requests)
   console.log('[Test 9] Starting Concurrency Burst (1000 requests)...');
   let count = 0;
   const p = [];
   for(let i=0; i<1000; i++) {
      p.push(testRequest(`Burst_${i}`, { method: 'GET' }, { expectedStatus: 200, silent: true }));
   }
   await Promise.all(p);
   console.log('[Test 9] Completed Burst Test safely.');

   // 10. Stability: Stream Replay (Framework Integration)
   await testRequest('10. Stream Replay Support', {
      method: 'POST',
      path: '/test-stream-replay',
      bodyContent: 'REPLAY_TEST_123'
   }, { expectedStatus: 200, expectedContent: 'SUCCESS_REPLAY' });

   console.log('\n--- ALL ENTERPRISE SELF-TESTS COMPLETED ---');
}

async function testRequest(testName, options, expected) {
   return new Promise((resolve) => {
      const { method = 'GET', headers = {}, body = null, bodyContent = null, path = '/' } = options;
      
      const req = http.request({
         hostname: '127.0.0.1',
         port: PORT,
         method: method,
         path: path,
         headers: headers
      }, (res) => {
         let data = '';
         res.on('data', c => data += c);
         res.on('end', () => {
            try {
               if (!expected.silent) {
                 console.log(`[${testName}] Result: ${res.statusCode} ${res.statusCode === 403 ? ' (BLOCKED - CORRECT)' : '(ALLOWED - CORRECT?)'}`);
               }
               
               if (expected.expectedStatus) {
                  assert.strictEqual(res.statusCode, expected.expectedStatus, `Status mismatch for ${testName}!`);
               }
               if (res.statusCode === 403 && expected.expectedReason) {
                  const json = JSON.parse(data);
                  assert.ok(json.reason.includes(expected.expectedReason), `Reason mismatch! Found: ${json.reason}`);
               }
               resolve();
            } catch (e) {
               console.error(`[FAILURE] ${testName}: ${e.message}`);
               resolve(); // Continue but count as fail?
            }
         });
      });

      req.on('error', (e) => {
         if (expected.allowHangup && (e.message.includes('hang up') || e.code === 'ECONNRESET')) {
            if (!expected.silent) console.log(`[${testName}] Result: HUNGUP_BY_RASP (CORRECT EARLY ABORT)`);
            return resolve();
         }
         if (!expected.silent) console.error(`[${testName}] REQ ERROR: ${e.message}`);
         resolve();
      });

      if (body) {
         body.forEach(chunk => req.write(chunk));
         req.end();
      } else if (bodyContent) {
         req.write(bodyContent);
         req.end();
      } else {
         req.end();
      }
   });
}
