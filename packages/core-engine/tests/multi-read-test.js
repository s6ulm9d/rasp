const http = require('http');
const assert = require('assert');

// Pre-load RASP
require('../src/index');

const targetServer = http.createServer((req, res) => {
   // READ 1: Framework body-parser (simulated)
   let firstRead = '';
   req.on('data', (c) => firstRead += c.toString());
   
   req.on('end', () => {
      // READ 2: Another middleware or manual read
      // This should fail in old ShieldRASP, but PASS in Architecture V2!
      let secondRead = '';
      
      // RE-ATTACH to prove multiple reads (Note: our rehydrator nextTicks this)
      req.on('data', (c) => secondRead += c.toString());
      
      req.on('end', () => {
         if (firstRead === 'MULTI_READ_DATA' && secondRead === 'MULTI_READ_DATA') {
            res.end('SUCCESS_MULTI_READ');
         } else {
            res.statusCode = 500;
            res.end(`FAILURE_MULTI_READ: First=[${firstRead}] Second=[${secondRead}]`);
         }
      });
   });
});

const PORT = 5002;
targetServer.listen(PORT, async () => {
   console.log(`[Multi-Read-Test] Server listening on ${PORT}`);
   await runTest();
   targetServer.close();
   process.exit(0);
});

async function runTest() {
   return new Promise((resolve) => {
      const req = http.request({
         hostname: '127.0.0.1', port: PORT, method: 'POST', path: '/'
      }, (res) => {
         let data = '';
         res.on('data', c => data += c);
         res.on('end', () => {
            console.log(`[Multi-Read-Test] Result: ${data}`);
            assert.strictEqual(data, 'SUCCESS_MULTI_READ');
            resolve();
         });
      });
      req.write('MULTI_READ_DATA');
      req.end();
   });
}
