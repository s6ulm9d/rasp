# ShieldRASP Penetration Testing & Verification Guide

This document provides a systematic protocol to verify every security boundary of the ShieldRASP platform.

## 🛠️ 1. Environment Setup

### Prerequisites
- **Node.js**: v18.0.0 or higher.
- **npm**: v9.0.0 or higher.

### Step 1: Clean Build
From the monorepo root:
```bash
# Install all dependencies
npm install

# Build the Agent and CLI
npm run build
```

### Step 2: Global Link (Optional but Recommended)
To use the `shieldrasp` command globally:
```bash
cd packages/cli
npm link
cd ../..
```

---

## 🚀 2. Verification Protocol

### A. Start the Monitor (Terminal A)
```bash
shieldrasp monitor
```
*Expected: "🚀 ShieldRASP CLI Monitor started on port 50052"*

### B. Start the Demo App with Zero-Code Injection (Terminal B)
```bash
cd apps/demo-app
$env:NODE_OPTIONS = "--require ../../packages/agent"
node index.js
```
*Expected: "[ShieldRASP] Current Mode: BLOCK"*

---

## ⚔️ 3. Attack Vector Testing (Terminal C)

### 3.1 SQL Injection
*   **Target**: `GET /vuln/sqli?id=`
*   **Why**: Verifies the `pg`, `mysql`, and `mysql2` hooks and unparameterized query detection.
*   **Command (Linux/macOS)**:
    ```bash
    curl "http://localhost:8081/vuln/sqli?id=1' UNION SELECT * FROM secrets--"
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe "http://localhost:8081/vuln/sqli?id=1' UNION SELECT * FROM secrets--"
    ```
*   **Expected Response**: `ShieldRASP: Blocked SQL Injection Attempt` (HTTP 500/Break) or custom 403.
*   **Monitor Output**: Table showing `SQL Injection` attack, 0.99 confidence, `Blocked: Yes`.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.sqli: true`.
    - *Taint Loss*: Check if Express middleware or custom routers are stripping the original URL string reference before the DB call.
    - *Hook Binding*: Confirm the `require-in-the-middle` hook successfully bound to the `pg` or `mysql` module before the app required it.

### 3.2 Command Injection
*   **Target**: `GET /vuln/cmd?host=`
*   **Why**: Verifies `child_process` hooks and shell metacharacter detection in tainted inputs.
*   **Command (Linux/macOS)**:
    ```bash
    curl "http://localhost:8081/vuln/cmd?host=google.com;whoami"
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe "http://localhost:8081/vuln/cmd?host=google.com;whoami"
    ```
*   **Expected Response**: `ShieldRASP: Blocked Command Injection Attempt`.
*   **Monitor Output**: Table showing `Command Injection` with payload `;whoami`.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.cmd: true`.
    - *Execution Variant*: Ensure the target app is using hooked methods (`exec`, `spawn`, `execFile`) and not a 3rd party native module.
    - *Taint Substring*: Validate that `isTainted` deep-lookup is correctly finding the substring match within the broader command.

### 3.3 Remote Code Execution (RCE)
*   **Target**: `GET /vuln/rce?code=`
*   **Why**: Verifies `eval()`, `Function()`, and `vm` module hooks.
*   **Command (Linux/macOS)**:
    ```bash
    curl "http://localhost:8081/vuln/rce?code=process.exit(1)"
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe "http://localhost:8081/vuln/rce?code=process.exit(1)"
    ```
*   **Expected Response**: `ShieldRASP: Blocked RCE Attempt (eval)`.
*   **Monitor Output**: Table showing `Remote Code Execution` attack.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.rce: true`.
    - *Module Context*: Node.js `eval` behaves differently in global vs module scope; ensure the monkey-patch on `global.eval` hasn't been bypassed by indirect `eval` usage.
    - *Code Execution Engine*: The backend might be utilizing an unhooked sandbox or V8 isolator library instead of standard `vm`. Verify the execution engine.

### 3.4 Prototype Pollution
*   **Target**: `POST /vuln/prototype` (JSON Body)
*   **Why**: Verifies `JSON.parse` hook and recursive object pollution detection.
*   **Command (Linux/macOS)**:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"__proto__":{"polluted":true}}' http://localhost:8081/vuln/prototype
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe -X POST -H "Content-Type: application/json" -d '{\"__proto__\":{\"polluted\":true}}' http://localhost:8081/vuln/prototype
    ```
*   **Expected Response**: `ShieldRASP: Blocked Prototype Pollution Attempt`.
*   **Monitor Output**: Table showing `Prototype Pollution`.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.prototype: true`.
    - *Stream Context*: If the body is fully parsed by native C++ extensions or `reviver` overrides `JSON.parse`, the string taint hook may miss the stream.
    - *Max Depth Reached*: Complex, deeply nested bodies might bypass the depth-limited recursive scanner (depth > 10). Adjust the recursion limit if needed.

### 3.5 Path Traversal (LFI)
*   **Target**: `GET /vuln/path?file=`
*   **Why**: Verifies `fs` hooks and jail directory enforcement.
*   **Command (Linux/macOS)**:
    ```bash
    curl "http://localhost:8081/vuln/path?file=../../../../etc/passwd"
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe "http://localhost:8081/vuln/path?file=../../../../etc/passwd"
    ```
*   **Expected Response**: `ShieldRASP: Blocked Path Traversal Attempt`.
*   **Monitor Output**: Table showing `Path Traversal`.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.path: true`.
    - *Proxy Binding Failure*: Read-only exports on `fs` can cause proxy reassignment to fail in newer Node.js versions; ensure the agent's proxy fallback is functioning.
    - *Path Normalization*: The application might resolve the path against a different working directory prior to `fs` interaction, obscuring the traversal tokens `..`.

### 3.6 SSRF (Server-Side Request Forgery)
*   **Target**: `GET /vuln/ssrf?url=`
*   **Why**: Verifies `http.request` hooks and internal IP/Metadata blocking.
*   **Command (Linux/macOS)**:
    ```bash
    curl "http://localhost:8081/vuln/ssrf?url=http://169.254.169.254/latest/meta-data/"
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe "http://localhost:8081/vuln/ssrf?url=http://169.254.169.254/latest/meta-data/"
    ```
*   **Expected Response**: `ShieldRASP: Blocked Server-Side Request Forgery Attempt`.
*   **Monitor Output**: Table showing `SSRF`.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.ssrf: true`.
    - *Hook Evasion*: Third-party request libraries might use `node-fetch`, `undici`, or native `fetch` which bypasses internal `http.request` hooks in Node 18+.
    - *URL Parsing*: Ensure the hook correctly extracts the host property from both string and `URL`-object invocations of `http.request`.

### 3.7 NoSQL Injection (MongoDB)
*   **Target**: `GET /vuln/nosql?filter=`
*   **Why**: Verifies `mongodb` collection hooks and recursive operator check.
*   **Command (Linux/macOS)**:
    ```bash
    curl "http://localhost:8081/vuln/nosql?filter=%7B%22%24where%22%3A%22sleep(5000)%22%7D"
    ```
*   **Command (Windows PowerShell)**:
    ```powershell
    curl.exe "http://localhost:8081/vuln/nosql?filter=%7B%22%24where%22%3A%22sleep(5000)%22%7D"
    ```
*   **Expected Response**: `ShieldRASP: Blocked NoSQL Injection Attempt`.
*   **Monitor Output**: Table showing `NoSQL Injection`.
*   **What if it fails (Diagnostics)**:
    - *Agent Initialization*: Ensure `shieldrasp.json` has `protections.nosql: true`.
    - *Driver Version Mismatch*: Ensure the `mongodb` driver version being required isn't doing prototype manipulation that avoids standard hook interceptions.
    - *Taint Stringification Drop*: If the untrusted input undergoes a custom parsing/clone mechanism, taint metadata on primitive strings might be lost before reaching the MongoDB query processor.

---

## ⚙️ 4. Mode Switching & Edge Cases

### Alert Mode vs Block Mode
1.  Run `shieldrasp init` in the `demo-app` folder.
2.  Edit `shieldrasp.json` and set `"mode": "alert"`.
3.  Restart the demo app.
4.  Run any attack above.
5.  **Verification**: The app should return a result (or standard error), but the **Terminal A (Monitor)** should still show the attack with `Blocked: No`.

### Zero-Code Injection Verification
- Try running `node index.js` without the `--require` flag.
- Run an attack.
- The app should be fully vulnerable.
- This confirms that protection is truly runtime-injected and not hardcoded.

### Edge Cases Verification
To ensure ShieldRASP handles complex evasions, execute these specific edge case commands:

**1. Empty Payload (No crash)**
*   **Command (Linux/macOS)**: `curl "http://localhost:8081/vuln/sqli?id="`
*   **Command (Windows PowerShell)**: `curl.exe "http://localhost:8081/vuln/sqli?id="`
*   **Expected**: Normal HTTP response or DB error, no RASP intervention, no agent crash.

**2. Double-Encoded Payload (SQLi)**
*   **Command (Linux/macOS)**: `curl "http://localhost:8081/vuln/sqli?id=%2531%2527%2520%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554"`
*   **Command (Windows PowerShell)**: `curl.exe "http://localhost:8081/vuln/sqli?id=%2531%2527%2520%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554"`
*   **Expected**: Blocked SQL Injection.

**3. Chunked Body Injection (Prototype)**
*   **Command (Linux/macOS)**: `curl -X POST -H "Transfer-Encoding: chunked" -H "Content-Type: application/json" -d '{"__proto__":{"polluted":true}}' http://localhost:8081/vuln/prototype`
*   **Command (Windows PowerShell)**: `curl.exe -X POST -H "Transfer-Encoding: chunked" -H "Content-Type: application/json" -d '{\"__proto__\":{\"polluted\":true}}' http://localhost:8081/vuln/prototype`
*   **Expected**: Blocked Prototype Pollution Attempt.

**4. constructor.prototype Pollution Variant**
*   **Command (Linux/macOS)**: `curl -X POST -H "Content-Type: application/json" -d '{"constructor":{"prototype":{"polluted":true}}}' http://localhost:8081/vuln/prototype`
*   **Command (Windows PowerShell)**: `curl.exe -X POST -H "Content-Type: application/json" -d '{\"constructor\":{\"prototype\":{\"polluted\":true}}}' http://localhost:8081/vuln/prototype`
*   **Expected**: Blocked Prototype Pollution Attempt.

### Telemetry Stream Integrity
- Confirm that the number of events in the monitor matches the number of curls executed.
- Check `~/.shieldrasp/logs/agent.log` to ensure local persistence works alongside the stream.

---

## ❓ Troubleshooting Checklist
- **Issue**: Monitor doesn't show events.
  - **Check**: Is the agent port matching the monitor port (50052)?
  - **Check**: Is `NODE_OPTIONS` exported correctly? (On Windows PowerShell use `$env:NODE_OPTIONS`, on Linux use `export NODE_OPTIONS`).
- **Issue**: App crashes on startup.
  - **Check**: Are you using `require-in-the-middle` properly? Check for circular dependencies in hooks.
