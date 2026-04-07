# SHIELDRASP DESTRUCTIVE ADVERSARIAL PLAYBOOK
**CLASSIFICATION:** RED TEAM / CRITICAL VALIDATION  
**MAINTAINER:** ELITE SEC-OPS QA  

This is an execution-ready Destructive Playbook. It operates under the assumption that ShieldRASP is flawed, its execution boundary is permeable, and its logic can be raced. 

Execute these scenarios to validate production integrity. Do not deploy until these vectors are certifiably mitigated.

---

## PHASE 1: FRAGMENTATION & STREAM CORRUPTION
**Objective:** Defeat the Taint Tracker and Regex/Canary Matchers using protocol-level stream chunking. 
**Context:** ShieldRASP analyzes `http.inbound` via `req.on('data')`. TCP/TLS frames can fracture arbitrarily.

### 1.1 The Cross-Chunk Canary Evasion
* **Attack Simulation:** Force a multi-fragment payload transmission. Use `curl` or a raw TCP socket to inject the hardcoded canary string with deliberate pauses between frames.
  ```powershell
  # Using netcat or python to send chunk 1: `{"data": "__CANAR`
  # Delay 50ms
  # Send chunk 2: `Y_MEMORY_CAFE__"}`
  ```
* **Expected Behavior:** RASP reconstructs the body stream or tracks taint state across stateful buffers and enforces the memory block dynamically.
* **Failure Signal:** The payload executes or reaches the controller. The inbound hook `includes()` command evaluated the chunks independently and failed to spot the sequence.
* **Debug Focus:** RASP relies on isolated chunk iteration rather than aggregated buffered context in `packages/agent/src/hooks/inbound.ts`.

### 1.2 Multi-Boundary Multipart DoS
* **Attack Simulation:** Send a multipart/form-data request with 10,000 tiny boundaries where the payload chunks alternate endlessly, designed to bloat the Taint graph allocation.
* **Expected Behavior:** System detects memory exhaustion or rate-limits/terminates the anomalous pipe via max-buffer size.
* **Failure Signal:** Node.js process crashes due to OOM (Out of Memory) because the `TaintContext` array stores infinite strings from `ctx.taint(str)`.
* **Debug Focus:** `TaintContext` memory bounds and GC (Garbage Collection) management under extreme payload inflation.

---

## PHASE 2: ENTROPY DILUTION AND OBFUSCATION
**Objective:** Exploit the mathematical rules of the Detection Engine to sanitize malicious shellcode.
**Context:** ShieldRASP uses Shannon Entropy calculation. Highly compressed/base64 strings receive an automatic `+20` weight.

### 2.1 The Math Poisoning Attack (Entropy Dilution)
* **Attack Simulation:** The Engine fires if $Entropy > 0.8$. Send a highly lethal RCE payload (e.g., Base64 encoded reverse shellcode) but append 50,000 "A" characters to the string.
  ```json
  { "payload": "Y2hpbGRfcHJvY2Vzcy5leGVj...[thousands of 'A's]" }
  ```
* **Expected Behavior:** The engine calculates complexity *only* on the executable subset, or canonicalization intrinsically removes padding prior to entropy mapping.
* **Failure Signal:** The payload is evaluated. The sheer volume of 'A's drags the mathematical distribution ratio down, producing an entropy of $0.1$. The threat slips exactly under the block threshold limit.
* **Debug Focus:** The Shannon string parser in `calculateEntropy()` (`engine.ts`) averages over `str.length`, making it highly susceptible to length-padding bias.

### 2.2 Deep Canonicalization Overflow
* **Attack Simulation:** Double encode an injection vector using mixed Hex, Unicode, and Double-URL formats: 
  `%25%35%63%25%37%38%25%33%32...`
* **Expected Behavior:** RASP recursively strips all encapsulation until the raw root shellcode is visible in the graph.
* **Failure Signal:** System hits maximum stack depth causing a `RangeError: Maximum call stack size exceeded` in `canonicalize()` or fails after 2 iterations, executing the payload.
* **Debug Focus:** Recursive depth limits inside `packages/agent/src/taint/context.ts`.

---

## PHASE 3: EXECUTION RACE CONDITIONS (TOCTOU)
**Objective:** Outrun the asynchronous Security Gates before the engine issues a block directive.

### 3.1 DNS Re-Binding Roulette
* **Attack Simulation:** Target the SSRF vulnerability. Setup an attacker DNS server hosting `safe.example.com` with a TTL of 0.
  1. Engine interrogates `http.get`, resolving `safe.example.com` to `8.8.8.8`.
  2. Engine approves vector as benign.
  3. Attacker dynamically swaps DNS record to `169.254.169.254` (Cloud Metadata IP).
  4. Node's core C++ socket layer natively dials the IP.
* **Expected Behavior:** The DNS Guard tracks the explicit IP resolution explicitly mapped to the generated socket, throwing a connection-break when the IP mismatch occurs natively.
* **Failure Signal:** SSRF proxy echoes AWS Cloud Metadata back to the attacker.
* **Debug Focus:** `net.ts` vs `http.ts` hook synchronization boundaries. Is the RASP validating the URL string, or the resulting raw socket connection IP?

### 3.2 The Headless Exception Crash (Fatal Fallback)
* **Attack Simulation:** Send an injection payload that triggers `SecurityBlockException` *after* the target application has already started writing the `res.body` via pipelining.
* **Expected Behavior:** RASP forcibly drops the TCP socket pipe via `req.destroy()`.
* **Failure Signal:** The Node process fatally crashes with `ERR_HTTP_HEADERS_SENT`.
* **Debug Focus:** Fail-open vs Fail-closed handling. In `triggerAction()`, throwing an exception when execution context has already left the middleware boundary acts as an unhandled promise rejection in native environments.

---

## PHASE 4: STATEFUL ATTACK CHAINS 
**Objective:** Test the Context Correlation Engine (`engine.ts`) and ensure chained contextual threat patterns are accurately detected.

### 4.1 Fractional Exfiltration Mapping
* **Attack Simulation:** 
  1. Request 1: Write malicious `.js` file to `/tmp` via Path Traversal (`score: 40`).
  2. Request 2: Trigger application logic that executes `.js` file natively (`score: 40`).
  3. Request 3: File makes UDP dial out (`score: 40`).
* **Expected Behavior:** The engine maps these requests back to the source IP/Session and realizes an execution continuum is occurring, breaching the `80` cumulative blocking threshold.
* **Failure Signal:** Each request passes individually. System is context-blind across discrete HTTP sessions.
* **Debug Focus:** State correlation persistence. By default, V8 memory models dump `ctx` values when the promise is garbage collected.

---

### SUMMARY INTELLIGENCE
* **If Phase 1 Fails:** You cannot be trusted to protect any JSON streams spanning > 64Kb buffers.
* **If Phase 2 Fails:** Attackers will automate padding libraries into your product.
* **If Phase 3 Fails:** SSRF protection is completely hypothetical against sophisticated infrastructure. 
* **If Phase 4 Fails:** You possess a rule-based WAF, not an advanced runtime analyzer.

**Execute and Destroy.**
