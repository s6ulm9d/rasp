# ShieldRASP Production Testing & Validation Guide

## 1. Environment Setup

### Prerequisites
- Node.js v18+ running
- PM2 or cluster manager for high availability 

### Commands to Start Stack
1. Ensure strict environment variables are loaded:
```bash
export SHIELDRASP_MODE=BLOCK
export SHIELDRASP_POLICY_PATH=/etc/shieldrasp/policy.json
```

2. Start the Protected Application (example):
```bash
node --require @shieldrasp/agent apps/demo-app/index.js
```

## 2. Basic Validation Configuration

Ensure the system permits normal operational traffic smoothly.

**Normal Request Test:**
```bash
curl -X POST http://localhost:8081/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "password123"}'
```
**Expected Response:** `200 OK`

---

## 3. Advanced Attack Testing Scripts

The RASP must deterministically catch in-flight payloads without 500 crashes.

### 🔴 3.1 SQL Injection (Fragmented & Encoded)
*Simulates obfuscated payload sneaking past firewalls.*
```bash
curl -X POST http://localhost:8081/search \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "query=1' UNI" -d "ON SE" -d "LECT * FROM users--"
```
**Expected Response:** `403 Forbidden` (`{"error": "Forbidden", "message": "ShieldRASP Runtime Violation"...}`)

### 🔴 3.2 Large Payload Attack (Memory Check)
*Simulates body exhaustion before Express can parse.*
```bash
dd if=/dev/urandom bs=1M count=10 | curl -X POST http://localhost:8081/upload --data-binary @-
```
**Expected Response:** `403 Forbidden` or `ECONNRESET` immediately.

### 🔴 3.3 Server-Side Request Forgery & Command Injection (Sink Execution)
*Simulates an attacker successfully hijacking a `child_process.exec` wrapper.*
```bash
curl -X POST http://localhost:8081/ping \
     -H "Content-Type: application/json" \
     -d '{"host": "8.8.8.8; cat /etc/passwd"}'
```
**Expected Response:** `403 Forbidden` (Terminated specifically during `SinkMonitor` intercept phase, NO 500 leak).

### 🔴 3.4 Chunked Transfer Stream Smuggling
*Forces asynchronous node streaming fragmentation.*
```bash
curl -X POST http://localhost:8081/api -H "Transfer-Encoding: chunked" -d '
A
<script>
B
alert(1)
9
</script>
0
'
```
**Expected Response:** `403 Forbidden` 

---

## 4. Stress Testing & Concurrency

ShieldRASP must remain crash-proof across highly threaded asynchronous pressure without leaking tracking contexts.

### 🔴 4.1 Rapid Concurrency Assault
Using `autocannon` to slam the application to verify resource manager scaling.
```bash
npx autocannon -c 1000 -d 30 -m POST -b '{"test": "data"}' http://localhost:8081/
```
**Expected Behavior:** Active connections will reach `10000`, process memory stays below `MAX_MEMORY_GLOBAL` (500MB). Rate Limit handles IP rep bans if hit. No crashes. No `EADDRINUSE`.

---

## 5. Failure Detection & Log Observability

When monitoring logs inside production, identify the following markers:

**1. Normal Threat Mitigation Logs:**
```json
{
  "level": "warn",
  "msg": "ShieldRASP Block: SQL_INJECTION",
  "ip": "192.168.1.15",
  "requestId": "abc-123"
}
```

**2. Identifying a Failure (BUG):**
If you see the following in logs or console output, the RASP system needs patching:
- `TypeError: stream is not readable` -> Express attempted to consume after the stream closed.
- `ECONNRESET` inside the actual Node.js stack trace (Server failed to catch intercept).
- Response code `500 Server Error` under an explicit payload (Fail-closed is misconfigured).

---

## 6. Success Criteria

The RASP implementation is officially **Production-Ready** when:
1. **Zero Stream Corruption:** Application features execute precisely as usual if traffic is benign. 
2. **Predictable Memory Footprint:** RSS memory remains steady under 1000x concurrent `POST` requests.
3. **Deterministic Fail-Closed Boundaries:** Regardless of error state in detection logic or sinks, the client exclusively sees 403 blocks or silent socket drops. 
4. **Code cleanliness:** Global overrides are strictly encapsulated in `interceptor.js` and `reconstructor.js`.
