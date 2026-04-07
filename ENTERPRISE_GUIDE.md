# ShieldRASP Enterprise Engine Documentation

Welcome to the hardened ShieldRASP platform. The system has been structurally redesigned into a "Pre-Flight Monolithic" architecture, eliminating common protocol-level bypasses used against traditional RASP solutions.

## 🛡️ Key Protective Layers

### 1. Monolithic Stream Reconstructor
The engine now intercepts and reconstructs the full HTTP request body (up to 5MB) before any framework routing occurs.
- **Evasion Defeated**: Cross-chunk canary splitting and protocol-level fragmentation attacks.
- **Safety**: 10s assembly timeout and 5MB cap prevents Slowloris or Memory Exhaustion.

### 2. Unified Pre-Flight Semantic Pipeline
Instead of isolated hook-based analysis, ShieldRASP performs a holistic scan of the **Unified Input Context** (Headers + Query + Reconstructed Body).
- **Normalization**: Recursive URL decoding, HTMLEntity decoding, and Hex/Base64 opportunistic deobfuscation.
- **Early Block**: Malicious payloads are identified and rejected synchronously before Express middleware or route handlers receive the request.

### 3. Behavioral Correlation Engine (V1)
ShieldRASP tracks attacker intent across multiple request cycles using persistent IP-based state.
- **Chains Detected**: "Reconnaissance -> Exploitation". For example, a directory traversal attempt followed by an RCE probe will trigger a severe behavioral penalty (+50 risk score).
- **Correlation Logic**: Tracks "flows" and "anomalies" per IP with a 1-hour sliding window.

### 4. Enterprise Policy DSL (`shieldrasp.policy.json`)
Manage your security posture without code changes.
```json
{
    "mode": "block",
    "thresholds": { "block": 80, "log": 40 },
    "rules": {
        "sqli": { "action": "block", "threshold": 70 },
        "cmd": { "action": "block", "threshold": 90 }
    }
}
```

## 🚀 How to use
The system is automatically active via the `--require` hook. The policy file `shieldrasp.policy.json` will be automatically loaded from your project root.

---
**ShieldRASP: Pre-emptive, Synchronous, Resilient.**
