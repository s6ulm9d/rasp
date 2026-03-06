export function detectIngress(urlPath: string, queryParams: URLSearchParams) {
    const XSS_PATTERN = /<script\b[^>]*>|<\/script>|onerror=|javascript:/i;
    const SQLI_PATTERN = /UNION\s+SELECT|SLEEP\s*\(\d+\)|OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?|--|#/i;
    const DIR_TRAVERSAL_PATTERN = /\.\.\/|\.\.\\/i;

    // Check path for obvious directory traversal or XSS
    if (DIR_TRAVERSAL_PATTERN.test(urlPath)) {
        return { blocked: true, matched: true, attack_type: 'Directory Traversal', confidence: 0.95, cwe: 'CWE-22', payload: urlPath, timestamp: Date.now() };
    }

    // Proactive Endpoint Probing / Reconnaissance detection
    const PROBE_PATTERN = /^\/(?:user|api|login|config|db|admin|backup|v1|v2|download|image|fetch)(?:\/.*)?$/i;
    // If we're hitting a sensitive-looking prefix that isn't a known route, it's probing
    // Specifically catch common fuzzer patterns
    if (PROBE_PATTERN.test(urlPath)) {
        return { blocked: true, matched: true, attack_type: 'Endpoint Probing', confidence: 0.85, cwe: 'CWE-20', payload: urlPath, timestamp: Date.now() };
    }

    // Check query params
    for (const [key, value] of queryParams) {
        if (XSS_PATTERN.test(value)) {
            return { blocked: true, matched: true, attack_type: 'Cross-Site Scripting (XSS)', confidence: 0.95, cwe: 'CWE-79', payload: value, timestamp: Date.now() };
        }
        if (SQLI_PATTERN.test(value)) {
            return { blocked: true, matched: true, attack_type: 'SQL Injection', confidence: 0.85, cwe: 'CWE-89', payload: value, timestamp: Date.now() };
        }
        if (DIR_TRAVERSAL_PATTERN.test(value)) {
            return { blocked: true, matched: true, attack_type: 'Directory Traversal', confidence: 0.95, cwe: 'CWE-22', payload: value, timestamp: Date.now() };
        }
    }

    // Heuristic for arbitrary fuzzing tokens like Burp's §1§ and sensitive file brute-forcing
    const FUZZ_PATTERN = /§\d*§|\.env|\.git|\.xml|\.bak|\.sql|^\/admin$/i;
    if (FUZZ_PATTERN.test(urlPath)) {
        return { blocked: true, matched: true, attack_type: 'Scanner Activity', confidence: 0.80, cwe: 'CWE-20', payload: urlPath, timestamp: Date.now() };
    }

    // Generic anomaly heuristics for undefined/zero-day payloads
    const CODE_INJECTION_PATTERN = /(?:eval|setTimeout|setInterval|Function|exec|system|passthru|popen|shell_exec|os\.system|sh)\s*\(/i;
    const ATTR_XSS_PATTERN = /on(?:load|error|click|mouseover|focus|submit|keydown|change|blur)\s*=/i;
    const OBFUSCATION_PATTERN = /(?:base64|hex|atob|btoa|charcode|string\.fromcharcode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i;

    for (const [key, value] of queryParams) {
        // 1. Code Injection Primitives
        if (CODE_INJECTION_PATTERN.test(value)) {
            return { blocked: true, matched: true, attack_type: 'Code Injection', confidence: 0.85, cwe: 'CWE-94', payload: value, timestamp: Date.now() };
        }

        // 2. Attribute-based XSS (e.g. <img src=x onerror=alert(1)>)
        if (ATTR_XSS_PATTERN.test(value)) {
            return { blocked: true, matched: true, attack_type: 'Cross-Site Scripting (XSS)', confidence: 0.80, cwe: 'CWE-79', payload: value, timestamp: Date.now() };
        }

        // 3. Obfuscation detection (base64/hex/unicode escaping)
        if (OBFUSCATION_PATTERN.test(value)) {
            return { blocked: true, matched: true, attack_type: 'Obfuscated Payload', confidence: 0.70, cwe: 'CWE-20', payload: value, timestamp: Date.now() };
        }

        // 4. Character density analysis
        const specialChars = (value.match(/[<>\'\"\;\|\&\$\{\}\[\]\(\)\\]/g) || []).length;
        if (specialChars >= 8 || (value.length > 5 && (specialChars / value.length) > 0.4)) {
            return { blocked: true, matched: true, attack_type: 'Generic Anomaly', confidence: 0.70, cwe: 'CWE-20', payload: value, timestamp: Date.now() };
        }

        // 5. Entropy calculation (Shannon entropy) to detect shellcode/packing
        if (value.length > 15) {
            const freq: { [key: string]: number } = {};
            for (const char of value) freq[char] = (freq[char] || 0) + 1;
            let entropy = 0;
            for (const char in freq) {
                const p = freq[char] / value.length;
                entropy -= p * Math.log2(p);
            }
            if (entropy > 3.8) {
                return { blocked: true, matched: true, attack_type: 'High-Entropy Payload', confidence: 0.65, cwe: 'CWE-20', payload: value, timestamp: Date.now(), details: `Entropy: ${entropy.toFixed(2)}` };
            }
        }
    }

    return { blocked: false, matched: false };
}
