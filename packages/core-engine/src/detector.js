const dns = require('dns');
const net = require('net');
const url = require('url');

class DetectionEngine {
  constructor(policy) {
    this.policy = policy;
    this.patterns = [
      { id: 'SQI', name: 'SQL Injection', regex: /((\%27)|(\'))|(\b(union|select|insert|update|delete|drop|all|any|or|and)\b)|(--|\#)/i, weight: 0.6 },
      { id: 'CMD', name: 'Command Injection', regex: /(\b(ls|cat|whoami|id|sh|bash|powershell|calc\.exe)\b)|(;|\|\||&&|\$\(|\`|\||\$\{IFS\})/i, weight: 0.8 },
      { id: 'XSS', name: 'Cross Site Scripting', regex: /(<|%3c|\\u003c)\s*(script|iframe|object|embed|img|svg|body|a|link|meta)(\s|>|%3e|\\u003e)/i, weight: 0.8 },
      { id: 'LFI', name: 'Path Traversal/LFI', regex: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|%2e%2e%2e|%2fetc%2fpasswd|%2fetc%2fshadow|\/windows\/system32\/)/i, weight: 1.2 },
      { id: 'RCE', name: 'RCE Patterns', regex: /(fs\.readFile|child_process|require\(|eval\(|Function\(|Uint8Array|process\.mainModule|this\.constructor)/i, weight: 2.0 },
      { id: 'SUSP', name: 'Suspicious Char Sequence', regex: /(\$\{[^}]*\}|#\{[^}]*\})/i, weight: 0.7 },
      { id: 'NOSQL', name: 'NoSQL Injection', regex: /(\$ne|\$gt|\$lt|\$where|\$exists|\$regex)/i, weight: 1.0 },
      { id: 'PROTO', name: 'Prototype Pollution', regex: /(__proto__|constructor.*prototype)/i, weight: 2.0 }
    ];
    this.reputations = new Map(); // Simple in-memory reputation, should be LRU in production
    this._eventHistory = new Map(); // ip -> [{type, timestamp}]
    this._MAX_HISTORY_ENTRIES = 10000;
  }

  scan(inputs, clientIP) {
     let totalScore = 0;
     const triggered = [];

     // Yield slices for large payload dilution bypasses
     const slices = [fullStringified];
     const sliceSize = 5000;
     const stepSize = 2000;

     if (fullStringified.length > sliceSize) {
         for (let i = 0; i < fullStringified.length; i += stepSize) {
             slices.push(fullStringified.substring(i, i + sliceSize));
         }
     }
     
     // Build scanning targets including original inputs + payload slices
     const scanTargets = { ...inputs };
     slices.forEach((slice, i) => scanTargets[`__slice_${i}`] = slice);

     // 1. Pattern Matching (Scan individual fields AND full combined payload)
     for (const [key, rawValue] of Object.entries(scanTargets)) {
       const value = Buffer.isBuffer(rawValue) ? rawValue.toString('utf8') : 
                     (typeof rawValue === 'object' && rawValue !== null) ? JSON.stringify(rawValue) : 
                     String(rawValue);

       const normalized = this._normalizeInput(value);
       const compacted = normalized.replace(/\s+/g, ''); // compact representation for hidden keywords
       const alphaOnly = normalized.replace(/[^a-zA-Z]/g, '').toLowerCase(); // ultraCompact keyword extraction map
       
       // Semantic Heuristics check (No-AST dynamic execution check)
       if (
           alphaOnly.includes('globaleval') || 
           alphaOnly.includes('constructorconstructor') ||
           alphaOnly.includes('functionconstructor') ||
           alphaOnly.includes('processmainmodulerequire') ||
           /require.*childprocess/.test(alphaOnly)
       ) {
           totalScore += 2.0;
           triggered.push({ id: 'RCE_SEMANTIC', key });
           this._recordEvent(clientIP, 'RCE_SEMANTIC');
       }
       
       this.patterns.forEach(p => {
          if (p.regex.test(normalized) || p.regex.test(compacted) || p.regex.test(alphaOnly)) {
             totalScore += p.weight;
             triggered.push({ id: p.id, key });
             this._recordEvent(clientIP, p.id);
          }
       });
     }

     const uniqueTriggers = new Set(triggered.map(t => t.id));
     // Boost dynamically if we hit multiple distinct attack categories
     if (uniqueTriggers.size >= 2) {
         totalScore += 1.5;
     }

     // 2. Behavioral Sequence Detection (V2)
     const behaviorScore = this._analyzeBehavior(clientIP);
     totalScore += behaviorScore;

     // 3. Adaptive Threshold Check
     const threshold = this.policy.get('block_threshold') || 0.5;
     if (totalScore >= threshold) {
        // Increment reputational penalty
        this.reputations.set(clientIP, (this.reputations.get(clientIP) || 0) + 1);
        return { blocked: true, reason: `SUSPICIOUS_DYNAMIC_SCORE: ${totalScore.toFixed(2)}`, violations: triggered };
     }

     return { blocked: false };
  }

  _normalizeInput(rawValue) {
     if (typeof rawValue !== 'string') return '';
     let current = rawValue;
     let prev = '';
     let depth = 0;

     // 1. Recursive Decoding Loop (URL + Base64)
     while (current !== prev && depth < 10) {
        prev = current;
        try {
           const decoded = decodeURIComponent(current);
           if (decoded !== current) current = decoded;
        } catch(e) {}
        
        try {
           // Embedded base64 extraction scanner
           let modified = current;
           // Regex matches standard base64 strings of minimal length 12
           const b64Regex = /([A-Za-z0-9+/]{12,}={0,2})/g;
           let match;
           let replacements = false;
           
           while ((match = b64Regex.exec(current)) !== null) {
               const b64Str = match[1];
               const decoded = Buffer.from(b64Str, 'base64').toString('utf8');
               // Only apply if it resulted in printable utf8 characters over length 4 without trailing binary matchers
               // Rejects control chars / binary junk ensuring NO false positive overrides
               if (decoded !== b64Str && decoded.length >= 4 && /^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+$/.test(decoded)) {
                   modified = modified.replace(b64Str, decoded + ' ');
                   replacements = true;
               }
           }
           if (replacements) current = modified;
        } catch(e) {}
        depth++;
     }

     // 2. Remove inline comments (SQLi evasion /**/) and collapse whitespace
     current = current.replace(/\/\*[\s\S]*?\*\//g, ' ');
     current = current.replace(/\s+/g, ' ');
     return current.trim();
  }

  scanTaintedSink(payload, sinkArgs) {
     const normPayload = this._normalizeInput(payload);
     const normSinkArgs = this._normalizeInput(sinkArgs);

     for (const p of this.patterns) {
        // If the pattern exists in BOTH the request and the sink execution
        if (p.regex.test(normPayload) && p.regex.test(normSinkArgs)) {
           return { blocked: true, reason: `TAINTE_SINK_VIOLATION: ${p.id} reaching sensitive function.` };
        }
     }
     return { blocked: false };
  }

  _recordEvent(ip, type) {
     if (this._eventHistory.size >= this._MAX_HISTORY_ENTRIES && !this._eventHistory.has(ip)) {
         // Prevent memory growth by deleting oldest random map entry
         const firstKey = this._eventHistory.keys().next().value;
         this._eventHistory.delete(firstKey);
     }
  
     const history = this._eventHistory.get(ip) || [];
     history.push({ type, timestamp: Date.now() });
     // Keep only last 20 events per IP for the window
     if (history.length > 20) history.shift();
     this._eventHistory.set(ip, history);
  }

  _analyzeBehavior(ip) {
      const history = this._eventHistory.get(ip) || [];
      if (history.length < 2) return 0;

      const now = Date.now();
      const fiveMins = 300000;
      const recent = history.filter(h => now - h.timestamp < fiveMins);
      let score = 0;

      // 1. Time-based Decay Logic (Older events contribute less)
      const decayedScore = recent.reduce((sum, evt) => {
         const agePercent = (now - evt.timestamp) / fiveMins; // 0 to 1
         const weight = 1.0 - (agePercent * 0.5); // Decay up to 50%
         return sum + weight;
      }, 0);

      // 2. Recon-to-Exploit Sequence Detection
      const hasRecon = recent.some(r => r.type === 'SUSP' || r.type === 'LFI');
      const hasExploit = recent.some(r => r.type === 'CMD' || r.type === 'SQI' || r.type === 'RCE');

      if (hasRecon && hasExploit) {
         score += 2.0; // Escalated Sequence Penalty
      }

      // Behavioral Slow-Attack Bypass Fix
      if (recent.length >= 5) {
         score += 1.0;
      }

      // 3. Entropy/Probing Score
      if (decayedScore > 10) score += 1.0; 

      return score;
  }

  scanHeaderAndURL({ url: reqUrl, headers, ip }) {
     // 1. SSRF Check on Full URL (in case it's an absolute proxy req)
     const ssrfResult = this._checkSSRF(reqUrl);
     if (ssrfResult.blocked) return ssrfResult;

     // 2. SSRF Check on Query Params
     try {
        const parsed = url.parse(reqUrl, true);
        for (const [k, v] of Object.entries(parsed.query)) {
           if (typeof v === 'string' && (v.startsWith('http') || v.includes('://'))) {
              const res = this._checkSSRF(v);
              if (res.blocked) return res;
           }
        }
     } catch(e) {}

     return { blocked: false };
  }

  _checkSSRF(rawUrl) {
     try {
        const decoded = decodeURIComponent(rawUrl);
        const parsed = url.parse(decoded, true);
        let hostname = parsed.hostname;
        if (!hostname) {
           // Try to extract hostname from URLs like http://0x7f.0.0.1
           const match = decoded.match(/:\/\/(.[^/:]+)/);
           if (match) hostname = match[1];
        }

        if (!hostname) return { blocked: false };

        // Normalize hostname for checks
        const hl = hostname.toLowerCase();

        // 1. Check for @ (Userinfo trick)
        if (rawUrl.includes('@') && !this.policy.get('allow_userinfo')) {
           return { blocked: true, reason: 'SSRF_RESTRICTED_PROTOCOL: USERINFO_TRICK' };
        }

        // 2. Localhost / Private Subnet checks
        if (/(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|::0|\[::\]|::ffff:127\.0\.0\.1|::ffff:7f00:1)/i.test(hl)) {
           return { blocked: true, reason: 'SSRF_RESTRICTED_HOST: LOCALHOST' };
        }

        // 3. Private IP Ranges
        if (/^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\./.test(hl)) {
           return { blocked: true, reason: 'SSRF_RESTRICTED_HOST: PRIVATE_NETWORK' };
        }

        // 4. Hex/Octal (including dotted 0x7f.0.0.1)
        if (/0x[0-9a-f]+|^(0[0-7]+(\.|$)){4}$/i.test(hl)) {
            return { blocked: true, reason: 'SSRF_RESTRICTED_HOST: OBFUSCATED_IP' };
        }

        return { blocked: false };
     } catch (e) {
        return { blocked: false }; // Malformed URL, let application handle it or keep it simple
     }
  }

  // NOTE: DNS resolution check usually needs to be async, but our inspector call is async deepInspect.
  // We'll perform one sync check or async DNS lookup if needed.
}

module.exports = { DetectionEngine };
