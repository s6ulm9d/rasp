class ResponseInspector {
  constructor(policy) {
    this.policy = policy;
    this.sensitivePatterns = [
      { id: 'SSN', regex: /\d{3}-\d{2}-\d{4}/g },
      { id: 'PRIV_KEY', regex: /-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----/g },
      { id: 'VISA', regex: /4\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}/g }
    ];
  }

  inspect(res, chunk) {
    if (!chunk || typeof chunk !== 'string' && !Buffer.isBuffer(chunk)) return chunk;
    
    // 1. Content-Type Awareness
    const contentType = res.getHeader('content-type') || '';
    const inspectable = /text|json|html|javascript|xml/i.test(contentType);
    
    // Safely skip binary, images, etc.
    if (contentType && !inspectable) return chunk;

    let content = chunk.toString();
    let redacted = false;

    // ...

    for (const pattern of this.sensitivePatterns) {
       if (pattern.regex.test(content)) {
          console.warn(`[ShieldRASP] DATA_LEAK: Detected ${pattern.id} in response. Redacting.`);
          content = content.replace(pattern.regex, '[REDACTED]');
          redacted = true;
       }
    }

    return redacted ? Buffer.from(content) : chunk;
  }
}

module.exports = { ResponseInspector };
