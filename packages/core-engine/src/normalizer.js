const querystring = require('querystring');
const he = require('he'); // Since it's a "production-grade" RASP, I'll recommend using he but implement a basic internal fallback or assume it's in the repo.
// Actually, I'll use a simpler built-in way for HTML decoding to minimize dependencies, or assume dependencies are there.

class Normalizer {
  constructor(maxDepth = 3) {
    this.maxDepth = maxDepth;
  }

  normalizeAnything(val, depth = 0) {
    if (depth >= this.maxDepth) return val;

    if (typeof val === 'string') {
        return this.canonicalizeString(val, depth + 1);
    } else if (Array.isArray(val)) {
        return val.map(item => this.normalizeAnything(item, depth + 1));
    } else if (val && typeof val === 'object') {
        const normalized = {};
        for (const [k, v] of Object.entries(val)) {
          normalized[k] = this.normalizeAnything(v, depth + 1);
        }
        return normalized;
    }
    return val;
  }

  normalizeMap(map) {
     const normalized = {};
     for (const [k, v] of Object.entries(map)) {
        normalized[k] = this.normalizeAnything(v);
     }
     return normalized;
  }

  canonicalizeString(val, depth) {
    let current = val;
    let iterations = 0;
    const maxIterations = 5; // Prevent loops

    while(iterations < maxIterations) {
       let previous = current;
       
       // 1. URL Decode
       try { current = decodeURIComponent(current); } catch (e) { /* ignore */ }
       
       // 2. HTML Entities Decode (Basic)
       current = this._decodeHTMLEntities(current);

       // 3. Base64 Decode (If matches pattern)
       if (this._isBase64(current)) {
          try { current = Buffer.from(current, 'base64').toString('utf8'); } catch (e) { /* ignore */ }
       }

       // 4. Hex Decode (If matches pattern like \x41)
       if (this._isHexEnc(current)) {
          current = this._decodeHex(current);
       }

       if (current === previous) break;
       iterations++;
    }
    return current;
  }

  _decodeHTMLEntities(text) {
     // Basic fallback for HTML entities if 'he' isn't available
     // Ideally, we'd use 'he' for precision.
     return text.replace(/&(#?[a-z0-9]+);/gi, (match, entity) => {
        const entities = {
          'lt': '<', 'gt': '>', 'amp': '&', 'quot': '"', 'apos': "'", 'nbsp': ' '
        };
        if (entities[entity.toLowerCase()]) return entities[entity.toLowerCase()];
        if (entity.startsWith('#x')) return String.fromCharCode(parseInt(entity.substring(2), 16));
        if (entity.startsWith('#')) return String.fromCharCode(parseInt(entity.substring(1), 10));
        return match;
     });
  }

  _isBase64(str) {
      // Basic check for base64: min length 8, only alphanumeric + plus + slash + equals
      if (str.length < 8) return false;
      return /^[A-Za-z0-9+/]+={0,2}$/.test(str);
  }

  _isHexEnc(str) {
     // Check for \x41 or %41 patterns
     return /\\x[0-9a-f]{2}/i.test(str);
  }

  _decodeHex(str) {
     return str.replace(/\\x([0-9a-f]{2})/gi, (m, g) => String.fromCharCode(parseInt(g, 16)));
  }

  decodeURL(str) {
     try { return decodeURIComponent(str); } catch (e) { return str; }
  }
}

module.exports = { Normalizer };
