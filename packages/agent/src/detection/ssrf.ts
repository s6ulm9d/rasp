import { TaintContext, isTainted } from '../taint/context';

export function detectSSRF(url: string, ctx?: TaintContext) {
  if (typeof url !== 'string') return { blocked: false, matched: false };
  const tainted = ctx ? isTainted(new String(url)) : false;
  if (!tainted) return { blocked: false, matched: false };

  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    const blockedHosts = ['localhost', '127.0.0.1', '169.254.169.254'];
    
    if (blockedHosts.includes(host) || host.endsWith('.internal')) {
      return {
        blocked: true, matched: true, type: 'SSRF', confidence: 0.99,
        cwe: 'CWE-918', payload: url, timestamp: Date.now()
      };
    }
  } catch (e) {}

  return { blocked: false, matched: false };
}