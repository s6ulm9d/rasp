import { TaintContext, getTaintContext } from '../taint/context';

const SQL_INJECTION_PATTERN = /UNION\s+SELECT|SLEEP\s*\(\d+\)|OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?|DROP\s+TABLE|--|#|ALTER\s+TABLE/i;

export function detectSqlInjection(query: string, ctx?: TaintContext) {
    const matched = SQL_INJECTION_PATTERN.test(query);
    if (!matched) return { blocked: false, matched: false };

    const currentCtx = ctx || getTaintContext();
    if (!currentCtx) return { blocked: false, matched: false };

    // Simple heuristic: check if any part of the query contains a tainted value
    let tainted = false;
    for (const [taintedValue] of currentCtx.taintedObjects) {
        if (typeof taintedValue === 'string' && query.includes(taintedValue)) {
            tainted = true;
            break;
        }
    }

    if (tainted) {
        return {
            blocked: true, matched: true, attack_type: 'SQL Injection', confidence: 0.95,
            cwe: 'CWE-89', payload: query, timestamp: Date.now()
        };
    }
    return { blocked: false, matched: false };
}
