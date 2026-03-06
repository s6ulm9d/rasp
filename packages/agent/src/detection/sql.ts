import { TaintContext, getTaintContext } from '../taint/context';

const SQL_INJECTION_PATTERN = /UNION\s+SELECT|SLEEP\s*\(\d+\)|OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?|DROP\s+TABLE|--|#|ALTER\s+TABLE/i;

export function detectSqlInjection(query: string, ctx?: TaintContext) {
    const matched = SQL_INJECTION_PATTERN.test(query);
    const currentCtx = ctx || getTaintContext();
    if (!currentCtx) return { blocked: false, matched: false };

    let taintedValueMatched = '';
    let isTainted = false;

    for (const [taintedValue] of currentCtx.taintedObjects) {
        if (typeof taintedValue === 'string' && query.includes(taintedValue)) {
            isTainted = true;
            taintedValueMatched = taintedValue;
            break;
        }
    }

    // If it's a known exploit pattern AND tainted, it's an HIGH-CONFIDENCE block.
    if (matched && isTainted) {
        return {
            blocked: true, matched: true, attack_type: 'SQL Injection', confidence: 0.99,
            cwe: 'CWE-89', payload: query, timestamp: Date.now()
        };
    }

    // NEW: Proactive detection for "Undefined" SQL manipulation.
    // If the input is tainted and contains ANY SQL special control characters, block it 
    // because user input should NEVER be able to break out of the string literal even if it's not a known exploit!
    const SQL_CONTROL_CHARS = /['";#\\]|--/;
    if (isTainted && SQL_CONTROL_CHARS.test(taintedValueMatched)) {
        return {
            blocked: true, matched: true, attack_type: 'Undefined SQL Injection', confidence: 0.90,
            cwe: 'CWE-89', payload: query, timestamp: Date.now(),
            details: 'Tainted input contains SQL control characters and was used in a raw query'
        };
    }

    // Log as a vulnerability but don't block yet if only tainted but no control char (vulnerable but maybe okay?)
    if (isTainted) {
        return {
            blocked: false, matched: true, attack_type: 'Tainted SQL Sink', confidence: 0.50,
            cwe: 'CWE-89', payload: query, timestamp: Date.now(),
            details: 'User-controlled input reached an unparameterized SQL statement'
        };
    }

    return { blocked: false, matched: false };
}

