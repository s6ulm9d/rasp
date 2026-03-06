import { TaintContext, getTaintContext } from '../taint/context';

export function detectPrototypePollution(key: any, value: any, ctx?: TaintContext) {
    if (typeof key !== 'string') return { blocked: false, matched: false };

    const suspiciousKeys = ['__proto__', 'constructor', 'prototype'];
    const matched = suspiciousKeys.includes(key);

    if (!matched) return { blocked: false, matched: false };

    // If the key itself is tainted, it's a high-confidence attack
    const currentCtx = ctx || getTaintContext();
    if (!currentCtx) return { blocked: false, matched: false };

    let tainted = false;
    for (const [taintedValue] of currentCtx.taintedObjects) {
        if (typeof taintedValue === 'string' && key === taintedValue) {
            tainted = true;
            break;
        }
    }

    if (tainted) {
        return {
            blocked: true,
            matched: true,
            attack_type: 'Prototype Pollution',
            confidence: 0.99,
            cwe: 'CWE-1321',
            payload: `Attempted to set ${key}`,
            timestamp: Date.now()
        };
    }

    return { blocked: false, matched: false };
}
