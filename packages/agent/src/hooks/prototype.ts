import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupPrototypeHooks(engine: DetectionEngine) {
    const originalParse = JSON.parse;
    JSON.parse = function (text: string, reviver?: (this: any, key: string, value: any) => any) {
        const result = originalParse.call(this, text, reviver);
        const ctx = getTaintContext();

        // If the input text was tainted, we inspect the output object for pollution keys
        if (text && ctx && ctx.isTainted(text).tainted) {
            let polluted = false;
            const detectPollution = (obj: any, depth = 0) => {
                if (depth > 10 || !obj || typeof obj !== 'object' || polluted) return;

                const keys = Object.keys(obj);
                for (const key of keys) {
                    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                        polluted = true;
                        engine.evaluate(ctx, {
                            attack: 'Prototype Pollution',
                            payload: `Detected malicious key "${key}" in tainted JSON.parse output`,
                            sink: `JSON.parse`,
                            baseScore: 50,
                            tainted: true
                        });
                        break;
                    }
                    detectPollution(obj[key], depth + 1);
                }
            };

            detectPollution(result);
        }

        return result;
    };
}

