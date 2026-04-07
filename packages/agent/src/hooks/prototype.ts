import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupPrototypeHooks(engine: any) {
    const originalParse = JSON.parse;
    JSON.parse = function (text: string, reviver?: (this: any, key: string, value: any) => any) {
        const result = originalParse.call(this, text, reviver);
        const ctx = getTaintContext();

        if (text && ctx) {
            const taintCheck = ctx.isTainted(text);
            if (taintCheck) {
                // Taint the result object
                ctx.taint(result, 'json.parse.output');
                
                // Active scan for pollution keys
                const check = (obj: any) => {
                    if (!obj || typeof obj !== 'object') return;
                    if (obj['__proto__'] || obj['prototype'] || obj['constructor']) {
                        engine.reportThreat(ctx, 'Prototype Pollution', text, 'JSON.parse', 100);
                    }
                };
                check(result);
            }
        }

        return result;
    };
}

