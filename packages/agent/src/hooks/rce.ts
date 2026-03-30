const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupRceHooks(engine: DetectionEngine) {
    // 1. Hook Global eval
    const originalEval = global.eval;
    (global as any).eval = function (code: string) {
        const ctx = getTaintContext();
        if (typeof code === 'string' && ctx) {
            const taintCheck = ctx.isTainted(code);
            if (taintCheck.tainted) {
                engine.evaluate(ctx, {
                    attack: 'Remote Code Execution',
                    payload: code,
                    sink: `global.eval`,
                    baseScore: 50,
                    tainted: true
                });
            }
        }
        return originalEval.call(this, code);
    };

    // 2. Hook Function Constructor safely via Proxy
    const originalFunction = global.Function;
    global.Function = new Proxy(originalFunction, {
        apply(target, thisArg, args) {
            const ctx = getTaintContext();
            if (ctx) {
                const code = args.join(' ');
                const taintCheck = ctx.isTainted(code);
                if (taintCheck.tainted) {
                    engine.evaluate(ctx, {
                        attack: 'Remote Code Execution',
                        payload: `Function constructor: ${code}`,
                        sink: `global.Function`,
                        baseScore: 50,
                        tainted: true
                    });
                }
            }
            return Reflect.apply(target, thisArg, args);
        },
        construct(target, args, newTarget) {
            const ctx = getTaintContext();
            if (ctx) {
                const code = args.join(' ');
                const taintCheck = ctx.isTainted(code);
                if (taintCheck.tainted) {
                    engine.evaluate(ctx, {
                        attack: 'Remote Code Execution',
                        payload: `Function constructor: ${code}`,
                        sink: `global.Function`,
                        baseScore: 50,
                        tainted: true
                    });
                }
            }
            return Reflect.construct(target, args, newTarget);
        }
    });

    // 3. Hook VM module for dynamic execution
    Hook(['vm'], (exports: any) => {
        const methods = ['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction'];
        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                const code = typeof args[0] === 'string' ? args[0] : '';
                const ctx = getTaintContext();
                if (code && ctx) {
                    const taintCheck = ctx.isTainted(code);
                    if (taintCheck.tainted) {
                        engine.evaluate(ctx, {
                            attack: 'Remote Code Execution',
                            payload: `vm.${method}: ${code}`,
                            sink: `vm.${method}`,
                            baseScore: 50,
                            tainted: true
                        });
                    }
                }
                return original.apply(this, args);
            };
            exports[method].__shield_rasp_hooked = true;
        });
        return exports;
    });
}
