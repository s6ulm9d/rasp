const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupRceHooks(engine: any) {
    // 1. Hook Global eval
    const originalEval = global.eval;
    (global as any).eval = function (code: string) {
        try {
            SinkMonitor.validateExecution('eval', code);
        } catch (e: any) {
            if (e.name === 'SecurityBlockException') {
                const ctx = getTaintContext();
                if (ctx) engine.reportThreat(ctx, 'RCE', code, 'eval', 100);
                throw e;
            }
        }
        return originalEval.call(this, code);
    };

    // 2. Hook Function Constructor
    const originalFunction = global.Function;
    global.Function = new Proxy(originalFunction, {
        apply(target, thisArg, args) {
            try {
                SinkMonitor.validateExecution('Function', ...args);
            } catch (e: any) {
                if (e.name === 'SecurityBlockException') {
                    const ctx = getTaintContext();
                    if (ctx) engine.reportThreat(ctx, 'RCE', args.join(' '), 'Function', 100);
                    throw e;
                }
            }
            return Reflect.apply(target, thisArg, args);
        },
        construct(target, args, newTarget) {
            try {
                SinkMonitor.validateExecution('Function', ...args);
            } catch (e: any) {
                if (e.name === 'SecurityBlockException') {
                    const ctx = getTaintContext();
                    if (ctx) engine.reportThreat(ctx, 'RCE', args.join(' '), 'Function', 100);
                    throw e;
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
                try {
                    SinkMonitor.validateExecution(`vm.${method}`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'RCE', String(args[0]), `vm.${method}`, 100);
                        throw e;
                    }
                }
                return original.apply(this, args);
            };
            exports[method].__shield_rasp_hooked = true;
        });
        return exports;
    });
}
