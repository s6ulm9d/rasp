const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupSsrfHooks(engine: any) {
    // 1. DNS Resolution Hooking
    Hook(['dns'], (exports: any) => {
        const originalLookup = exports.lookup;
        if (!originalLookup || originalLookup.__shield_rasp_hooked) return exports;

        exports.lookup = function (this: any, ...args: any[]) {
            try {
                SinkMonitor.validateExecution('dns.lookup', ...args);
            } catch (e: any) {
                if (e.name === 'SecurityBlockException') {
                    const ctx = getTaintContext();
                    if (ctx) engine.reportThreat(ctx, 'SSRF', String(args[0]), 'dns.lookup', 100);
                    throw e;
                }
            }
            return originalLookup.apply(this, args);
        };
        exports.lookup.__shield_rasp_hooked = true;
        return exports;
    });

    // 2. HTTP/HTTPS layer hook
    Hook(['http', 'https'], (exports: any, name: string) => {
        const originalRequest = exports.request;
        const methods = ['request', 'get'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                try {
                    SinkMonitor.validateExecution(`${name}.${method}`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'SSRF', String(args[0]), `${name}.${method}`, 100);
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
