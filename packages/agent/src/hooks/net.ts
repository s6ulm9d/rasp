const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupNetHooks(engine: any) {
    // 1. Hook raw TCP sockets
    Hook(['net'], (exports: any) => {
        const methods = ['connect', 'createConnection'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                try {
                    SinkMonitor.validateExecution(`net.${method}`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'SSRF', String(args[0]), `net.${method}`, 100);
                        throw e;
                    }
                }
                return original.apply(this, args);
            };
            exports[method].__shield_rasp_hooked = true;
        });
        return exports;
    });

    // 2. Hook TLS
    Hook(['tls'], (exports: any) => {
        const original = exports.connect;
        if (!original || original.__shield_rasp_hooked) return exports;

        exports.connect = function (this: any, ...args: any[]) {
            try {
                SinkMonitor.validateExecution('tls.connect', ...args);
            } catch (e: any) {
                if (e.name === 'SecurityBlockException') {
                    const ctx = getTaintContext();
                    if (ctx) engine.reportThreat(ctx, 'SSRF', String(args[0]), 'tls.connect', 100);
                    throw e;
                }
            }
            return original.apply(this, args);
        };
        exports.connect.__shield_rasp_hooked = true;
        return exports;
    });
}
