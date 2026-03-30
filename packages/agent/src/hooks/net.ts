const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupNetHooks(engine: DetectionEngine) {
    // Hook raw TCP sockets - Neutralizes Protocol-Agnostic SSRF (Redis, FTP, SMTP, raw reverse shells)
    Hook(['net'], (exports: any) => {
        const methods = ['connect', 'createConnection'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                const ctx = getTaintContext();

                // Parse args since net.connect is highly variadic 
                // net.connect(port, host), net.connect(options), net.connect(path)
                let targetHost = '';
                if (typeof args[0] === 'object' && args[0] !== null) {
                    targetHost = args[0].host || args[0].hostname || '';
                } else if (typeof args[1] === 'string') {
                    targetHost = args[1];
                }

                if (targetHost && ctx) {
                    const taintCheck = ctx.isTainted(targetHost);
                    const isInternal = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(targetHost) ||
                        /localhost|metadata\.google\.internal|instance-data|0x7f/.test(targetHost);

                    if (isInternal || taintCheck.tainted) {
                        engine.evaluate(ctx, {
                            attack: 'SSRF',
                            payload: `Raw TCP outbound connection to host: ${targetHost}`,
                            sink: `net.${method}`,
                            baseScore: isInternal ? 80 : 30, // Extremely suspicious if raw socket goes to metadata or localhost
                            tainted: taintCheck.tainted
                        });
                    }
                }
                return original.apply(this, args);
            };
            exports[method].__shield_rasp_hooked = true;
        });
        return exports;
    });

    // Hook TLS symmetrically
    Hook(['tls'], (exports: any) => {
        const original = exports.connect;
        if (!original || original.__shield_rasp_hooked) return exports;

        exports.connect = function (this: any, ...args: any[]) {
            const ctx = getTaintContext();
            let targetHost = '';
            if (typeof args[0] === 'object' && args[0] !== null) {
                targetHost = args[0].host || args[0].servername || args[0].hostname || '';
            } else if (typeof args[1] === 'string') {
                targetHost = args[1];
            }

            if (targetHost && ctx) {
                const taintCheck = ctx.isTainted(targetHost);
                const isInternal = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(targetHost) ||
                    /localhost|metadata\.google\.internal|instance-data|0x7f/.test(targetHost);

                if (isInternal || taintCheck.tainted) {
                    engine.evaluate(ctx, {
                        attack: 'SSRF',
                        payload: `Secure TLS outbound connection to host: ${targetHost}`,
                        sink: `tls.connect`,
                        baseScore: isInternal ? 80 : 30,
                        tainted: taintCheck.tainted
                    });
                }
            }
            return original.apply(this, args);
        };
        exports.connect.__shield_rasp_hooked = true;
        return exports;
    });
}
