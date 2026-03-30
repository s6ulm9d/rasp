const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

import { dnsGuard } from '../dnsGuard';

export function setupNetHooks(engine: DetectionEngine) {
    // Hook raw TCP sockets - Neutralizes Protocol-Agnostic SSRF (Redis, FTP, SMTP, raw reverse shells)
    Hook(['net'], (exports: any) => {
        const methods = ['connect', 'createConnection'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                const ctx = getTaintContext();
                
                let targetHost = '';
                if (typeof args[0] === 'object' && args[0] !== null) {
                    targetHost = args[0].host || args[0].hostname || '';
                } else if (typeof args[1] === 'string') {
                    targetHost = args[1];
                }

                if (targetHost && ctx) {
                    console.log(`[HOOK] net.${method} triggered against: ${targetHost}`);
                    ctx.requestMeta.flow.push(`tcp_connect:${targetHost}`);
                    
                    // DNS Rebinding / Enforcement Check
                    const taintCheck = ctx.isTainted(targetHost);
                    const isInternal = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(targetHost) ||
                    /localhost|metadata\.google\.internal|instance-data|0x7f/.test(targetHost);

                    if (isInternal || taintCheck.tainted) {
                        engine.evaluate(ctx, {
                            attack: 'SSRF',
                            payload: `Raw TCP outbound connection to host: ${targetHost}`,
                            sink: `net.${method}`,
                            baseScore: isInternal ? 80 : 30, 
                            tainted: taintCheck.tainted
                        });
                    }

                    // Strict DNS lock enforcement
                    // We check if this resolved IP matched a pre-flight DNS lock to defeat TOCTOU attacks
                    // The socket itself will resolve it independently again, but if the pre-flight IP lists don't match or the hostname rebounds quickly, we kill the socket.
                    if (args[0] && typeof args[0] === 'object') {
                        // Enforce DNS Lock if it's attempting to dial directly to an IP or a resolved host
                        const ipToDial = targetHost; 
                        if (!dnsGuard.verify(targetHost, ipToDial)) {
                            engine.evaluate(ctx, {
                                attack: 'SSRF',
                                payload: `DNS Rebinding / TOCTOU evasion Detected on host: ${targetHost}`,
                                sink: `net.${method}`,
                                baseScore: 99, 
                                tainted: false
                            });
                        }
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
