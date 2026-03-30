const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

import { dnsGuard } from '../dnsGuard';

export function setupSsrfHooks(engine: DetectionEngine) {
    // 1. DNS Resolution Hooking
    // Catches SSRF evasion techniques that rely on routing domains to internal IPs
    Hook(['dns'], (exports: any) => {
        const originalLookup = exports.lookup;
        if (!originalLookup || originalLookup.__shield_rasp_hooked) return exports;

        exports.lookup = function (this: any, ...args: any[]) {
            const hostname = typeof args[0] === 'string' ? args[0] : '';
            const ctx = getTaintContext();

            // If we are fulfilling a DNS lookup inside a tainted HTTP transaction context
            if (hostname && ctx) {
                const originalCallback = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null;

                if (originalCallback) {
                    // Wrap the callback to inspect the resolved IP address dynamically
                    args[args.length - 1] = function (err: any, address: string, family: number) {
                        if (!err && address) {
                            dnsGuard.trackCallbackResolution(hostname, address);
                            const isInternal = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(address);
                            if (isInternal) {
                                engine.evaluate(ctx, {
                                    attack: 'SSRF',
                                    payload: `DNS Resolved internal IP: ${hostname} -> ${address}`,
                                    sink: `dns.lookup`,
                                    baseScore: 80,
                                    tainted: true // If we are doing a lookup for an external URL that suddenly hits internal, heavily penalize
                                });
                            }
                        }
                        return originalCallback.apply(this, arguments);
                    };
                }
            }
            return originalLookup.apply(this, args);
        };
        exports.lookup.__shield_rasp_hooked = true;
        return exports;
    });

    // 2. HTTP/HTTPS layer hook for initial string analysis (immediate drops for basic payloads)
    Hook(['http', 'https'], (exports: any, name: string) => {
        const originalRequest = exports.request;
        if (!originalRequest || originalRequest.__shield_rasp_hooked) return exports;

        exports.request = function (this: any, ...args: any[]) {
            const urlArg = args[0];
            const ctx = getTaintContext();

            let urlStr = '';
            if (typeof urlArg === 'string') {
                urlStr = urlArg;
            } else if (urlArg && typeof urlArg === 'object') {
                urlStr = urlArg.href || `${urlArg.protocol || 'http:'}//${urlArg.host || urlArg.hostname}${urlArg.path || '/'}`;
            }

            if (urlStr && ctx) {
                const taintCheck = ctx.isTainted(urlStr);

                // Static IP/Host check pre-DNS
                const isInternal = /^(https?:\/\/)?(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(urlStr) ||
                    /localhost|metadata\.google\.internal|instance-data|0x7f/.test(urlStr);

                if (isInternal || taintCheck.tainted) {
                    engine.evaluate(ctx, {
                        attack: 'SSRF',
                        payload: `Attempted access to host: ${urlStr}`,
                        sink: `${name}.request`,
                        baseScore: isInternal ? 50 : 20,
                        tainted: taintCheck.tainted
                    });
                }
            }
            return originalRequest.apply(this, args);
        };
        exports.request.__shield_rasp_hooked = true;

        if (exports.get) {
            const originalGet = exports.get;
            exports.get = function (this: any, ...args: any[]) {
                return originalGet.apply(this, args);
            };
        }
        return exports;
    });
}
