const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

// global __CANARY__ configuration (Memory Scraping detection)
(global as any).__SHIELDRASP_CANARY_DO_NOT_TOUCH__ = "CAFEBABE_9f8a7b_MEMORY_SCRAPE_TRAP";

export function setupBehavioralHooks(engine: DetectionEngine) {

    // 1. UDP Data Exfiltration Pipeline Guard
    Hook(['dgram'], (exports: any) => {
        if (!exports.Socket) return exports;
        
        const originalSend = exports.Socket.prototype.send;
        if (originalSend.__shield_rasp_hooked) return exports;

        exports.Socket.prototype.send = function (this: any, ...args: any[]) {
            const ctx = getTaintContext();
            
            // UDP is largely unused in typical node web servers. High-frequency UDP
            // usually signifies beaconing malware or CNC/DNS exfil.
            if (ctx) {
                ctx.requestMeta.flow.push("udp_outbound");
                ctx.metrics.outboundUDP++;

                if (ctx.metrics.outboundUDP > 5) {
                    engine.evaluate(ctx, {
                        attack: 'Anomaly (Network)',
                        payload: `Excessive UDP Exfiltration Detected. Buffer: ${args[0]?.toString().substring(0, 50)}`,
                        sink: `dgram.Socket.send`,
                        baseScore: 80,
                        tainted: false
                    });
                }
            }

            return originalSend.apply(this, args);
        };
        exports.Socket.prototype.send.__shield_rasp_hooked = true;
        return exports;
    });

    // 2. HTTP/2 Hooking (Modern Proxy/Smuggling evasion mapping)
    Hook(['http2'], (exports: any) => {
        const originalConnect = exports.connect;
        if (!originalConnect || originalConnect.__shield_rasp_hooked) return exports;

        exports.connect = function (this: any, ...args: any[]) {
            const ctx = getTaintContext();
            const authority = args[0];

            if (ctx && typeof authority === 'string') {
                ctx.requestMeta.flow.push("http2_outbound");
                
                const taintCheck = ctx.isTainted(authority);
                const isInternal = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(authority) ||
                /localhost|metadata\.google\.internal|instance-data|0x7f/.test(authority);

                if (isInternal || taintCheck.tainted) {
                    engine.evaluate(ctx, {
                        attack: 'SSRF',
                        payload: `Secure HTTP/2 outbound connection to host: ${authority}`,
                        sink: `http2.connect`,
                        baseScore: isInternal ? 80 : 30,
                        tainted: taintCheck.tainted
                    });
                }
            }

            return originalConnect.apply(this, args);
        };
        exports.connect.__shield_rasp_hooked = true;
        return exports;
    });

    // 3. Module layer natively tracking .node binary exploitation
    // Attackers loading malicious shared objects to bypass v8 protections
    const Module = require('module');
    const originalRequire = Module.prototype.require;

    Module.prototype.require = function (this: any, path: string) {
        if (path.endsWith('.node')) {
            const ctx = getTaintContext();
            if (ctx) {
                engine.evaluate(ctx, {
                    attack: 'Anomaly (Runtime)',
                    payload: `Native module dynamically loaded at runtime: ${path}`,
                    sink: `module.require`,
                    baseScore: 60, // Warn level: usually .node are pre-loaded at boot
                    tainted: false
                });
            } else {
                // If loaded outside context, it might be boot-up, so we don't alert heavily 
                // unless we want a global strict lock.
            }
        }
        return originalRequire.apply(this, arguments);
    };

}
