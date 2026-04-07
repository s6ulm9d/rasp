const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupBehavioralHooks(engine: any) {
    // 1. UDP Data Exfiltration Pipeline Guard
    Hook(['dgram'], (exports: any) => {
        if (!exports.Socket) return exports;
        
        const originalSend = exports.Socket.prototype.send;
        if (originalSend.__shield_rasp_hooked) return exports;

        exports.Socket.prototype.send = function (this: any, ...args: any[]) {
            const ctx = getTaintContext();
            if (ctx) {
                try {
                    SinkMonitor.validateExecution('dgram.send', ...args);
                } catch (e: any) {
                   if (e.name === 'SecurityBlockException') {
                      engine.reportThreat(ctx, 'Anomaly (Network)', 'UDP exfiltration', 'dgram.send', 100);
                      throw e;
                   }
                }
            }
            return originalSend.apply(this, args);
        };
        exports.Socket.prototype.send.__shield_rasp_hooked = true;
        return exports;
    });

    // 2. HTTP/2 Hooking
    Hook(['http2'], (exports: any) => {
        const originalConnect = exports.connect;
        if (!originalConnect || originalConnect.__shield_rasp_hooked) return exports;

        exports.connect = function (this: any, ...args: any[]) {
            try {
                SinkMonitor.validateExecution('http2.connect', ...args);
            } catch (e: any) {
                if (e.name === 'SecurityBlockException') {
                    const ctx = getTaintContext();
                    if (ctx) engine.reportThreat(ctx, 'SSRF', String(args[0]), 'http2.connect', 100);
                    throw e;
                }
            }
            return originalConnect.apply(this, args);
        };
        exports.connect.__shield_rasp_hooked = true;
        return exports;
    });

    // 3. Module layer natives tracking
    const Module = require('module');
    const originalRequire = Module.prototype.require;

    Module.prototype.require = function (this: any, path: string) {
        if (path.endsWith('.node')) {
            const ctx = getTaintContext();
            if (ctx) {
                engine.reportThreat(ctx, 'Anomaly (Runtime)', path, 'module.require', 80);
            }
        }
        return originalRequire.apply(this, arguments);
    };
}
