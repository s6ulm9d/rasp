const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupCmdHooks(engine: any) {
    Hook(['child_process'], (exports: any) => {
        const methods = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                try {
                    SinkMonitor.validateExecution(`child_process.${method}`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        // Report to engine for logging before blocking
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'Command Injection', String(args[0]), `child_process.${method}`, 100);
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
