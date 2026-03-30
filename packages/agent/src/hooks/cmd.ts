const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupCmdHooks(engine: DetectionEngine) {
    Hook(['child_process'], (exports: any) => {
        const methods = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                const command = typeof args[0] === 'string' ? args[0] : '';
                const file = args[0]; // for spawn/execFile
                const ctx = getTaintContext();

                if (ctx) {
                    const checkVal = command || (typeof file === 'string' ? file : '');
                    const taintCheck = ctx.isTainted(checkVal);

                    // Detect shell metacharacters in tainted command input
                    const shellMetachars = /[|&;<>$`\(\)\n\r\\]/;
                    const hasMetachars = shellMetachars.test(checkVal);

                    if (hasMetachars || taintCheck.tainted) {
                        engine.evaluate(ctx, {
                            attack: 'Command Injection',
                            payload: checkVal,
                            sink: `child_process.${method}`,
                            baseScore: hasMetachars ? 60 : 30,
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
}
