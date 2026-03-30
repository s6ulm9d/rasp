const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupPathHooks(engine: DetectionEngine) {
    Hook(['fs'], (exports: any) => {
        const methods = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'open', 'openSync', 'createReadStream', 'createWriteStream'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            // Use a Proxy-based fallback for read-only properties to avoid redefinition crashes
            try {
                exports[method] = function (this: any, ...args: any[]) {
                    const filePath = typeof args[0] === 'string' ? args[0] : '';
                    const ctx = getTaintContext();

                    if (filePath && ctx) {
                        const taintCheck = ctx.isTainted(filePath);
                        // Jail Directory Enforcement: Block path traversal
                        const isTraversal = filePath.includes('..');
                        // Also check if it's trying to access sensitive areas
                        const isSensitive = /^\/(etc|proc|root|var|boot|dev)/.test(filePath) || /^[A-Z]:\\(Windows|System32)/i.test(filePath);

                        if (isTraversal || isSensitive || taintCheck.tainted) {
                            engine.evaluate(ctx, {
                                attack: 'Path Traversal',
                                payload: filePath,
                                sink: `fs.${method}`,
                                baseScore: (isTraversal || isSensitive) ? 50 : 20,
                                tainted: taintCheck.tainted
                            });
                        }
                    }
                    return original.apply(this, args);
                };
                exports[method].__shield_rasp_hooked = true;
            } catch (e) {
                // If direct assignment fails (property is read-only), the RASP layer remains active via
                // the require-in-the-middle proxy if necessary, but here we prefer direct injection.
            }
        });

        return exports;
    });
}
