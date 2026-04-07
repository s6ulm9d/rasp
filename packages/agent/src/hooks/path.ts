const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupPathHooks(engine: any) {
    Hook(['fs'], (exports: any) => {
        const methods = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'unlink', 'unlinkSync', 'open', 'openSync', 'createReadStream', 'createWriteStream'];

        methods.forEach(method => {
            const original = exports[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports[method] = function (this: any, ...args: any[]) {
                try {
                    SinkMonitor.validateExecution(`fs.${method}`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'Path Traversal', String(args[0]), `fs.${method}`, 100);
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
