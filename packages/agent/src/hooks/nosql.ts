const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupNoSqlHooks(engine: DetectionEngine) {
    Hook(['mongodb'], (exports: any) => {
        if (!exports.Collection || !exports.Collection.prototype) return exports;

        const methods = ['find', 'findOne', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'aggregate'];

        methods.forEach(method => {
            const original = exports.Collection.prototype[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports.Collection.prototype[method] = function (this: any, ...args: any[]) {
                const query = args[0];
                const ctx = getTaintContext();

                if (query && typeof query === 'object' && ctx) {
                    const jsonStr = JSON.stringify(query);
                    const taintCheck = ctx.isTainted(jsonStr);

                    // Check for dangerous NoSQL operators in tainted data
                    const dangerousOperators = /\$where|\$regex|\$function|\$expr|\$ne|\$gt/i;
                    const hasDangerous = dangerousOperators.test(jsonStr);

                    if (hasDangerous || taintCheck.tainted) {
                        engine.evaluate(ctx, {
                            attack: 'NoSQL Injection',
                            payload: jsonStr,
                            sink: `mongodb.${method}`,
                            baseScore: hasDangerous ? 50 : 20,
                            tainted: taintCheck.tainted
                        });
                    }
                }
                return original.apply(this, args);
            };
            exports.Collection.prototype[method].__shield_rasp_hooked = true;
        });

        return exports;
    });
}
