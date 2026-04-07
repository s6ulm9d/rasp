const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupNoSqlHooks(engine: any) {
    Hook(['mongodb'], (exports: any) => {
        if (!exports.Collection || !exports.Collection.prototype) return exports;

        const methods = ['find', 'findOne', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'aggregate'];

        methods.forEach(method => {
            const original = exports.Collection.prototype[method];
            if (!original || original.__shield_rasp_hooked) return;

            exports.Collection.prototype[method] = function (this: any, ...args: any[]) {
                try {
                    SinkMonitor.validateExecution(`mongodb.${method}`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'NoSQL Injection', JSON.stringify(args[0]), `mongodb.${method}`, 100);
                        throw e;
                    }
                }
                return original.apply(this, args);
            };
            exports.Collection.prototype[method].__shield_rasp_hooked = true;
        });

        return exports;
    });
}
