const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupSqlHooks(engine: DetectionEngine) {
    // We hook pg, mysql, and mysql2. Note: we use require-in-the-middle to avoid 
    // redefinition errors on read-only exports.
    Hook(['pg', 'mysql', 'mysql2'], (exports: any, name: string) => {

        const wrapQuery = (original: any) => {
            if (!original || original.__shield_rasp_hooked) return original;
            const wrapped = function (this: any, ...args: any[]) {
                const query = typeof args[0] === 'string' ? args[0] : (args[0]?.text || args[0]?.sql || '');
                const ctx = getTaintContext();

                if (query && ctx) {
                    const taintCheck = ctx.isTainted(query);
                    // Check for common SQLi patterns in the query string
                    const sqliPattern = /UNION\s+SELECT|SLEEP\s*\(|OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?|DROP\s+TABLE|--|#|ALTER\s+TABLE/i;
                    const isDangerous = sqliPattern.test(query);

                    if (isDangerous || taintCheck.tainted) {
                        engine.evaluate(ctx, {
                            attack: 'SQL Injection',
                            payload: query,
                            sink: `${name}.query`,
                            baseScore: isDangerous ? 50 : 20,
                            tainted: taintCheck.tainted
                        });
                    }
                }
                return original.apply(this, args);
            };
            wrapped.__shield_rasp_hooked = true;
            return wrapped;
        };

        if (name === 'pg') {
            // Hook pg Client and Pool
            const proto = exports.Client?.prototype;
            if (proto && proto.query) proto.query = wrapQuery(proto.query);
            const poolProto = exports.Pool?.prototype;
            if (poolProto && poolProto.query) poolProto.query = wrapQuery(poolProto.query);
        } else if (name === 'mysql' || name === 'mysql2') {
            // Hook Connection and Pool
            const wrapMethods = (obj: any) => {
                if (obj.query) obj.query = wrapQuery(obj.query);
                if (obj.execute) obj.execute = wrapQuery(obj.execute);
            };

            const originalCreateConnection = exports.createConnection;
            if (originalCreateConnection) {
                exports.createConnection = function (...args: any[]) {
                    const conn = originalCreateConnection.apply(this, args);
                    wrapMethods(conn);
                    return conn;
                };
            }
            const originalCreatePool = exports.createPool;
            if (originalCreatePool) {
                exports.createPool = function (...args: any[]) {
                    const pool = originalCreatePool.apply(this, args);
                    wrapMethods(pool);
                    return pool;
                };
            }
        }
        return exports;
    });
}
