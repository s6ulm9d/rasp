const { Hook } = require('require-in-the-middle');
import { getTaintContext } from '../taint/context';
import { SinkMonitor } from '../analyzer/SinkMonitor';

export function setupSqlHooks(engine: any) {
    Hook(['pg', 'mysql', 'mysql2'], (exports: any, name: string) => {

        const wrapQuery = (original: any) => {
            if (!original || original.__shield_rasp_hooked) return original;
            const wrapped = function (this: any, ...args: any[]) {
                try {
                    SinkMonitor.validateExecution(`${name}.query`, ...args);
                } catch (e: any) {
                    if (e.name === 'SecurityBlockException') {
                        const ctx = getTaintContext();
                        if (ctx) engine.reportThreat(ctx, 'SQL Injection', String(args[0]), `${name}.query`, 100);
                        throw e;
                    }
                }
                return original.apply(this, args);
            };
            wrapped.__shield_rasp_hooked = true;
            return wrapped;
        };

        if (name === 'pg') {
            const proto = exports.Client?.prototype;
            if (proto && proto.query) proto.query = wrapQuery(proto.query);
            const poolProto = exports.Pool?.prototype;
            if (poolProto && poolProto.query) poolProto.query = wrapQuery(poolProto.query);
        } else if (name === 'mysql' || name === 'mysql2') {
            // Hook connection objects recursively
            const originalCreateConnection = exports.createConnection;
            if (originalCreateConnection) {
                exports.createConnection = function (...args: any[]) {
                    const conn = originalCreateConnection.apply(this, args);
                    if (conn.query) conn.query = wrapQuery(conn.query);
                    if (conn.execute) conn.execute = wrapQuery(conn.execute);
                    return conn;
                };
            }
        }
        return exports;
    });
}
