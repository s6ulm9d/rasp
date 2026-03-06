const { Hook } = require('require-in-the-middle');
import { detectSqlInjection } from '../detection/sql';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookMysql(config: AgentConfig, telemetry: TelemetryClient) {
    if (!config.protections.sqli) return;

    Hook(['mysql', 'mysql2'], (exports: any) => {
        // mysql2 uses Pool/Connection prototypes
        if (exports.createConnection || exports.createPool) {
            const originalCreateConnection = exports.createConnection;
            const originalCreatePool = exports.createPool;

            if (originalCreateConnection) {
                exports.createConnection = function (...args: any[]) {
                    const conn = originalCreateConnection.apply(this, args);
                    wrapConnection(conn, config, telemetry);
                    return conn;
                };
            }
            if (originalCreatePool) {
                exports.createPool = function (...args: any[]) {
                    const pool = originalCreatePool.apply(this, args);
                    wrapConnection(pool, config, telemetry);
                    return pool;
                };
            }
        }
        return exports;
    });
}

function wrapConnection(conn: any, config: AgentConfig, telemetry: TelemetryClient) {
    if (!conn || !conn.query) return;
    const originalQuery = conn.query;
    if (originalQuery.__shield_rasp_hooked) return;

    const wrapper = function (this: any, ...args: any[]) {
        const sql = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].sql ? args[0].sql : '');
        if (sql) {
            const ctx = getTaintContext();
            const result = detectSqlInjection(sql, ctx);
            if (result.matched) {
                telemetry.sendEvent(result);
                if (result.blocked && config.mode === 'block') {
                    throw new RASPBlockError(result);
                }
            }
        }
        return originalQuery.apply(this, args);
    };
    (wrapper as any).__shield_rasp_hooked = true;
    conn.query = wrapper;

    // mysql2 also has .execute()
    if (conn.execute) {
        const originalExecute = conn.execute;
        const executeWrapper = function (this: any, ...args: any[]) {
            const sql = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].sql ? args[0].sql : '');
            if (sql) {
                const ctx = getTaintContext();
                const result = detectSqlInjection(sql, ctx);
                if (result.matched) {
                    telemetry.sendEvent(result);
                    if (result.blocked && config.mode === 'block') {
                        throw new RASPBlockError(result);
                    }
                }
            }
            return originalExecute.apply(this, args);
        };
        (executeWrapper as any).__shield_rasp_hooked = true;
        conn.execute = executeWrapper;
    }
}
