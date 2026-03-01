const { Hook } = require('require-in-the-middle');
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectSqlInjection } from '../detection/sql';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookPg(config: AgentConfig, telemetry: TelemetryClient) {
    Hook(['pg'], (exports: any) => {
        if (!exports.Client || !exports.Client.prototype) return exports;

        const originalQuery = exports.Client.prototype.query;
        if (originalQuery && !originalQuery.__shield_rasp_hooked) {
            const wrapper = function (this: any, ...args: any[]) {
                const start = performance.now();
                const hookId = 'pg.query';
                if (globalCircuitBreaker.isHookDisabled(hookId)) return originalQuery.apply(this, args as any);

                try {
                    const sql = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].text ? args[0].text : '');
                    if (sql) {
                        const ctx = getTaintContext();
                        const result = detectSqlInjection(sql, ctx);
                        if (result.matched) {
                            telemetry.sendEvent(result);
                            if (result.blocked && config.mode === 'protect') {
                                throw new RASPBlockError(result);
                            }
                        }
                    }
                } catch (e: any) {
                    if (e instanceof RASPBlockError) throw e;
                } finally {
                    globalCircuitBreaker.record(hookId, performance.now() - start);
                }
                return originalQuery.apply(this, args as any);
            };
            (wrapper as any).__shield_rasp_hooked = true;
            exports.Client.prototype.query = wrapper;
        }
        return exports;
    });
}
