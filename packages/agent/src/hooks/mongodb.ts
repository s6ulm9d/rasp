const { Hook } = require('require-in-the-middle');
import { getTaintContext, isTainted } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookMongo(config: AgentConfig, telemetry: TelemetryClient) {
    if (!config.protections.sqli) return; // For NoSQLi we use the same toggle conceptually

    Hook(['mongodb'], (exports: any) => {
        if (!exports.Collection || !exports.Collection.prototype) return exports;

        const methods = ['find', 'findOne', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'aggregate'];

        for (const method of methods) {
            const original = exports.Collection.prototype[method];
            if (original && !original.__shield_rasp_hooked) {
                const wrapper = function (this: any, ...args: any[]) {
                    const filter = args[0];
                    if (filter && typeof filter === 'object') {
                        // Look for NoSQL injection tokens like $where, $gt, $ne etc in tainted data
                        const result = detectNoSqlInjection(filter);
                        if (result.matched) {
                            telemetry.sendEvent(result);
                            if (result.blocked && config.mode === 'block') {
                                throw new RASPBlockError(result);
                            }
                        }
                    }
                    return original.apply(this, args);
                };
                (wrapper as any).__shield_rasp_hooked = true;
                exports.Collection.prototype[method] = wrapper;
            }
        }

        return exports;
    });
}

function detectNoSqlInjection(obj: any): any {
    const jsonString = JSON.stringify(obj);

    // Check if the query itself is tainted or contains dangerous operators in tainted parts
    if (isTainted(jsonString)) {
        const dangerousOperators = /\$where|\$gt|\$ne|\$regex|\$expr/i;
        if (dangerousOperators.test(jsonString)) {
            return {
                blocked: true,
                matched: true,
                attack_type: 'NoSQL Injection',
                confidence: 0.90,
                cwe: 'CWE-943',
                payload: jsonString.substring(0, 500),
                timestamp: Date.now()
            };
        }
    }

    return { matched: false };
}
