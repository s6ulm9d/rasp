const { Hook } = require('require-in-the-middle');
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectCmdInjection } from '../detection/cmd';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookChildProcess(config: AgentConfig, telemetry: TelemetryClient) {
    if (!config.protections.cmd_injection) return;

    Hook(['child_process'], (exports: any) => {
        const methods = ['exec', 'spawn', 'execFile', 'spawnSync', 'execSync', 'execFileSync'];

        methods.forEach(method => {
            const original = exports[method];
            if (original && !original.__shield_rasp_hooked) {
                const wrapper = function (this: any, ...args: any[]) {
                    const start = performance.now();
                    const hookId = `child_process.${method}`;
                    if (globalCircuitBreaker.isHookDisabled(hookId)) return original.apply(this, args as any);

                    try {
                        const command = Array.isArray(args[0]) ? args[0].join(' ') : args[0];
                        if (typeof command === 'string') {
                            const result = detectCmdInjection(command);
                            if (result.matched) {
                                telemetry.sendEvent(result);
                                if (result.blocked && config.mode === 'block') {
                                    throw new RASPBlockError(result);
                                }
                            }
                        }
                    } catch (e: any) {
                        if (e instanceof RASPBlockError) throw e;
                    } finally {
                        globalCircuitBreaker.record(hookId, performance.now() - start);
                    }
                    return original.apply(this, args as any);
                };
                (wrapper as any).__shield_rasp_hooked = true;
                exports[method] = wrapper;
            }
        });

        return exports;
    });
}

