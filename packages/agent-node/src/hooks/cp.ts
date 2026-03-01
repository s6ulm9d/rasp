const { Hook } = require('require-in-the-middle');
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectCmdInjection } from '../detection/cmd';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookChildProcess(config: AgentConfig, telemetry: TelemetryClient) {
    Hook(['child_process'], (exports: any) => {
        const originalExec = exports.exec;

        if (originalExec && !originalExec.__shield_rasp_hooked) {
            // Function expression without assigning to a block-scoped variable first
            const wrapper = function (this: any, ...args: any[]) {
                const start = performance.now();
                const hookId = 'child_process.exec';
                if (globalCircuitBreaker.isHookDisabled(hookId)) return originalExec.apply(this, args as any);

                try {
                    const command = args[0];
                    const result = detectCmdInjection(command);

                    if (result.matched) {
                        telemetry.sendEvent(result);
                        if (result.blocked && config.mode === 'protect') {
                            throw new RASPBlockError(result);
                        }
                    }
                } catch (e: any) {
                    if (e instanceof RASPBlockError) throw e;
                } finally {
                    globalCircuitBreaker.record(hookId, performance.now() - start);
                }
                return originalExec.apply(this, args as any);
            };

            (wrapper as any).__shield_rasp_hooked = true;

            try {
                exports.exec = wrapper;
                return exports;
            } catch (e) {
                return new Proxy(exports, {
                    get(target, prop, receiver) {
                        if (prop === 'exec') return wrapper;
                        const value = Reflect.get(target, prop, receiver);
                        return typeof value === 'function' ? value.bind(target) : value;
                    }
                });
            }
        }
        return exports;
    });
}
