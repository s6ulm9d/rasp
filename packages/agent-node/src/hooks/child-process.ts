import { exec, spawn, execFile, fork } from 'child_process';
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectCmdInjection } from '../detection/cmd';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';

export class RASPBlockError extends Error {
    public result: any;
    constructor(result: any) {
        super(`ShieldRASP Blocked: ${result.attack_type}`);
        this.name = 'RASPBlockError';
        this.result = result;
    }
}

export function hookChildProcess(config: AgentConfig, telemetry: TelemetryClient) {
    const Module = require('module');
    const originalExec = exec;
    const originalSpawn = spawn;

    // @ts-ignore
    require('child_process').exec = function (...args: any[]) {
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

    // Skip other hooks for now to keep it lightweight, but can be expanded
}
