import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';
import { isTainted } from '../taint/context';
import * as vm from 'vm';
import * as shimmer from 'shimmer';

export function hookDynamicExc(config: AgentConfig, telemetry: TelemetryClient) {
    if (!config.protections.rce) return;

    // 1. Hook global eval
    const originalEval = global.eval;
    global.eval = function (code: string) {
        if (typeof code === 'string' && isTainted(code)) {
            const result = {
                blocked: true,
                matched: true,
                attack_type: 'Remote Code Execution',
                attack_subtype: 'Unsafe Eval',
                severity: 'critical',
                confidence: 1.0,
                cwe: 'CWE-94',
                payload: code.substring(0, 500),
                timestamp: Date.now()
            };

            telemetry.sendEvent(result);
            if (config.mode === 'block') {
                throw new RASPBlockError(result);
            }
        }
        return originalEval.apply(this, [code]);
    };

    // 2. Hook Function constructor
    const originalFunction: any = global.Function;
    const FunctionWrapper = function (this: any, ...args: string[]) {
        for (const arg of args) {
            if (typeof arg === 'string' && isTainted(arg)) {
                const result = {
                    blocked: true,
                    matched: true,
                    attack_type: 'Remote Code Execution',
                    attack_subtype: 'Dynamic Function Constructor',
                    severity: 'critical',
                    confidence: 1.0,
                    cwe: 'CWE-94',
                    payload: args.join(', ').substring(0, 500),
                    timestamp: Date.now()
                };

                telemetry.sendEvent(result);
                if (config.mode === 'block') {
                    throw new RASPBlockError(result);
                }
            }
        }
        return originalFunction.apply(this, args);
    } as any;

    FunctionWrapper.prototype = originalFunction.prototype;
    global.Function = FunctionWrapper;

    // 3. Hook VM module
    shimmer.wrap(vm, 'runInContext', wrapVmMethod);
    shimmer.wrap(vm, 'runInNewContext', wrapVmMethod);
    shimmer.wrap(vm, 'runInThisContext', wrapVmMethod);
    shimmer.wrap(vm, 'Script', (original: any) => {
        return function (this: any, code: string, options: any) {
            checkCode(code, 'VM Script Compilation');
            return new (original as any)(code, options);
        }
    });

    function wrapVmMethod(original: any) {
        return function (this: any, code: string, ...args: any[]) {
            checkCode(code, 'VM Execution');
            return original.apply(this, [code, ...args]);
        };
    }

    function checkCode(code: string, subtype: string) {
        if (typeof code === 'string' && isTainted(code)) {
            const result = {
                blocked: true,
                matched: true,
                attack_type: 'Remote Code Execution',
                attack_subtype: subtype,
                severity: 'critical',
                confidence: 1.0,
                cwe: 'CWE-94',
                payload: code.substring(0, 500),
                timestamp: Date.now()
            };

            telemetry.sendEvent(result);
            if (config.mode === 'block') {
                throw new RASPBlockError(result);
            }
        }
    }
}
