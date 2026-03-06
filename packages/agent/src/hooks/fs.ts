const { Hook } = require('require-in-the-middle');
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectPathTraversal } from '../detection/path';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';
import { detectSSRF } from '../detection/ssrf';

export function hookFs(config: AgentConfig, telemetry: TelemetryClient) {
  if (!config.protections.path_traversal) return;

  Hook(['fs'], (exports: any) => {
    const fsMethods = ['readFile', 'writeFile', 'open', 'createReadStream'];

    fsMethods.forEach(method => {
      const original = exports[method];
      if (original && !original.__shield_rasp_hooked) {
        const wrapper = function (this: any, ...args: any[]) {
          const start = performance.now();
          const hookId = `fs.${method}`;
          if (globalCircuitBreaker.isHookDisabled(hookId)) return original.apply(this, args as any);

          try {
            const pathArg = args[0] as string;
            if (typeof pathArg === 'string') {
              const ctx = getTaintContext();
              const result = detectPathTraversal(pathArg, ctx);
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
