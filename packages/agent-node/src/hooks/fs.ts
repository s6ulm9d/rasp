const { Hook } = require('require-in-the-middle');
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectPathTraversal } from '../detection/path';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookFs(config: AgentConfig, telemetry: TelemetryClient) {
  Hook(['fs'], (exports: any) => {
    const originalReadFile = exports.readFile;

    if (originalReadFile && !originalReadFile.__shield_rasp_hooked) {
      const wrappedNodeFsReadFile = function (this: any, ...args: any[]) {
        const start = performance.now();
        const hookId = 'fs.readFile';
        if (globalCircuitBreaker.isHookDisabled(hookId)) return originalReadFile.apply(this, args as any);

        try {
          const pathArg = args[0] as string;
          const ctx = getTaintContext();
          const result = detectPathTraversal(pathArg, ctx);
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
        return originalReadFile.apply(this, args as any);
      };

      (wrappedNodeFsReadFile as any).__shield_rasp_hooked = true;

      try {
        exports.readFile = wrappedNodeFsReadFile;
        return exports;
      } catch (e) {
        return new Proxy(exports, {
          get(target, prop, receiver) {
            if (prop === 'readFile') return wrappedNodeFsReadFile;
            const value = Reflect.get(target, prop, receiver);
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      }
    }
    return exports;
  });
}