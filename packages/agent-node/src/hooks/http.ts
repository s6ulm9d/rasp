const { Hook } = require('require-in-the-middle');
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectSSRF } from '../detection/ssrf';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from '../errors';

export function hookHttp(config: AgentConfig, telemetry: TelemetryClient) {
  Hook(['http', 'https'], (exports: any, name: string) => {
    const originalRequest = exports.request;

    if (originalRequest && !originalRequest.__shield_rasp_hooked) {
      const wrappedNodeHttpRequest = function (this: any, ...args: any[]) {
        const start = performance.now();
        const hookId = `${name}.request`;
        if (globalCircuitBreaker.isHookDisabled(hookId)) return originalRequest.apply(this, args as any);

        try {
          const urlArg = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].href ? args[0].href : '');
          if (urlArg) {
            const ctx = getTaintContext();
            const result = detectSSRF(urlArg, ctx);
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
        return originalRequest.apply(this, args as any);
      };

      (wrappedNodeHttpRequest as any).__shield_rasp_hooked = true;

      try {
        exports.request = wrappedNodeHttpRequest;
        return exports;
      } catch (e) {
        return new Proxy(exports, {
          get(target, prop, receiver) {
            if (prop === 'request') return wrappedNodeHttpRequest;
            const value = Reflect.get(target, prop, receiver);
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      }
    }
    return exports;
  });
}