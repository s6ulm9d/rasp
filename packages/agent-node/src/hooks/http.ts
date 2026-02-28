import * as http from 'http';
import * as https from 'https';
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectSSRF } from '../detection/ssrf';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from './child-process';

export function hookHttp(config: AgentConfig, telemetry: TelemetryClient) {
  const originalRequest = http.request;
  
  (http as any).request = function(...args: any[]) {
    const start = performance.now();
    const hookId = 'http.request';
    if (globalCircuitBreaker.isHookDisabled(hookId)) return originalRequest.apply(this, args as any);

    try {
      const urlArg = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].href ? args[0].href : '');
      if (urlArg) {
        const ctx = getTaintContext();
        const result = detectSSRF(urlArg, ctx);
        if (result.blocked) {
          telemetry.sendEvent(result);
          if (config.mode === 'protect') throw new RASPBlockError(result);
        }
        if (result.matched) telemetry.sendEvent(result);
      }
    } catch (e: any) {
      if (e instanceof RASPBlockError) throw e;
    } finally {
      globalCircuitBreaker.record(hookId, performance.now() - start);
    }
    return originalRequest.apply(this, args as any);
  };
}