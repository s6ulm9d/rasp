import * as fs from 'fs';
import { globalCircuitBreaker } from '../agent/circuit-breaker';
import { detectPathTraversal } from '../detection/path';
import { getTaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';
import { RASPBlockError } from './child-process';

export function hookFs(config: AgentConfig, telemetry: TelemetryClient) {
  const originalReadFile = fs.readFile;
  (fs as any).readFile = function(...args: any[]) {
    const start = performance.now();
    const hookId = 'fs.readFile';
    if (globalCircuitBreaker.isHookDisabled(hookId)) return originalReadFile.apply(this, args as any);

    try {
      const pathArg = args[0] as string;
      const ctx = getTaintContext();
      const result = detectPathTraversal(pathArg, ctx);
      if (result.blocked) {
        telemetry.sendEvent(result);
        if (config.mode === 'protect') throw new RASPBlockError(result);
      }
      if (result.matched) telemetry.sendEvent(result);
    } catch (e: any) {
      if (e instanceof RASPBlockError) throw e;
    } finally {
      globalCircuitBreaker.record(hookId, performance.now() - start);
    }
    return originalReadFile.apply(this, args as any);
  };
}