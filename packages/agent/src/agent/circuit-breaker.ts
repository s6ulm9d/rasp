export class CircuitBreaker {
  private timings: Map<string, number[]> = new Map();
  private disabledHooks: Set<string> = new Set();
  private readonly THRESHOLD_MS = 0.5;
  private readonly SAMPLES = 100;

  record(hookId: string, durationMs: number) {
    if (this.disabledHooks.has(hookId)) return;
    
    let stats = this.timings.get(hookId);
    if (!stats) {
      stats = [];
      this.timings.set(hookId, stats);
    }
    
    stats.push(durationMs);
    if (stats.length > this.SAMPLES) {
      stats.shift();
    }

    if (stats.length === this.SAMPLES) {
      const avg = stats.reduce((a, b) => a + b, 0) / this.SAMPLES;
      if (avg > this.THRESHOLD_MS) {
        this.disableHook(hookId, avg);
      }
    }
  }

  private disableHook(hookId: string, avgDuration: number) {
    this.disabledHooks.add(hookId);
    console.warn(`[ShieldRASP] Circuit Breaker: Auto-disabled hook '${hookId}' (avg lag: ${avgDuration.toFixed(2)}ms)`);
  }

  isHookDisabled(hookId: string): boolean {
    return this.disabledHooks.has(hookId);
  }
}

export const globalCircuitBreaker = new CircuitBreaker();