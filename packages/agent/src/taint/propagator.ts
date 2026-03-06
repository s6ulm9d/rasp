import { getTaintContext, isTainted, TaintLabel } from './context';

export function propagateTaint(source: any, dest: any, op: string) {
  const ctx = getTaintContext();
  if (!ctx || !source || !dest) return;
  if (typeof source !== 'object' || typeof dest !== 'object') return;

  if (isTainted(source)) {
    const parentLabel = ctx.taintedObjects.get(source)!;
    ctx.taintedObjects.set(dest, {
      sources: [...parentLabel.sources],
      path: [...parentLabel.path, op],
      timestamp: Date.now()
    });
  }
}

// In a real V8 implementation, we would patch String.prototype methods
// and the '+' operator via bytecode instrumentation or AST rewriting.