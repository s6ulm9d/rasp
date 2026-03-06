import * as path from 'path';
import { TaintContext, isTainted } from '../taint/context';

export function detectPathTraversal(targetPath: string, ctx?: TaintContext) {
  if (typeof targetPath !== 'string') return { blocked: false, matched: false };
  const tainted = ctx ? ctx.taintedObjects.has(Object(targetPath)) : isTainted(Object(targetPath));
  if (!tainted) return { blocked: false, matched: false };

  const jailDir = process.cwd();
  const normalizedPath = path.resolve(targetPath);

  if (!normalizedPath.startsWith(jailDir)) {
    return {
      blocked: true, matched: true, type: 'Path Traversal', confidence: 0.99,
      cwe: 'CWE-22', payload: targetPath, timestamp: Date.now()
    };
  }
  return { blocked: false, matched: false };
}