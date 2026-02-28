import { AsyncLocalStorage } from 'async_hooks';

export interface TaintLabel {
  sources: string[];
  path: string[];
  timestamp: number;
}

export class TaintContext {
  taintedObjects = new WeakMap<object, TaintLabel>();
  requestMeta = {
    userId: '', sessionId: '', sourceIp: '', requestId: '', httpMethod: '', httpPath: ''
  };
}

export const taintStorage = new AsyncLocalStorage<TaintContext>();

export function getTaintContext(): TaintContext | undefined {
  return taintStorage.getStore();
}

export function isTainted(obj: any): boolean {
  const ctx = getTaintContext();
  if (!ctx || !obj || typeof obj !== 'object') return false;
  return ctx.taintedObjects.has(obj);
}