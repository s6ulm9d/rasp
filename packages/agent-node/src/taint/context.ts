import { AsyncLocalStorage } from 'async_hooks';

export interface TaintLabel {
  sources: string[];
  path: string[];
  timestamp: number;
}

export class TaintContext {
  // Use a regular Map to allow primitives (strings) to be tainted.
  // Since TaintContext is scoped to a request in AsyncLocalStorage,
  // it will be garbage collected after the request is finished.
  taintedObjects = new Map<any, TaintLabel>();
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
  if (!ctx || obj === undefined || obj === null) return false;
  return ctx.taintedObjects.has(obj);
}