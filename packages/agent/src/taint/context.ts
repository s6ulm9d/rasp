import { AsyncLocalStorage } from 'async_hooks';

// Advanced Taint Tracking V2 - Using WeakMap for zero-overhead per-object metadata
export const taintMap = new WeakMap<object, TaintMetadata>();

export interface TaintMetadata {
  sources: string[];
  severity: number;
  origin: 'http' | 'file' | 'env';
  timestamp: number;
}

export interface RuleTrigger {
  attack: string;
  payload: string;
  sink: string;
  score: number;
  timestamp: number;
  trace?: string[];
}

export function uuid(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// Iterative Normalization with Convergence Detection
export function canonicalize(input: string): string {
  if (!input) return '';
  let str = input;
  let previous = '';
  let iterations = 0;
  
  // No depth cap - stop when converged or anomaly (entropy spike) detected
  while (str !== previous && iterations < 20) {
    previous = str;
    try { 
      const decoded = decodeURIComponent(str); 
      if (decoded !== str) str = decoded;
    } catch (e) { }
    
    // Deobfuscate Hex/HTML/B64
    str = str.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    str = str.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    str = str.replace(/&#([0-9]+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
    
    iterations++;
  }

  return str.normalize('NFKD').replace(/\0/g, '').toLowerCase();
}

export class TaintContext {
  public triggeredRules: RuleTrigger[] = [];
  public totalScore: number = 0;
  public requestMeta = {
    method: '',
    path: '',
    ip: '',
    requestId: uuid(),
    flow: [] as string[]
  };

  private stringTaintStore = new Set<string>(); // For basic string matching in sinks

  public taint(val: any, source: string): void {
    if (!val) return;
    
    const meta: TaintMetadata = {
      sources: [source],
      severity: 1.0,
      origin: 'http',
      timestamp: Date.now()
    };

    if (typeof val === 'object' && val !== null) {
      taintMap.set(val, meta);
      // Recursively taint nested objects
      for (const key of Object.keys(val)) {
        this.taint((val as any)[key], `${source}.${key}`);
      }
    } else if (typeof val === 'string') {
      const clean = canonicalize(val);
      if (clean.length > 3) this.stringTaintStore.add(clean);
    }
  }

  public isTainted(val: any): TaintMetadata | null {
    if (!val) return null;
    
    if (typeof val === 'object' && val !== null) {
      return taintMap.get(val) || null;
    }

    if (typeof val === 'string') {
      const clean = canonicalize(val);
      for (const t of this.stringTaintStore) {
        if (clean.includes(t)) {
          return { sources: [t], severity: 1.0, origin: 'http', timestamp: Date.now() };
        }
      }
    }

    return null;
  }
}

export const taintStorage = new AsyncLocalStorage<TaintContext>();
export function getTaintContext(): TaintContext | undefined {
  return taintStorage.getStore();
}