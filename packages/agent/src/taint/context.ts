import { AsyncLocalStorage } from 'async_hooks';

export interface TaintLabel {
  sources: string[];
  timestamp: number;
}

export interface RuleTrigger {
  attack: string;
  payload: string;
  sink: string;
  score: number;
  timestamp: number;
}

function uuid(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

export function canonicalize(input: string): string {
  if (!input) return '';
  let str = input;
  let previous = '';

  // Recursively decode to defeat double/triple URL encoding
  while (str !== previous) {
    previous = str;
    try { str = decodeURIComponent(str); } catch (e) { }
  }

  // Normalize Unicode representations, strip Null Bytes, enforce Lowercase for pattern matching
  return str.normalize('NFKD')
    .replace(/\0/g, '')
    .toLowerCase();
}

export class TaintContext {
  // We use a Map to track canonicalized tainted strings. 
  private taintedValues = new Map<string, TaintLabel>();

  // Guardrails: Limit map size to prevent OOM
  private readonly MAX_TAINT_ITEMS = 100;
  private readonly MAX_STRING_LENGTH = 10000;

  public triggeredRules: RuleTrigger[] = [];
  public totalScore: number = 0;

  public requestMeta = {
    method: '',
    path: '',
    ip: '',
    requestId: uuid()
  };

  public taint(val: string, source: string) {
    if (!val || typeof val !== 'string') return;
    if (this.taintedValues.size >= this.MAX_TAINT_ITEMS) return; // Cap memory usage

    // Truncate massively long strings before canonicalization to cap CPU burn
    const safeVal = val.length > this.MAX_STRING_LENGTH ? val.substring(0, this.MAX_STRING_LENGTH) : val;

    const clean = canonicalize(safeVal);
    if (!clean) return;

    this.taintedValues.set(clean, {
      sources: [source],
      timestamp: Date.now()
    });
  }

  public isTainted(query: string): { tainted: boolean; source?: string } {
    if (!query || typeof query !== 'string') return { tainted: false };

    const cleanQuery = canonicalize(query);

    // Exact match check
    if (this.taintedValues.has(cleanQuery)) {
      return { tainted: true, source: 'direct' };
    }

    // Substring-aware check against canonicalized inputs
    for (const [taintedVal] of this.taintedValues) {
      if (cleanQuery.includes(taintedVal)) {
        return { tainted: true, source: taintedVal };
      }
    }

    return { tainted: false };
  }
}


export const taintStorage = new AsyncLocalStorage<TaintContext>();

export function getTaintContext(): TaintContext | undefined {
  return taintStorage.getStore();
}