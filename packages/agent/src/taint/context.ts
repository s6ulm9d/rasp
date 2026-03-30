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

  // Deobfuscate Hex Encoded Payloads (\x27 \x3d)
  str = str.replace(/\\x([0-9a-fA-F]{2})/g, (match, hex) => String.fromCharCode(parseInt(hex, 16)));

  // Opportunistic Base64 Decoding (Extract commonly padded injections)
  if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(str) && str.length > 8) {
    try { 
        const b64 = Buffer.from(str, 'base64').toString('utf-8'); 
        // Only append if it looks like human-readable text or SQL to prevent binary corruption matching
        if (/^[ -~]+$/.test(b64)) str += ` | decode_b64(${b64})`;
    } catch (e) { }
  }

  // Normalize Unicode representations, strip Null Bytes, enforce Lowercase for pattern matching
  return str.normalize('NFKD')
    .replace(/\0/g, '')
    .toLowerCase();
}

export class TaintNode {
  value: string;
  source: string;
  weight: number;
  children: TaintNode[] = [];

  constructor(value: string, source: string) {
    this.value = value;
    this.source = source;
    this.weight = 1.0;
  }
}

export class TaintContext {
  // Replace simple string map with a Weighted Context Graph representing propagation
  private taintRoots = new Map<string, TaintNode>();

  private readonly MAX_TAINT_ITEMS = 100;
  private readonly MAX_STRING_LENGTH = 10000;

  public triggeredRules: RuleTrigger[] = [];
  public totalScore: number = 0;

  public requestMeta = {
    method: '',
    path: '',
    ip: '',
    requestId: uuid(),
    flow: [] as string[]
  };

  public metrics = {
    outboundUDP: 0,
    outboundConnections: 0,
    uniqueDomains: new Set<string>(),
    errors: 0
  };

  public taint(val: string, source: string, parentNode?: TaintNode): TaintNode | undefined {
    if (!val || typeof val !== 'string') return;
    if (this.taintRoots.size >= this.MAX_TAINT_ITEMS) return; // Cap memory usage
    
    // Truncate massively long strings before canonicalization to cap CPU burn
    const safeVal = val.length > this.MAX_STRING_LENGTH ? val.substring(0, this.MAX_STRING_LENGTH) : val;
    const clean = canonicalize(safeVal);
    if (!clean) return;

    if (parentNode) {
        // Taint Propagation Edge
        const child = new TaintNode(clean, source);
        child.weight = parentNode.weight * 0.9; // Diminishing returns on deep propagation obfuscations
        parentNode.children.push(child);
        return child;
    } else {
        // Root payload node from direct input layer boundaries
        const root = new TaintNode(clean, source);
        this.taintRoots.set(clean, root);
        return root;
    }
  }

  public isTainted(query: string): { tainted: boolean; source?: string; weight?: number; graphNode?: TaintNode } {
    if (!query || typeof query !== 'string') return { tainted: false };

    const cleanQuery = canonicalize(query);

    // Exact root hash match check (O(1))
    if (this.taintRoots.has(cleanQuery)) {
      const node = this.taintRoots.get(cleanQuery)!;
      return { tainted: true, source: 'direct', weight: node.weight, graphNode: node };
    }

    // Graph sub-hash aware check (Crucial for injection / path traversal)
    // BFS traversal of taint nodes for dynamic sub-matches
    const queue: TaintNode[] = Array.from(this.taintRoots.values());
    while (queue.length > 0) {
        const current = queue.shift()!;
        if (cleanQuery.includes(current.value)) {
            return { tainted: true, source: current.value, weight: current.weight, graphNode: current };
        }
        for (const child of current.children) {
            queue.push(child);
        }
    }

    return { tainted: false };
  }
}


export const taintStorage = new AsyncLocalStorage<TaintContext>();

export function getTaintContext(): TaintContext | undefined {
  return taintStorage.getStore();
}