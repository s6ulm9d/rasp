import * as acorn from 'acorn';
import { TaintContext, getTaintContext } from '../taint/context';

export interface SinkEvent {
  name: string;
  args: any[];
  context: TaintContext;
}

export class SinkMonitor {
  // Critical Sinks to monitor
  public static validateExecution(sinkName: string, ...args: any[]): void {
    const ctx = getTaintContext();
    if (!ctx) return;

    for (const arg of args) {
      const taint = ctx.isTainted(arg);
      
      // Rule 1: Taint at sink check (Signature-less)
      if (taint) {
        throw this.createBlockError(sinkName, arg, "TAINTED_EXECUTION_SINK");
      }

      // Rule 2: High-risk AST Patterns for string-based sinks (eval, Function)
      if (['eval', 'Function', 'setTimeout', 'setInterval', 'vm.run'].includes(sinkName) && typeof arg === 'string') {
        this.inspectAST(sinkName, arg);
      }
    }
  }

  private static inspectAST(sinkName: string, code: string) {
    try {
      // Parse with acorn to detect malicious code patterns without relying on regex
      const ast = acorn.parse(code, { ecmaVersion: 2020 });
      let suspensionLevel = 0;

      // Deep walk (Simplified for example, but looks for suspicious node types)
      const walk = (node: any) => {
        if (!node) return;
        
        // Block property-access of critical objects via computed members
        if (node.type === 'MemberExpression' && node.computed) {
            suspensionLevel += 40;
        }

        // Block constructor-based RCE
        if (node.type === 'CallExpression' && node.callee.name === 'require') {
            suspensionLevel += 100;
        }

        if (node.type === 'Identifier' && ['process', 'global', 'Buffer', 'child_process'].includes(node.name)) {
            suspensionLevel += 60;
        }

        for (const key in node) {
          if (typeof node[key] === 'object') walk(node[key]);
        }
      };

      walk(ast);

      if (suspensionLevel >= 100) {
        throw this.createBlockError(sinkName, code, "MALICIOUS_AST_PATTERN");
      }
    } catch (e: any) {
        if (e.name === 'SecurityBlockException') throw e;
        // If AST parsing fails on tainted sub-string, we fail closed
    }
  }

  private static createBlockError(sink: string, payload: any, reason: string) {
    const err = new Error(`Security Block: ${reason} in ${sink}`) as any;
    err.name = 'SecurityBlockException';
    err.details = { sink, reason, payload: String(payload).substring(0, 100) };
    return err;
  }
}
