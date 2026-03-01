import { TaintContext, isTainted } from '../taint/context';

const SHELL_METACHARS = /[;|`$><\n\\]|\$\(/;

export function detectCmdInjection(command: string, ctx?: TaintContext) {
  const matched = SHELL_METACHARS.test(command);
  const tainted = ctx ? ctx.taintedObjects.has(Object(command)) : isTainted(Object(command));

  if (matched && tainted) {
    return {
      blocked: true, matched: true, type: 'Command Injection', confidence: 0.99,
      cwe: 'CWE-78', payload: command, timestamp: Date.now()
    };
  }
  return { blocked: false, matched: false };
}