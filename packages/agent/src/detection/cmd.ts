import { TaintContext, getTaintContext } from '../taint/context';

const SHELL_METACHARS = /[;|`$><\n\\&]|\$\(/;

export function detectCmdInjection(command: string, ctx?: TaintContext) {
  const matched = SHELL_METACHARS.test(command);
  const currentCtx = ctx || getTaintContext();
  if (!currentCtx) return { blocked: false, matched: false };

  let isTainted = false;
  let taintedValueMatched = '';

  for (const [taintedValue] of currentCtx.taintedObjects) {
    if (typeof taintedValue === 'string' && command.includes(taintedValue)) {
      isTainted = true;
      taintedValueMatched = taintedValue;
      break;
    }
  }

  if (isTainted) {
    // If it contains metacharacters, it's definitely a command injection attempt.
    if (matched || SHELL_METACHARS.test(taintedValueMatched)) {
      return {
        blocked: true, matched: true, attack_type: 'Command Injection', confidence: 0.99,
        cwe: 'CWE-78', payload: command, timestamp: Date.now()
      };
    }

    // Even without metachars, user input in a shell command is extremely risky.
    return {
      blocked: false, matched: true, attack_type: 'Tainted Command Execution', confidence: 0.60,
      cwe: 'CWE-78', payload: command, timestamp: Date.now(),
      details: 'User-controlled data was passed to a shell execution function.'
    };
  }

  return { blocked: false, matched: false };
}

