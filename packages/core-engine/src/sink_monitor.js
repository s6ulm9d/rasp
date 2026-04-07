const Hook = require('require-in-the-middle');
const TaintEngine = require('./taint_engine');

class SinkMonitor {
  constructor(detector) {
    this.detector = detector;
  }

  start() {
    this._hookFileSystem();
    this._hookChildProcess();
    this._hookGlobalSinks(); // eval, Function
    console.log('[ShieldRASP] Advanded Sink Protection (Taint Tracking V2) Active.');
  }

  _checkTaint(args, sinkName) {
    const ctx = TaintEngine.getContext();
    if (!ctx) return;
    
    // Flatten arguments passed to global application sink 
    const stringifiedArgs = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
    
    let isCorrelated = false;
    let taintedInput = "";

    // Correlation Enhancement (Minimal Taint Overlap checks allowing fragmented correlation tracking)
    for (const tainted of ctx.taintedInputs) {
        if (typeof tainted === 'string' && tainted.length > 5) {
            const partial = tainted.substring(0, 20);
            // Check full or partial overlap securely
            if (stringifiedArgs.includes(tainted) || stringifiedArgs.includes(partial)) {
                isCorrelated = true;
                taintedInput = tainted;
                break;
            }
        }
    }

    if (isCorrelated && this.detector) {
        const result = this.detector.scanTaintedSink(taintedInput, stringifiedArgs);
        if (result && result.blocked) {
           console.error(`[ShieldRASP] SINK_ATTEMPT: ${sinkName} hit from request context!`);
           const violation = new Error(`ShieldRASP Runtime Violation: Malicious payload detected at ${sinkName}`);
           violation.name = 'SecurityBlockException';
           throw violation;
        }
    }
  }

  _hookGlobalSinks() {
     // Hook eval (Native approach)
     const originalEval = global.eval;
     global.eval = (code) => {
        this._checkTaint([code], 'eval()');
        return originalEval(code);
     };

     // Hook Function constructor
     const originalFunction = global.Function;
     global.Function = (...args) => {
        this._checkTaint(args, 'Function constructor');
        return originalFunction.apply(null, args);
     };
  }

  _hookFileSystem() {
     const self = this;
     Hook(['fs'], (exports) => {
        const wrap = (name) => {
           const original = exports[name];
           if (typeof original !== 'function') return;
           exports[name] = function(...args) {
              self._checkTaint(args, `fs.${name}`);
              return original.apply(this, args);
           }
        };
        ['readFile','readFileSync','writeFile','writeFileSync','unlink','mkdir'].forEach(wrap);
        return exports;
     });
  }

  _hookChildProcess() {
    const self = this;
    Hook(['child_process'], (exports) => {
      const wrap = (name) => {
        const original = exports[name];
        if (typeof original !== 'function') return;
        exports[name] = function(...args) {
          self._checkTaint(args, `child_process.${name}`);
          return original.apply(this, args);
        }
      };
      ['exec','execSync','spawn','spawnSync','fork'].forEach(wrap);
      return exports;
    });
  }
}

module.exports = { SinkMonitor };
