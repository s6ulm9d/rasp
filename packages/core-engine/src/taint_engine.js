const { AsyncLocalStorage } = require('async_hooks');

class TaintEngine {
  constructor() {
    this.storage = new AsyncLocalStorage();
  }

  runInContext(req, inputString, callback) {
    const context = {
      requestId: req.headers['x-request-id'] || Date.now().toString(),
      taintedInputs: new Set(),
      isCompromised: false
    };

    if (inputString) {
      context.taintedInputs.add(inputString);
    }

    return this.storage.run(context, callback);
  }

  getContext() {
    return this.storage.getStore();
  }

  taint(value) {
    const ctx = this.getContext();
    if (ctx && value) {
      ctx.taintedInputs.add(value);
    }
  }

  isTainted(value) {
    const ctx = this.getContext();
    if (!ctx) return false;
    for (const tainted of ctx.taintedInputs) {
      if (typeof value === 'string' && typeof tainted === 'string' && value.includes(tainted)) {
        return true;
      }
    }
    return false;
  }
}

module.exports = new TaintEngine();
