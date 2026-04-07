const Hook = require('require-in-the-middle');
const { RequestReconstructor } = require('./reconstructor');
const { Inspector } = require('./analyzer');
const { Blocker } = require('./blocker');
const { PolicyManager } = require('./policy');
const { ResourceManager } = require('./resource_manager');
const { SinkMonitor } = require('./sink_monitor');
const { ResponseInspector } = require('./response_inspector');
const TaintEngine = require('./taint_engine');

class ShieldRASPInterceptor {
  constructor() {
    this.policy = new PolicyManager();
    this.inspector = new Inspector(this.policy);
    this.blocker = new Blocker();
    this.resourceManager = new ResourceManager(this.policy);
    this.sinkMonitor = new SinkMonitor(this.inspector.detector);
    this.responseInspector = new ResponseInspector(this.policy);
    this._hooked = false;
  }

  start() {
    if (this._hooked) return;
    try {
      this.sinkMonitor.start(); // This already sets up some hooks
      this._setupServerHooks();
      this._hooked = true;
    } catch (e) {
      console.error('[ShieldRASP] Startup Error:', e);
    }
  }

  _setupServerHooks() {
    const self = this;
    // Centralized hook to prevent double wrapping / Node 22 conflicts
    Hook(['http', 'https'], (exports, name) => {
      // 1. Hook createServer
      const originalCreateServer = exports.createServer;
      exports.createServer = function(options, requestListener) {
        let listener = requestListener;
        let opts = options;
        if (typeof options === 'function') {
           listener = options;
           opts = {};
        }
        const wrappedListener = (req, res) => self._handleRequest(req, res, listener);
        return originalCreateServer.call(this, opts, wrappedListener);
      };

      // 2. Hook request (for outbound sinks)
      const originalRequest = exports.request;
      exports.request = function(...args) {
         try {
            self.sinkMonitor._checkTaint(args, `${name}.request (Outbound Path)`);
         } catch (e) {
            if (e.name === 'SecurityBlockException') throw e;
         }
         return originalRequest.apply(this, args);
      };

      return exports;
    });
  }

  _handleRequest(req, res, listener) {
    const ip = req.socket.remoteAddress || '127.0.0.1';
    
    // Safety check: Don't double-wrap or process twice
    if (req._shieldRaspHandled) return listener ? listener(req, res) : null;
    req._shieldRaspHandled = true;

    const emergencyFail = (reason) => {
      try {
        this.blocker.block(req, res, reason);
      } catch (e) {
        if (req.socket && !req.socket.destroyed) req.socket.destroy();
      }
      return false;
    };

    try {
      const resourceCheck = this.resourceManager.canAcceptRequest(ip);
      if (!resourceCheck.allowed) return emergencyFail(resourceCheck.reason);
      
      this.resourceManager.requestStarted(ip);
      
      let finished = false;
      const finalizeRequest = () => {
         if (finished) return;
         finished = true;
         try {
            this.resourceManager.requestFinished(ip, req._shieldRaspMem || 0);
         } catch (e) {}
      };
      
      res.on('finish', finalizeRequest);
      res.on('close', finalizeRequest);

      if (this._isProtocolAttack(req)) {
        this.resourceManager.penalizeIp(ip, 'PROTOCOL_VIOLATION');
        return emergencyFail('PROTOCOL_VIOLATION');
      }

      const preCheck = this.inspector.preFlightCheck(req);
      if (preCheck.blocked) {
        this.resourceManager.penalizeIp(ip, 'PREFLIGHT_VIOLATION');
        return emergencyFail(preCheck.reason);
      }

      this._hookResponse(res);

      const reconstructor = new RequestReconstructor(req, this.policy, this.inspector.detector, this.resourceManager);
      reconstructor.tap((reason) => {
         emergencyFail(reason);
      });

      if (listener) {
         return TaintEngine.runInContext(req, '', () => {
            try {
               return listener(req, res);
            } catch (e) {
               if (e.name === 'SecurityBlockException') return emergencyFail(e.message);
               throw e;
            }
         });
      }
    } catch (err) {
      return emergencyFail('INTERNAL_SECURITY_FAILSAFE');
    }
  }

  _isProtocolAttack(req) {
     try {
       const validMethods = ['GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH'];
       if (!validMethods.includes(req.method)) return true;
       const headers = Object.keys(req.headers);
       if (headers.some(h => /[\r\n]/.test(h) || /[\r\n]/.test(req.headers[h]))) return true;
       return false;
     } catch (e) { return true; }
  }

  _hookResponse(res) {
     const self = this;
     const originalWrite = res.write;
     const originalEnd = res.end;

     res.write = function(chunk, ...args) {
        try {
          if (!chunk) return originalWrite.call(res, chunk, ...args);
          const inspected = self.responseInspector.inspect(res, chunk);
          return originalWrite.call(res, inspected, ...args);
        } catch (e) { return originalWrite.call(res, chunk, ...args); }
     };

     res.end = function(chunk, ...args) {
        try {
          if (!chunk || typeof chunk === 'function') return originalEnd.call(res, chunk, ...args);
          const inspected = self.responseInspector.inspect(res, chunk);
          return originalEnd.call(res, inspected, ...args);
        } catch (e) { return originalEnd.call(res, chunk, ...args); }
     };
  }
}

module.exports = { ShieldRASPInterceptor };
