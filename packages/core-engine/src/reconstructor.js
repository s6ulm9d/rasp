class RequestReconstructor {
  constructor(req, policy, detector, resourceManager) {
    this.req = req;
    this.policy = policy;
    this.detector = detector;
    this.resourceManager = resourceManager;

    this.maxSize = policy.get('max_body_size') || 1024 * 1024;
    this.totalSize = 0;
    this.lastFragment = Buffer.alloc(0);
    this.chunks = [];
    this.isBlocked = false;

    const ct = (req.headers['content-type'] || '').toLowerCase();
    this.isScannable = ct.includes('application/json') || 
                       ct.includes('application/x-www-form-urlencoded') || 
                       ct === '' || 
                       ct.includes('text/');
  }

  tap(onBlock) {
    const req = this.req;
    const ip = req.socket?.remoteAddress || 'unknown';

    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return;
    }

    const self = this;
    const originalEmit = req.emit.bind(req);

    req._originalShieldRASPEmit = originalEmit;

    req.emit = function (eventName, ...args) {
      if (self.isBlocked === true) return false;

      try {
        if (eventName === 'data') {
          const raw = args[0];

          if (!Buffer.isBuffer(raw) && typeof raw !== 'string') {
            return originalEmit.apply(this, [eventName, ...args]);
          }

          const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
          
          self.totalSize += chunk.length;
          self.req._shieldRaspMem = self.totalSize;

          if (self.resourceManager) {
            const memCheck = self.resourceManager.trackMemory(ip, chunk.length);
            if (!memCheck.allowed) {
              return self._fail(onBlock, memCheck.reason, ip);
            }
          }

          if (self.totalSize > self.maxSize) {
            return self._fail(onBlock, 'PAYLOAD_TOO_LARGE', ip);
          }

          if (self.isScannable) {
             let scanBuffer = null;
             
             if (chunk.length < 512 || chunk.length < 50000) {
               scanBuffer = Buffer.concat([self.lastFragment, chunk]);
             } 

             if (scanBuffer) {
               const result = self.detector.scan({ stream: scanBuffer.toString('utf8') }, ip);
               if (result && result.blocked) {
                 return self._fail(onBlock, result.reason, ip);
               }
             }

             self.lastFragment = chunk.length > 512 ? chunk.slice(-512) : chunk;

             if (self.policy.get('full_body_scan') === true && self.chunks.length < 50) {
               self.chunks.push(chunk);
             }
          }

        } else if (eventName === 'end') {
          if (self.isScannable && self.chunks.length > 0) {
            const fullBody = Buffer.concat(self.chunks);
            const final = self.detector.scan({ stream: fullBody.toString('utf8') }, ip);

            if (final && final.blocked) {
              return self._fail(onBlock, final.reason, ip);
            }
          }
        }
      } catch (err) {
        return originalEmit.apply(this, [eventName, ...args]);
      }

      try {
        if (self.isBlocked === true) return false;
        return originalEmit.apply(this, [eventName, ...args]);
      } catch (frameworkErr) {
        throw frameworkErr;
      }
    };
  }

  _fail(onBlock, reason, ip) {
    if (this.isBlocked === true) return false;
    this.isBlocked = true;

    if (this.resourceManager && ['RATE_LIMIT_EXCEEDED', 'PAYLOAD_TOO_LARGE'].includes(reason) === false && !reason.includes('MEMORY')) {
      this.resourceManager.penalizeIp(ip, reason);
    } else if (this.resourceManager && (reason.includes('TOO_LARGE') || reason.includes('MEMORY'))) {
      this.resourceManager.penalizeIp(ip, 'RESOURCE_ABUSE');
    }
    
    onBlock(reason);

    setImmediate(() => {
        try {
          if (this.req.socket && !this.req.socket.destroyed) {
            this.req.socket.destroy();
          }
        } catch (e) {}
    });

    return false;
  }
}

module.exports = { RequestReconstructor };