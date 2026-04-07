const crypto = require('crypto');

class Blocker {
  block(req, res, reason) {
    try {
      if (res.headersSent || res.writableEnded) {
        if (req.socket && !req.socket.destroyed) {
          req.socket.destroy();
        }
        return false;
      }

      const payload = JSON.stringify({
        error: "Forbidden",
        message: "ShieldRASP Runtime Violation",
        requestId: req.headers['x-request-id'] || crypto.randomUUID(),
        timestamp: new Date().toISOString()
      });

      res.writeHead(403, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Connection': 'close'
      });
      res.end(payload);

      process.nextTick(() => {
        if (req.socket && !req.socket.destroyed) {
          req.socket.destroy();
        }
      });
    } catch (e) {
      try {
        if (req.socket && !req.socket.destroyed) {
          req.socket.destroy();
        }
      } catch (innerE) {}
    }

    return false;
  }
}

module.exports = { Blocker };
