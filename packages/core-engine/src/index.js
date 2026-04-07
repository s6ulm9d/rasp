const { ShieldRASPInterceptor } = require('./interceptor');

// Auto-start if running as a standalone require
const interceptor = new ShieldRASPInterceptor();
interceptor.start();

module.exports = {
  start: () => interceptor.start(),
  interceptor: interceptor
};
