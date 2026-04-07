class ResourceManager {
  constructor(policy) {
    this.policy = policy;
    this.globalMemoryUsed = 0;
    this.globalMaxMemory = policy.get('global_max_memory') || 500 * 1024 * 1024;
    this.maxMemoryPerIp = policy.get('max_memory_per_ip') || 10 * 1024 * 1024;
    this.maxConcurrentPerIp = policy.get('max_concurrent_per_ip') || 100;
    this.globalConcurrencyLimit = policy.get('global_concurrency') || 10000;
    
    this.ipStates = new Map();
    this.activeRequests = 0;
    
    setInterval(() => this._cleanupStaleStates(), 60000).unref();
  }

  _getIpState(ip) {
    if (!this.ipStates.has(ip)) {
      this.ipStates.set(ip, {
        memoryUsed: 0,
        activeRequests: 0,
        strikes: 0,
        banUntil: 0,
        requestCount: 0,
        windowStart: Date.now()
      });
    }
    return this.ipStates.get(ip);
  }

  canAcceptRequest(ip) {
    this.activeRequests = Math.max(0, this.activeRequests);

    if (this.activeRequests >= this.globalConcurrencyLimit) {
      return { allowed: false, reason: 'GLOBAL_CONCURRENCY_EXCEEDED' };
    }

    const state = this._getIpState(ip);
    const now = Date.now();

    if (state.banUntil > now) {
      return { allowed: false, reason: 'IP_BANNED' };
    } else if (state.banUntil > 0 && state.banUntil <= now) {
      state.banUntil = 0;
      state.strikes = Math.max(0, state.strikes - 1);
    }

    if (now - state.windowStart > 60000) {
      state.requestCount = 0;
      state.windowStart = now;
    }

    state.requestCount++;
    const rateLimit = this.policy.get('rate_limit_per_minute') || 1000;
    if (state.requestCount > rateLimit) {
      this.penalizeIp(ip, 'RATE_LIMIT_EXCEEDED');
      return { allowed: false, reason: 'RATE_LIMIT_EXCEEDED' };
    }

    if (state.activeRequests >= this.maxConcurrentPerIp) {
      return { allowed: false, reason: 'IP_CONCURRENCY_EXCEEDED' };
    }

    return { allowed: true };
  }

  requestStarted(ip) {
    this.activeRequests = Math.max(0, this.activeRequests + 1);
    const state = this._getIpState(ip);
    state.activeRequests = Math.max(0, state.activeRequests + 1);
  }

  requestFinished(ip, memoryToFree) {
    this.activeRequests = Math.max(0, this.activeRequests - 1);
    this.globalMemoryUsed = Math.max(0, this.globalMemoryUsed - memoryToFree);
    
    const state = this._getIpState(ip);
    state.activeRequests = Math.max(0, state.activeRequests - 1);
    state.memoryUsed = Math.max(0, state.memoryUsed - memoryToFree);
  }

  trackMemory(ip, bytes) {
    this.globalMemoryUsed = Math.max(0, this.globalMemoryUsed);
    if (this.globalMemoryUsed + bytes > this.globalMaxMemory) {
      return { allowed: false, reason: 'GLOBAL_MEMORY_EXCEEDED' };
    }

    const state = this._getIpState(ip);
    if (state.memoryUsed + bytes > this.maxMemoryPerIp) {
      return { allowed: false, reason: 'IP_MEMORY_EXCEEDED' };
    }

    this.globalMemoryUsed += bytes;
    state.memoryUsed += bytes;

    return { allowed: true };
  }

  penalizeIp(ip, _reason) {
    const state = this._getIpState(ip);
    state.strikes++;
    const penaltyMs = Math.min(
      Math.pow(2, state.strikes - 1) * 5000,
      5 * 60 * 1000
    );
    state.banUntil = Date.now() + penaltyMs;
  }

  _cleanupStaleStates() {
    const now = Date.now();
    for (const [ip, state] of this.ipStates.entries()) {
      if (state.activeRequests === 0 && state.banUntil < now && now - state.windowStart > 60000) {
        this.ipStates.delete(ip);
      }
    }
  }
}

module.exports = { ResourceManager };
