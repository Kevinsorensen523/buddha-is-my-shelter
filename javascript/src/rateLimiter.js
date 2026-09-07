'use strict';

/**
 * Process-local, fixed-window rate limiter store. Does NOT share state
 * across processes/instances -- see THREAT_MODEL.md.
 */
class MemoryRateLimiterStore {
  constructor() {
    this.buckets = new Map();
  }

  increment(key, windowMs) {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count;
  }
}

/**
 * Enforces a maximum number of actions per key within a rolling window.
 */
class RateLimiter {
  constructor(store, limit, windowMs) {
    this.store = store;
    this.limit = limit;
    this.windowMs = windowMs;
  }

  allow(key) {
    return this.store.increment(key, this.windowMs) <= this.limit;
  }
}

module.exports = { RateLimiter, MemoryRateLimiterStore };
