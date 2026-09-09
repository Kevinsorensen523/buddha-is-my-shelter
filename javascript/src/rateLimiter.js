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
 *
 * allow() is always async (returns a Promise<boolean>), even though
 * MemoryRateLimiterStore's own increment() is synchronous -- awaiting a
 * non-Promise value resolves it immediately, so this costs nothing for the
 * in-memory case, but it's required for any real network-backed store
 * (e.g. RedisRateLimiterStore), which cannot be synchronous. An earlier
 * version of this class was fully synchronous, which made it impossible
 * to implement a correct Redis-backed store at all (comparing a Promise
 * to limit with <= silently produces the wrong answer every time).
 */
class RateLimiter {
  constructor(store, limit, windowMs) {
    this.store = store;
    this.limit = limit;
    this.windowMs = windowMs;
  }

  async allow(key) {
    const count = await this.store.increment(key, this.windowMs);
    return count <= this.limit;
  }
}

module.exports = { RateLimiter, MemoryRateLimiterStore };
