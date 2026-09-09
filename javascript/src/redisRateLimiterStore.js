'use strict';

/**
 * RateLimiterStore backed by Redis, safe for multi-instance deployments
 * (unlike MemoryRateLimiterStore, which is process-local only -- see
 * THREAT_MODEL.md, and especially relevant for PM2 cluster mode / multiple
 * container replicas).
 *
 * Requires the optional `ioredis` dependency (installed by default via
 * npm's optionalDependencies unless --no-optional is used).
 */

// Atomically increments a counter and sets its expiry only on the first
// increment of a window -- avoiding a race where a process crashes between
// INCR and PEXPIRE and leaves a key with no TTL (which would then never
// reset, permanently blocking that key).
const INCR_EXPIRE_SCRIPT = `
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`;

class RedisRateLimiterStore {
  /**
   * @param {import('ioredis').Redis} client caller owns the client's lifecycle
   * @param {string} [keyPrefix]
   */
  constructor(client, keyPrefix = 'securekit:ratelimit:') {
    this.client = client;
    this.keyPrefix = keyPrefix;
    // ioredis lets you define custom commands backed by a Lua script,
    // reused across calls rather than re-sending the script body each time.
    if (typeof client.incrExpire !== 'function') {
      client.defineCommand('incrExpire', { numberOfKeys: 1, lua: INCR_EXPIRE_SCRIPT });
    }
  }

  async increment(key, windowMs) {
    const redisKey = this.keyPrefix + key;
    try {
      return await this.client.incrExpire(redisKey, windowMs);
    } catch {
      // Fail closed: if Redis is unreachable, treat this as "already over
      // limit" rather than silently allowing unlimited requests through,
      // since a rate limiter that fails open under outage is a rate
      // limiter that doesn't limit anything during one.
      return Number.MAX_SAFE_INTEGER;
    }
  }
}

module.exports = { RedisRateLimiterStore };
