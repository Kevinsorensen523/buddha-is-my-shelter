<?php

declare(strict_types=1);

namespace SecureKit;

use Predis\ClientInterface;

/**
 * RateLimiterStoreInterface backed by Redis, safe for multi-instance
 * deployments (unlike MemoryRateLimiterStore, which is process-local
 * only -- see THREAT_MODEL.md, and especially relevant for PHP-FPM's
 * multi-worker-per-server model). Uses a fixed-window counter per key.
 */
final class RedisRateLimiterStore implements RateLimiterStoreInterface
{
    /**
     * Atomically increments a counter and sets its expiry only on the
     * first increment of a window -- avoiding a race where a process
     * crashes between INCR and EXPIRE and leaves a key with no TTL
     * (which would then never reset, permanently blocking that key).
     */
    private const INCR_EXPIRE_SCRIPT = <<<'LUA'
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
    redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
LUA;

    /** @param ClientInterface $client caller owns the client's lifecycle */
    public function __construct(
        private readonly ClientInterface $client,
        private readonly string $keyPrefix = 'securekit:ratelimit:'
    ) {
    }

    public function increment(string $key, int $windowSeconds): int
    {
        $redisKey = $this->keyPrefix . $key;
        $windowMs = $windowSeconds * 1000;

        try {
            $count = (int) $this->client->eval(self::INCR_EXPIRE_SCRIPT, 1, $redisKey, (string) $windowMs);
            return $count;
        } catch (\Throwable $e) {
            // Fail closed: if Redis is unreachable, treat this as "already
            // over limit" rather than silently allowing unlimited requests
            // through, since a rate limiter that fails open under outage
            // is a rate limiter that doesn't limit anything during one.
            return PHP_INT_MAX;
        }
    }
}
