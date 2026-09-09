package io.github.securekit;

import redis.clients.jedis.UnifiedJedis;
import redis.clients.jedis.exceptions.JedisException;

import java.util.Collections;
import java.util.List;

/**
 * {@link RateLimiterStore} backed by Redis, safe for multi-instance
 * deployments (unlike {@link MemoryRateLimiterStore}, which is
 * process-local only -- see THREAT_MODEL.md). Uses a fixed-window counter
 * per key. Requires the optional {@code redis.clients:jedis} dependency.
 */
public final class RedisRateLimiterStore implements RateLimiterStore {

    /**
     * Atomically increments a counter and sets its expiry only on the
     * first increment of a window -- avoiding a race where a process
     * crashes between INCR and PEXPIRE and leaves a key with no TTL
     * (which would then never reset, permanently blocking that key).
     */
    private static final String INCR_EXPIRE_SCRIPT =
            "local current = redis.call('INCR', KEYS[1])\n"
            + "if tonumber(current) == 1 then\n"
            + "  redis.call('PEXPIRE', KEYS[1], ARGV[1])\n"
            + "end\n"
            + "return current\n";

    private final UnifiedJedis client;
    private final String keyPrefix;

    /** @param client caller owns the client's lifecycle (creation and close()) */
    public RedisRateLimiterStore(UnifiedJedis client) {
        this(client, "securekit:ratelimit:");
    }

    public RedisRateLimiterStore(UnifiedJedis client, String keyPrefix) {
        this.client = client;
        this.keyPrefix = keyPrefix;
    }

    @Override
    public int increment(String key, long windowMillis) {
        String redisKey = keyPrefix + key;
        try {
            Object result = client.eval(
                    INCR_EXPIRE_SCRIPT,
                    List.of(redisKey),
                    Collections.singletonList(Long.toString(windowMillis)));
            return ((Long) result).intValue();
        } catch (JedisException e) {
            // Fail closed: if Redis is unreachable, treat this as "already
            // over limit" rather than silently allowing unlimited requests
            // through, since a rate limiter that fails open under outage
            // is a rate limiter that doesn't limit anything during one.
            return Integer.MAX_VALUE;
        }
    }
}
