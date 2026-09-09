package io.github.securekit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import redis.clients.jedis.UnifiedJedis;
import redis.clients.jedis.exceptions.JedisConnectionException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Requires a real Redis instance reachable at localhost:6379. Tests are
 * skipped automatically if Redis isn't reachable, so the rest of the suite
 * still passes without Redis, but running them for real (not mocked) is
 * what actually proves this store's atomicity claims hold.
 */
class RedisRateLimiterStoreTest {

    private static UnifiedJedis client;

    @BeforeAll
    static void connect() {
        try {
            client = new UnifiedJedis("redis://localhost:6379");
            client.ping();
        } catch (JedisConnectionException e) {
            client = null;
        }
    }

    @AfterAll
    static void disconnect() {
        if (client != null) {
            client.close();
        }
    }

    private String prefix(String testName) {
        return "securekit-test:" + testName + ":";
    }

    @Test
    void allowsUnderLimitAndBlocksOver() {
        Assumptions.assumeTrue(client != null, "no Redis reachable at localhost:6379");
        String prefix = prefix("allowsUnderLimitAndBlocksOver");
        RedisRateLimiterStore store = new RedisRateLimiterStore(client, prefix);
        RateLimiter rl = new RateLimiter(store, 3, 60_000L);
        try {
            assertTrue(rl.allow("client-1"));
            assertTrue(rl.allow("client-1"));
            assertTrue(rl.allow("client-1"));
            assertFalse(rl.allow("client-1"));
        } finally {
            client.del(prefix + "client-1");
        }
    }

    @Test
    void tracksKeysIndependently() {
        Assumptions.assumeTrue(client != null, "no Redis reachable at localhost:6379");
        String prefix = prefix("tracksKeysIndependently");
        RedisRateLimiterStore store = new RedisRateLimiterStore(client, prefix);
        RateLimiter rl = new RateLimiter(store, 1, 60_000L);
        try {
            assertTrue(rl.allow("client-A"));
            assertTrue(rl.allow("client-B"));
        } finally {
            client.del(prefix + "client-A", prefix + "client-B");
        }
    }

    @Test
    void expiresAndResets() throws InterruptedException {
        Assumptions.assumeTrue(client != null, "no Redis reachable at localhost:6379");
        String prefix = prefix("expiresAndResets");
        RedisRateLimiterStore store = new RedisRateLimiterStore(client, prefix);
        RateLimiter rl = new RateLimiter(store, 1, 300L);
        try {
            assertTrue(rl.allow("client-1"));
            assertFalse(rl.allow("client-1"));
            Thread.sleep(400);
            assertTrue(rl.allow("client-1"));
        } finally {
            client.del(prefix + "client-1");
        }
    }

    @Test
    void setsExpiryOnFirstIncrementOnly() throws InterruptedException {
        Assumptions.assumeTrue(client != null, "no Redis reachable at localhost:6379");
        String prefix = prefix("setsExpiryOnFirstIncrementOnly");
        RedisRateLimiterStore store = new RedisRateLimiterStore(client, prefix);
        String redisKey = prefix + "client-1";
        try {
            store.increment("client-1", 3_600_000L);
            long ttl1 = client.pttl(redisKey);

            Thread.sleep(50);
            store.increment("client-1", 3_600_000L);
            long ttl2 = client.pttl(redisKey);

            assertTrue(ttl2 <= ttl1, "TTL should only count down, not reset");
        } finally {
            client.del(redisKey);
        }
    }
}
