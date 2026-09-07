package io.github.securekit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    @Test
    void allowsUnderLimitAndBlocksOver() {
        RateLimiter rl = new RateLimiter(new MemoryRateLimiterStore(), 3, 60_000L);
        assertTrue(rl.allow("client-1"));
        assertTrue(rl.allow("client-1"));
        assertTrue(rl.allow("client-1"));
        assertFalse(rl.allow("client-1"));
    }

    @Test
    void tracksKeysIndependently() {
        RateLimiter rl = new RateLimiter(new MemoryRateLimiterStore(), 1, 60_000L);
        assertTrue(rl.allow("client-A"));
        assertTrue(rl.allow("client-B"));
    }
}
