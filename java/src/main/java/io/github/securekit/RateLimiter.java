package io.github.securekit;

/**
 * Enforces a maximum number of actions per key within a rolling window.
 */
public final class RateLimiter {

    private final RateLimiterStore store;
    private final int limit;
    private final long windowMillis;

    public RateLimiter(RateLimiterStore store, int limit, long windowMillis) {
        this.store = store;
        this.limit = limit;
        this.windowMillis = windowMillis;
    }

    public boolean allow(String key) {
        return store.increment(key, windowMillis) <= limit;
    }
}
