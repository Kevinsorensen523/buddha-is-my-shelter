package io.github.securekit;

/**
 * Storage abstraction for {@link RateLimiter}. The package ships an
 * in-memory implementation; production multi-instance deployments should
 * implement this against Redis or similar shared storage.
 */
public interface RateLimiterStore {
    /**
     * Increments the counter for {@code key} within the current window,
     * creating the window if absent. Returns the new count.
     */
    int increment(String key, long windowMillis);
}
