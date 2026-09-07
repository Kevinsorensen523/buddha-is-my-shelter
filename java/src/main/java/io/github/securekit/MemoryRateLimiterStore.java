package io.github.securekit;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Process-local, thread-safe fixed-window rate limiter store. Does NOT
 * share state across processes/instances -- see THREAT_MODEL.md.
 */
public final class MemoryRateLimiterStore implements RateLimiterStore {

    private record Bucket(int count, long resetAt) {
    }

    private final ConcurrentHashMap<String, AtomicReference<Bucket>> buckets = new ConcurrentHashMap<>();

    @Override
    public int increment(String key, long windowMillis) {
        AtomicReference<Bucket> ref = buckets.computeIfAbsent(key, k -> new AtomicReference<>(new Bucket(0, 0L)));
        while (true) {
            Bucket current = ref.get();
            long now = System.currentTimeMillis();
            Bucket next = now > current.resetAt()
                    ? new Bucket(1, now + windowMillis)
                    : new Bucket(current.count() + 1, current.resetAt());
            if (ref.compareAndSet(current, next)) {
                return next.count();
            }
        }
    }
}
