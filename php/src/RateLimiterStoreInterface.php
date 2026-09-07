<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Storage abstraction for RateLimiter. The package ships an in-memory
 * implementation; production multi-instance deployments should implement
 * this against Redis or similar shared storage.
 */
interface RateLimiterStoreInterface
{
    /**
     * Increments the counter for $key within the current window, creating
     * the window if absent. Returns the new count.
     */
    public function increment(string $key, int $windowSeconds): int;
}
