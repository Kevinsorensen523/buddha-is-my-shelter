<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Enforces a maximum number of actions per key within a rolling window.
 */
final class RateLimiter
{
    public function __construct(
        private readonly RateLimiterStoreInterface $store,
        private readonly int $limit,
        private readonly int $windowSeconds
    ) {
    }

    public function allow(string $key): bool
    {
        return $this->store->increment($key, $this->windowSeconds) <= $this->limit;
    }
}
