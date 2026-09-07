<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Process-local, fixed-window rate limiter store. Does NOT share state
 * across processes/instances — see THREAT_MODEL.md.
 */
final class MemoryRateLimiterStore implements RateLimiterStoreInterface
{
    /** @var array<string, array{count: int, resetAt: float}> */
    private array $buckets = [];

    public function increment(string $key, int $windowSeconds): int
    {
        $now = microtime(true);
        if (!isset($this->buckets[$key]) || $now > $this->buckets[$key]['resetAt']) {
            $this->buckets[$key] = ['count' => 0, 'resetAt' => $now + $windowSeconds];
        }
        $this->buckets[$key]['count']++;
        return $this->buckets[$key]['count'];
    }
}
