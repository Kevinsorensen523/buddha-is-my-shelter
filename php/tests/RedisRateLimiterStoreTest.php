<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use Predis\Client;
use SecureKit\RateLimiter;
use SecureKit\RedisRateLimiterStore;

/**
 * These tests require a real Redis instance reachable at localhost:6379.
 * They're skipped automatically if Redis isn't reachable, so the rest of
 * the suite still passes without Redis, but running them for real (not
 * mocked) is what actually proves this store's atomicity claims hold.
 */
final class RedisRateLimiterStoreTest extends TestCase
{
    private static function client(): Client
    {
        $client = new Client(['host' => 'localhost', 'port' => 6379]);
        try {
            $client->connect();
        } catch (\Throwable $e) {
            self::markTestSkipped('no Redis reachable at localhost:6379: ' . $e->getMessage());
        }
        return $client;
    }

    public function testAllowsUnderLimitAndBlocksOver(): void
    {
        $client = self::client();
        $prefix = 'securekit-test:' . __FUNCTION__ . ':';
        $store = new RedisRateLimiterStore($client, $prefix);
        $rl = new RateLimiter($store, 3, 60);

        try {
            $this->assertTrue($rl->allow('client-1'));
            $this->assertTrue($rl->allow('client-1'));
            $this->assertTrue($rl->allow('client-1'));
            $this->assertFalse($rl->allow('client-1'));
        } finally {
            $client->del([$prefix . 'client-1']);
        }
    }

    public function testTracksKeysIndependently(): void
    {
        $client = self::client();
        $prefix = 'securekit-test:' . __FUNCTION__ . ':';
        $store = new RedisRateLimiterStore($client, $prefix);
        $rl = new RateLimiter($store, 1, 60);

        try {
            $this->assertTrue($rl->allow('client-A'));
            $this->assertTrue($rl->allow('client-B'));
        } finally {
            $client->del([$prefix . 'client-A', $prefix . 'client-B']);
        }
    }

    public function testExpiresAndResets(): void
    {
        $client = self::client();
        $prefix = 'securekit-test:' . __FUNCTION__ . ':';
        $store = new RedisRateLimiterStore($client, $prefix);
        $rl = new RateLimiter($store, 1, 1); // 1-second window

        try {
            $this->assertTrue($rl->allow('client-1'));
            $this->assertFalse($rl->allow('client-1'));
            usleep(1_100_000);
            $this->assertTrue($rl->allow('client-1'));
        } finally {
            $client->del([$prefix . 'client-1']);
        }
    }

    public function testSetsExpiryOnFirstIncrementOnly(): void
    {
        $client = self::client();
        $prefix = 'securekit-test:' . __FUNCTION__ . ':';
        $store = new RedisRateLimiterStore($client, $prefix);
        $redisKey = $prefix . 'client-1';

        try {
            $store->increment('client-1', 3600);
            $ttl1 = $client->pttl($redisKey);

            usleep(50_000);
            $store->increment('client-1', 3600);
            $ttl2 = $client->pttl($redisKey);

            $this->assertLessThanOrEqual($ttl1, $ttl2, 'TTL should only count down, not reset');
        } finally {
            $client->del([$redisKey]);
        }
    }
}
