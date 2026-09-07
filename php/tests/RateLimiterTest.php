<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\MemoryRateLimiterStore;
use SecureKit\RateLimiter;

final class RateLimiterTest extends TestCase
{
    public function testAllowsUnderLimitAndBlocksOver(): void
    {
        $rl = new RateLimiter(new MemoryRateLimiterStore(), 3, 60);
        $this->assertTrue($rl->allow('client-1'));
        $this->assertTrue($rl->allow('client-1'));
        $this->assertTrue($rl->allow('client-1'));
        $this->assertFalse($rl->allow('client-1'));
    }

    public function testTracksKeysIndependently(): void
    {
        $rl = new RateLimiter(new MemoryRateLimiterStore(), 1, 60);
        $this->assertTrue($rl->allow('client-A'));
        $this->assertTrue($rl->allow('client-B'));
    }
}
