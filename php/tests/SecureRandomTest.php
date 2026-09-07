<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\SecureRandom;

final class SecureRandomTest extends TestCase
{
    public function testBytesHasRequestedLength(): void
    {
        $this->assertSame(32, strlen(SecureRandom::bytes(32)));
    }

    public function testBytesAreUnique(): void
    {
        $this->assertNotSame(SecureRandom::bytes(32), SecureRandom::bytes(32));
    }

    public function testRejectsNonPositiveLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecureRandom::bytes(0);
    }

    public function testTokenIsUrlSafe(): void
    {
        $token = SecureRandom::token(32);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $token);
    }
}
