<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\ConstantTime;

final class ConstantTimeTest extends TestCase
{
    public function testEqualStringsMatch(): void
    {
        $this->assertTrue(ConstantTime::equals('abc123', 'abc123'));
    }

    public function testDifferentStringsDoNotMatch(): void
    {
        $this->assertFalse(ConstantTime::equals('abc123', 'abc124'));
    }

    public function testDifferentLengthStringsDoNotMatch(): void
    {
        $this->assertFalse(ConstantTime::equals('short', 'muchlongerstring'));
    }
}
