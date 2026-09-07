<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\PasswordHasher;

final class PasswordHasherTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct horse battery staple');
        $this->assertTrue($hasher->verify('correct horse battery staple', $hash));
    }

    public function testRejectsWrongPassword(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct-password');
        $this->assertFalse($hasher->verify('wrong-password', $hash));
    }

    public function testNeedsRehashDetectsWeakerParams(): void
    {
        $weak = new PasswordHasher(memoryCostKiB: 8192, timeCost: 1, parallelism: 1);
        $hash = $weak->hash('password');

        $strong = new PasswordHasher();
        $this->assertTrue($strong->needsRehash($hash));
    }

    public function testRejectsEmptyPassword(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new PasswordHasher())->hash('');
    }
}
