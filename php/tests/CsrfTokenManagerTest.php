<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\CsrfTokenManager;
use SecureKit\SecureRandom;

final class CsrfTokenManagerTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $mgr = new CsrfTokenManager(SecureRandom::bytes(32), 3600);
        $token = $mgr->generate('session-123');
        $this->assertTrue($mgr->verify('session-123', $token));
    }

    public function testRejectsWrongSession(): void
    {
        $mgr = new CsrfTokenManager(SecureRandom::bytes(32), 3600);
        $token = $mgr->generate('session-A');
        $this->assertFalse($mgr->verify('session-B', $token));
    }

    public function testRejectsExpiredToken(): void
    {
        $mgr = new CsrfTokenManager(SecureRandom::bytes(32), 1);
        $token = $mgr->generate('session-123');
        usleep(1_100_000);
        $this->assertFalse($mgr->verify('session-123', $token));
    }

    public function testRejectsForgedToken(): void
    {
        $mgr = new CsrfTokenManager(SecureRandom::bytes(32), 3600);
        $this->assertFalse($mgr->verify('session-123', 'forged.token.value'));
    }
}
