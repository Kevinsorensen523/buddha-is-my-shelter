<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\Ssrf;

final class SsrfTest extends TestCase
{
    public function testIsPrivateOrReservedIp(): void
    {
        foreach (['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fe80::1'] as $ip) {
            $this->assertTrue(Ssrf::isPrivateOrReservedIp($ip), "$ip should be flagged private/reserved");
        }
        foreach (['8.8.8.8', '1.1.1.1'] as $ip) {
            $this->assertFalse(Ssrf::isPrivateOrReservedIp($ip), "$ip should be flagged public");
        }
    }

    public function testIsPublicHttpUrlRejectsNonHttpScheme(): void
    {
        $this->assertFalse(Ssrf::isPublicHttpUrl('javascript:alert(1)'));
    }

    public function testIsPublicHttpUrlRejectsLocalhost(): void
    {
        $this->assertFalse(Ssrf::isPublicHttpUrl('http://localhost/'));
        $this->assertFalse(Ssrf::isPublicHttpUrl('http://127.0.0.1/'));
    }
}
