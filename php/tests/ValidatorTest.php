<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\Validator;

final class ValidatorTest extends TestCase
{
    public function testValidEmails(): void
    {
        $this->assertTrue(Validator::isValidEmail('user@example.com'));
        $this->assertFalse(Validator::isValidEmail('not-an-email'));
        $this->assertFalse(Validator::isValidEmail("user@example.com\r\nBcc: x"));
    }

    public function testValidUrls(): void
    {
        $this->assertTrue(Validator::isValidUrl('https://example.com/path'));
        $this->assertFalse(Validator::isValidUrl('javascript:alert(1)'));
        $this->assertFalse(Validator::isValidUrl('file:///etc/passwd'));
    }

    public function testSanitizeFilenameRejectsTraversal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Validator::sanitizeFilename('../../etc/passwd');
    }

    public function testSanitizeFilenameAcceptsCleanName(): void
    {
        $this->assertSame('report-2024.pdf', Validator::sanitizeFilename('report-2024.pdf'));
    }

    public function testEscapeHtmlPreventsXss(): void
    {
        $escaped = Validator::escapeHtml('<script>alert("xss")</script>');
        $this->assertStringNotContainsString('<script>', $escaped);
    }
}
