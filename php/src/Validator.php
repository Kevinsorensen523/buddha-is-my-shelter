<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Input validation and output-encoding helpers.
 */
final class Validator
{
    public static function isValidEmail(string $email): bool
    {
        if ($email === '' || preg_match('/[\r\n\t]/', $email)) {
            return false;
        }
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Only absolute http(s) URLs are accepted; other schemes
     * (javascript:, data:, file:, ...) are rejected.
     */
    public static function isValidUrl(string $url): bool
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $scheme = parse_url($url, PHP_URL_SCHEME);
        return $scheme === 'http' || $scheme === 'https';
    }

    /**
     * @param string $allowedChars a character-class body, e.g. "a-zA-Z0-9_-"
     */
    public static function isAllowListed(string $value, string $allowedChars): bool
    {
        return (bool) preg_match('/^[' . $allowedChars . ']*$/', $value);
    }

    /**
     * Guards against path traversal: rejects any path separators, NUL bytes,
     * and dot-only names. Returns the filename unmodified when safe.
     *
     * @throws \InvalidArgumentException on unsafe input
     */
    public static function sanitizeFilename(string $filename): string
    {
        if ($filename === '' || str_contains($filename, "\0")
            || str_contains($filename, '/') || str_contains($filename, '\\')) {
            throw new \InvalidArgumentException('securekit: invalid filename');
        }
        $trimmed = trim($filename);
        if ($trimmed === '' || $trimmed === '.' || $trimmed === '..') {
            throw new \InvalidArgumentException('securekit: invalid filename');
        }
        return $trimmed;
    }

    /**
     * HTML-escapes for safe inclusion in HTML body context (prevents XSS).
     */
    public static function escapeHtml(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
