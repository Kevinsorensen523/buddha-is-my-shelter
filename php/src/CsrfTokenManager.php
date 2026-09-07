<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Stateless CSRF token issuance/verification bound to a session ID and a
 * server-side secret, using HMAC-SHA256. No server-side token store needed.
 */
final class CsrfTokenManager
{
    public function __construct(
        private readonly string $secret,
        private readonly int $ttlSeconds = 3600
    ) {
    }

    public function generate(string $sessionId): string
    {
        $nonce = random_bytes(16);
        $issuedAt = (int) (microtime(true) * 1000);
        $tag = $this->sign($sessionId, $nonce, $issuedAt);
        $raw = pack('J', $issuedAt) . $nonce . $tag;
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function verify(string $sessionId, string $token): bool
    {
        $raw = base64_decode(strtr($token, '-_', '+/'), true);
        if ($raw === false || strlen($raw) < 8 + 16 + 32) {
            return false;
        }
        $issuedAt = unpack('J', substr($raw, 0, 8))[1];
        $nonce = substr($raw, 8, 16);
        $tag = substr($raw, 24, 32);

        if ($this->ttlSeconds > 0) {
            $ageMs = (int) (microtime(true) * 1000) - $issuedAt;
            if ($ageMs > $this->ttlSeconds * 1000) {
                return false;
            }
        }

        $expected = $this->sign($sessionId, $nonce, $issuedAt);
        return ConstantTime::equals($expected, $tag);
    }

    private function sign(string $sessionId, string $nonce, int $issuedAt): string
    {
        return hash_hmac('sha256', $sessionId . $nonce . pack('J', $issuedAt), $this->secret, true);
    }
}
