<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * CSPRNG-backed random generation. Never uses rand()/mt_rand().
 */
final class SecureRandom
{
    /**
     * @throws \Random\RandomException
     */
    public static function bytes(int $length): string
    {
        if ($length <= 0) {
            throw new \InvalidArgumentException('securekit: byte count must be positive');
        }
        return random_bytes($length);
    }

    /**
     * URL-safe base64 token (no padding).
     */
    public static function token(int $byteLength = 32): string
    {
        $b = self::bytes($byteLength);
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }

    public static function hex(int $byteLength = 16): string
    {
        return bin2hex(self::bytes($byteLength));
    }
}
