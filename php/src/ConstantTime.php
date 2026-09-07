<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Timing-attack-resistant comparison utility.
 */
final class ConstantTime
{
    public static function equals(string $a, string $b): bool
    {
        // hash_equals is constant-time for equal-length inputs and safely
        // short-circuits (in constant relative time) on length mismatch,
        // same trade-off as the Go/other ports: lengths of tokens aren't secret.
        return hash_equals($a, $b);
    }
}
