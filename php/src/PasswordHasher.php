<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Argon2id password hashing via PHP's native password_hash()/password_verify(),
 * which itself wraps libargon2. Falls back to bcrypt only if the runtime PHP
 * build lacks the Argon2id algorithm (rare on modern PHP builds without
 * --with-password-argon2).
 *
 * Output is the standard PHC string, cross-compatible with the Go/Python/
 * Node/Java ports: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
 */
final class PasswordHasher
{
    private string $algo;
    private array $options;

    public function __construct(
        int $memoryCostKiB = 65536,
        int $timeCost = 3,
        int $parallelism = 4
    ) {
        $this->algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $this->options = $this->algo === PASSWORD_ARGON2ID
            ? ['memory_cost' => $memoryCostKiB, 'time_cost' => $timeCost, 'threads' => $parallelism]
            : ['cost' => 12];
    }

    public function hash(string $password): string
    {
        if ($password === '') {
            throw new \InvalidArgumentException('securekit: password must not be empty');
        }
        // password_hash() with a valid algo/options never returns false in PHP 8+
        // (it throws on failure instead), so no false-check is needed here.
        return password_hash($password, $this->algo, $this->options);
    }

    public function verify(string $password, string $encodedHash): bool
    {
        return password_verify($password, $encodedHash);
    }

    public function needsRehash(string $encodedHash): bool
    {
        return password_needs_rehash($encodedHash, $this->algo, $this->options);
    }
}
