<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * Wraps SymmetricEncryptor with key-ID-tagged ciphertexts, so keys can be
 * rotated without losing the ability to decrypt data encrypted under a
 * previous key. Wire format: 1-byte key ID followed by whatever
 * SymmetricEncryptor::encrypt() produces. Supports up to 256 concurrently-
 * known key versions.
 */
final class VersionedEncryptor
{
    private SymmetricEncryptor $inner;
    /** @var array<int, string> */
    private array $keys;
    private int $currentId;

    /**
     * @param array<int, string> $keys keyId (0-255) => raw 32-byte key
     * @throws \InvalidArgumentException if $currentKeyId is not in $keys
     */
    public function __construct(array $keys, int $currentKeyId)
    {
        if (!array_key_exists($currentKeyId, $keys)) {
            throw new \InvalidArgumentException('securekit: current key ID not found in key set');
        }
        $this->inner = new SymmetricEncryptor();
        $this->keys = $keys;
        $this->currentId = $currentKeyId;
    }

    /** Registers a new key version without changing which key is current. */
    public function addKey(int $id, string $key): void
    {
        $this->keys[$id] = $key;
    }

    /**
     * Switches which registered key new encrypt() calls use.
     * @throws \InvalidArgumentException if $id was never registered
     */
    public function setCurrentKeyId(int $id): void
    {
        if (!array_key_exists($id, $this->keys)) {
            throw new \InvalidArgumentException('securekit: key ID not found in key set');
        }
        $this->currentId = $id;
    }

    public function encrypt(string $plaintext, string $aad = ''): string
    {
        $blob = $this->inner->encrypt($this->keys[$this->currentId], $plaintext, $aad);
        return chr($this->currentId) . $blob;
    }

    /**
     * @throws \RuntimeException with a generic message on any failure,
     * including an unrecognized key ID, to avoid leaking which key IDs
     * are valid.
     */
    public function decrypt(string $blob, string $aad = ''): string
    {
        if (strlen($blob) < 1) {
            throw new \RuntimeException('securekit: decryption failed');
        }
        $id = ord($blob[0]);
        if (!array_key_exists($id, $this->keys)) {
            throw new \RuntimeException('securekit: decryption failed');
        }
        return $this->inner->decrypt($this->keys[$id], substr($blob, 1), $aad);
    }
}
