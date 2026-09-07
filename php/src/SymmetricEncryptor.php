<?php

declare(strict_types=1);

namespace SecureKit;

/**
 * AEAD encryption using XChaCha20-Poly1305 via ext-sodium. Nonces are
 * generated internally and prepended to the ciphertext; there is no API to
 * supply a caller-chosen nonce, eliminating nonce-reuse misuse.
 */
final class SymmetricEncryptor
{
    private const KEY_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES; // 32
    private const NONCE_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24

    public function generateKey(): string
    {
        return sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    }

    public function encrypt(string $key, string $plaintext, string $aad = ''): string
    {
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new \InvalidArgumentException('securekit: key must be 32 bytes');
        }
        $nonce = random_bytes(self::NONCE_LENGTH);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
        return $nonce . $ciphertext;
    }

    /**
     * @throws \RuntimeException with a generic message on any failure
     */
    public function decrypt(string $key, string $blob, string $aad = ''): string
    {
        if (strlen($key) !== self::KEY_LENGTH || strlen($blob) < self::NONCE_LENGTH) {
            throw new \RuntimeException('securekit: decryption failed');
        }
        $nonce = substr($blob, 0, self::NONCE_LENGTH);
        $ciphertext = substr($blob, self::NONCE_LENGTH);
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key);
        if ($plaintext === false) {
            throw new \RuntimeException('securekit: decryption failed');
        }
        return $plaintext;
    }

    public function encryptToString(string $key, string $plaintext, string $aad = ''): string
    {
        return base64_encode($this->encrypt($key, $plaintext, $aad));
    }

    public function decryptFromString(string $key, string $encoded, string $aad = ''): string
    {
        $blob = base64_decode($encoded, true);
        if ($blob === false) {
            throw new \RuntimeException('securekit: decryption failed');
        }
        return $this->decrypt($key, $blob, $aad);
    }
}
