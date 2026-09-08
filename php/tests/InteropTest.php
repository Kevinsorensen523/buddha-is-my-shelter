<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\CsrfTokenManager;
use SecureKit\PasswordHasher;
use SecureKit\SymmetricEncryptor;

/**
 * Cross-language interop tests. Loads the shared fixtures in ../../vectors/*.json
 * (generated once from each language's own implementation) and verifies this
 * package can consume tokens/hashes/ciphertexts produced by every other port.
 */
final class InteropTest extends TestCase
{
    private const VECTORS_DIR = __DIR__ . '/../../vectors';

    private function loadVectors(string $name): array
    {
        $path = self::VECTORS_DIR . '/' . $name;
        $data = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        return $data;
    }

    public function testPasswordHashesInterop(): void
    {
        $vecs = $this->loadVectors('password_hashes.json');
        $hasher = new PasswordHasher();

        foreach ($vecs['hashes'] as $lang => $hash) {
            $this->assertTrue(
                $hasher->verify($vecs['password'], $hash),
                "$lang: hash did not verify against shared password (PHC format not portable)"
            );
        }
    }

    public function testCsrfTokensInterop(): void
    {
        $vecs = $this->loadVectors('csrf_tokens.json');
        $secret = base64_decode($vecs['secretBase64'], true);
        $mgr = new CsrfTokenManager($secret, 0); // ttl<=0: never expires, fixture-safe

        foreach ($vecs['tokens'] as $lang => $token) {
            $this->assertTrue(
                $mgr->verify($vecs['sessionId'], $token),
                "$lang: token did not verify (binary token format not portable)"
            );
        }
    }

    public function testAeadInteropWithinCompatibilityGroup(): void
    {
        $vecs = $this->loadVectors('aead_ciphertexts.json');
        $key = base64_decode($vecs['keyBase64'], true);
        $enc = new SymmetricEncryptor();

        $group = array_flip($vecs['compatibilityGroups']['xchacha20poly1305']);

        foreach ($vecs['ciphertexts'] as $lang => $ctB64) {
            $ct = base64_decode($ctB64, true);
            if (isset($group[$lang])) {
                $plaintext = $enc->decrypt($key, $ct);
                $this->assertSame($vecs['plaintext'], $plaintext, "$lang: decrypted plaintext mismatch");
            } else {
                try {
                    $enc->decrypt($key, $ct);
                    $this->fail("$lang: expected decrypt to fail (different AEAD construction), but it succeeded");
                } catch (\RuntimeException $e) {
                    $this->assertSame('securekit: decryption failed', $e->getMessage());
                }
            }
        }
    }
}
