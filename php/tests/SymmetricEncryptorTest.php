<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\SymmetricEncryptor;

final class SymmetricEncryptorTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $enc = new SymmetricEncryptor();
        $key = $enc->generateKey();
        $ciphertext = $enc->encrypt($key, 'attack at dawn');
        $this->assertSame('attack at dawn', $enc->decrypt($key, $ciphertext));
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $enc = new SymmetricEncryptor();
        $key = $enc->generateKey();
        $ciphertext = $enc->encrypt($key, 'secret');
        $tampered = substr($ciphertext, 0, -1) . chr(ord(substr($ciphertext, -1)) ^ 0xFF);

        $this->expectException(\RuntimeException::class);
        $enc->decrypt($key, $tampered);
    }

    public function testNoncesDiffer(): void
    {
        $enc = new SymmetricEncryptor();
        $key = $enc->generateKey();
        $c1 = $enc->encrypt($key, 'same message');
        $c2 = $enc->encrypt($key, 'same message');
        $this->assertNotSame($c1, $c2);
    }
}
