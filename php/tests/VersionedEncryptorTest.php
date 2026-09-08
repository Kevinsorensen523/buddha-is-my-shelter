<?php

declare(strict_types=1);

namespace SecureKit\Tests;

use PHPUnit\Framework\TestCase;
use SecureKit\SecureRandom;
use SecureKit\VersionedEncryptor;

final class VersionedEncryptorTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $key1 = SecureRandom::bytes(32);
        $ve = new VersionedEncryptor([1 => $key1], 1);

        $blob = $ve->encrypt('secret');
        $this->assertSame('secret', $ve->decrypt($blob));
    }

    public function testSurvivesKeyRotation(): void
    {
        $key1 = SecureRandom::bytes(32);
        $key2 = SecureRandom::bytes(32);
        $ve = new VersionedEncryptor([1 => $key1], 1);

        $oldBlob = $ve->encrypt('encrypted with v1');

        $ve->addKey(2, $key2);
        $ve->setCurrentKeyId(2);
        $newBlob = $ve->encrypt('encrypted with v2');

        $this->assertSame('encrypted with v1', $ve->decrypt($oldBlob));
        $this->assertSame('encrypted with v2', $ve->decrypt($newBlob));
    }

    public function testRejectsUnknownKeyId(): void
    {
        $key1 = SecureRandom::bytes(32);
        $ve = new VersionedEncryptor([1 => $key1], 1);
        $blob = $ve->encrypt('data');
        $tampered = chr(99) . substr($blob, 1);

        $this->expectException(\RuntimeException::class);
        $ve->decrypt($tampered);
    }

    public function testConstructorRejectsMissingCurrentKey(): void
    {
        $key1 = SecureRandom::bytes(32);
        $this->expectException(\InvalidArgumentException::class);
        new VersionedEncryptor([1 => $key1], 5);
    }
}
