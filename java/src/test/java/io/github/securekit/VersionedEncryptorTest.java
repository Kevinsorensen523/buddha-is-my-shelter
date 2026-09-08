package io.github.securekit;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VersionedEncryptorTest {

    @Test
    void roundTrip() {
        byte[] key1 = SecureRandomUtil.bytes(32);
        VersionedEncryptor ve = new VersionedEncryptor(Map.of(1, key1), 1);

        byte[] blob = ve.encrypt("secret".getBytes(StandardCharsets.UTF_8), null);
        assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), ve.decrypt(blob, null));
    }

    @Test
    void survivesKeyRotation() {
        byte[] key1 = SecureRandomUtil.bytes(32);
        byte[] key2 = SecureRandomUtil.bytes(32);
        VersionedEncryptor ve = new VersionedEncryptor(Map.of(1, key1), 1);

        byte[] oldBlob = ve.encrypt("encrypted with v1".getBytes(StandardCharsets.UTF_8), null);

        ve.addKey(2, key2);
        ve.setCurrentKeyId(2);
        byte[] newBlob = ve.encrypt("encrypted with v2".getBytes(StandardCharsets.UTF_8), null);

        assertArrayEquals("encrypted with v1".getBytes(StandardCharsets.UTF_8), ve.decrypt(oldBlob, null));
        assertArrayEquals("encrypted with v2".getBytes(StandardCharsets.UTF_8), ve.decrypt(newBlob, null));
    }

    @Test
    void rejectsUnknownKeyId() {
        byte[] key1 = SecureRandomUtil.bytes(32);
        VersionedEncryptor ve = new VersionedEncryptor(Map.of(1, key1), 1);
        byte[] blob = ve.encrypt("data".getBytes(StandardCharsets.UTF_8), null);
        blob[0] = 99;

        assertThrows(DecryptionException.class, () -> ve.decrypt(blob, null));
    }

    @Test
    void constructorRejectsMissingCurrentKey() {
        byte[] key1 = SecureRandomUtil.bytes(32);
        assertThrows(IllegalArgumentException.class, () -> new VersionedEncryptor(Map.of(1, key1), 5));
    }
}
