package io.github.securekit;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptorTest {

    @Test
    void roundTrip() {
        SymmetricEncryptor enc = new SymmetricEncryptor();
        byte[] key = enc.generateKey();
        byte[] plaintext = "attack at dawn".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = enc.encrypt(key, plaintext, null);
        byte[] decrypted = enc.decrypt(key, ciphertext, null);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void rejectsTamperedCiphertext() {
        SymmetricEncryptor enc = new SymmetricEncryptor();
        byte[] key = enc.generateKey();
        byte[] ciphertext = enc.encrypt(key, "secret".getBytes(StandardCharsets.UTF_8), null);
        ciphertext[ciphertext.length - 1] ^= 0xFF;

        assertThrows(DecryptionException.class, () -> enc.decrypt(key, ciphertext, null));
    }

    @Test
    void noncesDiffer() {
        SymmetricEncryptor enc = new SymmetricEncryptor();
        byte[] key = enc.generateKey();
        byte[] plaintext = "same message".getBytes(StandardCharsets.UTF_8);
        byte[] c1 = enc.encrypt(key, plaintext, null);
        byte[] c2 = enc.encrypt(key, plaintext, null);
        assertFalse(Arrays.equals(c1, c2));
    }
}
