package io.github.securekit;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AEAD encryption using AES-256-GCM via the standard JCE ({@code javax.crypto})
 * -- no custom crypto.
 *
 * <p>Nonces (IVs) are generated internally and prepended to the ciphertext;
 * there is no API to supply a caller-chosen nonce, eliminating nonce-reuse
 * misuse. Decryption failures always throw the generic
 * {@link DecryptionException}.
 */
public final class SymmetricEncryptor {

    private static final int KEY_LEN = 32;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;

    public byte[] generateKey() {
        return SecureRandomUtil.bytes(KEY_LEN);
    }

    public byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad) {
        if (key.length != KEY_LEN) {
            throw new IllegalArgumentException("securekit: key must be 32 bytes");
        }
        try {
            byte[] iv = SecureRandomUtil.bytes(IV_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] out = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("securekit: encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] key, byte[] blob, byte[] aad) {
        if (key.length != KEY_LEN || blob.length < IV_LEN) {
            throw new DecryptionException();
        }
        try {
            byte[] iv = Arrays.copyOfRange(blob, 0, IV_LEN);
            byte[] ciphertext = Arrays.copyOfRange(blob, IV_LEN, blob.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new DecryptionException(e);
        }
    }

    public String encryptToString(byte[] key, byte[] plaintext, byte[] aad) {
        return Base64.getEncoder().encodeToString(encrypt(key, plaintext, aad));
    }

    public byte[] decryptFromString(byte[] key, String encoded, byte[] aad) {
        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new DecryptionException(e);
        }
        return decrypt(key, blob, aad);
    }
}
