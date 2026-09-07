package io.github.securekit;

/**
 * Thrown for any decryption failure. The message is intentionally generic
 * (never distinguishes "too short" vs "tag mismatch") to avoid leaking
 * oracle information to an attacker.
 */
public final class DecryptionException extends RuntimeException {
    public DecryptionException() {
        super("securekit: decryption failed");
    }

    public DecryptionException(Throwable cause) {
        super("securekit: decryption failed", cause);
    }
}
