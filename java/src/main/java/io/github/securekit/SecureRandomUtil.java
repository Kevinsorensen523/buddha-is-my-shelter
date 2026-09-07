package io.github.securekit;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * CSPRNG-backed random generation via {@link SecureRandom}. Never uses
 * {@link java.util.Random}.
 */
public final class SecureRandomUtil {

    private static final SecureRandom RNG = new SecureRandom();

    private SecureRandomUtil() {
    }

    public static byte[] bytes(int n) {
        if (n <= 0) {
            throw new IllegalArgumentException("securekit: byte count must be positive");
        }
        byte[] buf = new byte[n];
        RNG.nextBytes(buf);
        return buf;
    }

    /** URL-safe base64 (unpadded) token built from n bytes of entropy. */
    public static String token(int n) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(n));
    }

    /** Lowercase hex-encoded random string built from n bytes of entropy. */
    public static String hex(int n) {
        return HexFormat.of().formatHex(bytes(n));
    }
}
