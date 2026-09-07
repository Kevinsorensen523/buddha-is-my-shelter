package io.github.securekit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Timing-attack-resistant comparison utility.
 */
public final class ConstantTime {

    private ConstantTime() {
    }

    public static boolean equals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            // Length mismatch is an intentional early exit -- see the Go
            // port's ConstantTimeEqual doc comment for rationale.
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    public static boolean equals(String a, String b) {
        return equals(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
