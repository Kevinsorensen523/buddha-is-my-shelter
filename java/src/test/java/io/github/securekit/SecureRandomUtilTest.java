package io.github.securekit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecureRandomUtilTest {

    @Test
    void bytesHasRequestedLength() {
        assertEquals(32, SecureRandomUtil.bytes(32).length);
    }

    @Test
    void bytesAreUnique() {
        assertFalse(java.util.Arrays.equals(SecureRandomUtil.bytes(32), SecureRandomUtil.bytes(32)));
    }

    @Test
    void rejectsNonPositiveLength() {
        assertThrows(IllegalArgumentException.class, () -> SecureRandomUtil.bytes(0));
    }

    @Test
    void tokenIsUrlSafe() {
        String token = SecureRandomUtil.token(32);
        assertTrue(token.matches("^[A-Za-z0-9_-]+$"));
    }
}
