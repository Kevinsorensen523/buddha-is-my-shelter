package io.github.securekit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CsrfTokenManagerTest {

    @Test
    void roundTrip() {
        CsrfTokenManager mgr = new CsrfTokenManager(SecureRandomUtil.bytes(32), 3600_000L);
        String token = mgr.generate("session-123");
        assertTrue(mgr.verify("session-123", token));
    }

    @Test
    void rejectsWrongSession() {
        CsrfTokenManager mgr = new CsrfTokenManager(SecureRandomUtil.bytes(32), 3600_000L);
        String token = mgr.generate("session-A");
        assertFalse(mgr.verify("session-B", token));
    }

    @Test
    void rejectsExpiredToken() throws InterruptedException {
        CsrfTokenManager mgr = new CsrfTokenManager(SecureRandomUtil.bytes(32), 5L);
        String token = mgr.generate("session-123");
        Thread.sleep(30);
        assertFalse(mgr.verify("session-123", token));
    }

    @Test
    void rejectsForgedToken() {
        CsrfTokenManager mgr = new CsrfTokenManager(SecureRandomUtil.bytes(32), 3600_000L);
        assertFalse(mgr.verify("session-123", "forged.token.value"));
    }
}
