package io.github.securekit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    @Test
    void roundTrip() {
        PasswordHasher hasher = new PasswordHasher();
        String hash = hasher.hash("correct horse battery staple");
        assertTrue(hasher.verify("correct horse battery staple", hash));
    }

    @Test
    void rejectsWrongPassword() {
        PasswordHasher hasher = new PasswordHasher();
        String hash = hasher.hash("correct-password");
        assertFalse(hasher.verify("wrong-password", hash));
    }

    @Test
    void needsRehashDetectsWeakerParams() {
        PasswordHasher weak = new PasswordHasher(8 * 1024, 1, 1, 16, 32);
        String hash = weak.hash("password");

        PasswordHasher strong = new PasswordHasher();
        assertTrue(strong.needsRehash(hash));
    }

    @Test
    void rejectsEmptyPassword() {
        assertThrows(IllegalArgumentException.class, () -> new PasswordHasher().hash(""));
    }
}
