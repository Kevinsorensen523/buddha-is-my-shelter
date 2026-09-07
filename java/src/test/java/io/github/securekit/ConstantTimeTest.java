package io.github.securekit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConstantTimeTest {

    @Test
    void equalStringsMatch() {
        assertTrue(ConstantTime.equals("abc123", "abc123"));
    }

    @Test
    void differentStringsDoNotMatch() {
        assertFalse(ConstantTime.equals("abc123", "abc124"));
    }

    @Test
    void differentLengthStringsDoNotMatch() {
        assertFalse(ConstantTime.equals("short", "muchlongerstring"));
    }
}
