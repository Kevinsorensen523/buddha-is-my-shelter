package io.github.securekit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ValidatorTest {

    @Test
    void validEmails() {
        assertTrue(Validator.isValidEmail("user@example.com"));
        assertFalse(Validator.isValidEmail("not-an-email"));
        assertFalse(Validator.isValidEmail("user@example.com\r\nBcc: x"));
    }

    @Test
    void validUrls() {
        assertTrue(Validator.isValidUrl("https://example.com/path"));
        assertFalse(Validator.isValidUrl("javascript:alert(1)"));
        assertFalse(Validator.isValidUrl("file:///etc/passwd"));
    }

    @Test
    void sanitizeFilenameRejectsTraversal() {
        assertThrows(IllegalArgumentException.class, () -> Validator.sanitizeFilename("../../etc/passwd"));
    }

    @Test
    void sanitizeFilenameAcceptsCleanName() {
        assertEquals("report-2024.pdf", Validator.sanitizeFilename("report-2024.pdf"));
    }

    @Test
    void escapeHtmlPreventsXss() {
        String escaped = Validator.escapeHtml("<script>alert(\"xss\")</script>");
        assertFalse(escaped.contains("<script>"));
    }
}
