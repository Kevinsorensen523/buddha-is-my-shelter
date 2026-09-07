package io.github.securekit;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Input validation and output-encoding helpers.
 */
public final class Validator {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\r\\n\\t]");
    private static final Map<String, Pattern> ALLOW_LIST_CACHE = new HashMap<>();

    private Validator() {
    }

    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty() || CONTROL_CHARS.matcher(email).find()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }

    /** Only absolute http(s) URLs are accepted. */
    public static boolean isValidUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            return ("http".equals(scheme) || "https".equals(scheme)) && uri.getHost() != null;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /** @param allowedChars a character-class body, e.g. "a-zA-Z0-9_-" */
    public static boolean isAllowListed(String value, String allowedChars) {
        Pattern p = ALLOW_LIST_CACHE.computeIfAbsent(allowedChars, ac -> Pattern.compile("^[" + ac + "]*$"));
        return p.matcher(value).matches();
    }

    /**
     * Guards against path traversal. Returns the bare filename when safe;
     * callers must still join it with a trusted, fixed base directory.
     */
    public static String sanitizeFilename(String filename) {
        if (filename == null || filename.isEmpty()
                || filename.indexOf('\0') >= 0 || filename.indexOf('/') >= 0 || filename.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("securekit: invalid filename");
        }
        String trimmed = filename.trim();
        if (trimmed.isEmpty() || trimmed.equals(".") || trimmed.equals("..")) {
            throw new IllegalArgumentException("securekit: invalid filename");
        }
        return trimmed;
    }

    /** HTML-escapes for safe inclusion in HTML body context (prevents XSS). */
    public static String escapeHtml(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&#39;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
