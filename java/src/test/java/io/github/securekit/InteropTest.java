package io.github.securekit;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-language interop tests. Loads the shared fixtures in
 * ../../../../../../vectors/*.json (generated once from each language's own
 * implementation) and verifies this package can consume tokens/hashes/
 * ciphertexts produced by every other port.
 *
 * <p>Uses a tiny hand-rolled JSON reader instead of pulling in a JSON
 * library dependency just for tests.
 */
class InteropTest {

    private static final Path VECTORS_DIR = Path.of("..", "vectors");

    private static String readFile(String name) throws IOException {
        return Files.readString(VECTORS_DIR.resolve(name), StandardCharsets.UTF_8);
    }

    /** Extracts a top-level string object's key/value pairs, e.g. "hashes": {...}. */
    private static Map<String, String> extractObject(String json, String key) {
        Pattern outer = Pattern.compile("\"" + key + "\"\\s*:\\s*\\{([^}]*)\\}", Pattern.DOTALL);
        Matcher m = outer.matcher(json);
        if (!m.find()) {
            throw new IllegalStateException("key not found: " + key);
        }
        Map<String, String> result = new LinkedHashMap<>();
        Pattern pair = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
        Matcher pm = pair.matcher(m.group(1));
        while (pm.find()) {
            result.put(pm.group(1), pm.group(2));
        }
        return result;
    }

    private static String extractString(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) {
            throw new IllegalStateException("key not found: " + key);
        }
        return m.group(1);
    }

    private static List<String> extractStringArray(String json, String groupsKey, String arrayKey) {
        Pattern outer = Pattern.compile("\"" + groupsKey + "\"\\s*:\\s*\\{(.*?)\\}\\s*\\}", Pattern.DOTALL);
        Matcher m = outer.matcher(json);
        if (!m.find()) {
            throw new IllegalStateException("key not found: " + groupsKey);
        }
        Pattern arr = Pattern.compile("\"" + arrayKey + "\"\\s*:\\s*\\[([^\\]]*)\\]");
        Matcher am = arr.matcher(m.group(1));
        if (!am.find()) {
            throw new IllegalStateException("key not found: " + arrayKey);
        }
        return List.of(am.group(1).replace("\"", "").split("\\s*,\\s*"));
    }

    @Test
    void passwordHashesInterop() throws IOException {
        String json = readFile("password_hashes.json");
        String password = extractString(json, "password");
        Map<String, String> hashes = extractObject(json, "hashes");

        PasswordHasher hasher = new PasswordHasher();
        for (Map.Entry<String, String> e : hashes.entrySet()) {
            assertTrue(hasher.verify(password, e.getValue()),
                    e.getKey() + ": hash did not verify (PHC format not portable)");
        }
    }

    @Test
    void csrfTokensInterop() throws IOException {
        String json = readFile("csrf_tokens.json");
        byte[] secret = Base64.getDecoder().decode(extractString(json, "secretBase64"));
        String sessionId = extractString(json, "sessionId");
        Map<String, String> tokens = extractObject(json, "tokens");

        CsrfTokenManager mgr = new CsrfTokenManager(secret, 0L); // ttl<=0: never expires
        for (Map.Entry<String, String> e : tokens.entrySet()) {
            assertTrue(mgr.verify(sessionId, e.getValue()),
                    e.getKey() + ": token did not verify (binary format not portable)");
        }
    }

    @Test
    void aeadInteropWithinCompatibilityGroup() throws IOException {
        String json = readFile("aead_ciphertexts.json");
        byte[] key = Base64.getDecoder().decode(extractString(json, "keyBase64"));
        String plaintext = extractString(json, "plaintext");
        Map<String, String> ciphertexts = extractObject(json, "ciphertexts");
        Set<String> group = new HashSet<>(extractStringArray(json, "compatibilityGroups", "aes256gcm"));

        SymmetricEncryptor enc = new SymmetricEncryptor();
        for (Map.Entry<String, String> e : ciphertexts.entrySet()) {
            byte[] ct = Base64.getDecoder().decode(e.getValue());
            if (group.contains(e.getKey())) {
                byte[] pt = enc.decrypt(key, ct, null);
                assertEquals(plaintext, new String(pt, StandardCharsets.UTF_8),
                        e.getKey() + ": plaintext mismatch");
            } else {
                assertThrows(DecryptionException.class, () -> enc.decrypt(key, ct, null),
                        e.getKey() + ": expected decrypt to fail (different AEAD construction)");
            }
        }
    }
}
