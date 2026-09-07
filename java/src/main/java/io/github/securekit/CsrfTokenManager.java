package io.github.securekit;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stateless CSRF token issuance/verification bound to a session ID and a
 * server-side secret, using HMAC-SHA256.
 */
public final class CsrfTokenManager {

    private final byte[] secret;
    private final long ttlMillis;

    /**
     * @param secret    at least 32 random bytes, kept server-side
     * @param ttlMillis token lifetime in ms; &lt;=0 disables expiry
     */
    public CsrfTokenManager(byte[] secret, long ttlMillis) {
        this.secret = secret.clone();
        this.ttlMillis = ttlMillis;
    }

    public String generate(String sessionId) {
        byte[] nonce = SecureRandomUtil.bytes(16);
        long issuedAt = System.currentTimeMillis();
        byte[] tag = sign(sessionId, nonce, issuedAt);

        ByteBuffer buf = ByteBuffer.allocate(8 + nonce.length + tag.length);
        buf.putLong(issuedAt).put(nonce).put(tag);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
    }

    public boolean verify(String sessionId, String token) {
        byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (raw.length < 8 + 16 + 32) {
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(raw);
        long issuedAt = buf.getLong();
        byte[] nonce = new byte[16];
        buf.get(nonce);
        byte[] tag = new byte[32];
        buf.get(tag);

        if (ttlMillis > 0 && System.currentTimeMillis() - issuedAt > ttlMillis) {
            return false;
        }
        byte[] expected = sign(sessionId, nonce, issuedAt);
        return ConstantTime.equals(expected, tag);
    }

    private byte[] sign(String sessionId, byte[] nonce, long issuedAt) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update(sessionId.getBytes(StandardCharsets.UTF_8));
            mac.update(nonce);
            mac.update(ByteBuffer.allocate(8).putLong(issuedAt).array());
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("securekit: HMAC-SHA256 unavailable", e);
        }
    }
}
