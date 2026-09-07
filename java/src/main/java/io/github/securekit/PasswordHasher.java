package io.github.securekit;

import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id password hashing via Bouncy Castle's {@link Argon2BytesGenerator}
 * -- no custom crypto.
 *
 * <p>Output is the standard PHC string, cross-compatible with the Go/PHP/
 * Python/Node ports: {@code $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>}
 */
public final class PasswordHasher {

    private static final Pattern PHC_PATTERN =
            Pattern.compile("^\\$argon2id\\$v=(\\d+)\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$([^$]+)\\$([^$]+)$");
    private static final Base64.Encoder ENC = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getDecoder();

    private final int memoryCostKiB;
    private final int iterations;
    private final int parallelism;
    private final int saltLen;
    private final int hashLen;

    public PasswordHasher() {
        this(64 * 1024, 3, 4, 16, 32);
    }

    public PasswordHasher(int memoryCostKiB, int iterations, int parallelism, int saltLen, int hashLen) {
        this.memoryCostKiB = memoryCostKiB;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.saltLen = saltLen;
        this.hashLen = hashLen;
    }

    public String hash(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("securekit: password must not be empty");
        }
        byte[] salt = SecureRandomUtil.bytes(saltLen);
        byte[] hash = deriveKey(password, salt, memoryCostKiB, iterations, parallelism, hashLen);
        return String.format(
                Locale.ROOT,
                "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
                memoryCostKiB, iterations, parallelism,
                ENC.encodeToString(salt), ENC.encodeToString(hash));
    }

    public boolean verify(String password, String encodedHash) {
        Matcher m = PHC_PATTERN.matcher(encodedHash);
        if (!m.matches()) {
            return false;
        }
        int m_ = Integer.parseInt(m.group(2));
        int t = Integer.parseInt(m.group(3));
        int p = Integer.parseInt(m.group(4));
        byte[] salt = DEC.decode(m.group(5));
        byte[] expected = DEC.decode(m.group(6));

        byte[] candidate = deriveKey(password, salt, m_, t, p, expected.length);
        return ConstantTime.equals(candidate, expected);
    }

    public boolean needsRehash(String encodedHash) {
        Matcher m = PHC_PATTERN.matcher(encodedHash);
        if (!m.matches()) {
            return true;
        }
        int m_ = Integer.parseInt(m.group(2));
        int t = Integer.parseInt(m.group(3));
        int p = Integer.parseInt(m.group(4));
        byte[] salt = DEC.decode(m.group(5));
        byte[] hashBytes = DEC.decode(m.group(6));
        return m_ < memoryCostKiB || t < iterations || p < parallelism
                || salt.length < saltLen || hashBytes.length < hashLen;
    }

    private static byte[] deriveKey(String password, byte[] salt, int memKiB, int iterations, int parallelism, int outLen) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memKiB)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[outLen];
        gen.generateBytes(password.toCharArray(), out);
        return out;
    }
}
