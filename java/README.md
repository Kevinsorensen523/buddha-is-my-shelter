# Buddha is My Shelter (Java)

Java port of the Buddha is My Shelter security toolkit, mirroring the Go
reference implementation's behavior and PHC hash / token wire formats.

## Requirements

- Java 17+
- Maven 3.8+

## Install

```xml
<dependency>
  <groupId>io.github.kevinsorensen523</groupId>
  <artifactId>buddha-is-my-shelter</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'io.github.kevinsorensen523:buddha-is-my-shelter:0.1.0'
```

## Modules

### SecureRandomUtil

```java
import io.github.securekit.SecureRandomUtil;

String token = SecureRandomUtil.token(32); // URL-safe base64
String hex = SecureRandomUtil.hex(16);
byte[] raw = SecureRandomUtil.bytes(32);
```

### PasswordHasher (Argon2id)

```java
import io.github.securekit.PasswordHasher;

PasswordHasher hasher = new PasswordHasher();
String hash = hasher.hash("correct horse battery staple");
boolean ok = hasher.verify("correct horse battery staple", hash);
if (hasher.needsRehash(hash)) {
    // re-hash and update stored value on next successful login
}
```

Backed by Bouncy Castle's `Argon2BytesGenerator`. Output is a standard PHC
string, compatible with the other language ports.

### SymmetricEncryptor (AES-256-GCM AEAD)

```java
import io.github.securekit.SymmetricEncryptor;

SymmetricEncryptor enc = new SymmetricEncryptor();
byte[] key = enc.generateKey();

byte[] ciphertext = enc.encrypt(key, plaintext, null); // aad optional
byte[] decrypted = enc.decrypt(key, ciphertext, null);
```

Backed by the standard JCE (`javax.crypto`, `AES/GCM/NoPadding`). Nonces
(IVs) are generated internally and prepended to the ciphertext — there is no
API to supply your own. `decrypt()` always throws the generic
`DecryptionException`.

### Validator

```java
import io.github.securekit.Validator;

Validator.isValidEmail("user@example.com");     // true
Validator.isValidUrl("https://example.com");     // true, rejects non-http(s)
String name = Validator.sanitizeFilename("report.pdf"); // throws on traversal
String safe = Validator.escapeHtml("<script>alert(1)</script>");
```

### VersionedEncryptor (key rotation)

```java
import io.github.securekit.VersionedEncryptor;

VersionedEncryptor ve = new VersionedEncryptor(Map.of(1, keyV1), 1);
byte[] blob = ve.encrypt("secret".getBytes(StandardCharsets.UTF_8), null);

// later, after rotating in a new key:
ve.addKey(2, keyV2);
ve.setCurrentKeyId(2); // new encryptions use keyV2; old ciphertexts (keyId=1) still decrypt
byte[] plaintext = ve.decrypt(blob, null);
```

### SSRF guard

```java
import io.github.securekit.Ssrf;

Ssrf.isPublicHttpUrl("https://example.com");     // true
Ssrf.isPublicHttpUrl("http://169.254.169.254/"); // false: resolves to link-local
```

Performs a real DNS lookup — use `Validator.isValidUrl()` first for cheap
structural checks, and this only right before making a server-side request
to a caller-supplied URL. See the Javadoc for the DNS-rebinding caveat.

### CsrfTokenManager

```java
import io.github.securekit.CsrfTokenManager;
import io.github.securekit.SecureRandomUtil;

byte[] secret = SecureRandomUtil.bytes(32); // store server-side
CsrfTokenManager mgr = new CsrfTokenManager(secret, 3_600_000L); // ttl in ms

String token = mgr.generate(sessionId);
boolean ok = mgr.verify(sessionId, submittedToken);
```

### RateLimiter

```java
import io.github.securekit.RateLimiter;
import io.github.securekit.MemoryRateLimiterStore;

RateLimiter limiter = new RateLimiter(new MemoryRateLimiterStore(), 100, 60_000L);
if (!limiter.allow(clientIp)) {
    // reject: too many requests
}
```

`MemoryRateLimiterStore` is process-local only. Implement `RateLimiterStore`
against Redis for multi-instance deployments — see
[../THREAT_MODEL.md](../THREAT_MODEL.md).

### ConstantTime

```java
import io.github.securekit.ConstantTime;
ConstantTime.equals(a, b); // wraps MessageDigest.isEqual
```

## Framework Integration

See [../examples/java](../examples/java) for a Spring Boot filter example
wiring `CsrfTokenManager` and `RateLimiter` into the request pipeline.
**Read [../examples/README.md](../examples/README.md) first** -- covers
real deployment gotchas (multi-instance state, reverse-proxy trust) these
examples are subject to.

## Testing

```bash
mvn test
mvn spotbugs:check
```

## Security Notes

- Argon2id comes from Bouncy Castle (`bcprov-jdk18on`); AES-GCM comes from
  the JDK's own JCE provider — no custom crypto.
- `Validator.sanitizeFilename()` returns only a bare filename; callers must
  still join it with a trusted, fixed base directory.
