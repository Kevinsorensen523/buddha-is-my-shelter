# securekit (Go)

Reference implementation of the securekit security toolkit. All other
language ports (PHP, Python, JavaScript, Java) mirror this package's
behavior and PHC hash / token wire formats.

## Requirements

- Go 1.22+

## Install

```bash
go get github.com/kevinsorensen523/securekit/go@latest
```

Then import as:

```go
import securekit "github.com/kevinsorensen523/securekit/go"
```

## Modules

### SecureRandom

```go
token, err := securekit.SecureRandomToken(32) // URL-safe base64
hex, err := securekit.SecureRandomHex(16)
raw, err := securekit.SecureRandomBytes(32)
```

### PasswordHasher (Argon2id)

```go
hasher := securekit.NewDefaultPasswordHasher()

hash, err := hasher.Hash("correct horse battery staple")
ok, err := hasher.Verify("correct horse battery staple", hash)
if hasher.NeedsRehash(hash) {
    // re-hash and update stored value on next successful login
}
```

Hashes are encoded as PHC strings (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`),
compatible with the other language ports.

### SymmetricEncryptor (XChaCha20-Poly1305 AEAD)

```go
enc := securekit.NewSymmetricEncryptor()
key, err := enc.GenerateKey()

ciphertext, err := enc.Encrypt(key, []byte("secret message"), nil) // aad optional
plaintext, err := enc.Decrypt(key, ciphertext, nil)
```

Nonces are generated internally and prepended to the ciphertext automatically
— there is no API to supply your own nonce, which eliminates nonce-reuse
misuse. Decryption failures always return the generic `ErrDecryptionFailed`.

### InputValidator / Sanitizer

```go
securekit.ValidateEmail("user@example.com")     // true
securekit.ValidateURL("https://example.com")     // true, rejects non-http(s) schemes
securekit.ValidateAllowList("abc123", "a-z0-9")  // true
name, err := securekit.SanitizeFilename("../../etc/passwd") // err != nil
safe := securekit.EscapeHTML(`<script>alert(1)</script>`)
```

### CsrfTokenManager

```go
secret, _ := securekit.SecureRandomBytes(32) // store server-side
mgr := securekit.NewCsrfTokenManager(secret, time.Hour)

token, err := mgr.Generate(sessionID)
ok := mgr.Verify(sessionID, submittedToken)
```

### RateLimiter

```go
limiter := securekit.NewRateLimiter(securekit.NewMemoryStore(), 100, time.Minute)
if !limiter.Allow(clientIP) {
    // reject: too many requests
}
```

`MemoryStore` is process-local only. For multi-instance deployments,
implement `RateLimiterStore` against Redis or similar shared storage (see
[../THREAT_MODEL.md](../THREAT_MODEL.md)).

### ConstantTimeEqual

```go
securekit.ConstantTimeEqualString(a, b) // resists timing attacks
```

## Testing

```bash
go test ./... -v
go vet ./...
```

## Security Notes

- All cryptographic primitives come from `crypto/rand`, `golang.org/x/crypto/argon2`,
  and `golang.org/x/crypto/chacha20poly1305` — no custom crypto.
- Errors from `SymmetricEncryptor.Decrypt` are always the same generic
  `ErrDecryptionFailed`, regardless of failure cause.
