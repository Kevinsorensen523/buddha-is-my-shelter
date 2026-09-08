# Roadmap

This tracks the full ambition for Buddha is My Shelter beyond the initial
v0.1.0 release, so the scope is visible even while execution happens
incrementally across sessions. Status legend: ✅ done · 🚧 in progress ·
📋 planned.

## Hardening the existing five modules

- ✅ **Cross-language interop test vectors** (`vectors/`) — proves
  PasswordHasher and CsrfTokenManager wire formats are portable across all
  five ports; found and fixed a real bug (Go's CSRF timestamp was in
  nanoseconds while the other four used milliseconds).
- ✅ **SSRF-hardening** (`isPublicHttpUrl` / `is_public_http_url` /
  `IsPublicHTTPURL`) — DNS-resolves a URL's hostname and rejects it if any
  resolved address is private/loopback/link-local/reserved, specifically
  blocking the common cloud-metadata SSRF target (169.254.169.254).
  Documented TOCTOU/DNS-rebinding caveat; full request-level IP pinning is
  still 📋 planned (see below).
- ✅ **Key rotation for SymmetricEncryptor** (`VersionedEncryptor`) — tags
  ciphertext with a key ID so keys can be rotated without losing the
  ability to decrypt data encrypted under a previous key.
- 📋 **char[]/byte[] password overloads** — Java's `PasswordHasher` (and
  the equivalents elsewhere where the language allows it) should accept
  `char[]`/mutable byte buffers, not just immutable `String`, so callers
  can zero the password from memory after use.
- 📋 **Statistical constant-time proof** — a dudect-style timing harness
  that actually measures `ConstantTimeCompare` across many samples, rather
  than relying on "the stdlib function is documented as constant-time."
- 📋 **Redis-backed `RateLimiterStore`** reference implementation per
  language, for real multi-instance deployments (the shipped
  `MemoryRateLimiterStore` is explicitly process-local only).
- 📋 **Unify `SymmetricEncryptor`'s AEAD construction across all five
  languages** (documented gap: Go+PHP use XChaCha20-Poly1305, JS+Java use
  AES-256-GCM, Python uses plain ChaCha20-Poly1305 — three incompatible
  islands). Likely direction: standardize on AES-256-GCM everywhere, since
  every language's vetted library already supports it natively.

## New security modules

- 📋 **SSRF-safe HTTP fetcher** — a full wrapper around each language's
  HTTP client that resolves DNS once, validates the IP, and pins the
  connection to that exact IP (closing the TOCTOU gap `isPublicHttpUrl`
  alone can't close), re-validating on every redirect hop.
- 📋 **Breached-password check** — HaveIBeenPwned k-anonymity API client,
  a natural pairing with `PasswordHasher` (NIST 800-63B recommends this
  over complexity rules).
- 📋 **LoginAttemptGuard** — account-lockout policy distinct from the
  generic `RateLimiter`: tracks failed attempts per `username+IP`,
  exponential backoff, temporary lockout.
- 📋 **Secure cookie / session helper** — `HttpOnly; Secure; SameSite`
  flag builder, plus a session-ID regeneration helper (session fixation
  defense).
- 📋 **API key generator with prefix + checksum** — Stripe-style
  (`sk_live_...`) keys that automated secret scanners (GitHub push
  protection, etc.) can recognize if accidentally leaked.
- 📋 **Envelope encryption / KMS integration layer** — wraps a data key
  with a KEK from an external KMS (AWS KMS, Vault), reducing how long a
  raw key lives in application memory.
- 📋 **TOTP/2FA** (RFC 6238).
- 📋 **Webhook signature verifier** (Stripe/GitHub-style HMAC verification).
- 📋 **HKDF** — derive multiple subkeys from one master key.
- 📋 **Passphrase generator** (diceware-style, human-memorable).
- 📋 **File upload validator** — MIME sniffing + size limit + extension
  allow-list, extending `Validator`.

## Publishing & operations

- 🚧 Publish v0.1.0 to Packagist, PyPI, npm, and Maven Central — see
  [PUBLISHING.md](PUBLISHING.md) for exact steps and live status.
  Go already works via `go get` (verified end-to-end, no publish step
  needed). Release automation for Python/npm is wired up in
  `.github/workflows/publish.yml`, gated on tags + registry secrets that
  require the repo owner's own account.
- 📋 SBOM generation (CycloneDX) and artifact signing (Sigstore/cosign).
- 📋 Docs site with auto-generated API reference per language.
- 📋 OWASP ASVS control mapping / compliance checklist.

## How to use this file

Pick an item, move it to 🚧, implement it with tests across every language
it applies to, update the relevant README/THREAT_MODEL section, then mark
it ✅ and log it in CHANGELOG.md under Unreleased.
