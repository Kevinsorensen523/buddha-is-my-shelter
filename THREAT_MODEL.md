# Threat Model

This document describes what each securekit module protects against, and —
just as importantly — what it does **not** guarantee. It applies identically
to all five language ports, which share the same design.

## General Principles

- **No custom cryptography.** Every cryptographic primitive is delegated to
  a vetted, audited library (see root [README.md](README.md#vetted-cryptography-per-language)).
  securekit's own code is limited to safe composition, encoding, and
  misuse-resistant API design.
- **Generic crypto error messages.** Decryption failures never distinguish
  "ciphertext too short" from "tag mismatch" from "wrong key" — all report
  the same generic failure, to avoid turning error messages into a padding-
  or tag-mismatch oracle.
- **No caller-chosen nonces/IVs.** `SymmetricEncryptor` always generates its
  own nonce internally per call; there is no parameter to override it. This
  removes the most common AEAD misuse (nonce reuse under a fixed key, which
  can catastrophically break confidentiality and, for GCM/Poly1305,
  authenticity too).

## Module-by-Module

### SecureRandom

- **Protects against:** predictable tokens/IDs from weak PRNGs
  (`Math.random()`, `rand()`, `mt_rand()`, etc.).
- **Does not protect against:** entropy exhaustion on the underlying OS
  CSPRNG (extremely rare on modern platforms; the OS blocks or errors rather
  than returning weak output).

### PasswordHasher (Argon2id)

- **Protects against:** offline brute-force/dictionary attacks on a stolen
  password database, via a memory-hard, tunable-cost KDF; timing leaks
  during verification (uses constant-time comparison internally).
- **Does not protect against:** weak/reused passwords chosen by users
  (pair with a breached-password check, e.g. HaveIBeenPwned's k-anonymity
  API, which is out of scope for this library); an attacker who already has
  the plaintext password (e.g. via phishing or keylogging).
- **Defaults:** OWASP-recommended cost parameters as of 2024 (64 MiB memory,
  3 iterations, parallelism 4). `needsRehash()`/`needs_rehash()` lets you
  detect hashes stored under weaker parameters and upgrade them
  transparently on next login.

### SymmetricEncryptor (AEAD)

- **Protects against:** confidentiality and integrity of data at rest or in
  transit under a symmetric key; tampering (AEAD auth tag detects any
  ciphertext modification, including of the optional AAD).
- **Does not protect against:** key management — securekit does not provide
  key storage, rotation, or a KMS integration. Store keys in an environment
  variable, secret manager, or HSM appropriate to your deployment; never
  hardcode them. Also does not protect against a compromised endpoint that
  has the key and reads plaintext directly (encryption protects data, not a
  compromised process).
- **Cross-language ciphertext portability — NOT guaranteed, unlike
  PasswordHasher and CsrfTokenManager.** The five ports use three different
  AEAD constructions (see root README's cryptography table), and this is
  empirically verified by [`vectors/aead_ciphertexts.json`](vectors/aead_ciphertexts.json)
  and each port's interop test: **Go and PHP** both use XChaCha20-Poly1305
  (24-byte nonce) and can decrypt each other's ciphertext; **JavaScript and
  Java** both use AES-256-GCM (12-byte nonce + 16-byte tag) and can decrypt
  each other's ciphertext; **Python** uses plain ChaCha20-Poly1305 (12-byte
  nonce) and cannot decrypt, or be decrypted by, any of the other four —
  not even JavaScript/Java, despite producing a same-length blob, because
  the underlying cipher differs. If your system encrypts in one language
  and decrypts in another, confirm both are in the same compatibility
  group before relying on this, or standardize all five ports on a single
  construction (e.g. AES-256-GCM everywhere, since every language's crypto
  library already supports it) as a follow-up change.

### InputValidator / Sanitizer

- **Protects against:** malformed email/URL input reaching business logic;
  path traversal via `sanitizeFilename`/`sanitize_filename`; reflected XSS
  when output is passed through the HTML-escape helper before insertion
  into HTML body context.
- **Does not protect against:** XSS in non-HTML-body contexts (HTML
  attribute, `<script>` block, CSS, URL contexts each need their own
  encoding — this library only covers HTML body text); SQL injection (use
  parameterized queries/prepared statements, not sanitization, for SQL);
  every possible SSRF vector (`isValidUrl`/`ValidateURL` only restricts to
  http(s) schemes — it does not resolve DNS or block private/internal IP
  ranges; add that check separately if your app fetches user-supplied URLs
  server-side). `sanitizeFilename` returns a bare filename only — callers
  must still join it with a trusted, fixed base directory, not a
  caller-supplied prefix.

### CsrfTokenManager

- **Protects against:** cross-site request forgery on state-changing
  requests, when the token is verified against the requesting session
  before the action executes; forged tokens (HMAC-SHA256 keyed by a
  server-side secret); replay past the configured TTL.
- **Does not protect against:** a compromised secret (rotate it — this
  invalidates all outstanding tokens, which is expected); XSS on the same
  origin (if an attacker can run JS on your page, they can simply read a
  valid token and use it — CSRF tokens do not defend against XSS; a strong
  Content-Security-Policy is the relevant mitigation for that).

### RateLimiter

- **Protects against:** brute-force and abuse of a single endpoint from a
  given key (IP, user ID, API key, etc.) within one process instance, using
  `MemoryRateLimiterStore`.
- **Does not protect against — this is the most important caveat in this
  document:** distributed abuse across multiple instances. The shipped
  `MemoryRateLimiterStore` (Go: `MemoryStore`) is **process-local**. Behind
  a load balancer or in any horizontally-scaled deployment, each instance
  enforces its own independent limit, so the *effective* limit is
  `configured_limit × instance_count`. For production multi-instance
  deployments, implement the storage interface
  (`RateLimiterStore`/`RateLimiterStoreInterface`) against Redis (e.g.
  `INCR` + `EXPIRE`, or a Lua script for atomicity) or another shared,
  low-latency store.
- Also does not protect against attackers who can churn through many
  distinct keys (e.g. IP rotation) — pair with other abuse-detection
  signals for adversarial traffic.

### ConstantTimeCompare

- **Protects against:** timing side-channel attacks that could otherwise
  let an attacker recover a secret byte-by-byte by measuring comparison
  latency.
- **Does not protect against:** timing leaks introduced elsewhere in your
  application logic around the comparison (e.g., an early-return before the
  comparison is even reached, or a database lookup keyed by a secret whose
  existence/absence is itself timing-observable). Also does not hide length
  differences: like most implementations, mismatched-length inputs
  short-circuit to `false` without a constant-time comparison of the full
  buffers, since token/tag lengths are fixed and not themselves secret in
  the flows this library targets (CSRF tags, password hash tags).

## Out of Scope Entirely

- Transport security (use TLS; securekit does not implement or configure it).
- Authentication/session management beyond password verification and CSRF
  token binding (no session store, no JWT issuance).
- Authorization / access control.
- Logging, auditing, and intrusion detection.
- Denial-of-service protection beyond basic rate limiting (no distributed
  DDoS mitigation).
