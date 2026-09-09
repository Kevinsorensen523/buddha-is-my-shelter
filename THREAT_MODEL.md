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

### VersionedEncryptor

- **Protects against:** the "rotating a key breaks all old ciphertext"
  problem — each ciphertext is tagged with a 1-byte key ID, so old and new
  keys can coexist during and after a rotation.
- **Does not protect against:** key storage/distribution (same caveat as
  SymmetricEncryptor); an attacker who can call `addKey`/`setCurrentKeyId`
  on your running instance (this is an in-process API, not a network
  service — protect it the same way you'd protect any code path that
  touches key material). Also does not automatically expire or forget old
  keys — if you need to make old ciphertext permanently unrecoverable
  (crypto-shredding for a right-to-erasure request), you must remove that
  key ID from the key set yourself and ensure no other copy of it survives.

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

### SSRF Guard (`isPublicHttpUrl` / `IsPublicHTTPURL`)

- **Protects against:** the single most common root cause of real SSRF
  breaches — a server-side request to a caller-supplied URL landing on an
  internal service or a cloud metadata endpoint (e.g. `169.254.169.254`,
  the vector in the 2019 Capital One breach). Resolves DNS and rejects the
  URL if any resolved address is loopback, private-use, link-local,
  multicast, or otherwise reserved.
- **Does not protect against — read this before relying on it in
  production:** DNS rebinding / TOCTOU. This function checks the IP(s)
  resolved *at the moment you call it*. If your actual HTTP request
  happens afterward and re-resolves DNS itself (which almost every HTTP
  client does), an attacker who controls the DNS answer for their domain
  can return a public IP for your check and then a private IP for the real
  request. **Full protection requires resolving once, validating with
  `isPrivateOrReservedIp`, and forcing your HTTP client to connect to that
  exact validated IP** — this guard is the validation primitive, not a
  complete fetcher. A full SSRF-safe fetcher that closes this gap is
  tracked in [ROADMAP.md](ROADMAP.md). Also does not follow or re-validate
  redirects — if you allow redirects in your actual HTTP client, re-check
  every redirect target with this same function before following it.

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
- **Does not protect against, if you use the default store:**
  distributed abuse across multiple instances. `MemoryRateLimiterStore`
  (Go: `MemoryStore`) is **process-local**. Behind a load balancer or in
  any horizontally-scaled deployment, each instance enforces its own
  independent limit, so the *effective* limit is
  `configured_limit × instance_count`. All five languages now ship a
  **`RedisRateLimiterStore`** (requires an optional Redis client
  dependency, already wired into each package's manifest) implementing
  the atomic `INCR`+`PEXPIRE`-in-one-Lua-script pattern, verified against
  a real Redis instance in every language's test suite — use it for any
  multi-instance deployment. It fails closed (treats an unreachable Redis
  as over-limit) rather than silently allowing unlimited requests through
  during a Redis outage.
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
