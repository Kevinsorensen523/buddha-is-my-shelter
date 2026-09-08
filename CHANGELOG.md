# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
— versioned independently per language package (`go/`, `php/`, `python/`,
`javascript/`, `java/`).

## [Unreleased]

### Added

- `VersionedEncryptor` in all five languages — wraps `SymmetricEncryptor`
  with a 1-byte key-ID prefix so encryption keys can be rotated without
  losing the ability to decrypt data encrypted under a previous key.
- SSRF guard (`isPublicHttpUrl`/`IsPublicHTTPURL`/`is_public_http_url`) in
  all five languages — DNS-resolves a URL's hostname and rejects it if any
  resolved address is private/loopback/link-local/reserved, specifically
  blocking the common cloud-metadata SSRF target (169.254.169.254).
  Documented DNS-rebinding/TOCTOU limitation in THREAT_MODEL.md.
- `ROADMAP.md` — full backlog of planned modules and hardening work.
- `vectors/` — cross-language interop test fixtures (password hashes, CSRF
  tokens, AEAD ciphertexts) generated from each language's own
  implementation, plus an interop test in every port that verifies it can
  consume what every other language produced.

### Fixed

- **Go**: `CsrfTokenManager` embedded its issue timestamp in nanoseconds
  while PHP/Python/JavaScript/Java all use milliseconds. This didn't break
  same-language round-trips, but silently broke cross-language token
  verification for any positive TTL. Found by the new interop test suite.

### Changed

- Renamed all package/module identifiers from `securekit` to
  `buddha-is-my-shelter` to match the repository name (go.mod, composer.json,
  pyproject.toml, package.json, pom.xml, and every install command in the
  READMEs). In-code namespaces/import identifiers (Go's `securekit` package
  name, PHP's `SecureKit\` namespace, Python's `securekit` import package,
  Java's `io.github.securekit` package) were intentionally left unchanged,
  since they're decoupled from the registry package name in every ecosystem
  except Go.

### Added (publishing)

- `.github/workflows/publish.yml` — automated PyPI and npm publish on
  `python/vX.Y.Z` / `js/vX.Y.Z` tags (gated on `PYPI_API_TOKEN` /
  `NPM_TOKEN` repo secrets).
- `PUBLISHING.md` — honest per-registry status and exact setup steps.
  Verified end-to-end that `go get github.com/kevinsorensen523/buddha-is-my-shelter/go@latest`
  genuinely works today (no publish step needed); confirmed the Python
  wheel and npm tarball both build and install correctly, pending each
  registry's one-time account setup.

### Documented

- `SymmetricEncryptor` ciphertexts are **not** portable across all five
  languages, unlike `PasswordHasher` and `CsrfTokenManager`. Three
  compatibility islands exist: Go+PHP (XChaCha20-Poly1305), JS+Java
  (AES-256-GCM), and Python alone (ChaCha20-Poly1305). See THREAT_MODEL.md.

## [0.1.0] - 2026-09-07

### Added

- Initial release of all five language ports with full feature parity:
  - `SecureRandom` — CSPRNG-backed byte/token/hex generation.
  - `PasswordHasher` — Argon2id password hashing with `needsRehash` upgrade
    detection (bcrypt fallback in the JavaScript port).
  - `SymmetricEncryptor` — AEAD encryption (XChaCha20-Poly1305 or
    AES-256-GCM depending on language) with internally-generated nonces.
  - `InputValidator`/`Validator` — email/URL validation, allow-list
    matching, path-traversal-safe filename sanitization, HTML-escaping.
  - `CsrfTokenManager` — stateless, HMAC-signed, session-bound, TTL-expiring
    CSRF tokens.
  - `RateLimiter` — fixed-window rate limiting with a pluggable storage
    interface (in-memory implementation included).
  - `ConstantTimeCompare`/`constant_time_equal`/etc. — timing-safe
    comparison utility.
- `README.md`, `SECURITY.md`, `THREAT_MODEL.md`, `CONTRIBUTING.md` at the
  repository root.
- Per-language `README.md` with install instructions and usage examples.
- Unit test suites for every module in every language.
- CI workflow (`.github/workflows/ci.yml`) running tests and a security
  linter per language.

[Unreleased]: https://github.com/kevinsorensen523/securekit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kevinsorensen523/securekit/releases/tag/v0.1.0
