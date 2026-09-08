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

### Added (Java framework coverage)

- `examples/java/MicronautFilterExample.java` -- Micronaut's reactive
  `HttpServerFilter`, needed because Micronaut deliberately skips the
  Servlet API entirely (unlike Spring Boot).
- `examples/java/FRAMEWORKS.md` -- notes that the existing Spring Boot
  example already implements the standard `jakarta.servlet.Filter`
  interface and therefore works unmodified on any Jakarta EE server
  (Quarkus in servlet mode, Payara, WildFly, Tomcat, Jetty); covers
  Quarkus/Helidon MP's JAX-RS `ContainerRequestFilter` path, Helidon SE's
  reactive routing, and Play Framework's Akka-based `Filter`. Hibernate
  and MyBatis are marked not applicable -- they're ORM/persistence
  libraries with no request pipeline to hook into.

### Added (Node.js backend framework coverage)

- `examples/js/fastifyExample.js`, `examples/js/koaExample.js`,
  `examples/js/nestjsExample.md` (NestJS uses a Guard, not raw middleware)
  -- alongside the existing Express example. `examples/js/FRAMEWORKS.md`
  extended with a backend-frameworks table (Hapi, AdonisJS, Feathers.js,
  Restify, LoopBack, Sails.js, Meteor) noting these all run purely in
  Node.js -- no browser/Edge split to worry about, just each framework's
  own middleware/hook/guard shape.

### Added (JS/TS frontend framework coverage)

- `examples/js/FRAMEWORKS.md` -- compatibility index for React, Angular,
  Vue.js, Svelte, SolidJS, Preact, Next.js, Nuxt.js, SvelteKit, Remix, and
  Astro. Key point: pure client-side libraries (React/Vue/Svelte/SolidJS/
  Preact/Angular without SSR) have no backend of their own and must pair
  with a real server for anything security-sensitive, using only the
  `/browser` export themselves; the five meta-frameworks split by
  file/function the same way Next.js does (documented in
  `nextjsExample.md`).

### Added (PHP framework coverage)

- `examples/php/Psr15MiddlewareExample.php` -- generic PSR-15 middleware,
  covering CakePHP 4+, Slim, Laminas/Mezzio, Yii3, and every other
  actively-maintained framework that implements or bridges to PSR-15.
- `examples/php/SymfonyEventSubscriberExample.php` -- idiomatic Symfony
  kernel event subscriber (Symfony also works via the generic PSR-15
  example if preferred).
- `examples/php/CodeIgniter4FilterExample.php` -- CodeIgniter 4's own
  Filter interface, which predates PSR-15 in its core.
- `examples/php/FRAMEWORKS.md` -- sorted, searchable compatibility index
  covering ~80 PHP frameworks (from a user-supplied list), mapping each
  actively-maintained one to the right example and explaining why testing
  tools, non-framework libraries, and ~30 discontinued/unverifiable
  projects don't get one (rather than guessing at APIs that can't be
  confirmed to still exist).

### Added (browser/Next.js support)

- `@kevinsorensen523/buddha-is-my-shelter/browser` subpath export --
  Web-Crypto-based `SecureRandom`, pure-JS `ConstantTimeCompare`, and the
  already-portable `Validator` functions, for use in React/Next.js Client
  Components, Next.js Edge Runtime, or any other non-Node.js JS
  environment. Verified by actually bundling it with esbuild
  `--platform=browser` and confirming zero Node built-ins leak in.
  `PasswordHasher`, `SymmetricEncryptor`, `CsrfTokenManager`,
  `RateLimiter`, `VersionedEncryptor`, and the SSRF guard remain
  deliberately Node-only -- not just a technical limitation, but because
  they should never run client-side (see the JS README's new "Browser &
  Next.js Usage" section). `examples/js/nextjsExample.md` shows the
  correct client/server split.

### Fixed (framework examples)

- **`examples/php/LaravelMiddlewareExample.php`**: the middleware
  constructed `RateLimiter`/`CsrfTokenManager` in its own constructor,
  which Laravel resolves fresh per request unless bound as a singleton --
  meaning the rate limiter's counters reset every request and silently
  blocked nothing, ever. Fixed by moving construction into a service
  provider's singleton bindings, with fail-fast validation of the CSRF
  secret at boot.
- **`examples/go/main.go`**: keyed the rate limiter on `r.RemoteAddr`,
  which includes the ephemeral TCP port -- a new connection from the same
  client gets a new port and therefore a new rate-limit key, defeating the
  limiter almost entirely. Fixed to strip the port via
  `net.SplitHostPort`. Also fixed a stale import path left over from the
  securekit → buddha-is-my-shelter rename.
- All five framework examples now: exempt a configurable list of paths
  from CSRF checking (third-party webhooks and bearer-token APIs can never
  supply a session-bound CSRF token), and carry an explicit comment at
  the point where client IP is read, warning that behind a reverse
  proxy/load balancer this returns the proxy's address unless the
  framework is told which hop(s) to trust.
- Added `examples/README.md` consolidating these lessons (stateful-manager
  lifecycle, reverse-proxy trust, per-process state limits -- PHP-FPM
  especially) as guidance that applies across all five languages, linked
  from every per-language README.

### Added (security credibility)

- `.github/workflows/scorecard.yml` — weekly OpenSSF Scorecard analysis,
  published to the public Scorecard API and as a README badge.
- `.github/workflows/codeql.yml` — CodeQL SAST for Go, JavaScript, Java,
  and Python (CodeQL has no PHP support).
- `go/fuzz_test.go` — native Go fuzz tests for the email/filename/CSRF/AEAD
  parsers, verified clean over millions of executions; wired into a
  nightly `.github/workflows/fuzz.yml` job. Fuzzing for the other four
  languages, and OSS-Fuzz/ClusterFuzzLite submission, tracked in
  ROADMAP.md as it requires more setup (and, for OSS-Fuzz, external
  review).

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
