'use strict';

/**
 * Browser-safe subset of securekit. Import this from a React/Next.js
 * client component, Next.js Edge Runtime/middleware, or any other
 * non-Node.js JS environment: `require('@kevinsorensen523/buddha-is-my-shelter/browser')`.
 *
 * Deliberately excludes PasswordHasher, SymmetricEncryptor,
 * CsrfTokenManager, RateLimiter, VersionedEncryptor, and the SSRF guard --
 * not just because they depend on Node built-ins (`crypto`, `dns`) or a
 * native addon (`argon2`) that browser bundlers can't resolve, but because
 * they should never run client-side at all: password hashing needs a
 * secret comparison against a value that must never reach the browser,
 * encryption needs a key the browser must never hold, CSRF tokens are
 * only meaningful verified server-side against a server-held secret, and
 * rate limiting enforced only in client JS is trivially bypassed by
 * anyone who opens devtools. See the main package README's
 * "Browser & Next.js Usage" section for the full explanation.
 */

module.exports = {
  ...require('./secureRandom'),
  ...require('./constantTime'),
  ...require('../validator'), // already has zero Node dependency
};
