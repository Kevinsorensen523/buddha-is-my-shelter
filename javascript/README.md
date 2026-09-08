# Buddha is My Shelter (JavaScript / Node.js)

Node.js port of the Buddha is My Shelter security toolkit, mirroring the
Go reference implementation's behavior.

## Requirements

- Node.js 18+

## Install

```bash
npm install @kevinsorensen523/buddha-is-my-shelter
```

## Modules

### SecureRandom

```js
const { secureRandomToken, secureRandomHex, secureRandomBytes } = require('@kevinsorensen523/buddha-is-my-shelter');

const token = secureRandomToken(32); // URL-safe base64
const hex = secureRandomHex(16);
const raw = secureRandomBytes(32);
```

### PasswordHasher (Argon2id, bcrypt fallback)

```js
const { PasswordHasher } = require('@kevinsorensen523/buddha-is-my-shelter');

const hasher = new PasswordHasher();
const hash = await hasher.hash('correct horse battery staple');
const ok = await hasher.verify('correct horse battery staple', hash);
if (await hasher.needsRehash(hash)) {
  // re-hash and update stored value on next successful login
}
```

Uses the `argon2` package (native bindings) when its native module loads
successfully; otherwise falls back to bcrypt via `bcryptjs` (pure JS, no
native build step) so the toolkit still works in constrained environments.
Argon2id output is the standard PHC string, compatible with the other
language ports.

### SymmetricEncryptor (AES-256-GCM AEAD)

```js
const { SymmetricEncryptor } = require('@kevinsorensen523/buddha-is-my-shelter');

const enc = new SymmetricEncryptor();
const key = enc.generateKey();

const ciphertext = enc.encrypt(key, Buffer.from('secret message')); // aad optional
const plaintext = enc.decrypt(key, ciphertext);
```

Backed by Node's built-in `crypto` module. Nonces (IVs) are generated
internally and prepended to the ciphertext — there is no API to supply your
own. `decrypt()` always throws the generic `DecryptionError`.

### Validator

```js
const { isValidEmail, isValidUrl, sanitizeFilename, escapeHtml } = require('@kevinsorensen523/buddha-is-my-shelter');

isValidEmail('user@example.com');    // true
isValidUrl('https://example.com');   // true, rejects non-http(s) schemes
sanitizeFilename('../../etc/passwd'); // throws RangeError
const safe = escapeHtml('<script>alert(1)</script>');
```

### VersionedEncryptor (key rotation)

```js
const { VersionedEncryptor } = require('@kevinsorensen523/buddha-is-my-shelter');

const ve = new VersionedEncryptor({ 1: keyV1 }, 1);
const blob = ve.encrypt(Buffer.from('secret'));

// later, after rotating in a new key:
ve.addKey(2, keyV2);
ve.setCurrentKeyId(2); // new encryptions use keyV2; old ciphertexts (keyId=1) still decrypt
const plaintext = ve.decrypt(blob);
```

### SSRF guard

```js
const { isPublicHttpUrl } = require('@kevinsorensen523/buddha-is-my-shelter');

await isPublicHttpUrl('https://example.com');    // true
await isPublicHttpUrl('http://169.254.169.254/'); // false: resolves to link-local
```

Performs a real DNS lookup (async) — use `isValidUrl()` first for cheap
structural checks, and this only right before making a server-side request
to a caller-supplied URL. See the doc comment for the DNS-rebinding caveat.

### CsrfTokenManager

```js
const { CsrfTokenManager, secureRandomBytes } = require('@kevinsorensen523/buddha-is-my-shelter');

const secret = secureRandomBytes(32); // store server-side
const mgr = new CsrfTokenManager(secret, 3600000); // ttl in ms

const token = mgr.generate(sessionId);
const ok = mgr.verify(sessionId, submittedToken);
```

### RateLimiter

```js
const { RateLimiter, MemoryRateLimiterStore } = require('@kevinsorensen523/buddha-is-my-shelter');

const limiter = new RateLimiter(new MemoryRateLimiterStore(), 100, 60000);
if (!limiter.allow(clientIp)) {
  // reject: too many requests
}
```

`MemoryRateLimiterStore` is process-local only. Implement the
`RateLimiterStore` interface against Redis for multi-instance deployments
(e.g. behind a load balancer / PM2 cluster) — see
[../THREAT_MODEL.md](../THREAT_MODEL.md).

### constantTimeEqual

```js
const { constantTimeEqual } = require('@kevinsorensen523/buddha-is-my-shelter');
constantTimeEqual(a, b); // wraps crypto.timingSafeEqual
```

## Browser & Next.js Usage

**The main package export (`require('@kevinsorensen523/buddha-is-my-shelter')`)
is Node.js-only.** It uses Node's `crypto`/`dns` built-ins and the `argon2`
native addon (a compiled binary, not JS) -- none of which a browser bundler
(webpack, Vite, Turbopack) can resolve, and none of which exist in
**Next.js's Edge Runtime** (middleware, `export const runtime = 'edge'`
routes), which runs in a restricted V8 isolate without full Node APIs or
native addons.

| Where you're running | Use |
|---|---|
| Plain Node.js backend (Express, Fastify, ...) | Main export -- works fully |
| Next.js API routes / Server Components / Server Actions, **Node.js runtime** (the default) | Main export -- works fully |
| Next.js **Edge Runtime** (middleware, `runtime: 'edge'`) | `/browser` export only (see below) -- the main export will fail to load |
| React/Next.js **Client Components**, or any browser bundle | `/browser` export only |

### The browser-safe subset

```js
import { secureRandomToken, isValidEmail, escapeHtml, constantTimeEqual }
  from '@kevinsorensen523/buddha-is-my-shelter/browser';
```

This subpath re-implements `SecureRandom` using the Web Crypto API
(`globalThis.crypto.getRandomValues`, available in every modern browser and
Node 19+) and `ConstantTimeCompare` in pure JS -- zero Node built-ins,
verified by actually bundling it with esbuild's `--platform=browser` (which
refuses to resolve Node built-ins) and confirming the output is clean.
`Validator`'s functions are also re-exported here since they were already
pure JS with no Node dependency.

**Deliberately not included, and this isn't just a bundler limitation --
these should never run client-side at all, even if it were technically
possible:** `PasswordHasher`, `SymmetricEncryptor`, `CsrfTokenManager`,
`RateLimiter`, `VersionedEncryptor`, and the SSRF guard. Password hashing
needs a value compared server-side that must never reach the browser;
encryption needs a key the browser must never hold; a CSRF token is only
meaningful when verified server-side against a server-held secret; and
rate limiting enforced only in client JS is trivially bypassed by anyone
who opens devtools and calls your API directly. If you need one of these
in a Next.js Edge Runtime route specifically, move that logic to a
Node.js-runtime API route instead -- Edge Runtime isn't the right place
for it regardless of this library.

## Framework Integration

See [../examples/js](../examples/js) for an Express.js example wiring
`CsrfTokenManager` and `RateLimiter` into middleware. **Read
[../examples/README.md](../examples/README.md) first** -- covers real
deployment gotchas (PM2 cluster/multi-instance state, reverse-proxy trust)
this example is subject to.

## Testing

```bash
npm install
npm test
npm run lint
```

## Security Notes

- Cryptography is delegated to `argon2`, `bcryptjs`, and Node's built-in
  `crypto` — no custom crypto.
- This package ships a CommonJS API (`require`); it also works from ESM via
  Node's CJS interop (`import securekit from '@kevinsorensen523/buddha-is-my-shelter'`).
