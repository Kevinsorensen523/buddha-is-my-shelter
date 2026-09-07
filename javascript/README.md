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

## Framework Integration

See [../examples/js](../examples/js) for an Express.js example wiring
`CsrfTokenManager` and `RateLimiter` into middleware.

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
