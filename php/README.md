# Buddha is My Shelter (PHP)

PHP port of the Buddha is My Shelter security toolkit, mirroring the Go
reference implementation's behavior and PHC hash / token wire formats.

## Requirements

- PHP 8.1+
- ext-sodium (bundled by default on modern PHP builds)

## Install

```bash
composer require kevinsorensen523/buddha-is-my-shelter
```

## Modules

### SecureRandom

```php
use SecureKit\SecureRandom;

$token = SecureRandom::token(32); // URL-safe base64
$hex   = SecureRandom::hex(16);
$raw   = SecureRandom::bytes(32);
```

### PasswordHasher (Argon2id)

```php
use SecureKit\PasswordHasher;

$hasher = new PasswordHasher();
$hash = $hasher->hash('correct horse battery staple');
$ok = $hasher->verify('correct horse battery staple', $hash);
if ($hasher->needsRehash($hash)) {
    // re-hash and update stored value on next successful login
}
```

Uses PHP's native `password_hash(PASSWORD_ARGON2ID)` / `password_verify()`,
which wraps libargon2. Falls back to bcrypt only on PHP builds lacking
Argon2id support. Output is the standard PHC string, compatible with the
other language ports.

### SymmetricEncryptor (XChaCha20-Poly1305 AEAD)

```php
use SecureKit\SymmetricEncryptor;

$enc = new SymmetricEncryptor();
$key = $enc->generateKey();

$ciphertext = $enc->encrypt($key, 'secret message'); // $aad optional
$plaintext = $enc->decrypt($key, $ciphertext);
```

Backed by ext-sodium. Nonces are generated internally and prepended to the
ciphertext automatically — there is no API to supply your own nonce.
Decryption failures always throw a generic `RuntimeException('securekit: decryption failed')`.

### Validator

```php
use SecureKit\Validator;

Validator::isValidEmail('user@example.com');     // true
Validator::isValidUrl('https://example.com');     // true, rejects non-http(s)
Validator::isAllowListed('abc123', 'a-z0-9');     // true
$name = Validator::sanitizeFilename('report.pdf'); // throws on traversal
$safe = Validator::escapeHtml('<script>alert(1)</script>');
```

### VersionedEncryptor (key rotation)

```php
use SecureKit\VersionedEncryptor;

$ve = new VersionedEncryptor([1 => $keyV1], 1);
$blob = $ve->encrypt('secret');

// later, after rotating in a new key:
$ve->addKey(2, $keyV2);
$ve->setCurrentKeyId(2); // new encryptions use keyV2; old ciphertexts (keyId=1) still decrypt
$plaintext = $ve->decrypt($blob);
```

### SSRF guard

```php
use SecureKit\Ssrf;

Ssrf::isPublicHttpUrl('https://example.com');    // true
Ssrf::isPublicHttpUrl('http://169.254.169.254/'); // false: resolves to link-local
```

Performs a real DNS lookup — use `Validator::isValidUrl()` first for cheap
structural checks, and this only right before making a server-side request
to a caller-supplied URL. See the doc comment for the DNS-rebinding caveat.

### CsrfTokenManager

```php
use SecureKit\CsrfTokenManager;
use SecureKit\SecureRandom;

$secret = SecureRandom::bytes(32); // store server-side
$mgr = new CsrfTokenManager($secret, 3600);

$token = $mgr->generate($sessionId);
$ok = $mgr->verify($sessionId, $submittedToken);
```

### RateLimiter

```php
use SecureKit\RateLimiter;
use SecureKit\MemoryRateLimiterStore;

$limiter = new RateLimiter(new MemoryRateLimiterStore(), 100, 60);
if (!$limiter->allow($clientIp)) {
    // reject: too many requests
}
```

`MemoryRateLimiterStore` is process-local only (not safe across PHP-FPM
workers/instances without shared storage). Implement
`RateLimiterStoreInterface` against Redis for production. See
[../THREAT_MODEL.md](../THREAT_MODEL.md).

### ConstantTime

```php
use SecureKit\ConstantTime;

ConstantTime::equals($a, $b); // wraps hash_equals()
```

## Framework Integration

See [../examples/php](../examples/php) for a Laravel/Symfony-style example
wiring `CsrfTokenManager` and `RateLimiter` into HTTP middleware.

## Testing

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse src
```

## Security Notes

- All cryptography is delegated to `ext-sodium` and PHP's native
  `password_hash()` — no custom crypto.
- `Validator::sanitizeFilename()` returns only a bare filename; callers must
  still join it with a trusted, fixed base directory.
