# Buddha is My Shelter (Python)

Python port of the Buddha is My Shelter security toolkit, mirroring the Go
reference implementation's behavior and PHC hash / token wire formats
where possible.

## Requirements

- Python 3.10+

## Install

```bash
pip install buddha-is-my-shelter
```

## Modules

### SecureRandom

```python
from securekit import secure_random_token, secure_random_hex, secure_random_bytes

token = secure_random_token(32)  # URL-safe base64
hexs = secure_random_hex(16)
raw = secure_random_bytes(32)
```

### PasswordHasher (Argon2id)

```python
from securekit import PasswordHasher

hasher = PasswordHasher()
hashed = hasher.hash("correct horse battery staple")
ok = hasher.verify("correct horse battery staple", hashed)
if hasher.needs_rehash(hashed):
    ...  # re-hash and update stored value on next successful login
```

Backed by `argon2-cffi` (bindings to the reference Argon2 C library).
Output is a standard PHC string, compatible with the other language ports.

### SymmetricEncryptor (AEAD)

```python
from securekit import SymmetricEncryptor

enc = SymmetricEncryptor()
key = enc.generate_key()

ciphertext = enc.encrypt(key, b"secret message")  # aad optional
plaintext = enc.decrypt(key, ciphertext)
```

Backed by `cryptography`'s hazmat `ChaCha20Poly1305` AEAD, with a
CSPRNG-generated 96-bit nonce prepended to every ciphertext automatically —
there is no API to supply your own nonce. `decrypt()` always raises the
generic `DecryptionError` on any failure.

### Validator

```python
from securekit import is_valid_email, is_valid_url, sanitize_filename, escape_html

is_valid_email("user@example.com")   # True
is_valid_url("https://example.com")  # True, rejects non-http(s) schemes
name = sanitize_filename("report.pdf")  # raises ValueError on traversal
safe = escape_html('<script>alert(1)</script>')
```

### CsrfTokenManager

```python
from securekit import CsrfTokenManager, secure_random_bytes

secret = secure_random_bytes(32)  # store server-side
mgr = CsrfTokenManager(secret, ttl_seconds=3600)

token = mgr.generate(session_id)
ok = mgr.verify(session_id, submitted_token)
```

### RateLimiter

```python
from securekit import RateLimiter, MemoryRateLimiterStore

limiter = RateLimiter(MemoryRateLimiterStore(), limit=100, window_seconds=60)
if not limiter.allow(client_ip):
    ...  # reject: too many requests
```

`MemoryRateLimiterStore` is process-local only. Implement the
`RateLimiterStore` protocol against Redis for multi-instance deployments —
see [../THREAT_MODEL.md](../THREAT_MODEL.md).

### constant_time_equal

```python
from securekit import constant_time_equal
constant_time_equal(a, b)  # wraps hmac.compare_digest
```

## Framework Integration

See [../examples/python](../examples/python) for Flask and Django examples.

## Testing

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -v
.venv/bin/bandit -r securekit
```

## Security Notes

- All cryptography comes from `secrets`, `argon2-cffi`, and `cryptography` —
  no custom crypto.
- `sanitize_filename()` returns only a bare filename; callers must still
  join it with a trusted, fixed base directory.
