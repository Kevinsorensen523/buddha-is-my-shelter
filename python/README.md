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

### VersionedEncryptor (key rotation)

```python
from securekit import VersionedEncryptor

ve = VersionedEncryptor({1: key_v1}, current_key_id=1)
blob = ve.encrypt(b"secret")

# later, after rotating in a new key:
ve.add_key(2, key_v2)
ve.set_current_key_id(2)  # new encryptions use key_v2; old ciphertexts (key_id=1) still decrypt
plaintext = ve.decrypt(blob)
```

### SSRF guard

```python
from securekit import is_public_http_url

is_public_http_url("https://example.com")    # True
is_public_http_url("http://169.254.169.254/")  # False: resolves to link-local
```

Performs a real DNS lookup — use `is_valid_url()` first for cheap
structural checks, and this only right before making a server-side request
to a caller-supplied URL. See the docstring for the DNS-rebinding caveat.

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

`MemoryRateLimiterStore` is process-local only. For multi-instance
deployments, use `RedisRateLimiterStore` (requires the optional `redis`
extra: `pip install "buddha-is-my-shelter[redis]"`):

```python
import redis
from securekit import RateLimiter, RedisRateLimiterStore

client = redis.Redis(host="localhost", port=6379)
limiter = RateLimiter(RedisRateLimiterStore(client), limit=100, window_seconds=60)
if not limiter.allow(client_ip):
    ...  # reject: too many requests -- now shared correctly across every worker
```

Uses an atomic Lua script (`INCR` + `PEXPIRE` in one round trip) so a
crash between the two operations can't leave a key with no expiry. If
Redis is unreachable, `RedisRateLimiterStore` fails closed (treats it as
over-limit) rather than silently allowing unlimited requests through
during an outage. See [../THREAT_MODEL.md](../THREAT_MODEL.md).

### constant_time_equal

```python
from securekit import constant_time_equal
constant_time_equal(a, b)  # wraps hmac.compare_digest
```

## Framework Integration

See [../examples/python](../examples/python) for dedicated Flask,
Django, and FastAPI examples. **See
[../examples/python/FRAMEWORKS.md](../examples/python/FRAMEWORKS.md)**
for Pyramid, Tornado, Masonite, and Bottle, and for why ML/GUI/testing/
scraping libraries (PyTorch, Tkinter, Pytest, Scrapy, etc.) don't get an
integration example at all. **Read
[../examples/README.md](../examples/README.md) first** -- covers real
deployment gotchas (multi-worker state, reverse-proxy trust) these
examples are subject to.

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
