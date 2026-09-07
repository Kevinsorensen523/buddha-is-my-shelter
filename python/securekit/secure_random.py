"""CSPRNG-backed random generation. Never uses random.random()/random.randint()."""

import base64
import secrets


def secure_random_bytes(n: int) -> bytes:
    """Return n cryptographically secure random bytes."""
    if n <= 0:
        raise ValueError("securekit: byte count must be positive")
    return secrets.token_bytes(n)


def secure_random_token(n: int = 32) -> str:
    """Return a URL-safe base64 (unpadded) token built from n bytes of entropy."""
    return base64.urlsafe_b64encode(secure_random_bytes(n)).rstrip(b"=").decode("ascii")


def secure_random_hex(n: int = 16) -> str:
    """Return a lowercase hex-encoded random string built from n bytes of entropy."""
    return secure_random_bytes(n).hex()
