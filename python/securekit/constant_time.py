"""Timing-attack-resistant comparison utility."""

import hmac


def constant_time_equal(a: bytes | str, b: bytes | str) -> bool:
    """Compare a and b in constant time. Accepts str or bytes (encoded as UTF-8)."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)
