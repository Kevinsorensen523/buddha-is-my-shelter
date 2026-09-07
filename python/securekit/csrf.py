"""Stateless CSRF token issuance/verification bound to a session ID and a
server-side secret, using HMAC-SHA256."""

import hashlib
import hmac
import base64
import struct
import time

from .secure_random import secure_random_bytes
from .constant_time import constant_time_equal


class CsrfTokenManager:
    def __init__(self, secret: bytes, ttl_seconds: float = 3600) -> None:
        self._secret = secret
        self._ttl_seconds = ttl_seconds

    def generate(self, session_id: str) -> str:
        nonce = secure_random_bytes(16)
        issued_at_ms = int(time.time() * 1000)
        tag = self._sign(session_id, nonce, issued_at_ms)
        raw = struct.pack(">Q", issued_at_ms) + nonce + tag
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    def verify(self, session_id: str, token: str) -> bool:
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = base64.urlsafe_b64decode(padded)
        except Exception:
            return False
        if len(raw) < 8 + 16 + 32:
            return False
        issued_at_ms = struct.unpack(">Q", raw[:8])[0]
        nonce = raw[8:24]
        tag = raw[24:56]

        if self._ttl_seconds > 0:
            age_seconds = (time.time() * 1000 - issued_at_ms) / 1000
            if age_seconds > self._ttl_seconds:
                return False

        expected = self._sign(session_id, nonce, issued_at_ms)
        return constant_time_equal(expected, tag)

    def _sign(self, session_id: str, nonce: bytes, issued_at_ms: int) -> bytes:
        msg = session_id.encode("utf-8") + nonce + struct.pack(">Q", issued_at_ms)
        return hmac.new(self._secret, msg, hashlib.sha256).digest()
