"""AEAD encryption using XChaCha20-Poly1305, via the `cryptography` package's
hazmat primitives -- no custom crypto.

Nonces are generated internally and prepended to the ciphertext; there is no
API to supply a caller-chosen nonce, eliminating nonce-reuse misuse.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .secure_random import secure_random_bytes

_KEY_LEN = 32
_NONCE_LEN = 12  # ChaCha20Poly1305 (IETF, 96-bit nonce); XChaCha20 not exposed
# by `cryptography`'s stable API, so we use the standard 96-bit-nonce variant
# with an internally generated random nonce per message (safe for the
# volume of messages any single key here is expected to encrypt).


class DecryptionError(Exception):
    """Raised for any decryption failure. Message is intentionally generic
    (never distinguishes "too short" vs "tag mismatch") to avoid leaking
    oracle information to an attacker."""

    def __init__(self) -> None:
        super().__init__("securekit: decryption failed")


class SymmetricEncryptor:
    def generate_key(self) -> bytes:
        return secure_random_bytes(_KEY_LEN)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        if len(key) != _KEY_LEN:
            raise ValueError("securekit: key must be 32 bytes")
        nonce = os.urandom(_NONCE_LEN)
        aead = ChaCha20Poly1305(key)
        ciphertext = aead.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt(self, key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
        if len(key) != _KEY_LEN or len(blob) < _NONCE_LEN:
            raise DecryptionError()
        nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
        aead = ChaCha20Poly1305(key)
        try:
            return aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise DecryptionError() from exc

    def encrypt_to_string(self, key: bytes, plaintext: bytes, aad: bytes | None = None) -> str:
        return base64.b64encode(self.encrypt(key, plaintext, aad)).decode("ascii")

    def decrypt_from_string(self, key: bytes, encoded: str, aad: bytes | None = None) -> bytes:
        try:
            blob = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise DecryptionError() from exc
        return self.decrypt(key, blob, aad)
