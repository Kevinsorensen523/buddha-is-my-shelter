"""Wraps SymmetricEncryptor with key-ID-tagged ciphertexts, so keys can be
rotated without losing the ability to decrypt data encrypted under a
previous key."""

from .symmetric_encryptor import SymmetricEncryptor, DecryptionError


class VersionedEncryptor:
    """Wire format: 1-byte key ID followed by whatever
    SymmetricEncryptor.encrypt() produces. Supports up to 256 concurrently-
    known key versions."""

    def __init__(self, keys: dict[int, bytes], current_key_id: int) -> None:
        if current_key_id not in keys:
            raise ValueError("securekit: current key ID not found in key set")
        self._inner = SymmetricEncryptor()
        self._keys = dict(keys)
        self._current_id = current_key_id

    def add_key(self, key_id: int, key: bytes) -> None:
        """Registers a new key version without changing which key is current."""
        self._keys[key_id] = key

    def set_current_key_id(self, key_id: int) -> None:
        if key_id not in self._keys:
            raise ValueError("securekit: key ID not found in key set")
        self._current_id = key_id

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        blob = self._inner.encrypt(self._keys[self._current_id], plaintext, aad)
        return bytes([self._current_id]) + blob

    def decrypt(self, blob: bytes, aad: bytes | None = None) -> bytes:
        """Raises the generic DecryptionError on any failure, including an
        unrecognized key ID, to avoid leaking which key IDs are valid."""
        if len(blob) < 1:
            raise DecryptionError()
        key_id = blob[0]
        if key_id not in self._keys:
            raise DecryptionError()
        return self._inner.decrypt(self._keys[key_id], blob[1:], aad)
