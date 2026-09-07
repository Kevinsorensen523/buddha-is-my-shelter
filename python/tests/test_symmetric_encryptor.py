import pytest
from securekit import SymmetricEncryptor, DecryptionError


def test_round_trip():
    enc = SymmetricEncryptor()
    key = enc.generate_key()
    ciphertext = enc.encrypt(key, b"attack at dawn")
    assert enc.decrypt(key, ciphertext) == b"attack at dawn"


def test_rejects_tampered_ciphertext():
    enc = SymmetricEncryptor()
    key = enc.generate_key()
    ciphertext = bytearray(enc.encrypt(key, b"secret"))
    ciphertext[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        enc.decrypt(key, bytes(ciphertext))


def test_nonces_differ():
    enc = SymmetricEncryptor()
    key = enc.generate_key()
    c1 = enc.encrypt(key, b"same message")
    c2 = enc.encrypt(key, b"same message")
    assert c1 != c2
