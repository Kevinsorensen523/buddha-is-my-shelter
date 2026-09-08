import pytest
from securekit import VersionedEncryptor, secure_random_bytes, DecryptionError


def test_round_trip():
    key1 = secure_random_bytes(32)
    ve = VersionedEncryptor({1: key1}, 1)

    blob = ve.encrypt(b"secret")
    assert ve.decrypt(blob) == b"secret"


def test_survives_key_rotation():
    key1 = secure_random_bytes(32)
    key2 = secure_random_bytes(32)
    ve = VersionedEncryptor({1: key1}, 1)

    old_blob = ve.encrypt(b"encrypted with v1")

    ve.add_key(2, key2)
    ve.set_current_key_id(2)
    new_blob = ve.encrypt(b"encrypted with v2")

    assert ve.decrypt(old_blob) == b"encrypted with v1"
    assert ve.decrypt(new_blob) == b"encrypted with v2"


def test_rejects_unknown_key_id():
    key1 = secure_random_bytes(32)
    ve = VersionedEncryptor({1: key1}, 1)
    blob = bytearray(ve.encrypt(b"data"))
    blob[0] = 99

    with pytest.raises(DecryptionError):
        ve.decrypt(bytes(blob))


def test_constructor_rejects_missing_current_key():
    key1 = secure_random_bytes(32)
    with pytest.raises(ValueError):
        VersionedEncryptor({1: key1}, 5)
