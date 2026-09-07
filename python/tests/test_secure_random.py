import re
import pytest
from securekit import secure_random_bytes, secure_random_token, secure_random_hex


def test_bytes_has_requested_length():
    assert len(secure_random_bytes(32)) == 32


def test_bytes_are_unique():
    assert secure_random_bytes(32) != secure_random_bytes(32)


def test_rejects_non_positive_length():
    with pytest.raises(ValueError):
        secure_random_bytes(0)


def test_token_is_url_safe():
    token = secure_random_token(32)
    assert re.match(r"^[A-Za-z0-9_-]+$", token)


def test_hex_encoding():
    h = secure_random_hex(16)
    assert len(h) == 32
    assert re.match(r"^[0-9a-f]+$", h)
