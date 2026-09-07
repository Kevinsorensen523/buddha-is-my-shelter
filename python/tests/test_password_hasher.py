import pytest
from securekit import PasswordHasher


def test_round_trip():
    hasher = PasswordHasher()
    hash_ = hasher.hash("correct horse battery staple")
    assert hasher.verify("correct horse battery staple", hash_)


def test_rejects_wrong_password():
    hasher = PasswordHasher()
    hash_ = hasher.hash("correct-password")
    assert not hasher.verify("wrong-password", hash_)


def test_needs_rehash_detects_weaker_params():
    weak = PasswordHasher(memory_cost_kib=8 * 1024, time_cost=1, parallelism=1)
    hash_ = weak.hash("password")

    strong = PasswordHasher()
    assert strong.needs_rehash(hash_)


def test_rejects_empty_password():
    with pytest.raises(ValueError):
        PasswordHasher().hash("")
