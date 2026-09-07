import time
from securekit import CsrfTokenManager, secure_random_bytes


def test_round_trip():
    mgr = CsrfTokenManager(secure_random_bytes(32), ttl_seconds=3600)
    token = mgr.generate("session-123")
    assert mgr.verify("session-123", token)


def test_rejects_wrong_session():
    mgr = CsrfTokenManager(secure_random_bytes(32), ttl_seconds=3600)
    token = mgr.generate("session-A")
    assert not mgr.verify("session-B", token)


def test_rejects_expired_token():
    mgr = CsrfTokenManager(secure_random_bytes(32), ttl_seconds=0.01)
    token = mgr.generate("session-123")
    time.sleep(0.05)
    assert not mgr.verify("session-123", token)


def test_rejects_forged_token():
    mgr = CsrfTokenManager(secure_random_bytes(32), ttl_seconds=3600)
    assert not mgr.verify("session-123", "forged.token.value")
