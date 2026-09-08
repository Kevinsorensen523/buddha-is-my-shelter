from securekit import is_private_or_reserved_ip, is_public_http_url


def test_is_private_or_reserved_ip():
    for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1"]:
        assert is_private_or_reserved_ip(ip), f"{ip} should be flagged private/reserved"
    for ip in ["8.8.8.8", "1.1.1.1"]:
        assert not is_private_or_reserved_ip(ip), f"{ip} should be flagged public"


def test_is_public_http_url_rejects_non_http_scheme():
    assert not is_public_http_url("javascript:alert(1)")


def test_is_public_http_url_rejects_localhost():
    assert not is_public_http_url("http://localhost/")
    assert not is_public_http_url("http://127.0.0.1/")
