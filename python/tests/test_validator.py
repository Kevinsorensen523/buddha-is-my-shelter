import pytest
from securekit import is_valid_email, is_valid_url, sanitize_filename, escape_html


def test_valid_emails():
    assert is_valid_email("user@example.com")
    assert not is_valid_email("not-an-email")
    assert not is_valid_email("user@example.com\r\nBcc: x")


def test_valid_urls():
    assert is_valid_url("https://example.com/path")
    assert not is_valid_url("javascript:alert(1)")
    assert not is_valid_url("file:///etc/passwd")


def test_sanitize_filename_rejects_traversal():
    with pytest.raises(ValueError):
        sanitize_filename("../../etc/passwd")


def test_sanitize_filename_accepts_clean_name():
    assert sanitize_filename("report-2024.pdf") == "report-2024.pdf"


def test_escape_html_prevents_xss():
    escaped = escape_html('<script>alert("xss")</script>')
    assert "<script>" not in escaped
