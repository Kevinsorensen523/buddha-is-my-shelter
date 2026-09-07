"""Input validation and output-encoding helpers."""

import html
import re
from email.utils import parseaddr
from urllib.parse import urlparse

_CONTROL_CHARS = re.compile(r"[\r\n\t]")
_ALLOW_LIST_CACHE: dict[str, re.Pattern[str]] = {}


def is_valid_email(email: str) -> bool:
    if not email or _CONTROL_CHARS.search(email):
        return False
    name, addr = parseaddr(email)
    if not addr or addr != email:
        return False
    # A minimal structural check beyond parseaddr, which is lenient.
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr))


def is_valid_url(url: str) -> bool:
    """Only absolute http(s) URLs are accepted."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def is_allow_listed(value: str, allowed_chars: str) -> bool:
    """allowed_chars is a character-class body, e.g. 'a-zA-Z0-9_-'."""
    pattern = _ALLOW_LIST_CACHE.get(allowed_chars)
    if pattern is None:
        pattern = re.compile(f"^[{allowed_chars}]*$")
        _ALLOW_LIST_CACHE[allowed_chars] = pattern
    return bool(pattern.match(value))


def sanitize_filename(filename: str) -> str:
    """Guards against path traversal. Returns the bare filename when safe;
    callers must still join it with a trusted, fixed base directory."""
    if not filename or "\x00" in filename or "/" in filename or "\\" in filename:
        raise ValueError("securekit: invalid filename")
    trimmed = filename.strip()
    if trimmed in ("", ".", ".."):
        raise ValueError("securekit: invalid filename")
    return trimmed


def escape_html(value: str) -> str:
    """HTML-escapes for safe inclusion in HTML body context (prevents XSS)."""
    return html.escape(value, quote=True)
