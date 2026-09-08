"""securekit: misuse-resistant security toolkit.

All cryptography is delegated to vetted libraries (secrets, argon2-cffi,
cryptography) -- no custom crypto is implemented here.
"""

from .secure_random import secure_random_bytes, secure_random_token, secure_random_hex
from .password_hasher import PasswordHasher
from .symmetric_encryptor import SymmetricEncryptor, DecryptionError
from .validator import (
    is_valid_email,
    is_valid_url,
    is_allow_listed,
    sanitize_filename,
    escape_html,
)
from .csrf import CsrfTokenManager
from .rate_limiter import RateLimiter, MemoryRateLimiterStore, RateLimiterStore
from .constant_time import constant_time_equal
from .ssrf import is_private_or_reserved_ip, is_public_http_url
from .versioned_encryptor import VersionedEncryptor

__all__ = [
    "secure_random_bytes",
    "secure_random_token",
    "secure_random_hex",
    "PasswordHasher",
    "SymmetricEncryptor",
    "DecryptionError",
    "is_valid_email",
    "is_valid_url",
    "is_allow_listed",
    "sanitize_filename",
    "escape_html",
    "CsrfTokenManager",
    "RateLimiter",
    "MemoryRateLimiterStore",
    "RateLimiterStore",
    "constant_time_equal",
    "is_private_or_reserved_ip",
    "is_public_http_url",
    "VersionedEncryptor",
]
