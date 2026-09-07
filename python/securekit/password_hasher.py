"""Argon2id password hashing via argon2-cffi (bindings to the reference
Argon2 C library) -- no custom crypto.

Output is the standard PHC string, cross-compatible with the Go/PHP/Node/Java
ports: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
"""

from argon2 import PasswordHasher as _Argon2PasswordHasher
from argon2 import exceptions as _argon2_exceptions
from argon2.low_level import Type as _Argon2Type


class PasswordHasher:
    """Hashes and verifies passwords using Argon2id.

    Defaults follow OWASP guidance: 64 MiB memory, 3 iterations, parallelism 4.
    """

    def __init__(
        self,
        memory_cost_kib: int = 64 * 1024,
        time_cost: int = 3,
        parallelism: int = 4,
        hash_len: int = 32,
        salt_len: int = 16,
    ) -> None:
        self._impl = _Argon2PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=_Argon2Type.ID,
        )

    def hash(self, password: str) -> str:
        if not password:
            raise ValueError("securekit: password must not be empty")
        return self._impl.hash(password)

    def verify(self, password: str, encoded_hash: str) -> bool:
        try:
            self._impl.verify(encoded_hash, password)
            return True
        except _argon2_exceptions.VerifyMismatchError:
            return False
        except _argon2_exceptions.InvalidHashError:
            return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        return self._impl.check_needs_rehash(encoded_hash)
