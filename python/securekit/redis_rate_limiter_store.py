"""RateLimiterStore backed by Redis, safe for multi-instance deployments
(unlike MemoryRateLimiterStore, which is process-local only -- see
THREAT_MODEL.md).

Requires the optional `redis` extra: pip install "buddha-is-my-shelter[redis]"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis import Redis

# Atomically increments a counter and sets its expiry only on the first
# increment of a window -- avoiding a race where a process crashes between
# INCR and PEXPIRE and leaves a key with no TTL (which would then never
# reset, permanently blocking that key).
_INCR_EXPIRE_SCRIPT = """
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
    redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
"""


class RedisRateLimiterStore:
    """Fixed-window counter store backed by Redis.

    :param client: a redis.Redis (or compatible) client instance; caller
        owns its lifecycle.
    :param key_prefix: namespaces keys in shared Redis instances.
    """

    def __init__(self, client: "Redis", key_prefix: str = "securekit:ratelimit:") -> None:
        self._client = client
        self._key_prefix = key_prefix
        self._script = client.register_script(_INCR_EXPIRE_SCRIPT)

    def increment(self, key: str, window_seconds: float) -> int:
        redis_key = self._key_prefix + key
        window_ms = int(window_seconds * 1000)
        try:
            return int(self._script(keys=[redis_key], args=[window_ms]))
        except Exception:
            # Fail closed: if Redis is unreachable, treat this as "already
            # over limit" rather than silently allowing unlimited requests
            # through, since a rate limiter that fails open under outage
            # is a rate limiter that doesn't limit anything during one.
            return 2**63 - 1
