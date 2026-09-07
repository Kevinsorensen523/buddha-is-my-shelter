"""Fixed-window rate limiting with a pluggable storage backend."""

import threading
import time
from typing import Protocol


class RateLimiterStore(Protocol):
    def increment(self, key: str, window_seconds: float) -> int:
        """Increment the counter for key, creating the window if absent,
        and return the new count."""
        ...


class MemoryRateLimiterStore:
    """Process-local, thread-safe fixed-window store. Does NOT share state
    across processes/instances -- see THREAT_MODEL.md."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[int, float]] = {}

    def increment(self, key: str, window_seconds: float) -> int:
        with self._lock:
            now = time.time()
            count, reset_at = self._buckets.get(key, (0, 0.0))
            if now > reset_at:
                count, reset_at = 0, now + window_seconds
            count += 1
            self._buckets[key] = (count, reset_at)
            return count


class RateLimiter:
    def __init__(self, store: RateLimiterStore, limit: int, window_seconds: float) -> None:
        self._store = store
        self._limit = limit
        self._window_seconds = window_seconds

    def allow(self, key: str) -> bool:
        return self._store.increment(key, self._window_seconds) <= self._limit
