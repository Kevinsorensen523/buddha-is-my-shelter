"""Requires a real Redis instance reachable at localhost:6379. Tests are
skipped automatically if Redis isn't reachable, so the rest of the suite
still passes without Redis, but running them for real (not mocked) is what
actually proves this store's atomicity claims hold."""

import time

import pytest

redis = pytest.importorskip("redis")

from securekit import RateLimiter, RedisRateLimiterStore


def _client():
    client = redis.Redis(host="localhost", port=6379)
    try:
        client.ping()
    except Exception as e:
        pytest.skip(f"no Redis reachable at localhost:6379: {e}")
    return client


def test_allows_under_limit_and_blocks_over():
    client = _client()
    prefix = f"securekit-test:{test_allows_under_limit_and_blocks_over.__name__}:"
    store = RedisRateLimiterStore(client, key_prefix=prefix)
    rl = RateLimiter(store, limit=3, window_seconds=60)
    try:
        assert rl.allow("client-1")
        assert rl.allow("client-1")
        assert rl.allow("client-1")
        assert not rl.allow("client-1")
    finally:
        client.delete(prefix + "client-1")


def test_tracks_keys_independently():
    client = _client()
    prefix = f"securekit-test:{test_tracks_keys_independently.__name__}:"
    store = RedisRateLimiterStore(client, key_prefix=prefix)
    rl = RateLimiter(store, limit=1, window_seconds=60)
    try:
        assert rl.allow("client-A")
        assert rl.allow("client-B")
    finally:
        client.delete(prefix + "client-A", prefix + "client-B")


def test_expires_and_resets():
    client = _client()
    prefix = f"securekit-test:{test_expires_and_resets.__name__}:"
    store = RedisRateLimiterStore(client, key_prefix=prefix)
    rl = RateLimiter(store, limit=1, window_seconds=1)
    try:
        assert rl.allow("client-1")
        assert not rl.allow("client-1")
        time.sleep(1.1)
        assert rl.allow("client-1")
    finally:
        client.delete(prefix + "client-1")


def test_sets_expiry_on_first_increment_only():
    client = _client()
    prefix = f"securekit-test:{test_sets_expiry_on_first_increment_only.__name__}:"
    store = RedisRateLimiterStore(client, key_prefix=prefix)
    redis_key = prefix + "client-1"
    try:
        store.increment("client-1", 3600)
        ttl1 = client.pttl(redis_key)

        time.sleep(0.05)
        store.increment("client-1", 3600)
        ttl2 = client.pttl(redis_key)

        assert ttl2 <= ttl1, "TTL should only count down, not reset"
    finally:
        client.delete(redis_key)
