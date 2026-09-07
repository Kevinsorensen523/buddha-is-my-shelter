from securekit import RateLimiter, MemoryRateLimiterStore


def test_allows_under_limit_and_blocks_over():
    rl = RateLimiter(MemoryRateLimiterStore(), limit=3, window_seconds=60)
    assert rl.allow("client-1")
    assert rl.allow("client-1")
    assert rl.allow("client-1")
    assert not rl.allow("client-1")


def test_tracks_keys_independently():
    rl = RateLimiter(MemoryRateLimiterStore(), limit=1, window_seconds=60)
    assert rl.allow("client-A")
    assert rl.allow("client-B")
