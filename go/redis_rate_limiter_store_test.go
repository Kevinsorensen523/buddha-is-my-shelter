package securekit

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// These tests require a real Redis instance reachable at localhost:6379
// (set REDIS_TEST_ADDR to override). They're skipped automatically if
// Redis isn't reachable, so `go test ./...` still passes in environments
// without Redis, but running them for real (not mocked) is what actually
// proves this store's atomicity claims hold against real Redis semantics.
func newTestRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skipf("skipping: no Redis reachable at localhost:6379: %v", err)
	}
	return client
}

func TestRedisRateLimiterStoreAllowsUnderLimitAndBlocksOver(t *testing.T) {
	client := newTestRedisClient(t)
	defer client.Close()

	store := NewRedisRateLimiterStore(client)
	store.KeyPrefix = "securekit-test:" + t.Name() + ":"
	rl := NewRateLimiter(store, 3, time.Minute)

	key := "client-1"
	defer client.Del(context.Background(), store.KeyPrefix+key)

	for i := 0; i < 3; i++ {
		if !rl.Allow(key) {
			t.Fatalf("expected request %d to be allowed", i+1)
		}
	}
	if rl.Allow(key) {
		t.Fatal("expected 4th request to be blocked")
	}
}

func TestRedisRateLimiterStoreTracksKeysIndependently(t *testing.T) {
	client := newTestRedisClient(t)
	defer client.Close()

	store := NewRedisRateLimiterStore(client)
	store.KeyPrefix = "securekit-test:" + t.Name() + ":"
	rl := NewRateLimiter(store, 1, time.Minute)

	defer client.Del(context.Background(), store.KeyPrefix+"client-A", store.KeyPrefix+"client-B")

	if !rl.Allow("client-A") {
		t.Fatal("expected first request for client-A to be allowed")
	}
	if !rl.Allow("client-B") {
		t.Fatal("expected first request for client-B to be allowed independently")
	}
}

func TestRedisRateLimiterStoreExpiresAndResets(t *testing.T) {
	client := newTestRedisClient(t)
	defer client.Close()

	store := NewRedisRateLimiterStore(client)
	store.KeyPrefix = "securekit-test:" + t.Name() + ":"
	rl := NewRateLimiter(store, 1, 200*time.Millisecond)

	key := "client-1"
	defer client.Del(context.Background(), store.KeyPrefix+key)

	if !rl.Allow(key) {
		t.Fatal("expected first request to be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("expected second request within window to be blocked")
	}
	time.Sleep(300 * time.Millisecond)
	if !rl.Allow(key) {
		t.Fatal("expected request after window expiry to be allowed again")
	}
}

func TestRedisRateLimiterStoreSetsExpiryOnFirstIncrementOnly(t *testing.T) {
	// Verifies the atomic script's core correctness property: TTL is set
	// once (on the first increment) and not reset on every subsequent
	// increment, which would otherwise let a client avoid ever hitting the
	// window boundary by making requests just under the interval forever.
	client := newTestRedisClient(t)
	defer client.Close()

	store := NewRedisRateLimiterStore(client)
	store.KeyPrefix = "securekit-test:" + t.Name() + ":"
	key := "client-1"
	redisKey := store.KeyPrefix + key
	defer client.Del(context.Background(), redisKey)

	store.Increment(key, time.Hour)
	ttl1, _ := client.PTTL(context.Background(), redisKey).Result()

	time.Sleep(50 * time.Millisecond)
	store.Increment(key, time.Hour)
	ttl2, _ := client.PTTL(context.Background(), redisKey).Result()

	if ttl2 > ttl1 {
		t.Fatalf("expected TTL to only count down, not reset: ttl1=%v ttl2=%v", ttl1, ttl2)
	}
}
