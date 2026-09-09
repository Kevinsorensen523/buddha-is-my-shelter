package securekit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// atomicIncrExpireScript increments a counter and sets its expiry only on
// the first increment of a window, atomically -- avoiding a race where a
// process crashes between INCR and EXPIRE and leaves a key with no TTL
// (which would then never reset, permanently blocking that key).
var atomicIncrExpireScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`)

// RedisRateLimiterStore is a RateLimiterStore backed by Redis, safe for
// multi-instance deployments (unlike MemoryStore, which is process-local
// only -- see THREAT_MODEL.md). Uses a fixed-window counter per key.
type RedisRateLimiterStore struct {
	client *redis.Client
	// KeyPrefix namespaces keys in shared Redis instances (e.g. "ratelimit:").
	KeyPrefix string
}

// NewRedisRateLimiterStore constructs a store using the given client.
// Callers own the client's lifecycle (creation and Close()).
func NewRedisRateLimiterStore(client *redis.Client) *RedisRateLimiterStore {
	return &RedisRateLimiterStore{client: client, KeyPrefix: "securekit:ratelimit:"}
}

// Increment implements RateLimiterStore, atomically incrementing the
// counter for key and setting its expiry to window on first increment.
func (s *RedisRateLimiterStore) Increment(key string, window time.Duration) (int, time.Time) {
	ctx := context.Background()
	redisKey := s.KeyPrefix + key

	result, err := atomicIncrExpireScript.Run(ctx, s.client, []string{redisKey}, window.Milliseconds()).Result()
	if err != nil {
		// Fail closed: if Redis is unreachable, treat this as "already
		// over limit" rather than silently allowing unlimited requests
		// through, since a rate limiter that fails open under outage is a
		// rate limiter that doesn't limit anything during an outage.
		return int(^uint(0) >> 1), time.Now().Add(window)
	}

	count, _ := result.(int64)
	ttl, err := s.client.PTTL(ctx, redisKey).Result()
	resetAt := time.Now().Add(window)
	if err == nil && ttl > 0 {
		resetAt = time.Now().Add(ttl)
	}
	return int(count), resetAt
}
