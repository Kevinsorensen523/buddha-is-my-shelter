package securekit

import (
	"sync"
	"time"
)

// RateLimiterStore is the storage abstraction RateLimiter depends on. The
// package ships an in-memory implementation (MemoryStore); production
// multi-instance deployments should implement this against Redis or similar
// shared storage (see THREAT_MODEL.md).
type RateLimiterStore interface {
	// Increment increments the counter for key and returns the new count
	// along with the window's expiry time, creating the window if absent.
	Increment(key string, window time.Duration) (count int, resetAt time.Time)
}

// MemoryStore is a process-local, goroutine-safe RateLimiterStore using a
// fixed-window counter. It does NOT share state across processes/instances.
type MemoryStore struct {
	mu      sync.Mutex
	buckets map[string]*memoryBucket
}

type memoryBucket struct {
	count   int
	resetAt time.Time
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{buckets: make(map[string]*memoryBucket)}
}

// Increment implements RateLimiterStore using a fixed-window algorithm.
func (s *MemoryStore) Increment(key string, window time.Duration) (int, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	b, ok := s.buckets[key]
	if !ok || now.After(b.resetAt) {
		b = &memoryBucket{count: 0, resetAt: now.Add(window)}
		s.buckets[key] = b
	}
	b.count++
	return b.count, b.resetAt
}

// RateLimiter enforces a maximum number of actions per key within a rolling
// window, backed by a pluggable RateLimiterStore.
type RateLimiter struct {
	store  RateLimiterStore
	limit  int
	window time.Duration
}

// NewRateLimiter constructs a RateLimiter allowing at most `limit` actions
// per `window` per key, using the given store.
func NewRateLimiter(store RateLimiterStore, limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{store: store, limit: limit, window: window}
}

// Allow reports whether the action identified by key is permitted right
// now, and increments its counter as a side effect (checked and consumed
// atomically with respect to the store's own locking).
func (r *RateLimiter) Allow(key string) bool {
	count, _ := r.store.Increment(key, r.window)
	return count <= r.limit
}
