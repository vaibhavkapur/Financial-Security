package signing

import (
	"sync"
	"time"
)

// NonceStore defines the replay-prevention persistence boundary (in-memory or Redis/PostgreSQL adapter).
type NonceStore interface {
	// CheckAndRecord returns true if the scoped nonce was already seen and has not expired.
	// Otherwise it records the nonce with the given TTL and returns false.
	CheckAndRecord(scopeKey string, now time.Time, ttl time.Duration) bool
	Size(now time.Time) int
}

// MemoryNonceStore is a bounded, thread-safe, deterministic in-memory NonceStore.
type MemoryNonceStore struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
}

func NewMemoryNonceStore(maxEntries int) *MemoryNonceStore {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &MemoryNonceStore{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
	}
}

func (s *MemoryNonceStore) CheckAndRecord(scopeKey string, now time.Time, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUTC := now.UTC()
	if exp, exists := s.entries[scopeKey]; exists {
		if nowUTC.Before(exp) {
			return true // Replay detected!
		}
		delete(s.entries, scopeKey)
	}

	if len(s.entries) >= s.maxEntries {
		// Evict expired entries first.
		for k, exp := range s.entries {
			if !nowUTC.Before(exp) {
				delete(s.entries, k)
			}
		}
		// If still full, evict earliest-expiring entry deterministically.
		if len(s.entries) >= s.maxEntries {
			var oldestKey string
			var oldestExp time.Time
			first := true
			for k, exp := range s.entries {
				if first || exp.Before(oldestExp) || (exp.Equal(oldestExp) && k < oldestKey) {
					oldestKey = k
					oldestExp = exp
					first = false
				}
			}
			if !first {
				delete(s.entries, oldestKey)
			}
		}
	}

	s.entries[scopeKey] = nowUTC.Add(ttl)
	return false
}

func (s *MemoryNonceStore) Size(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	nowUTC := now.UTC()
	count := 0
	for _, exp := range s.entries {
		if nowUTC.Before(exp) {
			count++
		}
	}
	return count
}
