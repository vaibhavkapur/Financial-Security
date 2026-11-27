package ratelimit

import (
	"math"
	"sync"
	"time"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// Result captures the deterministic outcome of a rate-limit check.
type Result struct {
	Allowed           bool
	Remaining         int
	Limit             int
	RetryAfterSeconds int
}

// Limiter defines the rate-limiting boundary (in-memory or Redis adapter).
type Limiter interface {
	Allow(bucketKey string, rps float64, burst int) Result
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// TokenBucketLimiter is a thread-safe, clock-driven token bucket rate limiter.
type TokenBucketLimiter struct {
	mu      sync.Mutex
	clock   domain.Clock
	buckets map[string]*bucket
}

func NewTokenBucketLimiter(clock domain.Clock) *TokenBucketLimiter {
	if clock == nil {
		clock = domain.RealClock{}
	}
	return &TokenBucketLimiter{
		clock:   clock,
		buckets: make(map[string]*bucket),
	}
}

func (l *TokenBucketLimiter) Allow(bucketKey string, rps float64, burst int) Result {
	if rps <= 0 || burst <= 0 {
		return Result{Allowed: false, Remaining: 0, Limit: 0, RetryAfterSeconds: 1}
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now().UTC()
	b, ok := l.buckets[bucketKey]
	if !ok {
		b = &bucket{
			tokens:     float64(burst),
			lastRefill: now,
		}
		l.buckets[bucketKey] = b
	} else {
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(float64(burst), b.tokens+elapsed*rps)
			b.lastRefill = now
		}
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return Result{
			Allowed:   true,
			Remaining: int(math.Floor(b.tokens)),
			Limit:     burst,
		}
	}

	deficit := 1.0 - b.tokens
	retrySec := int(math.Ceil(deficit / rps))
	if retrySec < 1 {
		retrySec = 1
	}
	return Result{
		Allowed:           false,
		Remaining:         0,
		Limit:             burst,
		RetryAfterSeconds: retrySec,
	}
}
