package domain

import (
	"sync"
	"time"
)

// Clock abstracts wall-clock time so all security decisions and tests are deterministic.
type Clock interface {
	Now() time.Time
}

// RealClock delegates to time.Now().UTC().
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

// FixedClock provides a thread-safe controllable clock for deterministic testing and replay.
type FixedClock struct {
	mu  sync.RWMutex
	now time.Time
}

func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{now: t.UTC()}
}

func (c *FixedClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *FixedClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t.UTC()
}

func (c *FixedClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}
