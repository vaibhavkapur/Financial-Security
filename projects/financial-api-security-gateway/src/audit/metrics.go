package audit

import (
	"sync"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// MetricsSnapshot is a serializable point-in-time view of gateway diagnostic counters.
type MetricsSnapshot struct {
	TotalRequests     uint64                       `json:"total_requests"`
	AllowedRequests   uint64                       `json:"allowed_requests"`
	DeniedRequests    uint64                       `json:"denied_requests"`
	UpstreamTimeouts  uint64                       `json:"upstream_timeouts"`
	ReplayRejections  uint64                       `json:"replay_rejections"`
	RateLimitHits     uint64                       `json:"rate_limit_hits"`
	ReasonCodeCounts  map[domain.ReasonCode]uint64 `json:"reason_code_counts"`
}

// Metrics tracks thread-safe diagnostic counters for gateway decisions and failures.
type Metrics struct {
	mu           sync.RWMutex
	total        uint64
	allowed      uint64
	denied       uint64
	timeouts     uint64
	replays      uint64
	rateLimited  uint64
	reasonCounts map[domain.ReasonCode]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{reasonCounts: make(map[domain.ReasonCode]uint64)}
}

func (m *Metrics) Record(decision domain.Decision, reason domain.ReasonCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	if decision == domain.DecisionAllow {
		m.allowed++
	} else {
		m.denied++
	}
	m.reasonCounts[reason]++
	switch reason {
	case domain.ReasonNonceReplay:
		m.replays++
	case domain.ReasonRateLimited:
		m.rateLimited++
	case domain.ReasonUpstreamTimeout:
		m.timeouts++
	}
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rc := make(map[domain.ReasonCode]uint64, len(m.reasonCounts))
	for k, v := range m.reasonCounts {
		rc[k] = v
	}
	return MetricsSnapshot{
		TotalRequests:    m.total,
		AllowedRequests:  m.allowed,
		DeniedRequests:   m.denied,
		UpstreamTimeouts: m.timeouts,
		ReplayRejections: m.replays,
		RateLimitHits:    m.rateLimited,
		ReasonCodeCounts: rc,
	}
}
