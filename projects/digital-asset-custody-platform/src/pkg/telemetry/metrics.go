package telemetry

import (
	"io"
	"log/slog"
	"sync"
)

// Counters captures deterministic diagnostic telemetry across custody boundaries.
type Counters struct {
	mu                     sync.RWMutex
	IntentsSubmitted       int64 `json:"intents_submitted"`
	PolicyAllowed          int64 `json:"policy_allowed"`
	PolicyDenied           int64 `json:"policy_denied"`
	ApprovalsAccepted      int64 `json:"approvals_accepted"`
	ApprovalsRejected      int64 `json:"approvals_rejected"`
	SignaturesIssued       int64 `json:"signatures_issued"`
	SignaturesRejected     int64 `json:"signatures_rejected"`
	ReplaysBlocked         int64 `json:"replays_blocked"`
	SignerOutages          int64 `json:"signer_outages"`
	ReorgsDetected         int64 `json:"reorgs_detected"`
	KeyRotations           int64 `json:"key_rotations"`
	IntentsInvalidatedRot  int64 `json:"intents_invalidated_key_rotation"`
	ReconciliationsPassed  int64 `json:"reconciliations_passed"`
	ReconciliationsFailed  int64 `json:"reconciliations_failed"`
}

// Snapshot returns a value copy of all counters suitable for JSON serialization.
type Snapshot struct {
	IntentsSubmitted      int64 `json:"intents_submitted"`
	PolicyAllowed         int64 `json:"policy_allowed"`
	PolicyDenied          int64 `json:"policy_denied"`
	ApprovalsAccepted     int64 `json:"approvals_accepted"`
	ApprovalsRejected     int64 `json:"approvals_rejected"`
	SignaturesIssued      int64 `json:"signatures_issued"`
	SignaturesRejected    int64 `json:"signatures_rejected"`
	ReplaysBlocked        int64 `json:"replays_blocked"`
	SignerOutages         int64 `json:"signer_outages"`
	ReorgsDetected        int64 `json:"reorgs_detected"`
	KeyRotations          int64 `json:"key_rotations"`
	IntentsInvalidatedRot int64 `json:"intents_invalidated_key_rotation"`
	ReconciliationsPassed int64 `json:"reconciliations_passed"`
	ReconciliationsFailed int64 `json:"reconciliations_failed"`
}

func NewCounters() *Counters { return &Counters{} }

func (c *Counters) Inc(fn func(*Counters)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c)
}

func (c *Counters) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Snapshot{
		IntentsSubmitted:      c.IntentsSubmitted,
		PolicyAllowed:         c.PolicyAllowed,
		PolicyDenied:          c.PolicyDenied,
		ApprovalsAccepted:     c.ApprovalsAccepted,
		ApprovalsRejected:     c.ApprovalsRejected,
		SignaturesIssued:      c.SignaturesIssued,
		SignaturesRejected:    c.SignaturesRejected,
		ReplaysBlocked:        c.ReplaysBlocked,
		SignerOutages:         c.SignerOutages,
		ReorgsDetected:        c.ReorgsDetected,
		KeyRotations:          c.KeyRotations,
		IntentsInvalidatedRot: c.IntentsInvalidatedRot,
		ReconciliationsPassed: c.ReconciliationsPassed,
		ReconciliationsFailed: c.ReconciliationsFailed,
	}
}

// NewJSONLogger builds a structured JSON slog.Logger writing to w (or io.Discard if nil).
func NewJSONLogger(w io.Writer) *slog.Logger {
	if w == nil {
		w = io.Discard
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}
