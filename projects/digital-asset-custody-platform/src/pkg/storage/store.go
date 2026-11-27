package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/chain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/ledger"
)

// CustodySnapshot is the versioned persistence envelope for deterministic restart and rerun recovery.
// It contains zero private key material.
type CustodySnapshot struct {
	SchemaVersion string               `json:"schema_version"`
	PolicyVersion string               `json:"policy_version"`
	PolicyDigest  string               `json:"policy_digest"`
	SavedAt       string               `json:"saved_at"`
	Ledger        ledger.StateSnapshot `json:"ledger"`
	Chain         chain.ChainSnapshot  `json:"chain"`
	AuditEvents   []domain.AuditEvent  `json:"audit_events"`
}

// SnapshotStore defines the persistence boundary for custody state.
type SnapshotStore interface {
	Save(snap CustodySnapshot) error
	Load() (CustodySnapshot, bool, error)
}

// MemoryStore keeps the latest snapshot in memory (default for fast isolated tests).
type MemoryStore struct {
	mu   sync.RWMutex
	has  bool
	snap CustodySnapshot
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (m *MemoryStore) Save(snap CustodySnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snap = snap
	m.has = true
	return nil
}

func (m *MemoryStore) Load() (CustodySnapshot, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.has {
		return CustodySnapshot{}, false, nil
	}
	return m.snap, true, nil
}

// FileStore persists CustodySnapshot atomically using write-temp + rename for crash-safe restarts.
type FileStore struct {
	mu   sync.Mutex
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (f *FileStore) Save(snap CustodySnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "failed to create state directory", err)
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "failed to encode custody snapshot", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "failed to write temp snapshot", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return domain.WrapError(domain.ErrStorageUnavailable, "failed to atomically replace snapshot", err)
	}
	return nil
}

func (f *FileStore) Load() (CustodySnapshot, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	raw, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CustodySnapshot{}, false, nil
		}
		return CustodySnapshot{}, false, domain.WrapError(domain.ErrStorageUnavailable, "failed to read custody snapshot", err)
	}
	var snap CustodySnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return CustodySnapshot{}, false, domain.WrapError(domain.ErrStorageUnavailable, "corrupted custody snapshot JSON", err)
	}
	return snap, true, nil
}
