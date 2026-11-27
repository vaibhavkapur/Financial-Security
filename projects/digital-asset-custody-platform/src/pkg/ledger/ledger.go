package ledger

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
)

// StateSnapshot captures the complete serializable ledger state for deterministic persistence and restart.
type StateSnapshot struct {
	VaultEpochs   map[string]uint64              `json:"vault_epochs"`
	VaultNonces   map[string]uint64              `json:"vault_nonces"`
	Balances      map[string]domain.VaultBalance `json:"balances"`
	Intents       map[string]domain.IntentRecord `json:"intents"`
	Entries       []domain.LedgerEntry           `json:"entries"`
	DailySpent    map[string]int64               `json:"daily_spent"`
	ReservedByID  map[string]bool                `json:"reserved_by_id"`
	SettledByID   map[string]bool                `json:"settled_by_id"`
}

// Ledger manages pure domain custody accounting, balance reservations, nonces, and intent state transitions.
// It is decoupled from I/O, policy evaluation, and signing.
type Ledger struct {
	mu           sync.RWMutex
	vaultEpochs  map[string]uint64
	vaultNonces  map[string]uint64
	balances     map[string]domain.VaultBalance // key: vaultID|ASSET
	intents      map[string]domain.IntentRecord // key: intentID
	entries      []domain.LedgerEntry
	dailySpent   map[string]int64 // key: vaultID|ASSET|YYYY-MM-DD
	reservedByID map[string]bool  // intents currently holding a balance reservation
	settledByID  map[string]bool  // intents whose confirmed balance was deducted
}

func NewLedger(cfg domain.PolicyConfig, now time.Time) *Ledger {
	l := &Ledger{
		vaultEpochs:  make(map[string]uint64, len(cfg.Vaults)),
		vaultNonces:  make(map[string]uint64, len(cfg.Vaults)),
		balances:     make(map[string]domain.VaultBalance),
		intents:      make(map[string]domain.IntentRecord),
		entries:      make([]domain.LedgerEntry, 0),
		dailySpent:   make(map[string]int64),
		reservedByID: make(map[string]bool),
		settledByID:  make(map[string]bool),
	}
	nowStr := now.UTC().Format(time.RFC3339)
	for vaultID, vp := range cfg.Vaults {
		l.vaultEpochs[vaultID] = 1
		l.vaultNonces[vaultID] = 1
		for asset, ap := range vp.Assets {
			key := balKey(vaultID, asset)
			l.balances[key] = domain.VaultBalance{
				VaultID:          vaultID,
				Asset:            strings.ToUpper(asset),
				Unit:             ap.Unit,
				ConfirmedBalance: 0,
				ReservedBalance:  0,
				AvailableBalance: 0,
				UpdatedAt:        nowStr,
			}
		}
	}
	return l
}

func balKey(vaultID, asset string) string {
	return vaultID + "|" + strings.ToUpper(asset)
}

func dayKey(vaultID, asset string, t time.Time) string {
	return vaultID + "|" + strings.ToUpper(asset) + "|" + t.UTC().Format("2006-01-02")
}

// Deposit credits confirmed balance for a vault/asset.
func (l *Ledger) Deposit(vaultID, asset, unit string, amount int64, now time.Time) (domain.VaultBalance, error) {
	if amount <= 0 {
		return domain.VaultBalance{}, domain.NewError(domain.ErrInvalidAmount, "deposit amount must be positive")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	key := balKey(vaultID, asset)
	bal, ok := l.balances[key]
	if !ok {
		bal = domain.VaultBalance{
			VaultID: vaultID,
			Asset:   strings.ToUpper(asset),
			Unit:    unit,
		}
	}
	bal.ConfirmedBalance += amount
	bal.AvailableBalance = bal.ConfirmedBalance - bal.ReservedBalance
	bal.UpdatedAt = now.UTC().Format(time.RFC3339)
	l.balances[key] = bal
	l.appendEntryLocked(vaultID, bal.Asset, "", domain.LedgerDeposit, amount, 0, bal, now)
	return bal, nil
}

// GetBalance returns current balance state for a vault and asset.
func (l *Ledger) GetBalance(vaultID, asset string) (domain.VaultBalance, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	bal, ok := l.balances[balKey(vaultID, asset)]
	return bal, ok
}

// AllBalances returns all vault balances sorted deterministically by vault_id and asset.
func (l *Ledger) AllBalances() []domain.VaultBalance {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]domain.VaultBalance, 0, len(l.balances))
	for _, b := range l.balances {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VaultID == out[j].VaultID {
			return out[i].Asset < out[j].Asset
		}
		return out[i].VaultID < out[j].VaultID
	})
	return out
}

// DailySpent returns cumulative reserved/settled amount for (vault, asset, UTC day).
func (l *Ledger) DailySpent(vaultID, asset string, now time.Time) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dailySpent[dayKey(vaultID, asset, now)]
}

// ActiveKeyEpoch returns the vault's active key epoch recorded in the ledger.
func (l *Ledger) ActiveKeyEpoch(vaultID string) (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	ep, ok := l.vaultEpochs[vaultID]
	if !ok {
		return 0, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	return ep, nil
}

// NextNonce returns the next expected nonce for a vault.
func (l *Ledger) NextNonce(vaultID string) (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n, ok := l.vaultNonces[vaultID]
	if !ok {
		return 0, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	return n, nil
}

// RegisterIntent records a policy-evaluated intent, enforces replay/nonce/epoch invariants, and reserves funds if allowed.
func (l *Ledger) RegisterIntent(intent domain.TransferIntent, intentHash string, decision domain.PolicyDecision, now time.Time) (domain.IntentRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.intents[intent.IntentID]; exists {
		return domain.IntentRecord{}, domain.NewError(domain.ErrReplayDetected, "duplicate intent_id already recorded: "+intent.IntentID)
	}

	nowStr := now.UTC().Format(time.RFC3339)

	// Record denied intents without reserving funds or advancing nonce.
	if !decision.Allowed {
		rec := domain.IntentRecord{
			Intent:         intent,
			IntentHash:     intentHash,
			Status:         domain.StatusDenied,
			PolicyDecision: decision,
			FailureReason:  decision.Reason,
			UpdatedAt:      nowStr,
		}
		l.intents[intent.IntentID] = rec
		return rec, nil
	}

	// Verify active key epoch.
	activeEpoch, ok := l.vaultEpochs[intent.VaultID]
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+intent.VaultID)
	}
	if intent.KeyEpoch != activeEpoch {
		return domain.IntentRecord{}, domain.NewError(domain.ErrKeyEpochMismatch,
			fmt.Sprintf("intent key_epoch %d does not match active vault epoch %d", intent.KeyEpoch, activeEpoch))
	}

	// Verify sequential nonce and block replay of already-used nonces.
	expectedNonce := l.vaultNonces[intent.VaultID]
	if intent.Nonce < expectedNonce {
		return domain.IntentRecord{}, domain.NewError(domain.ErrReplayDetected,
			fmt.Sprintf("nonce %d was already consumed for vault %s (next expected %d)", intent.Nonce, intent.VaultID, expectedNonce))
	}
	if intent.Nonce > expectedNonce {
		return domain.IntentRecord{}, domain.NewError(domain.ErrNonceMismatch,
			fmt.Sprintf("nonce %d out of sequence for vault %s (expected %d)", intent.Nonce, intent.VaultID, expectedNonce))
	}

	// Reserve balance atomically.
	key := balKey(intent.VaultID, intent.Asset)
	bal, ok := l.balances[key]
	if !ok || bal.AvailableBalance < intent.Amount {
		return domain.IntentRecord{}, domain.NewError(domain.ErrInsufficientFunds,
			fmt.Sprintf("insufficient available balance for %s/%s: have %d, need %d", intent.VaultID, intent.Asset, bal.AvailableBalance, intent.Amount))
	}
	bal.ReservedBalance += intent.Amount
	bal.AvailableBalance = bal.ConfirmedBalance - bal.ReservedBalance
	bal.UpdatedAt = nowStr
	l.balances[key] = bal
	l.reservedByID[intent.IntentID] = true
	l.dailySpent[dayKey(intent.VaultID, intent.Asset, now)] += intent.Amount
	l.vaultNonces[intent.VaultID] = expectedNonce + 1
	l.appendEntryLocked(intent.VaultID, intent.Asset, intent.IntentID, domain.LedgerReserve, 0, intent.Amount, bal, now)

	rec := domain.IntentRecord{
		Intent:         intent,
		IntentHash:     intentHash,
		Status:         domain.StatusPendingApproval,
		PolicyDecision: decision,
		Approvals:      make([]domain.ApprovalSignature, 0),
		UpdatedAt:      nowStr,
	}
	l.intents[intent.IntentID] = rec
	return rec, nil
}

// GetIntent returns a copy of an IntentRecord.
func (l *Ledger) GetIntent(intentID string) (domain.IntentRecord, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	rec, ok := l.intents[intentID]
	return rec, ok
}

// AllIntents returns all intents sorted by IntentID.
func (l *Ledger) AllIntents() []domain.IntentRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]domain.IntentRecord, 0, len(l.intents))
	for _, rec := range l.intents {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Intent.IntentID < out[j].Intent.IntentID
	})
	return out
}

// RecordApproval appends a verified approval signature and transitions to APPROVED once quorum is reached.
func (l *Ledger) RecordApproval(intentID string, approval domain.ApprovalSignature, now time.Time) (domain.IntentRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.intents[intentID]
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrIntentNotFound, "intent not found: "+intentID)
	}
	if rec.Status != domain.StatusPendingApproval {
		return domain.IntentRecord{}, domain.NewError(domain.ErrInvalidStateTransition,
			fmt.Sprintf("cannot approve intent %s in status %s", intentID, rec.Status))
	}
	for _, existing := range rec.Approvals {
		if existing.ApproverID == approval.ApproverID {
			return domain.IntentRecord{}, domain.NewError(domain.ErrDuplicateApproval, "duplicate approval from "+approval.ApproverID)
		}
	}

	nowStr := now.UTC().Format(time.RFC3339)
	rec.Approvals = append(rec.Approvals, approval)
	rec.UpdatedAt = nowStr

	if len(rec.Approvals) >= rec.PolicyDecision.RequiredApprovals {
		rec.Status = domain.StatusApproved
		cert := &domain.ApprovalCertificate{
			IntentID:       rec.Intent.IntentID,
			IntentHash:     rec.IntentHash,
			KeyEpoch:       rec.Intent.KeyEpoch,
			PolicyDecision: rec.PolicyDecision,
			Approvals:      append([]domain.ApprovalSignature(nil), rec.Approvals...),
			CertifiedAt:    nowStr,
		}
		rec.Certificate = cert
	}

	l.intents[intentID] = rec
	return rec, nil
}

// MarkSigned stores a verified MultisigBundle and transitions APPROVED -> SIGNED.
func (l *Ledger) MarkSigned(intentID string, bundle domain.MultisigBundle, now time.Time) (domain.IntentRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.intents[intentID]
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrIntentNotFound, "intent not found: "+intentID)
	}
	if rec.Status != domain.StatusApproved {
		return domain.IntentRecord{}, domain.NewError(domain.ErrInvalidStateTransition,
			fmt.Sprintf("cannot mark intent %s signed from status %s", intentID, rec.Status))
	}
	b := bundle
	rec.Multisig = &b
	rec.TxHash = bundle.TxHash
	rec.Status = domain.StatusSigned
	rec.UpdatedAt = now.UTC().Format(time.RFC3339)
	l.intents[intentID] = rec
	return rec, nil
}

// MarkBroadcast transitions SIGNED -> BROADCAST.
func (l *Ledger) MarkBroadcast(intentID string, now time.Time) (domain.IntentRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.intents[intentID]
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrIntentNotFound, "intent not found: "+intentID)
	}
	if rec.Status != domain.StatusSigned {
		return domain.IntentRecord{}, domain.NewError(domain.ErrInvalidStateTransition,
			fmt.Sprintf("cannot broadcast intent %s from status %s", intentID, rec.Status))
	}
	rec.Status = domain.StatusBroadcast
	rec.UpdatedAt = now.UTC().Format(time.RFC3339)
	l.intents[intentID] = rec
	return rec, nil
}

// UpdateChainProgress reconciles an intent's status against a mock testnet transaction receipt.
// When tx is included or confirmed on-chain, the ledger deducts ConfirmedBalance and releases ReservedBalance atomically.
// When a reorg orphans a previously settled tx, the ledger reverts the settlement and restores the reservation (or releases it if permanently dropped).
func (l *Ledger) UpdateChainProgress(intentID string, tx domain.ChainTransaction, requiredConfirmations int, now time.Time) (domain.IntentRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.intents[intentID]
	if !ok {
		return domain.IntentRecord{}, false, domain.NewError(domain.ErrIntentNotFound, "intent not found: "+intentID)
	}

	nowStr := now.UTC().Format(time.RFC3339)
	reorgDetected := false
	key := balKey(rec.Intent.VaultID, rec.Intent.Asset)
	bal := l.balances[key]

	// Detect block hash change or return to mempool/orphaned after inclusion.
	if rec.BlockHash != "" && (tx.BlockHash != rec.BlockHash || tx.Status == domain.ChainTxMempool || tx.Status == domain.ChainTxOrphaned) {
		reorgDetected = true
		if l.settledByID[intentID] {
			// Revert confirmed deduction back to reserved while awaiting re-inclusion (or release if orphaned).
			bal.ConfirmedBalance += rec.Intent.Amount
			bal.ReservedBalance += rec.Intent.Amount
			bal.AvailableBalance = bal.ConfirmedBalance - bal.ReservedBalance
			bal.UpdatedAt = nowStr
			l.balances[key] = bal
			delete(l.settledByID, intentID)
			l.reservedByID[intentID] = true
			l.appendEntryLocked(rec.Intent.VaultID, rec.Intent.Asset, intentID, domain.LedgerReorgRevert, rec.Intent.Amount, rec.Intent.Amount, bal, now)
		}
	}

	switch tx.Status {
	case domain.ChainTxMempool:
		rec.Status = domain.StatusBroadcast
		rec.BlockHeight = 0
		rec.BlockHash = ""
		rec.Confirmations = 0
	case domain.ChainTxIncluded, domain.ChainTxConfirmed:
		// Deduct confirmed balance once included in a canonical block so ledger matches on-chain vault balance.
		if !l.settledByID[intentID] && l.reservedByID[intentID] {
			bal.ConfirmedBalance -= rec.Intent.Amount
			bal.ReservedBalance -= rec.Intent.Amount
			bal.AvailableBalance = bal.ConfirmedBalance - bal.ReservedBalance
			bal.UpdatedAt = nowStr
			l.balances[key] = bal
			delete(l.reservedByID, intentID)
			l.settledByID[intentID] = true
			l.appendEntryLocked(rec.Intent.VaultID, rec.Intent.Asset, intentID, domain.LedgerSettle, -rec.Intent.Amount, -rec.Intent.Amount, bal, now)
		}
		rec.BlockHeight = tx.BlockHeight
		rec.BlockHash = tx.BlockHash
		rec.Confirmations = tx.Confirmations
		if tx.Confirmations >= requiredConfirmations {
			rec.Status = domain.StatusConfirmed
		} else {
			rec.Status = domain.StatusConfirming
		}
	case domain.ChainTxOrphaned:
		// Permanently evicted by reorg: release reservation so funds return to available balance.
		if l.reservedByID[intentID] {
			bal.ReservedBalance -= rec.Intent.Amount
			bal.AvailableBalance = bal.ConfirmedBalance - bal.ReservedBalance
			bal.UpdatedAt = nowStr
			l.balances[key] = bal
			delete(l.reservedByID, intentID)
			l.appendEntryLocked(rec.Intent.VaultID, rec.Intent.Asset, intentID, domain.LedgerRelease, 0, -rec.Intent.Amount, bal, now)
		}
		rec.Status = domain.StatusReorgedDropped
		rec.BlockHeight = 0
		rec.BlockHash = ""
		rec.Confirmations = 0
		rec.FailureReason = "transaction orphaned and dropped during chain reorganization"
	}

	rec.UpdatedAt = nowStr
	l.intents[intentID] = rec
	return rec, reorgDetected, nil
}

// RotateKeyEpoch advances a vault's active epoch and invalidates all pre-signing pending intents bound to the superseded epoch,
// cleanly releasing their reserved balances so no funds are stranded and stale epochs cannot be signed.
func (l *Ledger) RotateKeyEpoch(vaultID string, newEpoch uint64, now time.Time) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cur, ok := l.vaultEpochs[vaultID]
	if !ok {
		return nil, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	if newEpoch != cur+1 {
		return nil, domain.NewError(domain.ErrKeyEpochMismatch, fmt.Sprintf("expected next epoch %d, got %d", cur+1, newEpoch))
	}
	l.vaultEpochs[vaultID] = newEpoch
	nowStr := now.UTC().Format(time.RFC3339)

	invalidated := make([]string, 0)
	for id, rec := range l.intents {
		if rec.Intent.VaultID != vaultID || rec.Intent.KeyEpoch >= newEpoch {
			continue
		}
		if rec.Status == domain.StatusPendingApproval || rec.Status == domain.StatusApproved {
			if l.reservedByID[id] {
				key := balKey(rec.Intent.VaultID, rec.Intent.Asset)
				bal := l.balances[key]
				bal.ReservedBalance -= rec.Intent.Amount
				bal.AvailableBalance = bal.ConfirmedBalance - bal.ReservedBalance
				bal.UpdatedAt = nowStr
				l.balances[key] = bal
				delete(l.reservedByID, id)
				// Also credit back daily spend for the invalidated pre-signing intent.
				if created, err := time.Parse(time.RFC3339, rec.Intent.CreatedAt); err == nil {
					dk := dayKey(rec.Intent.VaultID, rec.Intent.Asset, created)
					l.dailySpent[dk] -= rec.Intent.Amount
					if l.dailySpent[dk] < 0 {
						l.dailySpent[dk] = 0
					}
				}
				l.appendEntryLocked(rec.Intent.VaultID, rec.Intent.Asset, id, domain.LedgerRelease, 0, -rec.Intent.Amount, bal, now)
			}
			rec.Status = domain.StatusInvalidatedKeyRotation
			rec.FailureReason = fmt.Sprintf("superseded by key rotation to epoch %d; requires re-submission and re-approval", newEpoch)
			rec.UpdatedAt = nowStr
			l.intents[id] = rec
			invalidated = append(invalidated, id)
		}
	}
	sort.Strings(invalidated)
	return invalidated, nil
}

// PendingReservedSum computes the sum of amounts for all intents currently holding a balance reservation.
func (l *Ledger) PendingReservedSum(vaultID, asset string) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var total int64
	for id := range l.reservedByID {
		rec := l.intents[id]
		if rec.Intent.VaultID == vaultID && strings.EqualFold(rec.Intent.Asset, asset) {
			total += rec.Intent.Amount
		}
	}
	return total
}

// Entries returns a copy of the immutable double-entry ledger journal.
func (l *Ledger) Entries() []domain.LedgerEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]domain.LedgerEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Snapshot exports the complete ledger state for durable persistence.
func (l *Ledger) Snapshot() StateSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()

	snap := StateSnapshot{
		VaultEpochs:  make(map[string]uint64, len(l.vaultEpochs)),
		VaultNonces:  make(map[string]uint64, len(l.vaultNonces)),
		Balances:     make(map[string]domain.VaultBalance, len(l.balances)),
		Intents:      make(map[string]domain.IntentRecord, len(l.intents)),
		Entries:      append([]domain.LedgerEntry(nil), l.entries...),
		DailySpent:   make(map[string]int64, len(l.dailySpent)),
		ReservedByID: make(map[string]bool, len(l.reservedByID)),
		SettledByID:  make(map[string]bool, len(l.settledByID)),
	}
	for k, v := range l.vaultEpochs {
		snap.VaultEpochs[k] = v
	}
	for k, v := range l.vaultNonces {
		snap.VaultNonces[k] = v
	}
	for k, v := range l.balances {
		snap.Balances[k] = v
	}
	for k, v := range l.intents {
		snap.Intents[k] = v
	}
	for k, v := range l.dailySpent {
		snap.DailySpent[k] = v
	}
	for k, v := range l.reservedByID {
		snap.ReservedByID[k] = v
	}
	for k, v := range l.settledByID {
		snap.SettledByID[k] = v
	}
	return snap
}

// Restore loads a previously persisted StateSnapshot into the Ledger.
func (l *Ledger) Restore(snap StateSnapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.vaultEpochs = snap.VaultEpochs
	l.vaultNonces = snap.VaultNonces
	l.balances = snap.Balances
	l.intents = snap.Intents
	l.entries = append([]domain.LedgerEntry(nil), snap.Entries...)
	l.dailySpent = snap.DailySpent
	l.reservedByID = snap.ReservedByID
	l.settledByID = snap.SettledByID
}

func (l *Ledger) appendEntryLocked(vaultID, asset, intentID string, typ domain.LedgerEntryType, dConfirmed, dReserved int64, bal domain.VaultBalance, now time.Time) {
	entryID := fmt.Sprintf("le-%06d", len(l.entries)+1)
	l.entries = append(l.entries, domain.LedgerEntry{
		EntryID:        entryID,
		VaultID:        vaultID,
		Asset:          strings.ToUpper(asset),
		IntentID:       intentID,
		Type:           typ,
		DeltaConfirmed: dConfirmed,
		DeltaReserved:  dReserved,
		BalanceAfter:   bal.ConfirmedBalance,
		ReservedAfter:  bal.ReservedBalance,
		CreatedAt:      now.UTC().Format(time.RFC3339),
	})
}
