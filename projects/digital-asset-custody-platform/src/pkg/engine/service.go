package engine

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/audit"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/chain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/ledger"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/policy"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/signer"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/storage"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/telemetry"
)

// ServiceOptions configures a CustodyService instance across all four security boundaries.
type ServiceOptions struct {
	PolicyConfig    domain.PolicyConfig
	MasterSeed      string
	Clock           domain.Clock
	Store           storage.SnapshotStore
	Logger          *slog.Logger
	ApproverPubKeys map[string]ed25519.PublicKey
}

// CustodyService coordinates the policy, ledger, isolated signer, mock chain, and audit boundaries.
type CustodyService struct {
	policy          *policy.Engine
	ledger          *ledger.Ledger
	signers         *signer.MockMultisigCluster
	chain           *chain.MockChain
	audit           *audit.Log
	store           storage.SnapshotStore
	counters        *telemetry.Counters
	logger          *slog.Logger
	clock           domain.Clock
	approverPubKeys map[string]ed25519.PublicKey
}

// NewService creates a CustodyService and restores persisted state from Store if present.
func NewService(opts ServiceOptions) (*CustodyService, error) {
	if opts.Clock == nil {
		opts.Clock = domain.RealClock{}
	}
	if opts.Store == nil {
		opts.Store = storage.NewMemoryStore()
	}
	if opts.Logger == nil {
		opts.Logger = telemetry.NewJSONLogger(nil)
	}
	if strings.TrimSpace(opts.MasterSeed) == "" {
		return nil, domain.NewError(domain.ErrInvalidConfig, "master_seed is required for deterministic prototype key derivation")
	}

	polEngine, err := policy.NewEngine(opts.PolicyConfig)
	if err != nil {
		return nil, err
	}

	now := opts.Clock.Now()
	approverPubs := opts.ApproverPubKeys
	if approverPubs == nil {
		kr := signer.NewApproverKeyring(opts.MasterSeed, opts.PolicyConfig.Approvers)
		approverPubs = kr.PublicKeys()
	}

	svc := &CustodyService{
		policy:          polEngine,
		ledger:          ledger.NewLedger(opts.PolicyConfig, now),
		signers:         signer.NewMockMultisigCluster(opts.MasterSeed, opts.PolicyConfig, approverPubs, now),
		chain:           chain.NewMockChain(opts.PolicyConfig.ConfirmationDepth, now),
		audit:           audit.NewLog(),
		store:           opts.Store,
		counters:        telemetry.NewCounters(),
		logger:          opts.Logger,
		clock:           opts.Clock,
		approverPubKeys: approverPubs,
	}

	// Hydrate persisted state on restart/rerun if available.
	snap, found, err := opts.Store.Load()
	if err != nil {
		return nil, err
	}
	if found {
		if snap.PolicyVersion != opts.PolicyConfig.PolicyVersion {
			return nil, domain.NewError(domain.ErrInvalidConfig,
				fmt.Sprintf("persisted snapshot policy_version %s does not match loaded policy_version %s", snap.PolicyVersion, opts.PolicyConfig.PolicyVersion))
		}
		if err := svc.audit.Restore(snap.AuditEvents); err != nil {
			return nil, domain.WrapError(domain.ErrReconciliationMismatch, "persisted audit chain integrity check failed", err)
		}
		svc.ledger.Restore(snap.Ledger)
		svc.chain.Restore(snap.Chain)
		svc.signers.RestoreState(snap.Ledger.VaultEpochs, svc.ledger.AllIntents(), now)
		svc.audit.Append(now, "SERVICE_RESTARTED", "system", "", "OK", "", map[string]any{
			"policy_version": opts.PolicyConfig.PolicyVersion,
			"restored_at":    now.UTC().Format(time.RFC3339),
		})
		_ = svc.persist()
	}

	return svc, nil
}

func (s *CustodyService) PolicyEngine() *policy.Engine         { return s.policy }
func (s *CustodyService) Ledger() *ledger.Ledger               { return s.ledger }
func (s *CustodyService) Signers() *signer.MockMultisigCluster { return s.signers }
func (s *CustodyService) Chain() *chain.MockChain              { return s.chain }
func (s *CustodyService) AuditLog() *audit.Log                 { return s.audit }
func (s *CustodyService) Counters() *telemetry.Counters        { return s.counters }

// Deposit credits both the mock testnet on-chain vault address and the custody ledger.
func (s *CustodyService) Deposit(vaultID, asset, unit string, amount int64) (domain.VaultBalance, error) {
	vp, ok := s.policy.Config().Vaults[vaultID]
	if !ok {
		return domain.VaultBalance{}, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	ap, ok := vp.Assets[strings.ToUpper(asset)]
	if !ok {
		return domain.VaultBalance{}, domain.NewError(domain.ErrUnsupportedAsset, "unsupported asset for vault: "+asset)
	}
	if unit == "" {
		unit = ap.Unit
	}
	if err := s.chain.CreditAddress(vp.Network, vp.SourceAddress, strings.ToUpper(asset), amount); err != nil {
		return domain.VaultBalance{}, err
	}
	now := s.clock.Now()
	bal, err := s.ledger.Deposit(vaultID, strings.ToUpper(asset), unit, amount, now)
	if err != nil {
		return domain.VaultBalance{}, err
	}
	s.audit.Append(now, "DEPOSIT_CREDITED", "system", "", "OK", "", map[string]any{
		"vault_id": vaultID,
		"asset":    strings.ToUpper(asset),
		"amount":   amount,
		"unit":     unit,
	})
	s.logger.Info("deposit_credited", "vault_id", vaultID, "asset", strings.ToUpper(asset), "amount", amount)
	if err := s.persist(); err != nil {
		return domain.VaultBalance{}, err
	}
	return bal, nil
}

// SubmitIntent validates, policy-evaluates, hashes, and registers a custody TransferIntent.
func (s *CustodyService) SubmitIntent(intent domain.TransferIntent) (domain.IntentRecord, error) {
	now := s.clock.Now()
	intent.Normalize()
	s.counters.Inc(func(c *telemetry.Counters) { c.IntentsSubmitted++ })

	intentHash, err := intent.ComputeHash()
	if err != nil {
		s.counters.Inc(func(c *telemetry.Counters) { c.PolicyDenied++ })
		s.audit.Append(now, "INTENT_SUBMITTED", intent.RequestedBy, intent.IntentID, "DENIED", domain.CodeOf(err), map[string]any{"error": err.Error()})
		return domain.IntentRecord{}, err
	}

	dailySpent := s.ledger.DailySpent(intent.VaultID, intent.Asset, now)
	decision, polErr := s.policy.Evaluate(intent, dailySpent, now)
	if polErr != nil {
		s.counters.Inc(func(c *telemetry.Counters) { c.PolicyDenied++ })
		rec, regErr := s.ledger.RegisterIntent(intent, intentHash, decision, now)
		if regErr != nil && domain.CodeOf(regErr) == domain.ErrReplayDetected {
			s.counters.Inc(func(c *telemetry.Counters) { c.ReplaysBlocked++ })
			s.audit.Append(now, "INTENT_REPLAY_BLOCKED", intent.RequestedBy, intent.IntentID, "DENIED", domain.ErrReplayDetected, map[string]any{"intent_hash": intentHash})
			return domain.IntentRecord{}, regErr
		}
		s.audit.Append(now, "POLICY_EVALUATED", intent.RequestedBy, intent.IntentID, "DENIED", decision.ReasonCode, map[string]any{
			"intent_hash": intentHash,
			"reason":      decision.Reason,
		})
		s.logger.Warn("policy_denied", "intent_id", intent.IntentID, "code", decision.ReasonCode, "reason", decision.Reason)
		_ = s.persist()
		return rec, polErr
	}

	rec, err := s.ledger.RegisterIntent(intent, intentHash, decision, now)
	if err != nil {
		if domain.CodeOf(err) == domain.ErrReplayDetected {
			s.counters.Inc(func(c *telemetry.Counters) { c.ReplaysBlocked++ })
		}
		s.audit.Append(now, "INTENT_REGISTRATION_FAILED", intent.RequestedBy, intent.IntentID, "DENIED", domain.CodeOf(err), map[string]any{
			"intent_hash": intentHash,
			"error":       err.Error(),
		})
		s.logger.Warn("intent_registration_failed", "intent_id", intent.IntentID, "code", domain.CodeOf(err))
		return domain.IntentRecord{}, err
	}

	s.counters.Inc(func(c *telemetry.Counters) { c.PolicyAllowed++ })
	s.audit.Append(now, "INTENT_SUBMITTED", intent.RequestedBy, intent.IntentID, "ALLOWED", "", map[string]any{
		"intent_hash":        intentHash,
		"vault_id":           intent.VaultID,
		"asset":              intent.Asset,
		"amount":             intent.Amount,
		"destination":        intent.DestinationAddress,
		"nonce":              intent.Nonce,
		"key_epoch":          intent.KeyEpoch,
		"required_approvals": decision.RequiredApprovals,
		"required_signers":   decision.RequiredSigners,
	})
	s.logger.Info("intent_submitted", "intent_id", intent.IntentID, "intent_hash", intentHash, "required_approvals", decision.RequiredApprovals)
	if err := s.persist(); err != nil {
		return domain.IntentRecord{}, err
	}
	return rec, nil
}

// ApproveIntent verifies an independent Ed25519 approval signature bound to the intent hash.
func (s *CustodyService) ApproveIntent(intentID string, approval domain.ApprovalSignature) (domain.IntentRecord, error) {
	now := s.clock.Now()
	rec, ok := s.ledger.GetIntent(intentID)
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrIntentNotFound, "intent not found: "+intentID)
	}
	if err := rec.Intent.ValidateBasic(now); err != nil {
		s.counters.Inc(func(c *telemetry.Counters) { c.ApprovalsRejected++ })
		s.audit.Append(now, "APPROVAL_REJECTED", approval.ApproverID, intentID, "DENIED", domain.CodeOf(err), map[string]any{"error": err.Error()})
		return domain.IntentRecord{}, err
	}
	if approval.ApproverID == rec.Intent.RequestedBy {
		err := domain.NewError(domain.ErrSelfApprovalForbidden, "requester cannot approve own transfer intent")
		s.counters.Inc(func(c *telemetry.Counters) { c.ApprovalsRejected++ })
		s.audit.Append(now, "APPROVAL_REJECTED", approval.ApproverID, intentID, "DENIED", domain.ErrSelfApprovalForbidden, nil)
		return domain.IntentRecord{}, err
	}

	eligible := false
	for _, id := range rec.PolicyDecision.EligibleApprovers {
		if id == approval.ApproverID {
			eligible = true
			break
		}
	}
	if !eligible {
		err := domain.NewError(domain.ErrUnauthorizedApprover, "approver is not eligible under policy decision: "+approval.ApproverID)
		s.counters.Inc(func(c *telemetry.Counters) { c.ApprovalsRejected++ })
		s.audit.Append(now, "APPROVAL_REJECTED", approval.ApproverID, intentID, "DENIED", domain.ErrUnauthorizedApprover, nil)
		return domain.IntentRecord{}, err
	}

	if err := signer.VerifyApprovalSignature(s.approverPubKeys, rec.IntentHash, rec.PolicyDecision.PolicyVersion, approval); err != nil {
		s.counters.Inc(func(c *telemetry.Counters) { c.ApprovalsRejected++ })
		s.audit.Append(now, "APPROVAL_REJECTED", approval.ApproverID, intentID, "DENIED", domain.CodeOf(err), map[string]any{"error": err.Error()})
		return domain.IntentRecord{}, err
	}

	updated, err := s.ledger.RecordApproval(intentID, approval, now)
	if err != nil {
		s.counters.Inc(func(c *telemetry.Counters) { c.ApprovalsRejected++ })
		s.audit.Append(now, "APPROVAL_REJECTED", approval.ApproverID, intentID, "DENIED", domain.CodeOf(err), map[string]any{"error": err.Error()})
		return domain.IntentRecord{}, err
	}

	s.counters.Inc(func(c *telemetry.Counters) { c.ApprovalsAccepted++ })
	s.audit.Append(now, "APPROVAL_ACCEPTED", approval.ApproverID, intentID, "OK", "", map[string]any{
		"intent_hash":    rec.IntentHash,
		"approval_count": len(updated.Approvals),
		"status":         updated.Status,
	})
	s.logger.Info("approval_accepted", "intent_id", intentID, "approver", approval.ApproverID, "status", updated.Status)
	if err := s.persist(); err != nil {
		return domain.IntentRecord{}, err
	}
	return updated, nil
}

// RequestSignatureWithPayload crosses the isolated signer boundary directly with an explicit intent and certificate.
// Used both internally and in adversarial tests (tampered destination, missing quorum, stale epoch).
func (s *CustodyService) RequestSignatureWithPayload(intent domain.TransferIntent, cert domain.ApprovalCertificate) (domain.MultisigBundle, error) {
	now := s.clock.Now()
	bundle, err := s.signers.RequestMultisig(signer.SignRequest{
		Intent:      intent,
		Certificate: cert,
	}, now)
	if err != nil {
		code := domain.CodeOf(err)
		s.counters.Inc(func(c *telemetry.Counters) {
			c.SignaturesRejected++
			if code == domain.ErrReplayDetected {
				c.ReplaysBlocked++
			}
		})
		s.audit.Append(now, "SIGNING_REJECTED", "isolated-signer-cluster", intent.IntentID, "DENIED", code, map[string]any{
			"key_epoch": intent.KeyEpoch,
			"error":     err.Error(),
		})
		s.logger.Warn("signing_rejected", "intent_id", intent.IntentID, "code", code, "error", err.Error())
		_ = s.persist()
		return domain.MultisigBundle{}, err
	}

	s.counters.Inc(func(c *telemetry.Counters) { c.SignaturesIssued++ })
	signerIDs := make([]string, 0, len(bundle.Signatures))
	for _, ps := range bundle.Signatures {
		signerIDs = append(signerIDs, ps.SignerID)
	}
	s.audit.Append(now, "SIGNING_COMPLETED", "isolated-signer-cluster", intent.IntentID, "OK", "", map[string]any{
		"intent_hash": bundle.IntentHash,
		"tx_hash":     bundle.TxHash,
		"key_epoch":   bundle.KeyEpoch,
		"signers":     signerIDs,
	})
	return bundle, nil
}

// SignAndBroadcast requests threshold signatures from the isolated signer cluster and broadcasts to the mock testnet.
func (s *CustodyService) SignAndBroadcast(intentID string) (domain.IntentRecord, error) {
	now := s.clock.Now()
	rec, ok := s.ledger.GetIntent(intentID)
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrIntentNotFound, "intent not found: "+intentID)
	}
	if rec.Status == domain.StatusInvalidatedKeyRotation {
		err := domain.NewError(domain.ErrKeyEpochMismatch, "intent was invalidated by key rotation and cannot be signed")
		s.counters.Inc(func(c *telemetry.Counters) { c.SignaturesRejected++ })
		s.audit.Append(now, "SIGNING_REJECTED", "custody-engine", intentID, "DENIED", domain.ErrKeyEpochMismatch, nil)
		return domain.IntentRecord{}, err
	}
	if rec.Status != domain.StatusApproved || rec.Certificate == nil {
		err := domain.NewError(domain.ErrInsufficientApprovals,
			fmt.Sprintf("intent %s is not approved for signing (status=%s, approvals=%d/%d)",
				intentID, rec.Status, len(rec.Approvals), rec.PolicyDecision.RequiredApprovals))
		s.counters.Inc(func(c *telemetry.Counters) { c.SignaturesRejected++ })
		s.audit.Append(now, "SIGNING_REJECTED", "custody-engine", intentID, "DENIED", domain.ErrInsufficientApprovals, nil)
		return domain.IntentRecord{}, err
	}

	// Verify canonical hash matches approved certificate before crossing signer boundary.
	if err := rec.Intent.VerifyHash(rec.Certificate.IntentHash); err != nil {
		s.counters.Inc(func(c *telemetry.Counters) { c.SignaturesRejected++ })
		s.audit.Append(now, "SIGNING_REJECTED", "custody-engine", intentID, "DENIED", domain.ErrIntentHashMismatch, nil)
		return domain.IntentRecord{}, err
	}

	bundle, err := s.RequestSignatureWithPayload(rec.Intent, *rec.Certificate)
	if err != nil {
		return domain.IntentRecord{}, err
	}

	rec, err = s.ledger.MarkSigned(intentID, bundle, now)
	if err != nil {
		return domain.IntentRecord{}, err
	}

	tx, err := s.chain.Broadcast(rec.Intent, bundle, s.signers)
	if err != nil {
		if domain.CodeOf(err) == domain.ErrReplayDetected {
			s.counters.Inc(func(c *telemetry.Counters) { c.ReplaysBlocked++ })
		}
		s.audit.Append(now, "BROADCAST_FAILED", "mock-chain", intentID, "DENIED", domain.CodeOf(err), map[string]any{"error": err.Error()})
		return domain.IntentRecord{}, err
	}

	rec, err = s.ledger.MarkBroadcast(intentID, now)
	if err != nil {
		return domain.IntentRecord{}, err
	}

	s.audit.Append(now, "TX_BROADCAST", "custody-engine", intentID, "OK", "", map[string]any{
		"tx_hash":   tx.TxHash,
		"key_epoch": rec.Intent.KeyEpoch,
		"nonce":     rec.Intent.Nonce,
	})
	s.logger.Info("tx_broadcast", "intent_id", intentID, "tx_hash", tx.TxHash)
	if err := s.persist(); err != nil {
		return domain.IntentRecord{}, err
	}
	return rec, nil
}

// SetSignerOnline toggles an isolated signer node to simulate outage and recovery.
func (s *CustodyService) SetSignerOnline(signerID string, online bool) error {
	now := s.clock.Now()
	if err := s.signers.SetNodeOnline(signerID, online); err != nil {
		return err
	}
	eventType := "SIGNER_RECOVERED"
	if !online {
		eventType = "SIGNER_OUTAGE"
		s.counters.Inc(func(c *telemetry.Counters) { c.SignerOutages++ })
	}
	s.audit.Append(now, eventType, "operator", "", "OK", "", map[string]any{
		"signer_id": signerID,
		"online":    online,
	})
	s.logger.Info(strings.ToLower(eventType), "signer_id", signerID, "online", online)
	return s.persist()
}

// RotateVaultKeys rotates signing keys to epoch+1 in the isolated signer cluster and invalidates
// any pre-signing pending intents bound to the superseded epoch, releasing their reserved balances.
func (s *CustodyService) RotateVaultKeys(vaultID string) (domain.KeyEpochState, []string, error) {
	now := s.clock.Now()
	newState, err := s.signers.RotateVaultKeys(vaultID, now)
	if err != nil {
		return domain.KeyEpochState{}, nil, err
	}
	invalidated, err := s.ledger.RotateKeyEpoch(vaultID, newState.KeyEpoch, now)
	if err != nil {
		return domain.KeyEpochState{}, nil, err
	}

	s.counters.Inc(func(c *telemetry.Counters) {
		c.KeyRotations++
		c.IntentsInvalidatedRot += int64(len(invalidated))
	})
	s.audit.Append(now, "KEY_ROTATION_COMPLETED", "security-operator", "", "OK", "", map[string]any{
		"vault_id":            vaultID,
		"new_key_epoch":       newState.KeyEpoch,
		"invalidated_intents": invalidated,
	})
	for _, id := range invalidated {
		s.audit.Append(now, "INTENT_INVALIDATED_KEY_ROTATION", "custody-engine", id, "INVALIDATED", domain.ErrKeyEpochMismatch, map[string]any{
			"vault_id":      vaultID,
			"new_key_epoch": newState.KeyEpoch,
		})
	}
	s.logger.Info("key_rotation_completed", "vault_id", vaultID, "new_epoch", newState.KeyEpoch, "invalidated_count", len(invalidated))
	if err := s.persist(); err != nil {
		return domain.KeyEpochState{}, nil, err
	}
	return newState, invalidated, nil
}

// MineBlocks advances the deterministic mock testnet chain and synchronizes in-flight intent states.
func (s *CustodyService) MineBlocks(count int) ([]domain.Block, error) {
	if count < 1 {
		return nil, domain.NewError(domain.ErrInvalidSchema, "block count must be >= 1")
	}
	blocks := make([]domain.Block, 0, count)
	for i := 0; i < count; i++ {
		now := s.clock.Now()
		blk := s.chain.MineBlock(now)
		blocks = append(blocks, blk)
		if fc, ok := s.clock.(*domain.FixedClock); ok {
			fc.Advance(12 * time.Second)
		}
	}
	if err := s.SyncInFlight(); err != nil {
		return nil, err
	}
	return blocks, nil
}

// TriggerReorg simulates a mock testnet reorganization and synchronizes custody ledger accounting.
func (s *CustodyService) TriggerReorg(depth int, dropTxHashes []string) (domain.ReorgResult, error) {
	now := s.clock.Now()
	res, err := s.chain.TriggerReorg(depth, dropTxHashes, now)
	if err != nil {
		return domain.ReorgResult{}, err
	}
	s.audit.Append(now, "CHAIN_REORG_SIMULATED", "mock-chain", "", "REORG", "", map[string]any{
		"depth":          depth,
		"common_ancestor": res.CommonAncestor,
		"requeued_txs":   res.RequeuedTxHashes,
		"dropped_txs":    res.DroppedTxHashes,
	})
	if err := s.SyncInFlight(); err != nil {
		return domain.ReorgResult{}, err
	}
	return res, nil
}

// SyncInFlight reconciles every broadcast/confirming/confirmed intent with current mock chain receipts.
func (s *CustodyService) SyncInFlight() error {
	now := s.clock.Now()
	confDepth := s.policy.Config().ConfirmationDepth
	for _, rec := range s.ledger.AllIntents() {
		if rec.TxHash == "" {
			continue
		}
		if rec.Status != domain.StatusBroadcast && rec.Status != domain.StatusConfirming && rec.Status != domain.StatusConfirmed {
			continue
		}
		tx, ok := s.chain.GetTxReceipt(rec.TxHash)
		if !ok {
			continue
		}
		updated, reorgDetected, err := s.ledger.UpdateChainProgress(rec.Intent.IntentID, tx, confDepth, now)
		if err != nil {
			return err
		}
		if reorgDetected {
			s.counters.Inc(func(c *telemetry.Counters) { c.ReorgsDetected++ })
			s.audit.Append(now, "REORG_DETECTED", "custody-reconciler", rec.Intent.IntentID, "REVERTED", "", map[string]any{
				"tx_hash":        rec.TxHash,
				"previous_block": rec.BlockHash,
				"new_status":     updated.Status,
			})
			s.logger.Warn("reorg_detected", "intent_id", rec.Intent.IntentID, "tx_hash", rec.TxHash, "new_status", updated.Status)
		}
		if updated.Status == domain.StatusConfirmed && rec.Status != domain.StatusConfirmed {
			s.audit.Append(now, "TX_CONFIRMED", "custody-reconciler", rec.Intent.IntentID, "OK", "", map[string]any{
				"tx_hash":       rec.TxHash,
				"block_height":  updated.BlockHeight,
				"block_hash":    updated.BlockHash,
				"confirmations": updated.Confirmations,
			})
		}
	}
	return s.persist()
}

// Reconcile verifies exact balance, pending reservation, and audit hash-chain invariants across all vaults.
func (s *CustodyService) Reconcile() (domain.ReconciliationReport, error) {
	if err := s.SyncInFlight(); err != nil {
		return domain.ReconciliationReport{}, err
	}
	now := s.clock.Now()
	tip := s.chain.Tip()
	auditErr := s.audit.VerifyChain()

	report := domain.ReconciliationReport{
		GeneratedAt:     now.UTC().Format(time.RFC3339),
		ChainHeight:     tip.Height,
		ChainTipHash:    tip.Hash,
		Reconciled:      true,
		AuditChainValid: auditErr == nil,
		VaultChecks:     make([]domain.VaultReconciliation, 0),
	}
	if auditErr != nil {
		report.Reconciled = false
		report.Discrepancies = append(report.Discrepancies, "audit chain verification failed: "+auditErr.Error())
	}

	cfg := s.policy.Config()
	for _, bal := range s.ledger.AllBalances() {
		vp, ok := cfg.Vaults[bal.VaultID]
		if !ok {
			continue
		}
		onChain := s.chain.GetBalance(vp.Network, vp.SourceAddress, bal.Asset)
		pendingSum := s.ledger.PendingReservedSum(bal.VaultID, bal.Asset)

		balDelta := bal.ConfirmedBalance - onChain
		resDelta := bal.ReservedBalance - pendingSum
		matched := balDelta == 0 && resDelta == 0 && bal.AvailableBalance == (bal.ConfirmedBalance-bal.ReservedBalance) && bal.AvailableBalance >= 0

		check := domain.VaultReconciliation{
			VaultID:                  bal.VaultID,
			Asset:                    bal.Asset,
			LedgerConfirmedBalance:   bal.ConfirmedBalance,
			OnChainConfirmedBalance:  onChain,
			LedgerReservedBalance:    bal.ReservedBalance,
			SumPendingReservedAmount: pendingSum,
			LedgerAvailableBalance:   bal.AvailableBalance,
			BalanceDelta:             balDelta,
			ReservedDelta:            resDelta,
			Matched:                  matched,
		}
		report.VaultChecks = append(report.VaultChecks, check)
		if !matched {
			report.Reconciled = false
			report.Discrepancies = append(report.Discrepancies,
				fmt.Sprintf("mismatch on %s/%s: bal_delta=%d reserved_delta=%d", bal.VaultID, bal.Asset, balDelta, resDelta))
		}
	}

	raw, _ := json.Marshal(report)
	sum := sha256.Sum256(append([]byte("CUSTODY_RECON_V1:"), raw...))
	report.Checksum = hex.EncodeToString(sum[:])

	if report.Reconciled {
		s.counters.Inc(func(c *telemetry.Counters) { c.ReconciliationsPassed++ })
		s.audit.Append(now, "RECONCILIATION_PASSED", "custody-reconciler", "", "OK", "", map[string]any{
			"chain_height": tip.Height,
			"checksum":     report.Checksum,
		})
	} else {
		s.counters.Inc(func(c *telemetry.Counters) { c.ReconciliationsFailed++ })
		s.audit.Append(now, "RECONCILIATION_FAILED", "custody-reconciler", "", "FAILED", domain.ErrReconciliationMismatch, map[string]any{
			"discrepancies": report.Discrepancies,
		})
		return report, domain.NewError(domain.ErrReconciliationMismatch, strings.Join(report.Discrepancies, "; "))
	}

	_ = s.persist()
	return report, nil
}

func (s *CustodyService) persist() error {
	snap := storage.CustodySnapshot{
		SchemaVersion: domain.CurrentSchemaVersion,
		PolicyVersion: s.policy.Config().PolicyVersion,
		PolicyDigest:  s.policy.PolicyDigest(),
		SavedAt:       s.clock.Now().UTC().Format(time.RFC3339),
		Ledger:        s.ledger.Snapshot(),
		Chain:         s.chain.Snapshot(),
		AuditEvents:   s.audit.Events(),
	}
	return s.store.Save(snap)
}
