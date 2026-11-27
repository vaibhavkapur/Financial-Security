package scenarios

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/engine"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/policy"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/signer"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/telemetry"
)

// ReferenceFixture mirrors data/fixtures/reference_fixture.json.
type ReferenceFixture struct {
	FixtureVersion    string                `json:"fixture_version"`
	Description       string                `json:"description"`
	DeterministicSeed string                `json:"deterministic_seed"`
	BaseTime          string                `json:"base_time"`
	InitialDeposit    struct {
		VaultID string `json:"vault_id"`
		Asset   string `json:"asset"`
		Unit    string `json:"unit"`
		Amount  int64  `json:"amount"`
	} `json:"initial_deposit"`
	TransferIntent domain.TransferIntent `json:"transfer_intent"`
	Approvers      []string              `json:"approvers"`
	Signers        []string              `json:"signers"`
	BlocksToMine   int                   `json:"blocks_to_mine"`
}

// ExpectedReferenceOutput mirrors data/fixtures/expected_reference_output.json.
type ExpectedReferenceOutput struct {
	FixtureVersion                   string `json:"fixture_version"`
	OracleMethod                     string `json:"oracle_method"`
	ExpectedIntentHash               string `json:"expected_intent_hash"`
	ExpectedPolicyAllowed            bool   `json:"expected_policy_allowed"`
	ExpectedRequiredApprovals        int    `json:"expected_required_approvals"`
	ExpectedRequiredSigners          int    `json:"expected_required_signers"`
	ExpectedApprovalCount            int    `json:"expected_approval_count"`
	ExpectedSignatureCount           int    `json:"expected_signature_count"`
	ExpectedKeyEpoch                 uint64 `json:"expected_key_epoch"`
	ExpectedFinalStatus              string `json:"expected_final_status"`
	ExpectedConfirmations            int    `json:"expected_confirmations"`
	ExpectedVaultConfirmedBalance    int64  `json:"expected_vault_confirmed_balance"`
	ExpectedVaultReservedBalance     int64  `json:"expected_vault_reserved_balance"`
	ExpectedVaultAvailableBalance    int64  `json:"expected_vault_available_balance"`
	ExpectedDestinationOnChainBal    int64  `json:"expected_destination_onchain_balance"`
	ExpectedReconciled               bool   `json:"expected_reconciled"`
	ExpectedAuditChainValid          bool   `json:"expected_audit_chain_valid"`
}

// RuntimeMetadata records execution environment and configuration provenance.
type RuntimeMetadata struct {
	GoVersion     string `json:"go_version"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	NumCPU        int    `json:"num_cpu"`
	PolicyVersion string `json:"policy_version"`
	PolicyDigest  string `json:"policy_digest"`
	Seed          string `json:"deterministic_seed"`
	SimulatedTime string `json:"simulated_base_time"`
}

// BaselineReferenceReport captures machine-readable output of the reference fixture compared to the independent oracle.
type BaselineReferenceReport struct {
	ReportVersion         string                      `json:"report_version"`
	Runtime               RuntimeMetadata             `json:"runtime"`
	IntentID              string                      `json:"intent_id"`
	IntentHash            string                      `json:"intent_hash"`
	OracleIntentHash      string                      `json:"oracle_intent_hash"`
	OracleMatched         bool                        `json:"oracle_matched"`
	TxHash                string                      `json:"tx_hash"`
	KeyEpoch              uint64                      `json:"key_epoch"`
	ApprovalCount         int                         `json:"approval_count"`
	SignatureCount        int                         `json:"signature_count"`
	FinalStatus           domain.IntentStatus         `json:"final_status"`
	Confirmations         int                         `json:"confirmations"`
	VaultConfirmedBalance int64                       `json:"vault_confirmed_balance"`
	VaultReservedBalance  int64                       `json:"vault_reserved_balance"`
	VaultAvailableBalance int64                       `json:"vault_available_balance"`
	DestinationOnChainBal int64                       `json:"destination_onchain_balance"`
	Reconciliation        domain.ReconciliationReport `json:"reconciliation"`
	Counters              telemetry.Snapshot          `json:"counters"`
	Discrepancies         []string                    `json:"discrepancies,omitempty"`
}

// ScenarioOutcome records a single deterministic scenario execution result.
type ScenarioOutcome struct {
	ScenarioID      string             `json:"scenario_id"`
	Category        string             `json:"category"`
	Passed          bool               `json:"passed"`
	ObservedCode    domain.ErrorCode   `json:"observed_error_code,omitempty"`
	ExpectedCode    domain.ErrorCode   `json:"expected_error_code,omitempty"`
	Reconciled      bool               `json:"reconciled"`
	AuditChainValid bool               `json:"audit_chain_valid"`
	Summary         string             `json:"summary"`
	Details         map[string]any     `json:"details,omitempty"`
	Counters        telemetry.Snapshot `json:"counters"`
}

// ScenarioSuiteReport aggregates all required acceptance scenarios.
type ScenarioSuiteReport struct {
	ReportVersion string            `json:"report_version"`
	Runtime       RuntimeMetadata   `json:"runtime"`
	AllPassed     bool              `json:"all_passed"`
	Scenarios     []ScenarioOutcome `json:"scenarios"`
}

// RunReferenceFixture executes the deterministic reference fixture and validates against the independent oracle.
func RunReferenceFixture(policyPath, fixturePath, oraclePath string) (BaselineReferenceReport, error) {
	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		return BaselineReferenceReport{}, err
	}
	rawFix, err := os.ReadFile(fixturePath)
	if err != nil {
		return BaselineReferenceReport{}, err
	}
	var fix ReferenceFixture
	if err := json.Unmarshal(rawFix, &fix); err != nil {
		return BaselineReferenceReport{}, err
	}
	rawOracle, err := os.ReadFile(oraclePath)
	if err != nil {
		return BaselineReferenceReport{}, err
	}
	var oracle ExpectedReferenceOutput
	if err := json.Unmarshal(rawOracle, &oracle); err != nil {
		return BaselineReferenceReport{}, err
	}

	baseTime, err := time.Parse(time.RFC3339, fix.BaseTime)
	if err != nil {
		return BaselineReferenceReport{}, err
	}
	clock := domain.NewFixedClock(baseTime)
	kr := signer.NewApproverKeyring(fix.DeterministicSeed, cfg.Approvers)
	svc, err := engine.NewService(engine.ServiceOptions{
		PolicyConfig:    cfg,
		MasterSeed:      fix.DeterministicSeed,
		Clock:           clock,
		ApproverPubKeys: kr.PublicKeys(),
	})
	if err != nil {
		return BaselineReferenceReport{}, err
	}

	if _, err := svc.Deposit(fix.InitialDeposit.VaultID, fix.InitialDeposit.Asset, fix.InitialDeposit.Unit, fix.InitialDeposit.Amount); err != nil {
		return BaselineReferenceReport{}, err
	}

	rec, err := svc.SubmitIntent(fix.TransferIntent)
	if err != nil {
		return BaselineReferenceReport{}, err
	}

	for _, apprID := range fix.Approvers {
		clock.Advance(10 * time.Second)
		sig, err := kr.SignApproval(apprID, rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
		if err != nil {
			return BaselineReferenceReport{}, err
		}
		rec, err = svc.ApproveIntent(rec.Intent.IntentID, sig)
		if err != nil {
			return BaselineReferenceReport{}, err
		}
	}

	clock.Advance(5 * time.Second)
	rec, err = svc.SignAndBroadcast(rec.Intent.IntentID)
	if err != nil {
		return BaselineReferenceReport{}, err
	}

	if _, err := svc.MineBlocks(fix.BlocksToMine); err != nil {
		return BaselineReferenceReport{}, err
	}

	recon, err := svc.Reconcile()
	if err != nil {
		return BaselineReferenceReport{}, err
	}
	rec, _ = svc.Ledger().GetIntent(rec.Intent.IntentID)
	bal, _ := svc.Ledger().GetBalance(fix.InitialDeposit.VaultID, fix.InitialDeposit.Asset)
	dstBal := svc.Chain().GetBalance(fix.TransferIntent.Network, fix.TransferIntent.DestinationAddress, fix.TransferIntent.Asset)

	discrepancies := make([]string, 0)
	if rec.IntentHash != oracle.ExpectedIntentHash {
		discrepancies = append(discrepancies, fmt.Sprintf("intent_hash mismatch: got %s expected %s", rec.IntentHash, oracle.ExpectedIntentHash))
	}
	if string(rec.Status) != oracle.ExpectedFinalStatus {
		discrepancies = append(discrepancies, fmt.Sprintf("status mismatch: got %s expected %s", rec.Status, oracle.ExpectedFinalStatus))
	}
	if rec.Confirmations != oracle.ExpectedConfirmations {
		discrepancies = append(discrepancies, fmt.Sprintf("confirmations mismatch: got %d expected %d", rec.Confirmations, oracle.ExpectedConfirmations))
	}
	if bal.ConfirmedBalance != oracle.ExpectedVaultConfirmedBalance {
		discrepancies = append(discrepancies, fmt.Sprintf("confirmed balance mismatch: got %d expected %d", bal.ConfirmedBalance, oracle.ExpectedVaultConfirmedBalance))
	}
	if bal.ReservedBalance != oracle.ExpectedVaultReservedBalance {
		discrepancies = append(discrepancies, fmt.Sprintf("reserved balance mismatch: got %d expected %d", bal.ReservedBalance, oracle.ExpectedVaultReservedBalance))
	}
	if dstBal != oracle.ExpectedDestinationOnChainBal {
		discrepancies = append(discrepancies, fmt.Sprintf("destination balance mismatch: got %d expected %d", dstBal, oracle.ExpectedDestinationOnChainBal))
	}
	if recon.Reconciled != oracle.ExpectedReconciled || recon.AuditChainValid != oracle.ExpectedAuditChainValid {
		discrepancies = append(discrepancies, "reconciliation or audit chain mismatch")
	}

	sigCount := 0
	if rec.Multisig != nil {
		sigCount = len(rec.Multisig.Signatures)
	}

	return BaselineReferenceReport{
		ReportVersion: "1.0.0",
		Runtime: RuntimeMetadata{
			GoVersion:     runtime.Version(),
			GOOS:          runtime.GOOS,
			GOARCH:        runtime.GOARCH,
			NumCPU:        runtime.NumCPU(),
			PolicyVersion: cfg.PolicyVersion,
			PolicyDigest:  svc.PolicyEngine().PolicyDigest(),
			Seed:          fix.DeterministicSeed,
			SimulatedTime: fix.BaseTime,
		},
		IntentID:              rec.Intent.IntentID,
		IntentHash:            rec.IntentHash,
		OracleIntentHash:      oracle.ExpectedIntentHash,
		OracleMatched:         len(discrepancies) == 0,
		TxHash:                rec.TxHash,
		KeyEpoch:              rec.Intent.KeyEpoch,
		ApprovalCount:         len(rec.Approvals),
		SignatureCount:        sigCount,
		FinalStatus:           rec.Status,
		Confirmations:         rec.Confirmations,
		VaultConfirmedBalance: bal.ConfirmedBalance,
		VaultReservedBalance:  bal.ReservedBalance,
		VaultAvailableBalance: bal.AvailableBalance,
		DestinationOnChainBal: dstBal,
		Reconciliation:        recon,
		Counters:              svc.Counters().Snapshot(),
		Discrepancies:         discrepancies,
	}, nil
}

// RunAllScenarios executes the full suite of required custody resilience and security scenarios.
func RunAllScenarios(policyPath string) (ScenarioSuiteReport, error) {
	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		return ScenarioSuiteReport{}, err
	}
	seed := "CUSTODY-SCENARIOS-SEED-2026-0001"
	baseStr := "2026-01-15T12:00:00Z"
	baseTime, _ := time.Parse(time.RFC3339, baseStr)

	polEng, _ := policy.NewEngine(cfg)
	suite := ScenarioSuiteReport{
		ReportVersion: "1.0.0",
		Runtime: RuntimeMetadata{
			GoVersion:     runtime.Version(),
			GOOS:          runtime.GOOS,
			GOARCH:        runtime.GOARCH,
			NumCPU:        runtime.NumCPU(),
			PolicyVersion: cfg.PolicyVersion,
			PolicyDigest:  polEng.PolicyDigest(),
			Seed:          seed,
			SimulatedTime: baseStr,
		},
		AllPassed: true,
		Scenarios: make([]ScenarioOutcome, 0, 6),
	}

	run := func(fn func(domain.PolicyConfig, string, time.Time) ScenarioOutcome) {
		out := fn(cfg, seed, baseTime)
		if !out.Passed {
			suite.AllPassed = false
		}
		suite.Scenarios = append(suite.Scenarios, out)
	}

	run(runTamperedDestination)
	run(runMissingQuorum)
	run(runReplayProtection)
	run(runSignerOutage)
	run(runChainReorg)
	run(runKeyRotationWithPendingIntent)

	return suite, nil
}

func makeService(cfg domain.PolicyConfig, seed string, baseTime time.Time) (*engine.CustodyService, *signer.ApproverKeyring, *domain.FixedClock) {
	clock := domain.NewFixedClock(baseTime)
	kr := signer.NewApproverKeyring(seed, cfg.Approvers)
	svc, _ := engine.NewService(engine.ServiceOptions{
		PolicyConfig:    cfg,
		MasterSeed:      seed,
		Clock:           clock,
		ApproverPubKeys: kr.PublicKeys(),
	})
	_, _ = svc.Deposit("vault-treasury-01", "MOCK_ETH", "gwei", 10000000000)
	return svc, kr, clock
}

func baseIntent(id string, nonce, epoch uint64, amount int64, baseTime time.Time) domain.TransferIntent {
	return domain.TransferIntent{
		SchemaVersion:      domain.CurrentSchemaVersion,
		IntentID:           id,
		VaultID:            "vault-treasury-01",
		Network:            "mock-eth-sepolia",
		Asset:              "MOCK_ETH",
		Unit:               "gwei",
		Amount:             amount,
		SourceAddress:      "0x1111111111111111111111111111111111111111",
		DestinationAddress: "0x2222222222222222222222222222222222222222",
		Nonce:              nonce,
		RequestedBy:        "requester-treasury-bot",
		CreatedAt:          baseTime.UTC().Format(time.RFC3339),
		ExpiresAt:          baseTime.Add(time.Hour).UTC().Format(time.RFC3339),
		KeyEpoch:           epoch,
		Memo:               "scenario-" + id,
	}
}

func runTamperedDestination(cfg domain.PolicyConfig, seed string, baseTime time.Time) ScenarioOutcome {
	svc, kr, clock := makeService(cfg, seed, baseTime)
	intent := baseIntent("intent-tamper-01", 1, 1, 1000000000, baseTime)
	rec, _ := svc.SubmitIntent(intent)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
		rec, _ = svc.ApproveIntent(rec.Intent.IntentID, sig)
	}
	tampered := rec.Intent
	tampered.DestinationAddress = "0x3333333333333333333333333333333333333333"
	_, err := svc.RequestSignatureWithPayload(tampered, *rec.Certificate)
	code := domain.CodeOf(err)
	recon, reconErr := svc.Reconcile()
	passed := code == domain.ErrIntentHashMismatch && reconErr == nil && recon.Reconciled && recon.AuditChainValid
	return ScenarioOutcome{
		ScenarioID:      "scenario-tampered-destination",
		Category:        "domain_correctness",
		Passed:          passed,
		ObservedCode:    code,
		ExpectedCode:    domain.ErrIntentHashMismatch,
		Reconciled:      recon.Reconciled,
		AuditChainValid: recon.AuditChainValid,
		Summary:         "Isolated signer cluster rejected intent whose destination address was altered after approval.",
		Details: map[string]any{
			"approved_destination": rec.Intent.DestinationAddress,
			"tampered_destination": tampered.DestinationAddress,
			"signatures_issued":    svc.Counters().Snapshot().SignaturesIssued,
		},
		Counters: svc.Counters().Snapshot(),
	}
}

func runMissingQuorum(cfg domain.PolicyConfig, seed string, baseTime time.Time) ScenarioOutcome {
	svc, kr, clock := makeService(cfg, seed, baseTime)
	intent := baseIntent("intent-quorum-01", 1, 1, 1000000000, baseTime)
	rec, _ := svc.SubmitIntent(intent)
	sig, _ := kr.SignApproval("approver-ops-1", rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
	rec, _ = svc.ApproveIntent(rec.Intent.IntentID, sig)

	// Attempt both engine signing and direct isolated-signer signing with a forged incomplete certificate.
	_, engineErr := svc.SignAndBroadcast(rec.Intent.IntentID)
	incompleteCert := domain.ApprovalCertificate{
		IntentID:       rec.Intent.IntentID,
		IntentHash:     rec.IntentHash,
		KeyEpoch:       rec.Intent.KeyEpoch,
		PolicyDecision: rec.PolicyDecision,
		Approvals:      rec.Approvals,
		CertifiedAt:    clock.Now().UTC().Format(time.RFC3339),
	}
	_, signerErr := svc.RequestSignatureWithPayload(rec.Intent, incompleteCert)
	recon, reconErr := svc.Reconcile()
	passed := domain.CodeOf(engineErr) == domain.ErrInsufficientApprovals &&
		domain.CodeOf(signerErr) == domain.ErrInsufficientApprovals &&
		svc.Counters().Snapshot().SignaturesIssued == 0 &&
		reconErr == nil && recon.Reconciled && recon.AuditChainValid

	return ScenarioOutcome{
		ScenarioID:      "scenario-missing-quorum",
		Category:        "domain_correctness",
		Passed:          passed,
		ObservedCode:    domain.CodeOf(signerErr),
		ExpectedCode:    domain.ErrInsufficientApprovals,
		Reconciled:      recon.Reconciled,
		AuditChainValid: recon.AuditChainValid,
		Summary:         "Both custody engine and isolated signer refused to sign with 1 of 2 required approvals.",
		Details: map[string]any{
			"approvals_present": len(rec.Approvals),
			"approvals_needed":  rec.PolicyDecision.RequiredApprovals,
			"signatures_issued": svc.Counters().Snapshot().SignaturesIssued,
		},
		Counters: svc.Counters().Snapshot(),
	}
}

func runReplayProtection(cfg domain.PolicyConfig, seed string, baseTime time.Time) ScenarioOutcome {
	svc, kr, clock := makeService(cfg, seed, baseTime)
	intent := baseIntent("intent-replay-01", 1, 1, 1000000000, baseTime)
	rec, _ := svc.SubmitIntent(intent)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
		rec, _ = svc.ApproveIntent(rec.Intent.IntentID, sig)
	}
	rec, _ = svc.SignAndBroadcast(rec.Intent.IntentID)
	_, _ = svc.MineBlocks(2)

	// 1. Replay identical intent ID
	_, dupIDErr := svc.SubmitIntent(intent)
	// 2. Replay consumed nonce with new intent ID
	reusedNonce := baseIntent("intent-replay-02", 1, 1, 1000000000, baseTime)
	_, nonceErr := svc.SubmitIntent(reusedNonce)
	// 3. Replay signing request directly at isolated signer boundary
	_, signerReplayErr := svc.RequestSignatureWithPayload(rec.Intent, *rec.Certificate)

	recon, reconErr := svc.Reconcile()
	passed := domain.CodeOf(dupIDErr) == domain.ErrReplayDetected &&
		domain.CodeOf(nonceErr) == domain.ErrReplayDetected &&
		domain.CodeOf(signerReplayErr) == domain.ErrReplayDetected &&
		reconErr == nil && recon.Reconciled && recon.AuditChainValid

	return ScenarioOutcome{
		ScenarioID:      "scenario-replay",
		Category:        "integration_resilience",
		Passed:          passed,
		ObservedCode:    domain.CodeOf(signerReplayErr),
		ExpectedCode:    domain.ErrReplayDetected,
		Reconciled:      recon.Reconciled,
		AuditChainValid: recon.AuditChainValid,
		Summary:         "Duplicate intent ID, reused nonce, and signer-side payload replay were all blocked.",
		Details: map[string]any{
			"dup_id_code":        domain.CodeOf(dupIDErr),
			"reused_nonce_code":  domain.CodeOf(nonceErr),
			"signer_replay_code": domain.CodeOf(signerReplayErr),
			"replays_blocked":    svc.Counters().Snapshot().ReplaysBlocked,
		},
		Counters: svc.Counters().Snapshot(),
	}
}

func runSignerOutage(cfg domain.PolicyConfig, seed string, baseTime time.Time) ScenarioOutcome {
	svc, kr, clock := makeService(cfg, seed, baseTime)

	// Take 1 of 3 signers offline: 2-of-3 quorum still succeeds.
	_ = svc.SetSignerOnline("signer-hsm-sim-3", false)
	intent1 := baseIntent("intent-outage-01", 1, 1, 500000000, baseTime)
	rec1, _ := svc.SubmitIntent(intent1)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec1.IntentHash, rec1.PolicyDecision.PolicyVersion, clock.Now())
		rec1, _ = svc.ApproveIntent(rec1.Intent.IntentID, sig)
	}
	rec1, err1 := svc.SignAndBroadcast(rec1.Intent.IntentID)
	_, _ = svc.MineBlocks(2)

	// Take 2nd signer offline: only 1-of-3 online -> must fail closed with ERR_SIGNER_QUORUM_UNAVAILABLE.
	_ = svc.SetSignerOnline("signer-hsm-sim-2", false)
	intent2 := baseIntent("intent-outage-02", 2, 1, 500000000, baseTime)
	rec2, _ := svc.SubmitIntent(intent2)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec2.IntentHash, rec2.PolicyDecision.PolicyVersion, clock.Now())
		rec2, _ = svc.ApproveIntent(rec2.Intent.IntentID, sig)
	}
	_, outageErr := svc.SignAndBroadcast(rec2.Intent.IntentID)

	// Recover signer-2 and retry signing cleanly.
	_ = svc.SetSignerOnline("signer-hsm-sim-2", true)
	rec2, recoveryErr := svc.SignAndBroadcast(rec2.Intent.IntentID)
	_, _ = svc.MineBlocks(2)

	recon, reconErr := svc.Reconcile()
	passed := err1 == nil &&
		domain.CodeOf(outageErr) == domain.ErrSignerQuorumUnavailable &&
		recoveryErr == nil &&
		reconErr == nil && recon.Reconciled && recon.AuditChainValid

	return ScenarioOutcome{
		ScenarioID:      "scenario-signer-outage",
		Category:        "integration_resilience",
		Passed:          passed,
		ObservedCode:    domain.CodeOf(outageErr),
		ExpectedCode:    domain.ErrSignerQuorumUnavailable,
		Reconciled:      recon.Reconciled,
		AuditChainValid: recon.AuditChainValid,
		Summary:         "2-of-3 quorum tolerated 1 offline signer, failed closed with 2 offline signers, and recovered cleanly once quorum returned.",
		Details: map[string]any{
			"single_outage_tx_hash": rec1.TxHash,
			"recovered_tx_hash":     rec2.TxHash,
			"outage_code":           domain.CodeOf(outageErr),
		},
		Counters: svc.Counters().Snapshot(),
	}
}

func runChainReorg(cfg domain.PolicyConfig, seed string, baseTime time.Time) ScenarioOutcome {
	svc, kr, clock := makeService(cfg, seed, baseTime)
	intent := baseIntent("intent-reorg-01", 1, 1, 1000000000, baseTime)
	rec, _ := svc.SubmitIntent(intent)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
		rec, _ = svc.ApproveIntent(rec.Intent.IntentID, sig)
	}
	rec, _ = svc.SignAndBroadcast(rec.Intent.IntentID)
	_, _ = svc.MineBlocks(1) // 1 confirmation (CONFIRMING)
	beforeReorg, _ := svc.Ledger().GetIntent(rec.Intent.IntentID)
	oldBlockHash := beforeReorg.BlockHash

	// Trigger 1-block reorg that requeues the tx into mempool.
	reorgRes, err := svc.TriggerReorg(1, nil)
	afterReorg, _ := svc.Ledger().GetIntent(rec.Intent.IntentID)
	midRecon, midErr := svc.Reconcile()

	// Mine 2 blocks on the new canonical fork so tx re-confirms cleanly.
	_, _ = svc.MineBlocks(2)
	finalRec, _ := svc.Ledger().GetIntent(rec.Intent.IntentID)
	finalRecon, finalErr := svc.Reconcile()

	passed := err == nil &&
		afterReorg.Status == domain.StatusBroadcast &&
		midErr == nil && midRecon.Reconciled &&
		finalRec.Status == domain.StatusConfirmed &&
		finalRec.BlockHash != oldBlockHash &&
		finalErr == nil && finalRecon.Reconciled && finalRecon.AuditChainValid &&
		svc.Counters().Snapshot().ReorgsDetected >= 1

	return ScenarioOutcome{
		ScenarioID:      "scenario-chain-reorg",
		Category:        "integration_resilience",
		Passed:          passed,
		Reconciled:      finalRecon.Reconciled,
		AuditChainValid: finalRecon.AuditChainValid,
		Summary:         "Shallow reorg reverted provisional settlement back to reserved, reconciled mid-reorg, and re-confirmed on canonical fork.",
		Details: map[string]any{
			"orphaned_block_hash": oldBlockHash,
			"new_block_hash":      finalRec.BlockHash,
			"status_mid_reorg":    afterReorg.Status,
			"status_final":        finalRec.Status,
			"reorg_depth":         reorgRes.ReorgDepth,
		},
		Counters: svc.Counters().Snapshot(),
	}
}

func runKeyRotationWithPendingIntent(cfg domain.PolicyConfig, seed string, baseTime time.Time) ScenarioOutcome {
	svc, kr, clock := makeService(cfg, seed, baseTime)
	// Submit and approve an epoch-1 intent, leaving it pending before signing.
	intent1 := baseIntent("intent-rot-pending-01", 1, 1, 1000000000, baseTime)
	rec1, _ := svc.SubmitIntent(intent1)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec1.IntentHash, rec1.PolicyDecision.PolicyVersion, clock.Now())
		rec1, _ = svc.ApproveIntent(rec1.Intent.IntentID, sig)
	}
	staleCert := *rec1.Certificate

	// Rotate vault keys from epoch 1 -> epoch 2 while intent1 is APPROVED/pending.
	clock.Advance(30 * time.Second)
	newEpochState, invalidated, rotErr := svc.RotateVaultKeys("vault-treasury-01")

	// 1. Engine refuses signing the invalidated intent.
	_, engineSignErr := svc.SignAndBroadcast(rec1.Intent.IntentID)
	// 2. Direct call to isolated signer cluster with stale epoch-1 certificate also fails with ERR_KEY_EPOCH_MISMATCH.
	_, signerEpochErr := svc.RequestSignatureWithPayload(rec1.Intent, staleCert)

	// Verify reserved balance was released back to full 10,000,000,000 available.
	balAfterRot, _ := svc.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")

	// Submit replacement intent under epoch 2 (next nonce = 2) and confirm end-to-end.
	intent2 := baseIntent("intent-rot-epoch2-02", 2, 2, 1000000000, baseTime)
	rec2, err2 := svc.SubmitIntent(intent2)
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, _ := kr.SignApproval(a, rec2.IntentHash, rec2.PolicyDecision.PolicyVersion, clock.Now())
		rec2, _ = svc.ApproveIntent(rec2.Intent.IntentID, sig)
	}
	rec2, sign2Err := svc.SignAndBroadcast(rec2.Intent.IntentID)
	_, _ = svc.MineBlocks(2)
	finalRecon, reconErr := svc.Reconcile()
	rec1After, _ := svc.Ledger().GetIntent(rec1.Intent.IntentID)
	rec2After, _ := svc.Ledger().GetIntent(rec2.Intent.IntentID)

	passed := rotErr == nil &&
		newEpochState.KeyEpoch == 2 &&
		len(invalidated) == 1 && invalidated[0] == rec1.Intent.IntentID &&
		rec1After.Status == domain.StatusInvalidatedKeyRotation &&
		domain.CodeOf(engineSignErr) == domain.ErrKeyEpochMismatch &&
		domain.CodeOf(signerEpochErr) == domain.ErrKeyEpochMismatch &&
		balAfterRot.ReservedBalance == 0 &&
		balAfterRot.AvailableBalance == 10000000000 &&
		err2 == nil && sign2Err == nil &&
		rec2After.Status == domain.StatusConfirmed &&
		reconErr == nil && finalRecon.Reconciled && finalRecon.AuditChainValid

	return ScenarioOutcome{
		ScenarioID:      "scenario-key-rotation-pending-intent",
		Category:        "boundary_failure",
		Passed:          passed,
		ObservedCode:    domain.CodeOf(signerEpochErr),
		ExpectedCode:    domain.ErrKeyEpochMismatch,
		Reconciled:      finalRecon.Reconciled,
		AuditChainValid: finalRecon.AuditChainValid,
		Summary:         "Key rotation to epoch 2 invalidated pending epoch-1 intent, released reserved balance, rejected stale-epoch signing, and settled replacement epoch-2 intent.",
		Details: map[string]any{
			"new_key_epoch":           newEpochState.KeyEpoch,
			"invalidated_intent_ids":  invalidated,
			"reserved_after_rotation": balAfterRot.ReservedBalance,
			"replacement_status":      rec2After.Status,
			"replacement_tx_hash":     rec2After.TxHash,
		},
		Counters: svc.Counters().Snapshot(),
	}
}
