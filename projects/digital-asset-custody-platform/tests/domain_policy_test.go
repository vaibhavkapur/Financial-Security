package custody_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/engine"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/policy"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/scenarios"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/signer"
)

func projectPath(rel string) string {
	return filepath.Join("..", rel)
}

func newTestHarness(t *testing.T, seed string) (*engine.CustodyService, *signer.ApproverKeyring, *domain.FixedClock) {
	t.Helper()
	cfg, err := policy.LoadConfig(projectPath("config/default-policy.json"))
	if err != nil {
		t.Fatalf("failed to load default policy: %v", err)
	}
	baseTime, _ := time.Parse(time.RFC3339, "2026-01-15T10:00:00Z")
	clock := domain.NewFixedClock(baseTime)
	kr := signer.NewApproverKeyring(seed, cfg.Approvers)
	svc, err := engine.NewService(engine.ServiceOptions{
		PolicyConfig:    cfg,
		MasterSeed:      seed,
		Clock:           clock,
		ApproverPubKeys: kr.PublicKeys(),
	})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	if _, err := svc.Deposit("vault-treasury-01", "MOCK_ETH", "gwei", 10000000000); err != nil {
		t.Fatalf("deposit failed: %v", err)
	}
	return svc, kr, clock
}

func sampleIntent(id string, nonce, epoch uint64, amount int64, now time.Time) domain.TransferIntent {
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
		CreatedAt:          now.UTC().Format(time.RFC3339),
		ExpiresAt:          now.Add(time.Hour).UTC().Format(time.RFC3339),
		KeyEpoch:           epoch,
		Memo:               "unit-test-" + id,
	}
}

func TestReferenceFixtureMatchesIndependentOracle(t *testing.T) {
	report, err := scenarios.RunReferenceFixture(
		projectPath("config/default-policy.json"),
		projectPath("data/fixtures/reference_fixture.json"),
		projectPath("data/fixtures/expected_reference_output.json"),
	)
	if err != nil {
		t.Fatalf("reference fixture failed: %v", err)
	}
	if !report.OracleMatched {
		t.Fatalf("oracle mismatch: %v", report.Discrepancies)
	}
	if report.IntentHash != report.OracleIntentHash {
		t.Fatalf("intent hash mismatch: got %s want %s", report.IntentHash, report.OracleIntentHash)
	}
	if !report.Reconciliation.Reconciled || !report.Reconciliation.AuditChainValid {
		t.Fatalf("reconciliation or audit chain failed: %+v", report.Reconciliation)
	}
}

func TestInvalidInputsFixture(t *testing.T) {
	raw, err := os.ReadFile(projectPath("data/fixtures/invalid_inputs.json"))
	if err != nil {
		t.Fatalf("read invalid_inputs.json: %v", err)
	}
	var fx struct {
		Cases []struct {
			Name              string                `json:"name"`
			ExpectedErrorCode domain.ErrorCode      `json:"expected_error_code"`
			Intent            domain.TransferIntent `json:"intent"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal invalid_inputs.json: %v", err)
	}

	svc, _, _ := newTestHarness(t, "SEED-INVALID-INPUTS")
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := svc.SubmitIntent(tc.Intent)
			if err == nil {
				t.Fatalf("expected error %s, got nil", tc.ExpectedErrorCode)
			}
			if got := domain.CodeOf(err); got != tc.ExpectedErrorCode {
				t.Fatalf("expected code %s, got %s (%v)", tc.ExpectedErrorCode, got, err)
			}
		})
	}
	recon, err := svc.Reconcile()
	if err != nil || !recon.Reconciled {
		t.Fatalf("reconciliation after denied inputs failed: %v", err)
	}
}

func TestTamperedDestinationRejected(t *testing.T) {
	svc, kr, clock := newTestHarness(t, "SEED-TAMPER-01")
	intent := sampleIntent("intent-tamper-dest", 1, 1, 1000000000, clock.Now())

	rec, err := svc.SubmitIntent(intent)
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	for _, appr := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, err := kr.SignApproval(appr, rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
		if err != nil {
			t.Fatalf("sign approval failed: %v", err)
		}
		rec, err = svc.ApproveIntent(rec.Intent.IntentID, sig)
		if err != nil {
			t.Fatalf("approve failed: %v", err)
		}
	}

	// Adversary mutates destination address (even to another allowlisted address!) after approval.
	tamperedDest := rec.Intent
	tamperedDest.DestinationAddress = "0x3333333333333333333333333333333333333333"
	_, err = svc.RequestSignatureWithPayload(tamperedDest, *rec.Certificate)
	if got := domain.CodeOf(err); got != domain.ErrIntentHashMismatch {
		t.Fatalf("expected ERR_INTENT_HASH_MISMATCH for tampered destination, got %s (%v)", got, err)
	}

	// Adversary mutates amount after approval.
	tamperedAmt := rec.Intent
	tamperedAmt.Amount = 1999999999
	_, err = svc.RequestSignatureWithPayload(tamperedAmt, *rec.Certificate)
	if got := domain.CodeOf(err); got != domain.ErrIntentHashMismatch {
		t.Fatalf("expected ERR_INTENT_HASH_MISMATCH for tampered amount, got %s (%v)", got, err)
	}

	if svc.Counters().Snapshot().SignaturesIssued != 0 {
		t.Fatalf("expected zero unauthorized signatures, got %d", svc.Counters().Snapshot().SignaturesIssued)
	}
}

func TestMissingQuorumAndUnauthorizedApproval(t *testing.T) {
	svc, kr, clock := newTestHarness(t, "SEED-QUORUM-01")

	// 1. Self-approval forbidden: approver-ops-1 initiates transfer and attempts to approve it.
	selfIntent := sampleIntent("intent-self-appr", 1, 1, 500000000, clock.Now())
	selfIntent.RequestedBy = "approver-ops-1"
	recSelf, err := svc.SubmitIntent(selfIntent)
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	selfSig, _ := kr.SignApproval("approver-ops-1", recSelf.IntentHash, recSelf.PolicyDecision.PolicyVersion, clock.Now())
	_, err = svc.ApproveIntent(recSelf.Intent.IntentID, selfSig)
	if got := domain.CodeOf(err); got != domain.ErrSelfApprovalForbidden {
		t.Fatalf("expected ERR_SELF_APPROVAL_FORBIDDEN, got %s (%v)", got, err)
	}

	// 2. Missing quorum (1 of 2 approvals) & duplicate approver attempt.
	sigRisk, _ := kr.SignApproval("approver-risk-2", recSelf.IntentHash, recSelf.PolicyDecision.PolicyVersion, clock.Now())
	recSelf, err = svc.ApproveIntent(recSelf.Intent.IntentID, sigRisk)
	if err != nil {
		t.Fatalf("valid approval failed: %v", err)
	}
	if recSelf.Status != domain.StatusPendingApproval {
		t.Fatalf("expected PENDING_APPROVAL with 1/2 approvals, got %s", recSelf.Status)
	}
	_, dupErr := svc.ApproveIntent(recSelf.Intent.IntentID, sigRisk)
	if got := domain.CodeOf(dupErr); got != domain.ErrDuplicateApproval {
		t.Fatalf("expected ERR_DUPLICATE_APPROVAL, got %s", got)
	}
	_, signErr := svc.SignAndBroadcast(recSelf.Intent.IntentID)
	if got := domain.CodeOf(signErr); got != domain.ErrInsufficientApprovals {
		t.Fatalf("expected ERR_INSUFFICIENT_APPROVALS at engine, got %s", got)
	}

	// 3. Direct call to isolated signer with forged certificate containing only 1 approval must fail.
	forgedCert := domain.ApprovalCertificate{
		IntentID:       recSelf.Intent.IntentID,
		IntentHash:     recSelf.IntentHash,
		KeyEpoch:       1,
		PolicyDecision: recSelf.PolicyDecision,
		Approvals:      recSelf.Approvals,
		CertifiedAt:    clock.Now().UTC().Format(time.RFC3339),
	}
	_, isoErr := svc.RequestSignatureWithPayload(recSelf.Intent, forgedCert)
	if got := domain.CodeOf(isoErr); got != domain.ErrInsufficientApprovals {
		t.Fatalf("expected ERR_INSUFFICIENT_APPROVALS at isolated signer, got %s", got)
	}

	// 4. Forged Ed25519 signature bytes rejected.
	badSig := sigRisk
	badSig.ApproverID = "approver-sec-3"
	_, badSigErr := svc.ApproveIntent(recSelf.Intent.IntentID, badSig)
	if got := domain.CodeOf(badSigErr); got != domain.ErrInvalidSignature {
		t.Fatalf("expected ERR_INVALID_SIGNATURE for mismatched signer key, got %s", got)
	}

	// 5. High-value transfer (>= 2,000,000,000 gwei) requires 3-of-3 approvals.
	highIntent := sampleIntent("intent-high-val", 2, 1, 2500000000, clock.Now())
	recHigh, err := svc.SubmitIntent(highIntent)
	if err != nil {
		t.Fatalf("submit high value failed: %v", err)
	}
	if recHigh.PolicyDecision.RequiredApprovals != 3 {
		t.Fatalf("expected 3 required approvals for high value transfer, got %d", recHigh.PolicyDecision.RequiredApprovals)
	}
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		s, _ := kr.SignApproval(a, recHigh.IntentHash, recHigh.PolicyDecision.PolicyVersion, clock.Now())
		recHigh, err = svc.ApproveIntent(recHigh.Intent.IntentID, s)
		if err != nil {
			t.Fatalf("approve high value failed: %v", err)
		}
	}
	if recHigh.Status != domain.StatusPendingApproval {
		t.Fatalf("expected high-value intent to remain PENDING_APPROVAL after 2/3 approvals, got %s", recHigh.Status)
	}
	if svc.Counters().Snapshot().SignaturesIssued != 0 {
		t.Fatalf("expected 0 signatures issued, got %d", svc.Counters().Snapshot().SignaturesIssued)
	}
}

func TestDailyLimitEnforcement(t *testing.T) {
	svc, _, clock := newTestHarness(t, "SEED-DAILY-LIMIT")
	// Vault MOCK_ETH daily_limit = 10,000,000,000; max_single = 5,000,000,000.
	_, err := svc.SubmitIntent(sampleIntent("intent-dl-1", 1, 1, 5000000000, clock.Now()))
	if err != nil {
		t.Fatalf("first transfer should succeed: %v", err)
	}
	_, err = svc.SubmitIntent(sampleIntent("intent-dl-2", 2, 1, 5000000000, clock.Now()))
	if err != nil {
		t.Fatalf("second transfer hitting exact daily limit should succeed: %v", err)
	}
	// Deposit more funds so failure is strictly daily limit, not insufficient funds.
	_, _ = svc.Deposit("vault-treasury-01", "MOCK_ETH", "gwei", 5000000000)
	_, err = svc.SubmitIntent(sampleIntent("intent-dl-3", 3, 1, 1, clock.Now()))
	if got := domain.CodeOf(err); got != domain.ErrDailyLimitExceeded {
		t.Fatalf("expected ERR_DAILY_LIMIT_EXCEEDED, got %s (%v)", got, err)
	}
}
