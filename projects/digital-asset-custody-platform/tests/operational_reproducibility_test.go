package custody_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/audit"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/engine"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/policy"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/scenarios"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/signer"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/storage"
)

func TestDeterministicReproducibility(t *testing.T) {
	run1, err := scenarios.RunReferenceFixture(
		projectPath("config/default-policy.json"),
		projectPath("data/fixtures/reference_fixture.json"),
		projectPath("data/fixtures/expected_reference_output.json"),
	)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	run2, err := scenarios.RunReferenceFixture(
		projectPath("config/default-policy.json"),
		projectPath("data/fixtures/reference_fixture.json"),
		projectPath("data/fixtures/expected_reference_output.json"),
	)
	if err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}

	b1, _ := json.Marshal(run1)
	b2, _ := json.Marshal(run2)
	if string(b1) != string(b2) {
		t.Fatalf("reproducibility violation: outputs diverged between identical deterministic runs")
	}
}

func TestOperationalMissingAndInvalidConfig(t *testing.T) {
	// 1. Missing config file
	if _, err := policy.LoadConfig("/nonexistent/path/policy.json"); domain.CodeOf(err) != domain.ErrMissingConfig {
		t.Fatalf("expected ERR_MISSING_CONFIG, got %v", err)
	}

	// 2. Malformed JSON config
	tmpDir := t.TempDir()
	badJSON := filepath.Join(tmpDir, "bad.json")
	_ = os.WriteFile(badJSON, []byte("{not-json"), 0o600)
	if _, err := policy.LoadConfig(badJSON); domain.CodeOf(err) != domain.ErrInvalidConfig {
		t.Fatalf("expected ERR_INVALID_CONFIG for malformed JSON, got %v", err)
	}

	// 3. Mainnet network in policy config is strictly prohibited
	cfg, _ := policy.LoadConfig(projectPath("config/default-policy.json"))
	cfg.AllowedNetworks = []string{"ethereum-mainnet"}
	if err := policy.ValidateConfig(cfg); domain.CodeOf(err) != domain.ErrUnsupportedNetwork {
		t.Fatalf("expected ERR_UNSUPPORTED_NETWORK for mainnet config, got %v", err)
	}

	// 4. Nil PostgreSQL connection fails explicitly (no silent success)
	if _, err := storage.NewPostgresStore(nil); domain.CodeOf(err) != domain.ErrStorageUnavailable {
		t.Fatalf("expected ERR_STORAGE_UNAVAILABLE for nil postgres handle, got %v", err)
	}
}

func TestOperationalRestartAndRerunDurability(t *testing.T) {
	cfg, err := policy.LoadConfig(projectPath("config/default-policy.json"))
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "custody_state.json")
	seed := "SEED-RESTART-DURABILITY"
	baseTime, _ := time.Parse(time.RFC3339, "2026-01-15T10:00:00Z")
	clock := domain.NewFixedClock(baseTime)
	kr := signer.NewApproverKeyring(seed, cfg.Approvers)

	// Instance 1: deposit, submit, approve, sign, broadcast, mine 2 blocks, rotate keys to epoch 2.
	svc1, err := engine.NewService(engine.ServiceOptions{
		PolicyConfig:    cfg,
		MasterSeed:      seed,
		Clock:           clock,
		Store:           storage.NewFileStore(statePath),
		ApproverPubKeys: kr.PublicKeys(),
	})
	if err != nil {
		t.Fatalf("init svc1 failed: %v", err)
	}
	_, _ = svc1.Deposit("vault-treasury-01", "MOCK_ETH", "gwei", 10000000000)
	i1 := sampleIntent("intent-persist-1", 1, 1, 1000000000, clock.Now())
	r1, _ := svc1.SubmitIntent(i1)
	r1 = approveStandard(t, r1.Intent.IntentID, svc1, r1, kr, clock.Now())
	r1, err = svc1.SignAndBroadcast(r1.Intent.IntentID)
	if err != nil {
		t.Fatalf("sign/broadcast failed: %v", err)
	}
	_, _ = svc1.MineBlocks(2)
	_, _, _ = svc1.RotateVaultKeys("vault-treasury-01")

	// Verify persisted snapshot contains no private key material or master seed.
	rawSnap, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read persisted state failed: %v", err)
	}
	if strings.Contains(string(rawSnap), seed) {
		t.Fatalf("security violation: master seed leaked into persisted snapshot")
	}

	// Instance 2: cold restart from FileStore.
	clock.Advance(time.Minute)
	svc2, err := engine.NewService(engine.ServiceOptions{
		PolicyConfig:    cfg,
		MasterSeed:      seed,
		Clock:           clock,
		Store:           storage.NewFileStore(statePath),
		ApproverPubKeys: kr.PublicKeys(),
	})
	if err != nil {
		t.Fatalf("cold restart svc2 failed: %v", err)
	}

	// Replay of intent #1 after restart must still be blocked at both ledger and isolated signer boundaries.
	if _, err := svc2.SubmitIntent(i1); domain.CodeOf(err) != domain.ErrReplayDetected {
		t.Fatalf("expected ERR_REPLAY_DETECTED post-restart, got %v", err)
	}
	if _, err := svc2.RequestSignatureWithPayload(r1.Intent, *r1.Certificate); domain.CodeOf(err) != domain.ErrKeyEpochMismatch && domain.CodeOf(err) != domain.ErrReplayDetected {
		t.Fatalf("expected stale epoch or replay error post-restart, got %v", err)
	}

	// Active epoch must be restored as 2, and a new epoch-2 intent must succeed cleanly.
	ep, _ := svc2.Signers().ActiveKeyEpoch("vault-treasury-01")
	if ep != 2 {
		t.Fatalf("expected restored key epoch 2, got %d", ep)
	}
	i2 := sampleIntent("intent-persist-2", 2, 2, 500000000, clock.Now())
	r2, err := svc2.SubmitIntent(i2)
	if err != nil {
		t.Fatalf("post-restart submit failed: %v", err)
	}
	r2 = approveStandard(t, r2.Intent.IntentID, svc2, r2, kr, clock.Now())
	_, err = svc2.SignAndBroadcast(r2.Intent.IntentID)
	if err != nil {
		t.Fatalf("post-restart sign/broadcast failed: %v", err)
	}
	_, _ = svc2.MineBlocks(2)

	recon, err := svc2.Reconcile()
	if err != nil || !recon.Reconciled || !recon.AuditChainValid {
		t.Fatalf("post-restart reconciliation failed: %v", err)
	}
	bal, _ := svc2.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")
	if bal.ConfirmedBalance != 8500000000 || bal.ReservedBalance != 0 {
		t.Fatalf("expected 8,500,000,000 confirmed post-restart, got %+v", bal)
	}
}

func TestAuditRedactionAndTamperDetection(t *testing.T) {
	log := audit.NewLog()
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	fake128Hex := strings.Repeat("ab", 64)
	ev := log.Append(now, "TEST_EVENT", "tester", "intent-1", "OK", "", map[string]any{
		"private_key": "should-never-appear",
		"master_seed": "super-secret-seed",
		"raw_note":    "leaked " + fake128Hex,
		"safe_field":  "visible-value",
	})

	if ev.Details["private_key"] != "[REDACTED]" || ev.Details["master_seed"] != "[REDACTED]" {
		t.Fatalf("sensitive keys were not redacted: %+v", ev.Details)
	}
	if strings.Contains(ev.Details["raw_note"].(string), fake128Hex) {
		t.Fatalf("128-hex key material was not redacted: %v", ev.Details["raw_note"])
	}
	if err := log.VerifyChain(); err != nil {
		t.Fatalf("valid audit chain failed verification: %v", err)
	}

	// Tamper with an audit event and verify tamper detection triggers.
	events := log.Events()
	events[0].Outcome = "TAMPERED"
	if err := audit.VerifyEvents(events); err == nil {
		t.Fatalf("expected audit.VerifyEvents to detect tampering")
	}
}

func BenchmarkIntentHashAndPolicyEvaluate(b *testing.B) {
	cfg, _ := policy.LoadConfig(projectPath("config/default-policy.json"))
	pol, _ := policy.NewEngine(cfg)
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	intent := sampleIntent("intent-bench-1", 1, 1, 1500000000, now)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := intent.ComputeHash(); err != nil {
			b.Fatal(err)
		}
		if _, err := pol.Evaluate(intent, 0, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEndToEndCustodyTransfer(b *testing.B) {
	cfg, _ := policy.LoadConfig(projectPath("config/default-policy.json"))
	baseTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clock := domain.NewFixedClock(baseTime)
		kr := signer.NewApproverKeyring("BENCH-SEED", cfg.Approvers)
		svc, _ := engine.NewService(engine.ServiceOptions{
			PolicyConfig:    cfg,
			MasterSeed:      "BENCH-SEED",
			Clock:           clock,
			ApproverPubKeys: kr.PublicKeys(),
		})
		_, _ = svc.Deposit("vault-treasury-01", "MOCK_ETH", "gwei", 10000000000)
		intent := sampleIntent("intent-bench-e2e", 1, 1, 1000000000, clock.Now())
		rec, err := svc.SubmitIntent(intent)
		if err != nil {
			b.Fatal(err)
		}
		for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
			sig, _ := kr.SignApproval(a, rec.IntentHash, rec.PolicyDecision.PolicyVersion, clock.Now())
			rec, _ = svc.ApproveIntent(rec.Intent.IntentID, sig)
		}
		if _, err := svc.SignAndBroadcast(rec.Intent.IntentID); err != nil {
			b.Fatal(err)
		}
		_, _ = svc.MineBlocks(2)
		if _, err := svc.Reconcile(); err != nil {
			b.Fatal(err)
		}
	}
}
