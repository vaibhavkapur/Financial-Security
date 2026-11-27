package custody_test

import (
	"testing"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
	"github.com/financial-security/digital-asset-custody-platform/src/pkg/scenarios"
)

func approveStandard(t *testing.T, intentID string, svc interface {
	ApproveIntent(string, domain.ApprovalSignature) (domain.IntentRecord, error)
}, rec domain.IntentRecord, kr interface {
	SignApproval(string, string, string, time.Time) (domain.ApprovalSignature, error)
}, now time.Time) domain.IntentRecord {
	t.Helper()
	var err error
	for _, a := range []string{"approver-ops-1", "approver-risk-2"} {
		sig, serr := kr.SignApproval(a, rec.IntentHash, rec.PolicyDecision.PolicyVersion, now)
		if serr != nil {
			t.Fatalf("sign approval failed: %v", serr)
		}
		rec, err = svc.ApproveIntent(intentID, sig)
		if err != nil {
			t.Fatalf("approve intent failed: %v", err)
		}
	}
	return rec
}

func TestReplayProtection(t *testing.T) {
	svc, kr, clock := newTestHarness(t, "SEED-REPLAY-01")
	intent := sampleIntent("intent-replay-1", 1, 1, 1000000000, clock.Now())
	rec, err := svc.SubmitIntent(intent)
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	rec = approveStandard(t, rec.Intent.IntentID, svc, rec, kr, clock.Now())
	rec, err = svc.SignAndBroadcast(rec.Intent.IntentID)
	if err != nil {
		t.Fatalf("sign and broadcast failed: %v", err)
	}
	_, _ = svc.MineBlocks(2)

	// 1. Replay identical intent_id
	if _, err := svc.SubmitIntent(intent); domain.CodeOf(err) != domain.ErrReplayDetected {
		t.Fatalf("expected ERR_REPLAY_DETECTED on duplicate intent_id, got %v", err)
	}
	// 2. Replay consumed nonce with a brand-new intent_id
	dupNonce := sampleIntent("intent-replay-2", 1, 1, 1000000000, clock.Now())
	if _, err := svc.SubmitIntent(dupNonce); domain.CodeOf(err) != domain.ErrReplayDetected {
		t.Fatalf("expected ERR_REPLAY_DETECTED on reused nonce, got %v", err)
	}
	// 3. Replay signed payload directly to isolated signer cluster
	if _, err := svc.RequestSignatureWithPayload(rec.Intent, *rec.Certificate); domain.CodeOf(err) != domain.ErrReplayDetected {
		t.Fatalf("expected ERR_REPLAY_DETECTED at isolated signer boundary, got %v", err)
	}
	// 4. Replay exact signed tx bundle directly on mock chain
	if _, err := svc.Chain().Broadcast(rec.Intent, *rec.Multisig, svc.Signers()); domain.CodeOf(err) != domain.ErrReplayDetected {
		t.Fatalf("expected ERR_REPLAY_DETECTED on mock chain broadcast, got %v", err)
	}

	recon, err := svc.Reconcile()
	if err != nil || !recon.Reconciled || !recon.AuditChainValid {
		t.Fatalf("reconciliation failed after replay attempts: %v", err)
	}
}

func TestSignerOutageAndRecovery(t *testing.T) {
	svc, kr, clock := newTestHarness(t, "SEED-OUTAGE-01")

	// 1 of 3 signers offline: 2-of-3 quorum still available.
	if err := svc.SetSignerOnline("signer-hsm-sim-3", false); err != nil {
		t.Fatalf("set offline failed: %v", err)
	}
	i1 := sampleIntent("intent-out-1", 1, 1, 500000000, clock.Now())
	r1, err := svc.SubmitIntent(i1)
	if err != nil {
		t.Fatalf("submit i1 failed: %v", err)
	}
	r1 = approveStandard(t, r1.Intent.IntentID, svc, r1, kr, clock.Now())
	r1, err = svc.SignAndBroadcast(r1.Intent.IntentID)
	if err != nil {
		t.Fatalf("expected 2-of-3 signing to succeed with 1 offline signer: %v", err)
	}
	_, _ = svc.MineBlocks(2)

	// 2 of 3 signers offline: quorum unavailable -> must fail closed without advancing status.
	if err := svc.SetSignerOnline("signer-hsm-sim-2", false); err != nil {
		t.Fatalf("set offline failed: %v", err)
	}
	i2 := sampleIntent("intent-out-2", 2, 1, 500000000, clock.Now())
	r2, err := svc.SubmitIntent(i2)
	if err != nil {
		t.Fatalf("submit i2 failed: %v", err)
	}
	r2 = approveStandard(t, r2.Intent.IntentID, svc, r2, kr, clock.Now())
	if _, err := svc.SignAndBroadcast(r2.Intent.IntentID); domain.CodeOf(err) != domain.ErrSignerQuorumUnavailable {
		t.Fatalf("expected ERR_SIGNER_QUORUM_UNAVAILABLE, got %v", err)
	}

	// Recover signer-2 and retry cleanly.
	if err := svc.SetSignerOnline("signer-hsm-sim-2", true); err != nil {
		t.Fatalf("set online failed: %v", err)
	}
	r2, err = svc.SignAndBroadcast(r2.Intent.IntentID)
	if err != nil {
		t.Fatalf("expected recovery signing to succeed: %v", err)
	}
	_, _ = svc.MineBlocks(2)

	recon, err := svc.Reconcile()
	if err != nil || !recon.Reconciled || !recon.AuditChainValid {
		t.Fatalf("reconciliation failed: %v", err)
	}
	bal, _ := svc.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")
	if bal.ConfirmedBalance != 9000000000 || bal.ReservedBalance != 0 {
		t.Fatalf("unexpected final balance: %+v", bal)
	}
}

func TestChainReorgRequeueAndDrop(t *testing.T) {
	t.Run("reorg_requeues_and_reconfirms", func(t *testing.T) {
		svc, kr, clock := newTestHarness(t, "SEED-REORG-REQUEUE")
		i1 := sampleIntent("intent-reorg-rq", 1, 1, 1500000000, clock.Now())
		r1, _ := svc.SubmitIntent(i1)
		r1 = approveStandard(t, r1.Intent.IntentID, svc, r1, kr, clock.Now())
		r1, err := svc.SignAndBroadcast(r1.Intent.IntentID)
		if err != nil {
			t.Fatalf("sign/broadcast failed: %v", err)
		}
		_, _ = svc.MineBlocks(1) // 1 confirmation -> CONFIRMING
		before, _ := svc.Ledger().GetIntent(r1.Intent.IntentID)
		oldHash := before.BlockHash

		// Reorg depth 1 without dropping tx -> tx returns to mempool and balance reverts to reserved.
		if _, err := svc.TriggerReorg(1, nil); err != nil {
			t.Fatalf("reorg failed: %v", err)
		}
		midBal, _ := svc.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")
		if midBal.ConfirmedBalance != 10000000000 || midBal.ReservedBalance != 1500000000 {
			t.Fatalf("expected provisional settlement reverted to reserved mid-reorg, got %+v", midBal)
		}
		if recon, err := svc.Reconcile(); err != nil || !recon.Reconciled {
			t.Fatalf("mid-reorg reconciliation failed: %v", err)
		}

		// Mine 2 blocks on canonical fork -> re-included and finalized.
		_, _ = svc.MineBlocks(2)
		after, _ := svc.Ledger().GetIntent(r1.Intent.IntentID)
		if after.Status != domain.StatusConfirmed || after.BlockHash == oldHash {
			t.Fatalf("expected CONFIRMED on new canonical block hash, got status=%s hash=%s old=%s", after.Status, after.BlockHash, oldHash)
		}
		if recon, err := svc.Reconcile(); err != nil || !recon.Reconciled {
			t.Fatalf("post-reorg reconciliation failed: %v", err)
		}
	})

	t.Run("reorg_drops_tx_and_releases_reservation", func(t *testing.T) {
		svc, kr, clock := newTestHarness(t, "SEED-REORG-DROP")
		i1 := sampleIntent("intent-reorg-drop", 1, 1, 1500000000, clock.Now())
		r1, _ := svc.SubmitIntent(i1)
		r1 = approveStandard(t, r1.Intent.IntentID, svc, r1, kr, clock.Now())
		r1, _ = svc.SignAndBroadcast(r1.Intent.IntentID)
		_, _ = svc.MineBlocks(1)

		// Drop tx during reorg -> reservation must be released and full balance restored.
		if _, err := svc.TriggerReorg(1, []string{r1.TxHash}); err != nil {
			t.Fatalf("reorg drop failed: %v", err)
		}
		after, _ := svc.Ledger().GetIntent(r1.Intent.IntentID)
		if after.Status != domain.StatusReorgedDropped {
			t.Fatalf("expected REORGED_DROPPED, got %s", after.Status)
		}
		bal, _ := svc.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")
		if bal.ConfirmedBalance != 10000000000 || bal.ReservedBalance != 0 || bal.AvailableBalance != 10000000000 {
			t.Fatalf("expected full balance restored after dropped tx, got %+v", bal)
		}
		if recon, err := svc.Reconcile(); err != nil || !recon.Reconciled {
			t.Fatalf("reconciliation after dropped tx failed: %v", err)
		}
	})
}

func TestKeyRotationWithPendingIntent(t *testing.T) {
	svc, kr, clock := newTestHarness(t, "SEED-KEYROT-01")

	// Create intent #1 (already broadcast under epoch 1) to prove in-flight signed txs still settle cleanly.
	iBroadcast := sampleIntent("intent-ep1-broadcast", 1, 1, 1000000000, clock.Now())
	rBroadcast, err := svc.SubmitIntent(iBroadcast)
	if err != nil {
		t.Fatalf("submit broadcast intent failed: %v", err)
	}
	rBroadcast = approveStandard(t, rBroadcast.Intent.IntentID, svc, rBroadcast, kr, clock.Now())
	rBroadcast, err = svc.SignAndBroadcast(rBroadcast.Intent.IntentID)
	if err != nil {
		t.Fatalf("sign/broadcast ep1 failed: %v", err)
	}

	// Create intent #2 (APPROVED under epoch 1, NOT YET SIGNED) -> pending pre-signing intent.
	iPending := sampleIntent("intent-ep1-pending", 2, 1, 1500000000, clock.Now())
	rPending, err := svc.SubmitIntent(iPending)
	if err != nil {
		t.Fatalf("submit pending intent failed: %v", err)
	}
	rPending = approveStandard(t, rPending.Intent.IntentID, svc, rPending, kr, clock.Now())
	staleCert := *rPending.Certificate

	// Rotate vault keys from epoch 1 -> epoch 2.
	clock.Advance(20 * time.Second)
	newEpoch, invalidated, err := svc.RotateVaultKeys("vault-treasury-01")
	if err != nil {
		t.Fatalf("key rotation failed: %v", err)
	}
	if newEpoch.KeyEpoch != 2 {
		t.Fatalf("expected epoch 2, got %d", newEpoch.KeyEpoch)
	}
	if len(invalidated) != 1 || invalidated[0] != iPending.IntentID {
		t.Fatalf("expected only pending pre-signing intent invalidated, got %v", invalidated)
	}

	// Signing invalidated intent via engine OR directly via isolated signers MUST fail with ERR_KEY_EPOCH_MISMATCH.
	if _, err := svc.SignAndBroadcast(iPending.IntentID); domain.CodeOf(err) != domain.ErrKeyEpochMismatch {
		t.Fatalf("expected ERR_KEY_EPOCH_MISMATCH at engine, got %v", err)
	}
	if _, err := svc.RequestSignatureWithPayload(rPending.Intent, staleCert); domain.CodeOf(err) != domain.ErrKeyEpochMismatch {
		t.Fatalf("expected ERR_KEY_EPOCH_MISMATCH at isolated signer, got %v", err)
	}

	// Reserved balance for invalidated intent #2 must be released, while intent #1 remains reserved until mined.
	balMid, _ := svc.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")
	if balMid.ReservedBalance != 1000000000 {
		t.Fatalf("expected reserved balance 1,000,000,000 (only broadcast intent #1), got %d", balMid.ReservedBalance)
	}

	// Submit replacement intent #3 under epoch 2 (nonce 3) and settle both #1 and #3.
	iNew := sampleIntent("intent-ep2-new", 3, 2, 1500000000, clock.Now())
	rNew, err := svc.SubmitIntent(iNew)
	if err != nil {
		t.Fatalf("submit ep2 intent failed: %v", err)
	}
	rNew = approveStandard(t, rNew.Intent.IntentID, svc, rNew, kr, clock.Now())
	rNew, err = svc.SignAndBroadcast(rNew.Intent.IntentID)
	if err != nil {
		t.Fatalf("sign/broadcast ep2 failed: %v", err)
	}

	_, _ = svc.MineBlocks(2)
	recon, err := svc.Reconcile()
	if err != nil || !recon.Reconciled || !recon.AuditChainValid {
		t.Fatalf("final reconciliation after key rotation failed: %v", err)
	}

	finalBal, _ := svc.Ledger().GetBalance("vault-treasury-01", "MOCK_ETH")
	if finalBal.ConfirmedBalance != 7500000000 || finalBal.ReservedBalance != 0 {
		t.Fatalf("expected 7,500,000,000 confirmed and 0 reserved, got %+v", finalBal)
	}
}

func TestScenarioSuiteAllPass(t *testing.T) {
	suite, err := scenarios.RunAllScenarios(projectPath("config/default-policy.json"))
	if err != nil {
		t.Fatalf("RunAllScenarios failed: %v", err)
	}
	if !suite.AllPassed {
		for _, sc := range suite.Scenarios {
			if !sc.Passed {
				t.Errorf("scenario %s failed: %s (observed=%s expected=%s)", sc.ScenarioID, sc.Summary, sc.ObservedCode, sc.ExpectedCode)
			}
		}
	}
}
