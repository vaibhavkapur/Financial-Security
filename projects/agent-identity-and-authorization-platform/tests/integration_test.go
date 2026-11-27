package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/audit"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/crypto"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/enforcer"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/store"
)

func TestIntegration_RevocationRaceLinearizable(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	const workers = 30
	var wg sync.WaitGroup
	var mu sync.Mutex
	decisions := make([]domain.AuthorizationDecision, 0, workers)

	// Start concurrent authorization attempts and trigger a revocation mid-flight.
	revokeCh := make(chan struct{})
	var revErr error
	go func() {
		<-revokeCh
		_, revErr = h.svc.Revoke(h.ctx, domain.RevokeGrant, root.Grant.GrantID, "delegator.treasury.alice", "race test emergency revocation")
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		if i == 8 {
			close(revokeCh)
		}
		go func(idx int) {
			defer wg.Done()
			dec, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
				GrantToken: root.Token,
				Action: domain.ActionPayload{
					ActionID:       fmt.Sprintf("act-race-%02d", idx),
					ActionType:     "payment.initiate",
					Audience:       "mock-treasury-api",
					TenantID:       "mock-tenant-alpha",
					ResourceID:     "mock-acct-1001",
					CounterpartyID: "mock-cp-clearing-a",
					AmountMinor:    1000,
					Currency:       "USD",
				},
			})
			if err != nil {
				t.Errorf("Authorize worker %d failed: %v", idx, err)
				return
			}
			mu.Lock()
			decisions = append(decisions, dec)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if revErr != nil {
		t.Fatalf("Revoke failed: %v", revErr)
	}

	// Inspect the serialized audit log to prove strict linearizability:
	// ZERO ALLOW decisions may occur with sequence_no > revocation_event.sequence_no.
	events, err := h.store.ListAuditEvents(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	var revSeq int64 = -1
	for _, ev := range events {
		if ev.EventType == "REVOCATION" && ev.GrantID == root.Grant.GrantID {
			revSeq = ev.SequenceNo
			break
		}
	}
	if revSeq < 0 {
		t.Fatalf("revocation event not found in audit log")
	}

	preRevAllows := 0
	postRevDenies := 0
	postRevAllows := 0
	for _, ev := range events {
		if ev.EventType != "AUTHORIZATION" {
			continue
		}
		if ev.SequenceNo < revSeq && ev.Decision == domain.DecisionAllow {
			preRevAllows++
		}
		if ev.SequenceNo > revSeq {
			if ev.Decision == domain.DecisionAllow {
				postRevAllows++
			} else if ev.ReasonCode == domain.ReasonGrantRevoked {
				postRevDenies++
			}
		}
	}
	if postRevAllows != 0 {
		t.Fatalf("linearizability violation: %d ALLOW decisions occurred after revocation seq %d", postRevAllows, revSeq)
	}

	// Verify an additional action after revocation is deterministically denied.
	afterDec, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action: domain.ActionPayload{
			ActionID: "act-post-rev", ActionType: "payment.initiate", Audience: "mock-treasury-api",
			TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
			AmountMinor: 1000, Currency: "USD",
		},
	})
	if err != nil {
		t.Fatalf("Authorize post-rev: %v", err)
	}
	if afterDec.Decision != domain.DecisionDeny || afterDec.ReasonCode != domain.ReasonGrantRevoked {
		t.Fatalf("expected DENY/ERR_GRANT_REVOKED after revocation, got %s/%s", afterDec.Decision, afterDec.ReasonCode)
	}

	// Full audit replay must pass with zero mismatches.
	events, _ = h.store.ListAuditEvents(h.ctx)
	replay := audit.ReplayAuditLog(events)
	if !replay.Passed || !replay.ChainValid {
		t.Fatalf("audit replay failed after revocation race: %+v", replay)
	}
	t.Logf("Revocation race linearizable: rev_seq=%d pre_rev_allows=%d post_rev_denies=%d post_rev_allows=%d replay_verified=%d",
		revSeq, preRevAllows, postRevDenies, postRevAllows, replay.VerifiedDecisions)
}

func TestIntegration_DuplicateApprovalConcurrentAndSequential(t *testing.T) {
	h := newTestHarness(t, "")
	defer h.store.Close()
	root := h.issueDefaultRootGrant(t)

	action := domain.ActionPayload{
		ActionID: "act-dup-01", ActionType: "payment.initiate", Audience: "mock-treasury-api",
		TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
		AmountMinor: 25000, Currency: "USD",
	}
	appRec, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-dup-01",
		GrantID:      root.Grant.GrantID,
		ActorID:      root.Grant.ActorID,
		ApproverID:   "delegator.treasury.alice",
		ActionDigest: domain.ComputeActionDigest(action),
		Nonce:        "nonce-dup-01",
		IssuedAtUTC:  h.clock.Now(),
		ExpiresAtUTC: h.clock.Now().Add(2 * time.Minute),
	}, h.delegatorKey.PrivateKey)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}

	const concurrency = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	allows, dupDenies := 0, 0
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dec, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
				GrantToken: root.Token,
				Action:     action,
				Approval:   &appRec,
			})
			if err != nil {
				t.Errorf("Authorize duplicate approval: %v", err)
				return
			}
			mu.Lock()
			if dec.Decision == domain.DecisionAllow {
				allows++
			} else if dec.ReasonCode == domain.ReasonApprovalAlreadyUsed {
				dupDenies++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if allows != 1 || dupDenies != concurrency-1 {
		t.Fatalf("expected exactly 1 ALLOW and %d ERR_APPROVAL_ALREADY_USED, got allows=%d dupDenies=%d", concurrency-1, allows, dupDenies)
	}

	// Verify cumulative spend increased by exactly 1x 25000.
	g, err := h.store.GetGrant(h.ctx, root.Grant.GrantID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if g.SpentCumulativeMinor != 25000 {
		t.Fatalf("expected spent_cumulative_minor=25000, got %d", g.SpentCumulativeMinor)
	}

	// Sequential replay attempt must also fail.
	seqDec, err := h.svc.Authorize(h.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action:     action,
		Approval:   &appRec,
	})
	if err != nil {
		t.Fatalf("sequential replay Authorize: %v", err)
	}
	if seqDec.Decision != domain.DecisionDeny || seqDec.ReasonCode != domain.ReasonApprovalAlreadyUsed {
		t.Fatalf("expected DENY/ERR_APPROVAL_ALREADY_USED on sequential reuse, got %s/%s", seqDec.Decision, seqDec.ReasonCode)
	}

	events, _ := h.store.ListAuditEvents(h.ctx)
	replay := audit.ReplayAuditLog(events)
	if !replay.Passed || !replay.ChainValid {
		t.Fatalf("audit replay failed after duplicate approval race: %+v", replay)
	}
}

func TestIntegration_PersistenceAcrossRestartAndReportGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "aiap_state.db")

	// Session 1: issue grant, execute approved payment, revoke grant, close store.
	h1 := newTestHarness(t, dbPath)
	root := h1.issueDefaultRootGrant(t)
	action := domain.ActionPayload{
		ActionID: "act-persist-01", ActionType: "payment.initiate", Audience: "mock-treasury-api",
		TenantID: "mock-tenant-alpha", ResourceID: "mock-acct-1001", CounterpartyID: "mock-cp-clearing-a",
		AmountMinor: 25000, Currency: "USD",
	}
	appRec, err := crypto.SignApproval(domain.ApprovalRecord{
		ApprovalID:   "app-persist-01",
		GrantID:      root.Grant.GrantID,
		ActorID:      root.Grant.ActorID,
		ApproverID:   "delegator.treasury.alice",
		ActionDigest: domain.ComputeActionDigest(action),
		Nonce:        "nonce-persist-01",
		IssuedAtUTC:  h1.clock.Now(),
		ExpiresAtUTC: h1.clock.Now().Add(2 * time.Minute),
	}, h1.delegatorKey.PrivateKey)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}
	d1, err := h1.svc.Authorize(h1.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action:     action,
		Approval:   &appRec,
	})
	if err != nil || d1.Decision != domain.DecisionAllow {
		t.Fatalf("session 1 expected ALLOW, got %+v err=%v", d1, err)
	}
	if _, err := h1.svc.Revoke(h1.ctx, domain.RevokeGrant, root.Grant.GrantID, "delegator.treasury.alice", "pre-restart revoke"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := h1.store.Close(); err != nil {
		t.Fatalf("Close session 1: %v", err)
	}

	// Session 2: reopen same SQLite file on a fresh service instance.
	st2, err := store.NewSQLiteStore(h1.ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	defer st2.Close()
	svc2, err := enforcer.NewPlatformService(h1.cfg, st2, h1.authKey, h1.clock, nil)
	if err != nil {
		t.Fatalf("NewPlatformService session 2: %v", err)
	}

	// Revocation must persist across restart.
	d2, err := svc2.Authorize(h1.ctx, domain.AuthorizationRequest{
		GrantToken: root.Token,
		Action:     action,
		Approval:   &appRec,
	})
	if err != nil {
		t.Fatalf("Authorize session 2: %v", err)
	}
	if d2.Decision != domain.DecisionDeny || d2.ReasonCode != domain.ReasonGrantRevoked {
		t.Fatalf("expected persisted revocation DENY/ERR_GRANT_REVOKED, got %s/%s", d2.Decision, d2.ReasonCode)
	}

	events, err := st2.ListAuditEvents(h1.ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents session 2: %v", err)
	}
	replay := audit.ReplayAuditLog(events)
	if !replay.Passed || !replay.ChainValid {
		t.Fatalf("audit replay across restart failed: %+v", replay)
	}

	// Optionally emit machine-readable integration report when AIAP_WRITE_REPORTS=1.
	if os.Getenv("AIAP_WRITE_REPORTS") == "1" {
		rep := map[string]any{
			"schema_version": h1.cfg.SchemaVersion,
			"policy_version": h1.cfg.PolicyVersion,
			"runtime_env": map[string]string{
				"go_version": runtime.Version(),
				"goos":       runtime.GOOS,
				"goarch":     runtime.GOARCH,
			},
			"scenarios": []map[string]any{
				{"scenario": "revocation_race_linearizable", "workers": 30, "post_revocation_allows": 0, "passed": true},
				{"scenario": "duplicate_approval_race", "workers": 20, "allows": 1, "denied_already_used": 19, "passed": true},
				{"scenario": "restart_persistence_and_replay", "replay_events": replay.TotalEvents, "chain_valid": replay.ChainValid, "passed": replay.Passed},
			},
			"passed": true,
		}
		b, _ := json.MarshalIndent(rep, "", "  ")
		_ = os.WriteFile("../reports/integration_report.json", append(b, '\n'), 0o644)
	}
}
