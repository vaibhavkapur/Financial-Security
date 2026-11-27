# Operator & Developer Runbook

## 1. Prerequisites & Clean Checkout Setup

- **Go:** 1.23 or newer (validated on `go1.27.1`, `darwin/arm64`)
- **Python 3:** Optional, used only by `scripts/generate_reports.sh` to format `go test -bench` output into `reports/benchmark_results.json`.
- **Network access:** None required (zero external module dependencies; offline mock testnet).

```bash
cd projects/digital-asset-custody-platform
go version
```

## 2. Standard Commands

| Action | Command | Expected Result |
|---|---|---|
| Run reproducible reference demo | `./scripts/run_demo.sh` (or `make demo`) | Prints JSON baseline report with `"oracle_matched": true`, `"final_status": "CONFIRMED"`, `"reconciled": true` |
| Run full validation suite | `./scripts/validate.sh` (or `make validate`) | Runs `go vet`, `go test -race -count=1 -v ./...`, regenerates reports, checks for secret leaks |
| Run resilience & security scenarios | `go run ./src/cmd/custody scenarios --policy config/default-policy.json` | Prints JSON with `"all_passed": true` across all 6 scenarios |
| Run benchmarks only | `make bench` | Outputs `ns/op`, `B/op`, `allocs/op` for policy hashing and end-to-end custody flow |

## 3. Demo Walkthrough

1. Execute `./scripts/run_demo.sh`.
2. Observe the deterministic lifecycle:
   - Vault `vault-treasury-01` receives a `10,000,000,000` gwei (`10.0 MOCK_ETH`) deposit.
   - Transfer intent `intent-ref-0001` requests `1,500,000,000` gwei (`1.5 MOCK_ETH`) to allowlisted destination `0x2222...2222` under `key_epoch = 1`, `nonce = 1`.
   - Canonical `intent_hash` computes to `77fed00728a365eb0a7554623e56feee1fd5cc6a90fc2e502096f2a505bff7ef`, matching the independent Python SHA-256 oracle (`oracle_matched: true`).
   - Two independent approvers (`approver-ops-1`, `approver-risk-2`) produce Ed25519 approval signatures bound to the exact intent hash.
   - The isolated 2-of-3 signer cluster re-verifies hash, policy, quorum, epoch, and replay state, then issues Ed25519 partial signatures (`tx_hash: 0x3525f6e8...`).
   - Mock chain mines 2 blocks; reconciler confirms `vault_confirmed_balance = 8,500,000,000`, `vault_reserved_balance = 0`, `destination_onchain_balance = 1,500,000,000`, `reconciled = true`, `audit_chain_valid = true`.

## 4. Diagnostics & Telemetry Counters

Every `CustodyService` maintains structured `log/slog` JSON logs and `telemetry.Counters`:
- `policy_denied > 0`: Inspect `audit_events` for `POLICY_EVALUATED` with `reason_code` (`ERR_DESTINATION_NOT_ALLOWLISTED`, `ERR_AMOUNT_LIMIT_EXCEEDED`, `ERR_DAILY_LIMIT_EXCEEDED`, `ERR_UNSUPPORTED_NETWORK`).
- `signatures_rejected > 0`: **High-priority security signal.** Inspect `SIGNING_REJECTED` audit event `reason_code`:
  - `ERR_INTENT_HASH_MISMATCH`: Possible payload tampering between approval and signing boundaries. Halt automation and investigate caller integrity.
  - `ERR_INSUFFICIENT_APPROVALS`: Premature or forged signing request without full quorum.
  - `ERR_KEY_EPOCH_MISMATCH`: Stale pre-rotation intent submitted after key rotation.
  - `ERR_SIGNER_QUORUM_UNAVAILABLE`: Fewer than `T` signer nodes online.
- `replays_blocked > 0`: Duplicate `intent_id`, reused `nonce`, or replayed signed payload was blocked.
- `reorgs_detected > 0`: Chain tip reorganized; inspect `REORG_DETECTED` events and re-run `Reconcile()`.

## 5. Failure & Recovery Procedures

### 5.1 Missing or Invalid Policy Configuration
- **Symptom:** Startup fails with `ERR_MISSING_CONFIG`, `ERR_INVALID_CONFIG`, or `ERR_UNSUPPORTED_NETWORK`.
- **Recovery:** Verify `--policy` path exists, validate JSON syntax, ensure `allowed_networks` contains only mock/testnet networks, and verify `1 <= signing_threshold <= len(signer_ids)`. Never bypass startup validation.

### 5.2 Isolated Signer Outage
- **Symptom:** Signing fails closed with `ERR_SIGNER_QUORUM_UNAVAILABLE` when fewer than `T` (e.g., 2 of 3) signers are online.
- **Recovery:** Check signer health (`SIGNER_OUTAGE` audit events), restore offline signer nodes (`SetSignerOnline(id, true)`), and retry `SignAndBroadcast(intentID)`. Because quorum availability is pre-checked before mutating replay caches, retrying after recovery succeeds cleanly without duplicate nonces or stranded reservations.

### 5.3 Chain Reorganization (Reorg)
- **Symptom:** `REORG_DETECTED` audit event emitted during `SyncInFlight()` / `Reconcile()`.
- **Recovery:**
  - If the transaction was requeued to mempool (`status = BROADCAST`), provisional settlement is automatically reverted back to `ReservedBalance`; wait for canonical blocks (`MineBlocks`) and re-run `Reconcile()`.
  - If the transaction was permanently evicted (`status = REORGED_DROPPED`), the balance reservation is automatically released; verify via `Reconcile()` and submit a new transfer intent with the next sequential nonce if the transfer is still needed.

### 5.4 Key Rotation with Pending Intent
- **Symptom:** `RotateVaultKeys(vaultID)` transitions epoch `E -> E+1` and marks pre-signing pending intents `INVALIDATED_KEY_ROTATION` (`ERR_KEY_EPOCH_MISMATCH`).
- **Recovery:** Verify via `Reconcile()` that reserved balances for invalidated intents were released (`reserved_delta == 0`). Re-submit a replacement `TransferIntent` referencing `key_epoch = E+1` and the vault's next sequential nonce, collect fresh independent approvals, and sign/broadcast normally. Already-broadcast epoch-`E` transactions do not need resubmission and continue settling against retired epoch-`E` public keys.

### 5.5 Process Restart / Rerun
- **Symptom:** Service process stops mid-lifecycle.
- **Recovery:** Restart `CustodyService` pointing `storage.FileStore` at the persisted snapshot path with the matching `PolicyVersion`. Startup verifies audit hash-chain integrity, restores ledger balances, nonces, key epochs, and signer replay caches automatically. Run `Reconcile()` immediately after restart.

## 6. Known Limitations

- Prototype only; not security-certified or audited for production custody.
- Signers run in-process with deterministic test seeds rather than air-gapped hardware HSMs.
- Live PostgreSQL persistence and external blockchain RPCs are intentionally disabled/untested in this offline environment.
