# Digital Asset Custody Platform (Prototype)

> **Educational / Research Prototype Notice:** This repository implements an offline/mock-testnet prototype for policy-controlled digital asset custody with strictly separated policy, approval, ledger, and isolated threshold signing boundaries. **Never store real private keys, real customer records, or production funds in this software.** Mainnet networks and production environments are explicitly blocked by policy validation.

## Overview

This project implements the specification in [`plan.md`](plan.md) (Project 66 of 67) using **Go** (`go 1.23+`, validated on `go1.27.1`) and standard library cryptography (`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`) with **zero external runtime dependencies**.

### Core Capabilities

- **Deny-by-Default Policy Engine (`src/pkg/policy`):** Enforces mock/testnet-only networks, active vaults, asset/unit matching, destination allowlists with per-destination caps, single-transfer and UTC daily velocity limits, separation of duties (requesters cannot approve their own intents), and tiered approval quorums (e.g., 2-of-3 standard, 3-of-3 high-value).
- **Canonical Intent Hashing & Independent Approvals (`src/pkg/domain`, `src/pkg/signer`):** Every `TransferIntent` is deterministically canonicalized and hashed (`SHA-256("CUSTODY_INTENT_V1:" || canonical_json)`). Independent approvers sign the exact `IntentHash` with Ed25519.
- **Isolated T-of-N Multisig Signer Boundary (`src/pkg/signer`):** Isolated `SignerNode` instances hold no reference to ledger state or mutable policy configs. Each node independently re-verifies the canonical intent hash (catching tampered destinations/amounts), approval Ed25519 signatures and quorum, active `KeyEpoch`, expiry, and local replay caches before issuing a partial signature.
- **Double-Entry Custody Ledger & Mock Testnet Reconciler (`src/pkg/ledger`, `src/pkg/chain`, `src/pkg/engine`):** Tracks `ConfirmedBalance`, `ReservedBalance`, and `AvailableBalance` in integer minor units (no floats), simulates block confirmations and chain reorganizations (both requeue and tx drop), handles key rotation with pending intents, and reconciles ledger vs. on-chain balances plus a hash-chained redacted audit trail (`src/pkg/audit`).
- **Durable Restart & PostgreSQL Schema (`src/pkg/storage`, `config/schema.sql`):** Atomic crash-safe `FileStore` for offline restart/rerun verification plus PostgreSQL DDL and `database/sql` adapter boundary.

## Project Structure

```text
projects/digital-asset-custody-platform/
├── plan.md                                     # Original implementation plan
├── go.mod                                      # Zero-dependency Go module manifest
├── Makefile                                    # Build, test, demo, benchmark, validate targets
├── config/
│   ├── default-policy.json                     # Versioned deny-by-default custody policy
│   └── schema.sql                              # PostgreSQL relational schema
├── data/fixtures/
│   ├── reference_fixture.json                  # Deterministic reference scenario input
│   ├── expected_reference_output.json          # Independent Python SHA-256 + accounting oracle
│   ├── invalid_inputs.json                     # Invalid & boundary input test vectors
│   └── integration_scenarios.json              # Resilience & failure scenario catalog
├── src/
│   ├── cmd/custody/main.go                     # CLI for demo & scenario report generation
│   └── pkg/                                    # Typed Go packages (domain, policy, signer, ledger, chain, audit, storage, telemetry, engine, scenarios)
├── tests/                                      # Unit, integration, resilience, operational & benchmark suites
├── scripts/                                    # run_demo.sh, generate_reports.sh, validate.sh
├── docs/
│   ├── architecture.md                         # Security boundaries, Mermaid diagram, invariants, trade-offs
│   ├── contracts.md                            # Schemas, minor units, canonical hashing, error taxonomy
│   ├── integration.md                          # Adapter boundaries, sibling interfaces, licenses & provenance
│   ├── runbook.md                              # Setup, demo walkthrough, diagnostics & recovery playbooks
│   └── adr/0001-architecture-and-trust-boundaries.md
└── reports/
    ├── acceptance.md                           # Acceptance criteria mapped to measured evidence
    ├── baseline_reference.json                 # Measured baseline run output vs. oracle
    ├── scenario_results.json                   # Measured scenario suite outputs
    └── benchmark_results.json                  # Measured latency & allocation benchmarks
```

## Quickstart

### Prerequisites
- Go `1.23+` (verified on `go1.27.1`, `darwin/arm64`)
- No network access or external services required.

### 1. Run the Reproducible Reference Demo
```bash
cd projects/digital-asset-custody-platform
./scripts/run_demo.sh
```

**Actual Measured Example Output (`reports/baseline_reference.json`):**
```json
{
  "report_version": "1.0.0",
  "intent_id": "intent-ref-0001",
  "intent_hash": "77fed00728a365eb0a7554623e56feee1fd5cc6a90fc2e502096f2a505bff7ef",
  "oracle_intent_hash": "77fed00728a365eb0a7554623e56feee1fd5cc6a90fc2e502096f2a505bff7ef",
  "oracle_matched": true,
  "tx_hash": "0x3525f6e8cc16bbe962afadde472d9a36b64b4ee68c3d2eded3a051abb7023903",
  "key_epoch": 1,
  "approval_count": 2,
  "signature_count": 2,
  "final_status": "CONFIRMED",
  "confirmations": 2,
  "vault_confirmed_balance": 8500000000,
  "vault_reserved_balance": 0,
  "vault_available_balance": 8500000000,
  "destination_onchain_balance": 1500000000,
  "reconciliation": {
    "reconciled": true,
    "audit_chain_valid": true,
    "checksum": "f62bab1dc2b28ebe7c716c349cc29a2400d3707caef3cb2ae192cb6052fd04ed"
  }
}
```

### 2. Run Full Validation Suite (Vet, Race Tests, Reports, Leak Check)
```bash
./scripts/validate.sh
# or: make validate
```

### 3. Run Resilience & Security Scenarios Directly
```bash
go run ./src/cmd/custody scenarios --policy config/default-policy.json
```

## Documentation & Acceptance Evidence

- **Acceptance & Measured Evidence:** [`reports/acceptance.md`](reports/acceptance.md) (maps every criterion to automated tests, `reports/baseline_reference.json`, `reports/scenario_results.json`, and `reports/benchmark_results.json`)
- **Architecture & Trust Boundaries:** [`docs/architecture.md`](docs/architecture.md) and [`docs/adr/0001-architecture-and-trust-boundaries.md`](docs/adr/0001-architecture-and-trust-boundaries.md)
- **Data Contracts & Error Taxonomy:** [`docs/contracts.md`](docs/contracts.md)
- **Integration, Licenses & Provenance:** [`docs/integration.md`](docs/integration.md)
- **Operator & Developer Runbook:** [`docs/runbook.md`](docs/runbook.md)
- **CI Validation Workflow:** [`../../.github/workflows/digital-asset-custody-platform.yml`](../../.github/workflows/digital-asset-custody-platform.yml)

## Assumptions, Limitations, and Provenance

- **Measured vs. Synthetic:** All benchmark timings (`1.58 µs` policy evaluation + hashing; `0.42 ms` end-to-end transfer on `darwin/arm64`) and test outcomes in `reports/` are real measurements from running against synthetic offline fixtures.
- **Explicitly Not Run / Out of Scope:** Live PostgreSQL integration tests (no local Postgres server/driver in offline mode; `PostgresStore` fails explicitly with `ERR_STORAGE_UNAVAILABLE`), hardware HSM/enclave signing, MPC-TSS key generation, Solidity deployment, and any live testnet/mainnet broadcasting.
- **Licenses & Provenance:** Pure Go standard library (`BSD-3-Clause`, zero external dependencies). All code and fixtures are original synthetic educational artifacts with zero confidential, customer, or employer/SAAT data.
