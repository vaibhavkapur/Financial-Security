# ADR 0001: Separate Identity/Policy, Enforcement, and Redacted Audit Boundaries with Deny-by-Default Controls

- **Status:** Accepted
- **Date:** 2026-11-27
- **Context:** Financial AI Red Teaming Framework (M1 Foundation)

## Context

Simulated financial agents process both trusted operator instructions and untrusted external documents (vendor notices, counterparty filings, questionnaires) while interacting with read and write financial tools. Combining authorization logic, tool execution, and logging inside a single agent loop makes it difficult to prove fail-closed behavior, isolate domain logic for deterministic testing, or prevent secret canary leakage into telemetry.

## Decision

1. **Three strict runtime boundaries:**
   - **Identity & Policy (`identity_policy.py`):** Pure, I/O-free `PolicyEngine` enforcing deny-by-default RBAC/ABAC rules (`GoldPolicySet.default_decision == DENY`), per-role notional caps, dual-approval requirements, taint-mutation blocking, and conflict fail-closed halts.
   - **Enforcement Gateway (`enforcement.py`):** Mediates every tool invocation and assistant response, tracks provenance taint (`SourceTrust.UNTRUSTED_EXTERNAL`), runs `CanaryGuard` on outgoing arguments and final responses, and delegates only authorized calls to a deep-copied per-scenario `MockFinancialSandbox`.
   - **Redacted Audit (`audit.py`):** Emits deterministic, structured `AuditEvent` records and diagnostic counters after passing all payloads through `CanaryGuard.redact_payload`.
2. **Synthetic safety invariants in data contracts:** `CanarySecret` enforces the `SYNTHETIC_CANARY_` prefix and `MockAccount` enforces the `ACC-SYNTH-` prefix at schema validation time.
3. **Reference oracle first:** Before expanding the full suite, a 4-scenario hand-calculated `reference_oracle.json` anchors expected decisions, metrics (`ASR = 0.0`, `FRR = 0.0`), and fail-closed reason codes.

## Consequences

- **Positive:** Domain policy transitions are unit-testable with zero I/O; canary secrets cannot leak into logs even during unguarded exploit reproduction; every scenario runs in an isolated sandbox with deterministic `run_id` and `event_id` values.
- **Negative / Trade-offs:** Coarse-grained scenario taint blocks any mutating tool call after reading an untrusted external document until a separate trusted session or human approval workflow resets provenance. This favors safety over multi-step convenience in the prototype.
