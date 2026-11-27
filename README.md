# Financial Security

Five independent security engineering projects use synthetic offline fixtures to test API gateway controls, delegated agent identity and authorization, trading infrastructure threat detection, digital asset custody workflows, and financial AI red teaming. Four projects use Go, and the AI red-teaming framework uses Python.

## Getting started

Start with the Financial API Security Gateway. Its local-lab demo requires Go 1.27 or later and uses only the Go standard library to exercise TLS 1.3 mTLS, OIDC JWT verification, canonical request signing, policy enforcement, and redacted audit logging.

```bash
git clone https://github.com/vaibhavkapur/Financial-Security.git
cd Financial-Security/projects/financial-api-security-gateway
./scripts/setup.sh
./scripts/demo.sh
```

The demo sends valid, replayed, escalated, revoked, and timed-out requests through the gateway and writes redacted JSONL records to [`projects/financial-api-security-gateway/reports/audit_sample.jsonl`](projects/financial-api-security-gateway/reports/audit_sample.jsonl). Each project runs independently under `projects/`. Run its setup, demo, and validation commands from that project's directory.

## Projects

- [Financial API Security Gateway](projects/financial-api-security-gateway/) — Protects simulated financial APIs with TLS 1.3 mTLS, OAuth2/OIDC JWT verification, canonical request signing, nonce replay prevention, per-resource policy enforcement, rate limiting, and redacted audit logs.
- [Agent Identity and Authorization Platform](projects/agent-identity-and-authorization-platform/) — Issues short-lived Ed25519 delegation grants with monotonic attenuation, enforces atomic spending limits and cascading revocation, binds single-use approvals to exact action digests, and verifies hash-chained audit logs.
- [Trading Infrastructure Security Monitor](projects/trading-infrastructure-security-monitor/) — Normalizes and redacts synthetic trading infrastructure telemetry, evaluates Sigma-style YAML rules and stateful detectors, correlates alerts into cases, and simulates dual-control containment proposals.
- [Digital Asset Custody Platform](projects/digital-asset-custody-platform/) — Separates deny-by-default custody policy, canonical intent approvals, isolated T-of-N Ed25519 threshold signers, and double-entry ledger reconciliation across simulated block confirmations, reorgs, and key rotation.
- [Financial AI Red Teaming Framework](projects/financial-ai-red-teaming-framework/) — Evaluates simulated financial AI agents against indirect prompt injection, unsafe tool requests, privilege escalation, conflicting directives, approval outages, and canary leakage with deterministic replay and regression reporting.

Each project README links to its architecture, data contracts, integration boundaries, operator runbook, and validation evidence.
