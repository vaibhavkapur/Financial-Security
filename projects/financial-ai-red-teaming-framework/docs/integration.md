# Integration & Adapter Boundaries

## 1. Neighboring `Financial-Security` Repository Interfaces

The `Financial-Security` repository contains five independent sibling projects under `projects/`:

| Sibling Project | Module Type | Reusable Integration Boundary (Adapter Pattern) |
|---|---|---|
| `../agent-identity-and-authorization-platform/` | Go module | `PolicyEngine` (`src/fin_redteam/identity_policy.py`) isolates identity/policy evaluation behind a pure `evaluate_tool_call(...) -> PolicyDecision` interface so a thin runnable adapter can delegate role/token verification without modifying `EnforcementGateway`. |
| `../financial-api-security-gateway/` | Go module | `EnforcementGateway` (`src/fin_redteam/enforcement.py`) mirrors gateway mediation semantics (tool call inspection, egress filtering, rate/step caps). Scenarios can be replayed against a local mock HTTP adapter for that gateway. |
| `../trading-infrastructure-security-monitor/` | Go module | `AuditLogger` (`src/fin_redteam/audit.py`) emits structured JSON `AuditEvent` records with deterministic IDs and redacted details suitable for ingestion by a security monitoring collector adapter. |
| `../digital-asset-custody-platform/` | Go module | `ApprovalServiceStatus` and dual-approval tokens in `PolicyEngine` model multi-party approval gates and fail-closed outage behavior compatible with custody approval adapters. |

Each sibling runs independently with **zero cross-directory imports**, exposing clean, self-contained runnable adapters instead of duplicating code.

## 2. Optional LLM Provider Adapter Boundary

`src/fin_redteam/agent.py` defines the abstract `FinancialAgentAdapter` interface:
- `initial_tool_calls(scenario, canary_guard) -> list[ToolCallRequest]`
- `follow_up_tool_calls(scenario, tool_output, canary_guard) -> list[ToolCallRequest]`
- `compose_final_response(scenario, tool_outputs, canary_guard) -> str`

Two concrete adapters are provided:
1. `DeterministicFinancialAgent`: Offline, zero-network reference implementation used by default (`deterministic_guarded` / `deterministic_unguarded`).
2. `OptionalLLMProviderStub`: Offline stub adapter (`optional_llm_stub`) verifying the integration contract without external API calls. Instantiating it with `live_enabled=True` raises `UnsupportedInputError` by design so no synthetic or accidental prompts are ever sent to third-party services without a separate authorization review.

## 3. Dependency Licenses & Fixture Provenance

| Dependency | Purpose | License |
|---|---|---|
| `pydantic` (`>=2.10,<3.0`, locked at `2.14.4`) | Strict schema validation and JSON serialization | MIT |
| `pytest` (dev, locked at `8.4.2`) | Automated unit, integration, and boundary test runner | MIT |
| `ruff` (dev) | Static linting and import/style checks | MIT |
| `hatchling` (build backend) | PEP 517 Python package build | MIT |

**Fixture provenance:** Every file under `config/` and `data/fixtures/` was authored from scratch specifically for this educational prototype (`provenance: "synthetic_offline_fixture"`). No third-party datasets, real customer records, production credentials, or proprietary employer/SAAT artifacts are included.
