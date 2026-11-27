# Integration, Adapters, and Provenance

## 1. Sibling Repository Boundaries (`Financial-Security`)

Verified sibling project directories under `projects/` in `Financial-Security`:

| Sibling Project | Verified Path | Integration Boundary | Status |
|---|---|---|---|
| Financial API Security Gateway | `../financial-api-security-gateway/` | Consumes AIAP EdDSA JWK (`KeyPair.PublicJWK()`) and calls `PlatformService.Authorize` as an external PEP/PDP authorization hook before forwarding mock financial API calls | Independent sibling module; adapter boundary documented |
| Digital Asset Custody Platform | `../digital-asset-custody-platform/` | Consumes AIAP `ApprovalRecord` exact-action digests and `AuthorizationDecision` outputs as a pre-signing policy gate for simulated custody transfers | Independent sibling module; adapter boundary documented |
| Trading Infrastructure Security Monitor | `../trading-infrastructure-security-monitor/` | Ingests AIAP redacted structured JSON logs (`slog`) and SHA-256 hash-chained `AuditEvent` streams for anomaly detection and compliance replay | Independent sibling module; adapter boundary documented |
| Financial AI Red-Teaming Framework | `../financial-ai-red-teaming-framework/` | Invokes `audit.RunAdversarialSuite` or submits adversarial `AuthorizationRequest` vectors against `PlatformService` to benchmark delegation escalation resistance | Independent sibling module; adapter boundary documented |

No code is copied from sibling projects, and there is **zero dependency** on private employer or SAAT code or data. All integration boundaries are defined strictly via typed Go interfaces (`store.Store`, `domain.Clock`, `enforcer.PlatformService`) and versioned JSON contracts (`docs/contracts.md`).

---

## 2. Storage Adapter Compatibility

| Adapter | Implementation | Schema File | Concurrency Guarantee | Verification Status |
|---|---|---|---|---|
| SQLite (default) | `src/store/sqlite.go` (`modernc.org/sqlite`) | `config/schema/sqlite.sql` | Serialized `BEGIN IMMEDIATE` transactions + mutex | **Verified** via unit, concurrency (`-race`), restart persistence, and replay tests |
| PostgreSQL | `src/store/postgres.go` (`github.com/jackc/pgx/v5`) | `config/schema/postgres.sql` | `SERIALIZABLE` isolation + `SELECT ... FOR UPDATE` row locking | **Compiled & type-checked**; live PostgreSQL server execution **NOT RUN** (no local PostgreSQL daemon in offline test environment) |

---

## 3. Dependency Inventory and Licenses

All third-party dependencies are pinned in `go.mod` / `go.sum`:

| Module | Version | Purpose | License |
|---|---|---|---|
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | RFC 7519 / RFC 8037 EdDSA (Ed25519) JWT signing & verification | MIT |
| `github.com/google/uuid` | `v1.6.0` | RFC 4122 UUID generation for grant, decision, and revocation IDs | BSD-3-Clause |
| `github.com/jackc/pgx/v5` | `v5.11.0` | PostgreSQL driver & connection pool adapter | MIT |
| `modernc.org/sqlite` | `v1.60.1` | Pure-Go embedded SQLite ACID database (no CGo required) | BSD-3-Clause |
| Go Standard Library (`crypto/ed25519`, `crypto/sha256`, `log/slog`, `database/sql`) | Go 1.24+ | Established Ed25519 signing, SHA-256 hashing, structured logging | BSD-3-Clause |

---

## 4. Fixture Provenance

All files under `data/fixtures/` (`reference_scenario.json`, `boundary_and_invalid.json`) and synthetic identities in `src/audit/adversarial.go` and `tests/` are **100% synthetic educational fixtures** created specifically for this prototype:
- No real customer names, account numbers, PII, production keys, or live capital.
- Synthetic Ed25519 fixture keys are deterministically derived from labeled mock seeds (`aiap.synthetic.fixture.key.v1:...`) solely for offline reproducibility.
