# Integration & Adapter Boundaries

## 1. Repository Context (`Financial-Security`)

Sibling projects under `projects/` in `Financial-Security`:
- `projects/agent-identity-and-authorization-platform/` (Go module sibling)
- `projects/digital-asset-custody-platform/` (Go module sibling)
- `projects/financial-ai-red-teaming-framework/` (Python package sibling)
- `projects/financial-api-security-gateway/` (Go module sibling)

Because sibling security projects are independent modules, TISM exposes **independent, typed Go library interfaces and JSONL/JSON contracts** rather than copying or importing sibling implementations. No private employer or SAAT code is referenced or imported.

## 2. Reusable Adapter Interfaces

1. **Event Ingestion (`contracts.RawEvent` JSONL):**
   - Any upstream gateway (such as `financial-api-security-gateway`) or custody service (such as `digital-asset-custody-platform`) can emit JSONL records conforming to `docs/contracts.md` into `tism run --input <path>` or invoke `pipeline.RunRawEvents(ctx, events)` directly as a Go library.
2. **Identity / Policy Integration (`config/policy.json`):**
   - An external IAM/authorization platform (such as `agent-identity-and-authorization-platform`) can export approved change tickets, service accounts, privileged roles, and authorized reviewers into the `SecurityPolicy` schema.
3. **Storage Adapter (`store.EventStore` in `src/store/store.go`):**
   - `MemoryStore` + `WriteNormalizedJSONL`/`LoadNormalizedJSONL`: default offline, deterministic replay store.
   - `PostgresStore`: implements `EventStore` against `config/postgres_schema.sql` using Go's standard `database/sql` interface. Bring any SQL driver (`pgx/v5/stdlib` or `lib/pq`) in an external wrapper binary when connecting to a live PostgreSQL instance. Fails fast with `ErrMissingConfig` if initialized with a `nil` `*sql.DB`.
4. **OpenTelemetry Export (`src/telemetry/otel.go`):**
   - Emits OTLP-structured JSON (`OTLPExport`) with W3C `trace_id`/`span_id`, resource metadata, redacted attributes, and diagnostic counters (`--otel-out`). Can be forwarded by an external OTLP collector agent without coupling core detection logic to network I/O.

## 3. Dependency Licenses and Fixture Provenance

- **Runtime & Test Dependencies:** Go standard library only (BSD-3-Clause license; zero third-party modules in `go.mod`).
- **Fixtures:** 100% original, hand-crafted synthetic trading infrastructure logs (`data/fixtures/`) using RFC 5737 documentation IP ranges (`198.51.100.0/24`, `203.0.113.0/24`), RFC 1918 private ranges (`10.10.0.0/16`, `10.20.0.0/16`), synthetic ticket IDs (`CHG-2026-*`), and synthetic placeholder secrets (`synthetic-*`, `tism_sim_*`). Zero real credentials, transactions, customer records, or production hostnames.
