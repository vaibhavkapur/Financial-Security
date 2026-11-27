# ADR-0001: Architecture, Language Stack, and Offline Defensive Lab Boundaries

- **Status:** Accepted
- **Date:** 2026-11-27
- **Context:** Project 65 (`trading-infrastructure-security-monitor`) requires a reproducible, strongly typed security monitoring prototype capable of normalizing/redacting synthetic trading infrastructure logs, evaluating Sigma-style rules, correlating evidence-backed cases, simulating reviewed containment, and integrating cleanly with OpenTelemetry and PostgreSQL boundaries.

## Decision

1. **Language & Runtime:** Implement in **Go 1.24+** using only the Go standard library (`go.mod` with zero third-party runtime dependencies).
   - Provides strong static typing for domain contracts (`src/contracts`), fast execution, built-in race detection (`go test -race`), structured JSON logging (`log/slog`), and built-in benchmarking (`go test -bench`).
2. **Sigma-Style Rule Engine:** Implement an embedded, strict Sigma-style YAML parser and recursive-descent boolean condition evaluator (`src/rules/sigma.go`) supporting field modifiers (`|contains`, `|startswith`, `|endswith`, `|in`, `|re`, `|neq`) and quantifiers (`1 of selection*`, `all of selection*`).
3. **OpenTelemetry Compatibility:** Emit OTLP/JSON spans and diagnostic counters (`src/telemetry/otel.go`) with deterministic W3C trace/span IDs and mandatory attribute redaction, avoiding external collector dependencies during offline runs while preserving clean collector export contracts.
4. **Storage & PostgreSQL Boundary:** Define an `EventStore` interface (`src/store/store.go`) backed by a deterministic `MemoryStore` + JSONL replay persistence for offline runs, alongside a `PostgresStore` (`database/sql`) adapter and full relational DDL (`config/postgres_schema.sql`).
5. **No Live Containment Guard:** Hard-code `containment_mode = "simulation_only"` and `live_containment_enabled = false` at both configuration validation and simulator execution boundaries.

## Consequences

- **Positive:** Clean checkout builds and passes all unit, integration, regression, boundary, and benchmark suites in seconds with zero network access or external package licenses to manage.
- **Trade-offs / Limitations:** Live PostgreSQL execution and live OTLP gRPC/HTTP collector shipping are explicitly untested in the offline lab and marked `Not Run` in `reports/acceptance.md`. Production deployment would require a live SQL driver (`pgx`), OTLP exporter transport, hardened key/secret management, and a separate security/operational review.
