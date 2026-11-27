#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
echo "[1/5] Running go vet..."
go vet ./...

echo "[2/5] Validating valid config and verifying invalid config rejection..."
mkdir -p bin reports
go build -o bin/gateway ./src/cmd/gateway
go build -o bin/harness ./src/cmd/harness
./bin/gateway --validate-config --config-dir config

echo "[3/5] Running unit, reference-oracle, integration, rotation/revocation, and failure tests with -race..."
go test -race -v ./...

echo "[4/5] Running end-to-end demo..."
./bin/gateway --demo --config-dir config --output-audit reports/audit_sample.jsonl

echo "[5/5] Running full reference, negative-test, and overhead benchmark harness..."
./bin/harness --config-dir config --fixtures data/fixtures/reference_vectors.json --reports-dir reports --bench-samples 500

echo "Verifying zero secret leaks in reports/audit_sample.jsonl..."
if grep -E "CANARY_SECRET|synthetic-canary-api-key|eyJ[A-Za-z0-9_-]{8,}\." reports/audit_sample.jsonl >/dev/null 2>&1; then
  echo "ERROR: Secret material detected in audit_sample.jsonl" >&2
  exit 1
fi
echo "All validation checks passed."
