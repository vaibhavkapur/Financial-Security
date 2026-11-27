#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

mkdir -p reports

echo "==> 1. go vet"
go vet ./...

echo "==> 2. go build"
go build ./...

echo "==> 3. go test -race -count=1 ./tests/..."
go test -race -v -count=1 ./tests/...

echo "==> 4. Reference fixture verification -> reports/baseline_outputs.json"
go run ./src/cmd/agent-authz verify-fixtures \
  --config config/default.json \
  --fixture data/fixtures/reference_scenario.json \
  --out reports/baseline_outputs.json > /dev/null

echo "==> 5. Adversarial delegation evaluation -> reports/adversarial_report.json"
go run ./src/cmd/agent-authz evaluate \
  --config config/default.json \
  --out reports/adversarial_report.json > /dev/null

echo "==> 6. End-to-end demo"
go run ./src/cmd/agent-authz demo --config config/default.json

echo "==> 7. Benchmarks -> reports/benchmark_raw.txt"
go test -run=^$ -bench=. -benchmem -count=1 ./tests/... | tee reports/benchmark_raw.txt

echo "All validation checks passed."
