#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export GOCACHE="${GOCACHE:-/tmp/tism-gocache}"

echo "==> Running go vet..."
go vet ./...

echo "==> Running unit, integration, Sigma regression, boundary, and acceptance tests with race detector..."
go test -race -count=1 -v ./...

echo "==> Validating CLI config and evaluation..."
go run ./src/cmd/tism validate-config --config config/monitor_config.json
go run ./src/cmd/tism evaluate \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/synthetic_eval_dataset.jsonl \
  --ground-truth data/fixtures/scenarios/synthetic_eval_ground_truth.json

echo "==> All validation checks passed."
