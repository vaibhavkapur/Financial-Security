#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export GOCACHE="${GOCACHE:-/tmp/tism-gocache}"

echo "==> [1/3] Validating monitor configuration and Sigma rules..."
go run ./src/cmd/tism validate-config --config config/monitor_config.json

echo "==> [2/3] Running end-to-end synthetic security monitoring demo (simulation-only containment)..."
go run ./src/cmd/tism demo \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/synthetic_eval_dataset.jsonl \
  --output reports/demo_reviewed_report.json \
  --otel-out reports/demo_otel_telemetry.json

echo "==> [3/3] Evaluating synthetic detection recall and false-positive rate..."
go run ./src/cmd/tism evaluate \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/synthetic_eval_dataset.jsonl \
  --ground-truth data/fixtures/scenarios/synthetic_eval_ground_truth.json \
  --output reports/evaluation_metrics.json
