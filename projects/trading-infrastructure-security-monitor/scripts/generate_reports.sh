#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export GOCACHE="${GOCACHE:-/tmp/tism-gocache}"

mkdir -p reports

echo "==> Generating baseline reference report..."
go run ./src/cmd/tism run \
  --config config/monitor_config.json \
  --input data/fixtures/reference/reference_events.jsonl \
  --output reports/baseline_reference.json

echo "==> Generating integration & resilience report (missing telemetry + duplicates)..."
go run ./src/cmd/tism run \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/missing_telemetry_and_duplicates.jsonl \
  --output reports/integration_resilience.json

echo "==> Generating reviewed containment & suppression audit report..."
go run ./src/cmd/tism demo \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/suppression_and_reviewer_audit.jsonl \
  --output reports/containment_review_audit.json

echo "==> Generating synthetic evaluation metrics and OTLP telemetry..."
go run ./src/cmd/tism demo \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/synthetic_eval_dataset.jsonl \
  --output reports/demo_reviewed_report.json \
  --otel-out reports/demo_otel_telemetry.json

go run ./src/cmd/tism evaluate \
  --config config/monitor_config.json \
  --input data/fixtures/scenarios/synthetic_eval_dataset.jsonl \
  --ground-truth data/fixtures/scenarios/synthetic_eval_ground_truth.json \
  --output reports/evaluation_metrics.json

echo "==> Reports generated in reports/."
