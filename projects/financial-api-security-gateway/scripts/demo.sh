#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p bin reports
go build -o bin/gateway ./src/cmd/gateway
./bin/gateway --demo --config-dir config --output-audit reports/audit_sample.jsonl
