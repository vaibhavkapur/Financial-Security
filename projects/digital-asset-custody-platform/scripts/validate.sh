#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== [1/4] go vet ==="
go vet ./...

echo "=== [2/4] go test -race ==="
go test -race -count=1 -v ./...

echo "=== [3/4] Generating machine-readable reports ==="
./scripts/generate_reports.sh

echo "=== [4/4] Checking reports for leaked key material ==="
if grep -E -i "(BEGIN PRIVATE KEY|TESTNET_MOCK_SEED|privKey)" reports/*.json; then
  echo "ERROR: sensitive pattern detected in reports!"
  exit 1
fi

echo "=== ALL VALIDATION CHECKS PASSED ==="
