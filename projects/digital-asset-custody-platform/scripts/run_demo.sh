#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== Running Digital Asset Custody Platform Reference Demo (Offline Mock Testnet) ==="
go run ./src/cmd/custody demo \
  --policy config/default-policy.json \
  --fixture data/fixtures/reference_fixture.json \
  --oracle data/fixtures/expected_reference_output.json
