#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
echo "Checking Go toolchain..."
go version
mkdir -p bin reports
go build -o bin/gateway ./src/cmd/gateway
go build -o bin/harness ./src/cmd/harness
./bin/gateway --validate-config --config-dir config
echo "Setup complete. Binaries built in ./bin/"
