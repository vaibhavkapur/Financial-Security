#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p bin reports
go build -o bin/harness ./src/cmd/harness
echo "Running Go microbenchmark (pure evaluator)..."
go test -bench=BenchmarkEvaluatorFullPipeline -benchmem -count=3 ./tests
echo "Running live loopback mTLS vs direct upstream overhead benchmark..."
./bin/harness --config-dir config --fixtures data/fixtures/reference_vectors.json --reports-dir reports --bench-samples 500
cat reports/overhead_benchmark.json
