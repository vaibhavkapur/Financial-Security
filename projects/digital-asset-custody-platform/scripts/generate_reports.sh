#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p reports

echo "=== Generating Baseline Reference Report ==="
go run ./src/cmd/custody demo \
  --policy config/default-policy.json \
  --fixture data/fixtures/reference_fixture.json \
  --oracle data/fixtures/expected_reference_output.json \
  --out reports/baseline_reference.json > /dev/null

echo "=== Generating Integration & Resilience Scenario Report ==="
go run ./src/cmd/custody scenarios \
  --policy config/default-policy.json \
  --out reports/scenario_results.json > /dev/null

echo "=== Running Benchmarks and Recording Metadata ==="
BENCH_RAW="$(go test -bench=. -benchmem -run=^$ ./tests/...)"
GO_VER="$(go version)"

python3 - "$BENCH_RAW" "$GO_VER" <<'PY'
import json, platform, re, sys, datetime

bench_raw = sys.argv[1]
go_ver = sys.argv[2]

benchmarks = []
for line in bench_raw.splitlines():
    m = re.match(r"^(Benchmark\S+)\s+(\d+)\s+([\d.]+)\s+ns/op\s+(\d+)\s+B/op\s+(\d+)\s+allocs/op", line)
    if m:
        benchmarks.append({
            "name": m.group(1),
            "iterations": int(m.group(2)),
            "ns_per_op": float(m.group(3)),
            "bytes_per_op": int(m.group(4)),
            "allocs_per_op": int(m.group(5)),
        })

out = {
    "report_version": "1.0.0",
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "environment": {
        "go_version": go_ver,
        "os": platform.system(),
        "arch": platform.machine(),
    },
    "benchmarks": benchmarks,
}

with open("reports/benchmark_results.json", "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")
PY

echo "Reports written to reports/baseline_reference.json, reports/scenario_results.json, and reports/benchmark_results.json"
