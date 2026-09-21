#!/usr/bin/env bash
# SC-003 gate: BenchmarkForward p95 overhead must stay below 10 ms at 1,000 concurrency.
set -euo pipefail
max="${1:-10}"
out=$(go test -tags integration -run '^$' -bench '^BenchmarkForward$' -benchtime=20000x ./tests/integration/ 2>&1)
echo "$out"
p95=$(echo "$out" | awk '/p95_ms/ { for (i = 1; i <= NF; i++) if ($i == "p95_ms") print $(i-1) }' | tail -1)
[ -n "$p95" ] || { echo "perf-gate: no p95_ms metric reported" >&2; exit 1; }
awk -v p="$p95" -v m="$max" 'BEGIN { if (p + 0 > m + 0) { printf "perf-gate: p95 %.2f ms exceeds %.2f ms\n", p, m; exit 1 } else { printf "perf-gate: p95 %.2f ms within %.2f ms\n", p, m } }'
