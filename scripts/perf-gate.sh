#!/usr/bin/env bash
# Performance regression gate for helmet-core.
#
# Runs criterion benchmarks, parses results, and fails if any benchmark
# exceeds its latency budget. Designed for CI and pre-commit use.
#
# Usage:
#   scripts/perf-gate.sh              # Run and check
#   scripts/perf-gate.sh --dry-run    # Run and report only (no fail)
#
# Budget file: scripts/perf-budgets.toml
# Exit codes: 0 = pass, 1 = regression detected, 2 = infra error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUDGET_FILE="$SCRIPT_DIR/perf-budgets.toml"
DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

if [[ ! -f "$BUDGET_FILE" ]]; then
    echo "ERROR: Budget file not found: $BUDGET_FILE" >&2
    exit 2
fi

echo "=== Helmet Performance Gate ==="
echo ""

# Run benchmarks and capture output
BENCH_OUTPUT=$(cd "$ROOT_DIR" && cargo bench -p helmet-core --bench guard_hot_path 2>&1) || {
    echo "ERROR: Benchmark run failed" >&2
    echo "$BENCH_OUTPUT" >&2
    exit 2
}

# Use awk to do all parsing and checking in one pass — avoids bc dependency.
awk -v budget_file="$BUDGET_FILE" -v dry_run="$DRY_RUN" '
BEGIN {
    # Parse budget file
    section = ""
    while ((getline line < budget_file) > 0) {
        # Skip comments and blanks
        if (line ~ /^[[:space:]]*#/ || line ~ /^[[:space:]]*$/) continue
        # Section header [group/name]
        if (match(line, /^\[([a-z_/0-9]+)\]/, m)) {
            section = m[1]
            continue
        }
        # Key = value
        if (match(line, /^([a-z_0-9]+)[[:space:]]*=[[:space:]]*([0-9.]+)/, m)) {
            key = section "." m[1]
            budgets[key] = m[2] + 0
        }
    }
    close(budget_file)

    last_name = ""
    n_results = 0
}

# "Benchmarking group/name" line
/^Benchmarking [a-zA-Z_/0-9]+$/ {
    match($0, /^Benchmarking ([a-zA-Z_/0-9]+)$/, m)
    last_name = m[1]
    next
}

# Line with name and time:
/^[a-zA-Z_/0-9]+[[:space:]]+time:/ {
    match($0, /^([a-zA-Z_/0-9]+)[[:space:]]+time:/, m)
    last_name = m[1]
}

# Any line with time: — extract middle value
/time:[[:space:]]+\[/ {
    # Extract the three values and unit from: time:   [lo mid hi unit]
    if (match($0, /time:[[:space:]]+\[[0-9.]+ [a-zµ]+ ([0-9.]+) ([a-zµ]+)/, m)) {
        val = m[1] + 0
        unit = m[2]
        # Normalize to microseconds
        if (unit == "ns")      val = val / 1000
        else if (unit == "ms") val = val * 1000
        else if (unit == "s")  val = val * 1000000
        # µs stays as-is

        if (last_name != "") {
            results[last_name] = val
            result_order[n_results++] = last_name
            last_name = ""
        }
    }
}

END {
    if (n_results == 0) {
        print "ERROR: No benchmark results parsed" > "/dev/stderr"
        exit 2
    }

    printf "Results:\n--------\n"
    printf "%-35s %10s %10s %8s\n", "Benchmark", "Actual", "Budget", "Status"
    printf "%-35s %10s %10s %8s\n", "---------", "------", "------", "------"

    checked = 0
    failed = 0

    for (i = 0; i < n_results; i++) {
        name = result_order[i]
        actual = results[name]
        budget_key = name ".p95_us"

        if (budget_key in budgets) {
            budget = budgets[budget_key]
            checked++
            if (actual > budget) {
                failed++
                printf "%-35s %7.1f µs %7.0f µs %8s\n", name, actual, budget, "FAIL"
            } else {
                pct = (actual / budget) * 100
                printf "%-35s %7.1f µs %7.0f µs %6.0f%%\n", name, actual, budget, pct
            }
        } else {
            printf "%-35s %7.1f µs %10s %8s\n", name, actual, "none", "SKIP"
        }
    }

    printf "\nChecked %d benchmarks against budgets.\n", checked

    if (failed > 0) {
        if (dry_run == "true") {
            print "WARN: " failed " benchmark(s) exceeded budget (dry-run mode, not failing)."
            exit 0
        } else {
            print "FAIL: " failed " benchmark(s) exceeded budget."
            exit 1
        }
    } else {
        print "PASS: All benchmarks within budget."
        exit 0
    }
}
' <<< "$BENCH_OUTPUT"
