#!/usr/bin/env bash
# check-bench-overhead.sh — assert mean(benchA) - mean(benchB) <= max_ns.
#
# Usage: ./scripts/check-bench-overhead.sh <bench_hooked> <bench_bare> <max_overhead_ns>
#
# Reads target/criterion/<bench>/base/estimates.json for both benches,
# parses mean.point_estimate via jq, and exits 0 iff
#   mean(hooked) - mean(bare) <= max_overhead_ns
# else exits 1.
#
# Used by H-A4 to gate hook overhead in absolute nanoseconds. See the
# PowerShell sibling for full rationale on why ratio gating is unstable
# at the closure-invocation layer.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <bench_hooked> <bench_bare> <max_overhead_ns>" >&2
  exit 2
fi

HOOKED_NAME="$1"
BARE_NAME="$2"
MAX_OVERHEAD="$3"

read_mean() {
  local f="target/criterion/$1/base/estimates.json"
  if [[ ! -f "$f" ]]; then
    echo "ERROR: $f not found. Run 'cargo bench' first." >&2
    exit 1
  fi
  jq -r '.mean.point_estimate' "$f"
}

HOOKED=$(read_mean "$HOOKED_NAME")
BARE=$(read_mean "$BARE_NAME")

# awk handles floating point comparison portably.
RESULT=$(awk -v h="$HOOKED" -v b="$BARE" -v max="$MAX_OVERHEAD" '
  BEGIN {
    o = h - b
    if (o <= max) printf "PASS %.1f %.1f %.1f", o, h, b
    else          printf "FAIL %.1f %.1f %.1f", o, h, b
  }')

case "$RESULT" in
  PASS\ *)
    read -r _ overhead hval bval <<<"$RESULT"
    printf 'PASS: %s - %s overhead=%s ns <= %s ns (means: %s ns / %s ns)\n' \
      "$HOOKED_NAME" "$BARE_NAME" "$overhead" "$MAX_OVERHEAD" "$hval" "$bval"
    exit 0
    ;;
  FAIL\ *)
    read -r _ overhead hval bval <<<"$RESULT"
    printf 'FAIL: %s - %s overhead=%s ns > %s ns (means: %s ns / %s ns)\n' \
      "$HOOKED_NAME" "$BARE_NAME" "$overhead" "$MAX_OVERHEAD" "$hval" "$bval" >&2
    exit 1
    ;;
  *)
    echo "ERROR: unexpected awk output: $RESULT" >&2
    exit 1
    ;;
esac
