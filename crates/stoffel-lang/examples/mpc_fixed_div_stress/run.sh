#!/usr/bin/env bash
# Drives many secret fixed-point divisions to churn the prand_bit/prand_int/
# fpdiv_const/trunc exec counters past a u8 wrap.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
RUNNER="${STOFFEL_RUN_BIN:-$REPO_ROOT/target/release/stoffel-run}"
STOFFEL="${STOFFEL_BIN:-$REPO_ROOT/target/release/stoffel}"
STOFFEL_RUN_BIN="$RUNNER" "$STOFFEL" run "$(dirname "$0")" \
  --local --runner "$RUNNER" --timeout-secs 1100 \
  --client-input 0=1000000000
