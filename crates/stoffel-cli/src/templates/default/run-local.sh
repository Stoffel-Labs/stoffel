#!/usr/bin/env sh
set -eu

if [ -n "${STOFFEL_RUN_BIN:-}" ]; then
  runner=$STOFFEL_RUN_BIN
elif command -v stoffel-run >/dev/null 2>&1; then
  runner=$(command -v stoffel-run)
else
  printf '%s\n' \
    "Missing stoffel-run, which runs the local MPC nodes." \
    "Install the matching runner once:" \
    "  cargo install stoffel-vm-runner --version 0.1.2 --locked" \
    "Then rerun this script. You can also set STOFFEL_RUN_BIN to an existing stoffel-run binary." >&2
  exit 1
fi
if [ ! -x "$runner" ]; then
  printf '%s\n' "STOFFEL_RUN_BIN is not executable: $runner" >&2
  exit 1
fi
export STOFFEL_RUN_BIN="$runner"

stoffel_bin=${STOFFEL_BIN:-stoffel}
"$stoffel_bin" check
"$stoffel_bin" build --output artifacts/program.stflb
cargo build --bins
export STOFFEL_AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-stoffel-local-example}"
target_dir=${CARGO_TARGET_DIR:-target}

"$target_dir/debug/stoffel-coordinator" prepare
"$target_dir/debug/stoffel-coordinator" serve &
pids=$!
trap 'kill $pids 2>/dev/null || true' EXIT INT TERM

parties=$(sed -n 's/^[[:space:]]*parties[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' Stoffel.toml)
party=0
while [ "$party" -lt "$parties" ]; do
  "$target_dir/debug/stoffel-server" "$party" &
  pids="$pids $!"
  party=$((party + 1))
done

printf '%s\n' "Waiting for MPC preprocessing to finish..."
"$target_dir/debug/stoffel-coordinator" wait-ready
printf '%s\n' "Local Stoffel MPC services are ready for client input."
printf '%s\n' "In another terminal run: cargo run -- 42"
wait
