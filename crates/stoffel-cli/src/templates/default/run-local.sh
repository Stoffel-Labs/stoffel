#!/usr/bin/env sh
set -eu

# Single-host development launcher: build the shared contract, start the coordinator
# and MPC nodes as separate processes, then wait for protocol readiness. The
# participant client remains separate; see README.md for the integration sequence.
if [ -n "${STOFFEL_RUN_BIN:-}" ]; then
  runner=$STOFFEL_RUN_BIN
elif command -v stoffel-run >/dev/null 2>&1; then
  runner=$(command -v stoffel-run)
else
  printf '%s\n' \
    "Missing stoffel-run, which runs the development MPC node processes." \
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
# Keep source, bytecode, generated Rust types, and service binaries in sync.
"$stoffel_bin" check
"$stoffel_bin" build --output artifacts/program.stflb
cargo build --bins
export STOFFEL_AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-stoffel-local-example}"
export STOFFEL_AUTO_ADDRESSES=1
target_dir=${CARGO_TARGET_DIR:-target}

"$target_dir/debug/stoffel-coordinator" prepare
# Endpoint selection is complete. Every long-lived process reads the same file.
unset STOFFEL_AUTO_ADDRESSES
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
# Process health is not enough: clients submit only after input masks are ready.
"$target_dir/debug/stoffel-coordinator" wait-ready
printf '%s\n' "Development Stoffel deployment is ready for participant input."
printf '%s\n' "In another terminal run: cargo run -- 42"
wait
