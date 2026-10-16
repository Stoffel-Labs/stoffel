#!/usr/bin/env bash
# Recompiles the client-order-sensitive subtraction fixture the coordinator
# reserve-index and preprocessing-store suites run.
#
# The fixture used to be emitted by a hand-written instruction generator
# (crates/stoffel-vm-types/examples/generate_client_sub_order_program.rs), which
# could not produce a client-I/O manifest. The client path refuses a program
# whose manifest declares no clients, so those suites could not get past their
# first client. Compiling the StoffelLang source instead makes the compiler emit
# the manifest.
#
# The slot table the suites register must match the manifest exactly — a node
# refuses a registration whose per-slot input count disagrees with the program.
# Read it back with:
#   cargo run -p stoffel-vm-types --example inspect_client_io_manifest -- <out>
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${ROOT_DIR}/crates/stoffel-vm/src/tests/binaries/client_sub_order.stfl"
OUTPUT="${ROOT_DIR}/crates/stoffel-vm/src/tests/binaries/client_sub_order.stflb"

cargo build --release -p stoffellang --bin stoffellang
"${ROOT_DIR}/target/release/stoffellang" \
    --binary \
    --mpc-backend honeybadger \
    --mpc-curve bls12-381 \
    --output "${OUTPUT}" \
    "${SOURCE}"

echo "Regenerated ${OUTPUT}"
cargo run -q -p stoffel-vm-types --example inspect_client_io_manifest -- "${OUTPUT}"
