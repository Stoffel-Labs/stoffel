#!/usr/bin/env sh
set -eu
cargo run --bin stoffel-coordinator -- wait-ready
exec cargo run --bin stoffel-client -- "${1:-42}"
