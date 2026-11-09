#!/usr/bin/env sh
set -eu
# This is an ephemeral participant-owned client, not a service launcher.
# Replace this wrapper with the UI/service/device entrypoint described in README.md.
cargo run --bin stoffel-coordinator -- wait-ready
exec cargo run --bin stoffel-client -- "${1:-42}"
