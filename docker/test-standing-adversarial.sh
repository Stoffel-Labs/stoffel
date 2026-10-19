#!/usr/bin/env bash
set -euo pipefail

# The coordinator is the trusted party: it mints every execution identity and
# publishes each execution to the node roster. This driver is an operator of it,
# holding one of the certificates in --operator-certs, and submits executions
# over that authenticated link. No directory is mounted into the nodes.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${ROOT_DIR}/docker/standing-concurrency/acceptance.py" adversarial
