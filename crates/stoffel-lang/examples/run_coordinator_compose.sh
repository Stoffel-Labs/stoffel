#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="${ROOT_DIR}/examples"
WORKSPACE_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VM_DIR="${STOFFEL_VM_DIR:-${WORKSPACE_DIR}}"
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:?Set STOFFEL_COORDINATOR_CONTEXT to a stoffel-mpc-coordinator 0.3.0 checkout}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
OUT_DIR="${STOFFEL_EXAMPLES_OUT:-${EXAMPLES_DIR}/dist}"
COMPOSE_FILE="${EXAMPLES_DIR}/docker-compose.coordinator.yml"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-300}"
EXPECTED_OUTPUT="${EXPECTED_OUTPUT:-315}"
PROGRAM_NAME="${STOFFEL_PROGRAM_NAME:-mpc_share_arithmetic.stflb}"
PROGRAM_PATH="/app/examples/${PROGRAM_NAME}"
ENTRY="${STOFFEL_ENTRY:-main}"
# One `<inputs>:<outputs>` pair per client slot, in slot order, matching the two
# client services: both read STOFFEL_CLIENT_INPUT_COUNT inputs, client0 takes
# STOFFEL_OUTPUTS outputs and client1 takes STOFFEL_CLIENT1_OUTPUTS.
CLIENT_SLOTS="${STOFFEL_CLIENT_SLOTS:-${STOFFEL_CLIENT_INPUT_COUNT:-1}:${STOFFEL_OUTPUTS:-1},${STOFFEL_CLIENT_INPUT_COUNT:-1}:${STOFFEL_CLIENT1_OUTPUTS:-0}}"

WORKLOAD_CONTAINERS=(
  stoffel-examples-coord-party0
  stoffel-examples-coord-party1
  stoffel-examples-coord-party2
  stoffel-examples-coord-party3
  stoffel-examples-coord-party4
  stoffel-examples-coord-client0
  stoffel-examples-coord-client1
)

compose() {
  STOFFEL_VM_DIR="$VM_DIR" \
  STOFFEL_COORDINATOR_CONTEXT="$COORDINATOR_CONTEXT" \
  STOFFEL_NETWORK_CONTEXT="$NETWORK_CONTEXT" \
  STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
  STOFFEL_EXECUTION_ID="${EXECUTION_ID:-}" \
    docker compose -f "$COMPOSE_FILE" "$@"
}

# The coordinator decides what runs, so it has to be listening before anything
# can ask it. It mints the execution identity and publishes the execution to
# every party; the clients are not on the node roster, so they are handed the
# identity it printed.
mint_execution() {
  compose up --build -d coordinator
  local deadline=$(( $(date +%s) + 120 ))
  until compose ps coordinator | grep -q healthy; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "The coordinator did not become healthy." >&2
      compose logs coordinator >&2 || true
      return 1
    fi
    sleep 2
  done

  local submitted
  submitted="$(compose run --rm --no-deps -T \
    --entrypoint /app/stoffel party0 \
    coord-ctl submit \
    --coordinator coordinator:31415 \
    --coord-cert /app/ids/server_cert.crt \
    --cert /app/ids/operator/cert.crt \
    --key /app/ids/operator/key.der \
    --program-file "$PROGRAM_PATH" \
    --entry "$ENTRY" \
    --client-slots "$CLIENT_SLOTS" \
    --open-admission)"
  EXECUTION_ID="$(awk '{print $1}' <<<"$submitted" | tr -d '\r')"
  if ! [[ "$EXECUTION_ID" =~ ^[0-9a-f]{64}$ ]]; then
    echo "The coordinator did not mint an execution: ${submitted}" >&2
    return 1
  fi
  echo "Coordinator minted execution ${EXECUTION_ID}"
}

cleanup() {
  compose down --remove-orphans -v >/dev/null 2>&1 || true
}

capture_logs() {
  compose logs --no-color coordinator party0 party1 party2 party3 party4 client0 client1
}

wait_for_workload_exit() {
  local start_ts
  start_ts="$(date +%s)"

  while true; do
    local all_exited=1
    local container
    for container in "${WORKLOAD_CONTAINERS[@]}"; do
      local state
      state="$(docker inspect -f '{{.State.Status}}' "$container")"
      if [ "$state" != "exited" ]; then
        all_exited=0
        break
      fi
    done

    if [ "$all_exited" -eq 1 ]; then
      return 0
    fi

    if (( "$(date +%s)" - start_ts >= WAIT_TIMEOUT_SECS )); then
      echo "Timed out after ${WAIT_TIMEOUT_SECS}s waiting for coordinator workload" >&2
      compose ps -a >&2 || true
      capture_logs >&2 || true
      return 1
    fi

    sleep 2
  done
}

assert_zero_exit_codes() {
  local container
  for container in "${WORKLOAD_CONTAINERS[@]}"; do
    local exit_code
    exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$container")"
    if [ "$exit_code" != "0" ]; then
      echo "Container ${container} exited with ${exit_code}" >&2
      return 1
    fi
  done
}

if [ ! -f "${OUT_DIR}/${PROGRAM_NAME}" ]; then
  echo "Compiled coordinator program not found in ${OUT_DIR}." >&2
  echo "Run examples/validate_examples.sh first." >&2
  exit 2
fi

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true
mint_execution
compose up --build -d
if ! wait_for_workload_exit; then
  capture_logs >&2 || true
  exit 1
fi
if ! assert_zero_exit_codes; then
  compose ps -a >&2 || true
  capture_logs >&2 || true
  exit 1
fi

logs="$(capture_logs)"
if ! grep -Fq "outputs: [${EXPECTED_OUTPUT}]" <<<"$logs"; then
  echo "Missing expected coordinator client output: outputs: [${EXPECTED_OUTPUT}]" >&2
  capture_logs >&2 || true
  exit 1
fi

echo "Coordinator client I/O example passed with outputs: [${EXPECTED_OUTPUT}]"
