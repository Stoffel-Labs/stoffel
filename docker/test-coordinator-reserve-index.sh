#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-240}"
COMPOSE_BUILD_FLAG="${COMPOSE_BUILD_FLAG:---build}"
EXPECTED_OUTPUT="${EXPECTED_OUTPUT:--10}"
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:?Set STOFFEL_COORDINATOR_CONTEXT to a stoffel-mpc-coordinator 0.3.0 checkout}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
WORKLOAD_CONTAINERS=(
    stoffel-coord-party0
    stoffel-coord-party1
    stoffel-coord-party2
    stoffel-coord-party3
    stoffel-coord-party4
    stoffel-coord-client0
    stoffel-coord-client1
)

compose() {
    STOFFEL_EXECUTION_ID="${EXECUTION_ID:-}" \
    STOFFEL_COORDINATOR_CONTEXT="${COORDINATOR_CONTEXT}" \
    STOFFEL_NETWORK_CONTEXT="${NETWORK_CONTEXT}" \
        docker compose -f "${BASE_COMPOSE}" "$@"
}

cleanup() {
    compose down --remove-orphans -v >/dev/null 2>&1 || true
}

wait_for_workload_exit() {
    local start_ts
    start_ts="$(date +%s)"

    while true; do
        local all_exited=1
        local container
        for container in "${WORKLOAD_CONTAINERS[@]}"; do
            local state
            state="$(docker inspect -f '{{.State.Status}}' "${container}")"
            if [[ "${state}" != "exited" ]]; then
                all_exited=0
                break
            fi
        done

        if [[ "${all_exited}" == "1" ]]; then
            return 0
        fi

        if (( "$(date +%s)" - start_ts >= WAIT_TIMEOUT_SECS )); then
            echo "Timed out after ${WAIT_TIMEOUT_SECS}s waiting for workload containers to exit" >&2
            compose ps -a >&2 || true
            capture_logs >&2 || true
            return 1
        fi

        sleep 2
    done
}

assert_zero_exit_codes() {
    local container
    local exit_code
    for container in "${WORKLOAD_CONTAINERS[@]}"; do
        exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${container}")"
        if [[ "${exit_code}" != "0" ]]; then
            echo "Container ${container} exited with ${exit_code}" >&2
            return 1
        fi
    done
}

capture_logs() {
    compose logs --no-color coordinator party0 party1 party2 party3 party4 client0 client1
}

require_log() {
    local haystack="$1"
    local needle="$2"
    local description="$3"

    if ! grep -Fq "${needle}" <<<"${haystack}"; then
        echo "Missing ${description}: ${needle}" >&2
        return 1
    fi
}


# The coordinator decides what runs, so it has to be running before anything
# can ask it. It mints the execution identity and publishes the execution to
# every party; the clients are not on the node roster, so they are handed the
# identity it printed.
mint_execution() {
    local program="$1"
    local entry="$2"
    local slots="$3"
    shift 3

    compose up "${COMPOSE_BUILD_FLAG:---build}" -d coordinator
    local deadline=$(( $(date +%s) + 120 ))
    until compose ps coordinator | grep -q healthy; do
        if [ "$(date +%s)" -ge "${deadline}" ]; then
            echo "The coordinator did not become healthy." >&2
            compose logs coordinator >&2
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
        --program-file "${program}" \
        --entry "${entry}" \
        --client-slots "${slots}" \
        "$@")"
    # Last non-empty line only: `compose run` writes build progress to STDOUT, so
    # anything printed ahead of the id is noise. Images are built before the mint.
    EXECUTION_ID="$(awk 'NF{last=$1} END{print last}' <<<"${submitted}" | tr -d '\r')"
    if ! [[ "${EXECUTION_ID}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "The coordinator did not mint an execution: ${submitted}" >&2
        return 1
    fi
    echo "Coordinator minted execution ${EXECUTION_ID}"
}

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true
# Build before minting, with progress on stderr: mint_execution runs a container,
# so it would otherwise trigger the build and mix progress into what it parses.
if [[ "${COMPOSE_BUILD_FLAG}" == "--build" ]]; then
    compose build >&2
    COMPOSE_BUILD_FLAG="--no-build"
fi
mint_execution \
    "${STOFFEL_PROGRAM:-/app/programs/client_sub_order.stflb}" \
    "${STOFFEL_ENTRY:-main}" \
    "${STOFFEL_CLIENT_SLOTS:-1:1,1:1}" \
    --open-admission
export STOFFEL_EXECUTION_ID="${EXECUTION_ID}"
compose up "${COMPOSE_BUILD_FLAG}" -d
wait_for_workload_exit
assert_zero_exit_codes

logs="$(capture_logs)"
require_log "${logs}" "outputs: [${EXPECTED_OUTPUT}]" "expected coordinator client output"

echo "Coordinator reserve-index test passed with outputs: [${EXPECTED_OUTPUT}]"
