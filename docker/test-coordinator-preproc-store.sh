#!/usr/bin/env bash
#
# WHAT THIS SCRIPT WITNESSES, AND WHAT IT DOES NOT.
#
# It is a LIVENESS check for persisted standing preprocessing: that five
# parties can generate a reservoir, come back after a `down`/`up` and reuse it
# instead of rebuilding, and recover when one party's volume is gone. Those are
# the three phases below, and they are what it asserts.
#
# It is NOT evidence for the privacy property "no preprocessing item ever
# serves two executions" (design doc §9.1 stage V-0, §C.9 part 4, finding S12),
# and it must not be cited as such. Two reasons, both measured:
#
#  1. It cannot reach the code the property is about. The overlay makes all
#     five parties `--standing-node`, and `preprocess()` routes a standing
#     engine into `preprocess_standing()` before it can reach
#     `persist_preproc` — the one-shot commit path where the reuse defect
#     lived. `assert_no_party_committed_from_a_live_execution` below pins that
#     premise rather than leaving it to be re-derived.
#
#  2. It is insensitive to the guard that does carry the property. With
#     `take_bundle_from_reservoir`'s compaction write-back removed — the
#     physical removal that makes a drawn item unavailable to the next
#     execution — phases 1 and 2 still pass here in full.
#
# An integration script cannot close that gap, because single use is a claim
# about item IDENTITY and identity is only observable inside the process. The
# only way to compare run 1's items with run 2's from outside would be to print
# share bytes to the container logs, which is the very disclosure the property
# exists to prevent. So the witnesses are unit tests, where the items are in
# hand: `material_one_execution_used_is_never_handed_to_a_later_execution`
# (HoneyBadger) and `client_masks_one_execution_used_are_never_handed_to_a_later_execution`
# (AVSS) for the cross-execution case,
# `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them` for
# two concurrent executions of one program on one node, and
# `two_executions_never_receive_the_same_reservoir_item_content` plus
# `a_standing_reservoir_never_hands_two_executions_the_same_item` for the draw.
# All of them run in CI under `cargo test --workspace --all-features`.
#
# The companion script is `docker/test-oneshot-preproc-store.sh`. It drives the
# same image with ONE-SHOT parties over a retained `--preproc-store` volume,
# which is the deployment that does reach `persist_preproc`, and it asserts the
# presence of the same commit marker this script asserts the absence of. It
# cannot witness V-0 either, for the same reason, but together the two pin both
# directions of the marker: one that a commit is greppable at all, the other
# that a standing party never emits one.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=docker/preproc-log-markers.sh
. "${ROOT_DIR}/docker/preproc-log-markers.sh"
# Read before anything is built: this assertion is an ABSENCE, so a marker the
# script cannot resolve has to stop the run here rather than let three phases
# pass while grepping for nothing.
COMMIT_MARKER="$(read_preproc_log_marker PREPROC_COMMIT_LOG_MARKER)"
BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
PREPROC_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.preproc.yml"
PROJECT_NAME="${PROJECT_NAME:-coordri-preproc}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-240}"
# No default: a sibling checkout is not necessarily the 0.3.0 the workspace
# requires, and a build context at another version is silently discarded by
# cargo rather than refused.
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:?Set STOFFEL_COORDINATOR_CONTEXT to a stoffel-mpc-coordinator 0.3.0 checkout}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
# Only the clients exit: the parties are standing nodes and run until the stack
# comes down, so waiting on them would hang forever.
WORKLOAD_CONTAINERS=(
    stoffel-coord-client0
    stoffel-coord-client1
)

compose() {
    STOFFEL_EXECUTION_ID="${EXECUTION_ID:-}" \
    STOFFEL_COORDINATOR_CONTEXT="${COORDINATOR_CONTEXT}" \
    STOFFEL_NETWORK_CONTEXT="${NETWORK_CONTEXT}" \
        docker compose \
        -p "${PROJECT_NAME}" \
        -f "${BASE_COMPOSE}" \
        -f "${PREPROC_COMPOSE}" \
        "$@"
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
            local status
            status="$(docker inspect -f '{{.State.Status}}' "${container}")"
            if [[ "${status}" != "exited" ]]; then
                all_exited=0
                break
            fi
        done

        if [[ "${all_exited}" == "1" ]]; then
            return 0
        fi

        if (( "$(date +%s)" - start_ts >= WAIT_TIMEOUT_SECS )); then
            echo "Timed out after ${WAIT_TIMEOUT_SECS}s waiting for workload containers to exit" >&2
            docker compose \
                -p "${PROJECT_NAME}" \
                -f "${BASE_COMPOSE}" \
                -f "${PREPROC_COMPOSE}" \
                ps -a >&2 || true
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
            capture_logs >&2 || true
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

require_log_count() {
    local haystack="$1"
    local needle="$2"
    local expected="$3"
    local description="$4"
    local actual
    actual="$(grep -Fc "${needle}" <<<"${haystack}" || true)"
    if (( actual < expected )); then
        echo "Missing ${description}: expected at least ${expected} occurrences of ${needle}, got ${actual}" >&2
        return 1
    fi
}

# A standing node reports an execution's progress against its identity —
# `[party N] execution <id> preparing|ready|completed|...` — rather than the
# one-shot runner's "Starting VM execution of 'main'". Asserting against the
# minted id is stricter than the line it replaces: it pins each party to THIS
# execution instead of to any VM run that happened to occur.
assert_all_parties_crossed_mpc_execution() {
    local run_label="$1"
    local party party_logs
    for party in party0 party1 party2 party3 party4; do
        party_logs="$(compose logs --no-color "${party}")"
        require_log \
            "${party_logs}" \
            "execution ${EXECUTION_ID} preparing" \
            "${run_label} ${party} execution published and prepared"
        require_log \
            "${party_logs}" \
            "execution ${EXECUTION_ID} completed" \
            "${run_label} ${party} execution completed"
    done
}


# Every party here is a standing node, and a standing engine never reaches
# `persist_preproc`: `preprocess()` hands it to `preprocess_standing()` first,
# and material it banks goes through an agreed `top_up_exact` BEFORE any
# execution is served from it. A party that logged a commit would therefore be
# banking material from inside a live execution, which is the shape of the
# defect §9.1 V-0 fixed — and it would also mean this script had quietly become
# a stack whose scope note above is false.
#
# Asserting the absence is deliberately weak, and that is the point: it pins
# this script's PREMISE, not the privacy property, which only the unit tests
# named above can witness.
#
# The phrase it greps for is NOT written here. `${COMMIT_MARKER}` is read out
# of crates/stoffel-vm/src/storage/preproc.rs, which both engines interpolate,
# so rewording the human half of either commit message cannot make this
# assertion vacuous and deleting the constant stops the run. An absence
# assertion cannot demonstrate its own sensitivity, so its positive control is
# `docker/test-oneshot-preproc-store.sh`, which asserts the PRESENCE of the
# same marker on the same image; the pair is jointly non-vacuous.
assert_no_party_committed_from_a_live_execution() {
    local run_label="$1"
    local logs="$2"

    if grep -Fq "${COMMIT_MARKER}" <<<"${logs}"; then
        echo "${run_label}: a standing party committed preprocessing material from inside a live execution:" >&2
        grep -F "${COMMIT_MARKER}" <<<"${logs}" >&2
        echo "Standing preprocessing is owned in memory and banked only by an agreed top-up (§9.1 V-0)." >&2
        return 1
    fi
}


# The coordinator decides what runs, so it has to be running before anything can
# ask it. It mints the execution identity and publishes the execution to every
# party; the clients are not on the node roster and are handed what it printed.
mint_execution() {
    compose up --build -d coordinator
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
    # Images are built BEFORE the first mint (see below): `compose run` writes
    # build progress to STDOUT, so a build triggered here would land inside
    # `submitted` and the id parse would read "#1" instead of the execution id.
    # (`compose run` has no --no-build flag, hence the ordering rather than a flag.)
    submitted="$(compose run --rm --no-deps -T \
        --entrypoint /app/stoffel-coord-ctl party0 \
        submit \
        --coordinator coordinator:31415 \
        --coord-cert /app/ids/server_cert.crt \
        --cert /app/ids/operator/cert.crt \
        --key /app/ids/operator/key.der \
        --program "${PROGRAM_ID}" \
        --entry "${STOFFEL_ENTRY:-main}" \
        --client-slots "${STOFFEL_CLIENT_SLOTS:-1:1,1:1}" \
        --client "0=/app/ids/clients/cert0.crt" \
        --client "1=/app/ids/clients/cert1.crt")"
    # Last non-empty line only: anything compose prints ahead of the id is noise.
    EXECUTION_ID="$(awk 'NF{last=$1} END{print last}' <<<"${submitted}" | tr -d '\r')"
    if ! [[ "${EXECUTION_ID}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "The coordinator did not mint an execution: ${submitted}" >&2
        return 1
    fi
    echo "Coordinator minted execution ${EXECUTION_ID}"
}

# Admission is PRE-REGISTERED, not open: a standing node refuses an open policy
# because it holds a program catalog, and an open policy would let any
# certificate holder bind a slot of a program it holds.
#
# Standing nodes resolve a program by content id out of a shared directory, so
# the operator submits `--program <id>` and never ships bytes. Deliver the
# artifact under that id before any node starts, because a node freezes its
# catalog at startup.
PROGRAMS_DIR="${STOFFEL_RESERVE_PROGRAMS_DIR:-${ROOT_DIR}/.reserve-index-state/programs}"
export STOFFEL_RESERVE_PROGRAMS_DIR="${PROGRAMS_DIR}"
HOST_PROGRAM="${STOFFEL_HOST_PROGRAM:-${ROOT_DIR}/crates/stoffel-vm/src/tests/binaries/client_sub_order.stflb}"
# Certificates only: a standing node parses every file in its client-cert dir,
# so ids/clients (which also holds the private keys) cannot be handed over.
CLIENT_CERTS_DIR="${STOFFEL_RESERVE_CLIENT_CERTS_DIR:-${ROOT_DIR}/.reserve-index-state/client-certs}"
export STOFFEL_RESERVE_CLIENT_CERTS_DIR="${CLIENT_CERTS_DIR}"

deliver_client_certificates() {
    mkdir -p "${CLIENT_CERTS_DIR}"
    rm -f "${CLIENT_CERTS_DIR}"/*.crt
    cp "${ROOT_DIR}"/ids/clients/*.crt "${CLIENT_CERTS_DIR}/"
    echo "Delivered $(ls -1 "${CLIENT_CERTS_DIR}" | wc -l | tr -d ' ') client certificate(s) to ${CLIENT_CERTS_DIR}"
}

deliver_program() {
    mkdir -p "${PROGRAMS_DIR}"
    local printed
    # `--print-program-id` writes the id on stdout; compose build progress goes
    # there too, so the images are built first and only the last id is taken.
    printed="$(compose run --rm --no-deps -T \
        --entrypoint /app/stoffel-run party0 \
        --print-program-id /app/programs/client_sub_order.stflb)"
    PROGRAM_ID="$(grep -oE '[0-9a-f]{64}' <<<"${printed}" | tail -1)"
    if [[ -z "${PROGRAM_ID}" ]]; then
        echo "Could not derive the program id: ${printed}" >&2
        return 1
    fi
    cp "${HOST_PROGRAM}" "${PROGRAMS_DIR}/${PROGRAM_ID}.stflb"
    echo "Delivered program ${PROGRAM_ID} to ${PROGRAMS_DIR}"
}

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== First run: build and persist preprocessing =="
# Build before the first mint, not as part of `up`: mint_execution runs a
# container, so it would otherwise trigger the build itself and mix progress
# into the output it parses. Progress goes to stderr so nothing captures it.
if [[ "${STOFFEL_SKIP_BUILD:-0}" != "1" ]]; then
    compose build >&2
fi
first_up_args=(--no-build)
deliver_client_certificates
deliver_program
mint_execution
export STOFFEL_EXECUTION_ID="${EXECUTION_ID}"
compose up "${first_up_args[@]}" -d
wait_for_workload_exit
assert_zero_exit_codes
first_logs="$(capture_logs)"
require_log "${first_logs}" "outputs: [-10]" "default subtraction output"
require_log_count "${first_logs}" "HB standing preprocessing agreement: action=Rebuild" 5 "fresh-volume rebuild agreement"
assert_no_party_committed_from_a_live_execution first-run "${first_logs}"
assert_all_parties_crossed_mpc_execution first-run

echo "== Second run: load preprocessing from LMDB =="
compose down --remove-orphans
# A fresh execution: an execution identity is single use, and the coordinator
# mints a new one for every submission.
mint_execution
export STOFFEL_EXECUTION_ID="${EXECUTION_ID}"
compose up --no-build -d
wait_for_workload_exit
assert_zero_exit_codes
second_logs="$(capture_logs)"
require_log "${second_logs}" "outputs: [-10]" "default subtraction output after load"
require_log_count "${second_logs}" "HB standing preprocessing agreement: action=" 5 "retained-volume preprocessing agreement"
if grep -Fq "HB standing preprocessing agreement: action=Rebuild" <<<"${second_logs}"; then
    echo "Matching retained stores unexpectedly selected a rebuild" >&2
    exit 1
fi
assert_no_party_committed_from_a_live_execution retained-run "${second_logs}"
assert_all_parties_crossed_mpc_execution retained-run

echo "== Third run: recover from one party's missing preprocessing volume =="
compose down --remove-orphans
docker volume rm "${PROJECT_NAME}_coordri-preproc-party2" >/dev/null
mint_execution
export STOFFEL_EXECUTION_ID="${EXECUTION_ID}"
compose up --no-build -d
wait_for_workload_exit
assert_zero_exit_codes
third_logs="$(capture_logs)"
require_log "${third_logs}" "outputs: [-10]" "default subtraction output after asymmetric recovery"
require_log_count "${third_logs}" "HB standing preprocessing agreement: action=Rebuild" 5 "asymmetric-volume rebuild agreement"
assert_no_party_committed_from_a_live_execution asymmetric-run "${third_logs}"
assert_all_parties_crossed_mpc_execution asymmetric-run

if grep -Eq 'RanShaError|BatchReconError|Preprocessing failed' <<<"${third_logs}"; then
    echo "Protocol failure detected after asymmetric preprocessing recovery" >&2
    exit 1
fi

echo "Coordinator preprocessing fresh/load/asymmetric-recovery test passed."
