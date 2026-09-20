#!/usr/bin/env bash
set -euo pipefail

# Restart check for the reserve-index coordinator stack
# (docs/design/bootnode-elimination.md §9.F.2). The script keeps its name from
# when it checked that preprocessing material survived a restart; it now checks
# the opposite and what a restart must still give:
#
#   * no preprocessing material is persisted or loaded in either run — no
#     preprocessing item serves two executions (§9.C.9 part 4);
#   * both runs reveal client[0] - client[1] = -10 at every party;
#   * the second run's session instance_id differs from the first's, although
#     the roster, program and execution id are unchanged: the per-party epoch
#     store the override keeps on a named volume advanced (blocker B5).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
PREPROC_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.preproc.yml"
PROJECT_NAME="${PROJECT_NAME:-coordri-preproc}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-240}"
# TEMPORARY — docs/design/bootnode-elimination.md §9.F.5: the images build against the
# unpublished stoffel-mpc-coordinator 0.3.0, so the checkout must be named explicitly.
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:?set STOFFEL_COORDINATOR_CONTEXT (or STOFFEL_COORDINATOR_DIR) to the stoffel-mpc-coordinator 0.3.0 checkout until it is published}}"
# The node roster the stack's coordinator serves: the §9.B golden digest of the
# five certificates under ids/nodes. Every party and client is started with it as
# STOFFEL_EXPECT_ROSTER_DIGEST, so a coordinator serving any other roster is
# refused (docs/design/bootnode-elimination.md §9.D.2). Set it empty to skip.
EXPECT_ROSTER_DIGEST="${STOFFEL_EXPECT_ROSTER_DIGEST-da7fa2fee0f97aaef9e77aa8534a2be721fbaf3ab26a52b5c2fd560f41a8e00d}"
WORKLOAD_CONTAINERS=(
    stoffel-coord-party0
    stoffel-coord-party1
    stoffel-coord-party2
    stoffel-coord-party3
    stoffel-coord-party4
    stoffel-coord-client0
    stoffel-coord-client1
)

# Which topology this run exercises (docs/design/bootnode-elimination.md). There
# is one: the compose stack writes STOFFEL_PEERS as
# ${STOFFEL_PEERS-<the other four addresses>}, and clearing it no longer selects
# a second path — stoffel-run refuses an empty seed list by name. The banner
# stays because an overridden peer list is worth saying out loud in a result.
if [ -n "${STOFFEL_PEERS+set}" ] && [ -z "${STOFFEL_PEERS}" ]; then
    echo "ERROR: STOFFEL_PEERS is empty. The bootnode was removed; a party forms its" >&2
    echo "       session by dialing its peers, so the list cannot be cleared." >&2
    exit 2
fi
if [ -z "${STOFFEL_PEERS+set}" ]; then
    TOPOLOGY="roster mesh (compose default)"
else
    TOPOLOGY="roster mesh (STOFFEL_PEERS overridden)"
fi
echo "Topology: ${TOPOLOGY}"

compose() {
    STOFFEL_COORDINATOR_CONTEXT="${COORDINATOR_CONTEXT}" \
    STOFFEL_EXPECT_ROSTER_DIGEST="${EXPECT_ROSTER_DIGEST}" \
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

refute_log() {
    local haystack="$1"
    local needle="$2"
    local description="$3"

    if grep -Fq "${needle}" <<<"${haystack}"; then
        echo "Unexpected ${description}: ${needle}" >&2
        return 1
    fi
}

# Assert the run actually formed a mesh. Kept as a positive *and* a negative:
# the negative is what would catch a reintroduced bootstrap step, which every
# value assertion in this script would otherwise still pass.
assert_topology() {
    local logs="$1"
    require_log "${logs}" "forming a roster-pinned mesh" "mesh formation"
    # Membership is the coordinator's node roster, fetched once by every party
    # before it binds (docs/design/bootnode-elimination.md §9.D.1).
    require_log "${logs}" "serves 5 nodes (n=5, t=1, digest=" "coordinator node roster fetch"
    refute_log "${logs}" "connecting to bootnode" "bootnode registration"
}

# No container carries a roster of its own: every party's membership and every
# client's node legs are pinned to the node roster the pinned coordinator
# serves (docs/design/bootnode-elimination.md §9.D, §9.E.1), and stoffel-run
# refuses --roster by name.

# No preprocessing item serves two executions (§9.C.9 part 4): the override no
# longer sets STOFFEL_PREPROC_STORE (the entrypoint refuses it), so neither run
# may persist material and the second may not load any.
refute_preprocessing_reuse() {
    local logs="$1"
    local run="$2"
    refute_log "${logs}" "Persisted preprocessing material to store" "preprocessing persistence (${run})"
    refute_log "${logs}" "Loaded preprocessing material from store" "preprocessing load (${run})"
}

assert_every_party_returned() {
    local expected="$1"
    local party
    for party in party0 party1 party2 party3 party4; do
        if ! compose logs --no-color "${party}" | grep -Fq "Program returned: ${expected}"; then
            echo "Missing ${party}'s revealed result: Program returned: ${expected}" >&2
            return 1
        fi
    done
}

# Each party's session instance_id, one per line in party order, from the line
# stoffel-run prints once the mesh has agreed its session.
instance_ids() {
    local party
    local id
    for party in party0 party1 party2 party3 party4; do
        id="$(compose logs --no-color "${party}" \
            | sed -n 's/.*Session started: instance_id=\([^,]*\),.*/\1/p' | tail -n 1)"
        if [ -z "${id}" ]; then
            echo "Missing ${party}'s session start line" >&2
            return 1
        fi
        echo "${id}"
    done
}

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== First run =="
compose up --build -d
wait_for_workload_exit
assert_zero_exit_codes
first_logs="$(capture_logs)"
# client_sub_order sends neither client anything, so the value is the one every
# party reveals and prints (§9.D.7 step 12, §9.F.2).
assert_every_party_returned "-10"
refute_preprocessing_reuse "${first_logs}" "first run"
assert_topology "${first_logs}"
first_ids="$(instance_ids)"
if [ "$(sort -u <<<"${first_ids}" | wc -l | tr -d ' ')" != "1" ]; then
    echo "The parties did not agree one instance_id in the first run:" >&2
    echo "${first_ids}" >&2
    exit 1
fi

echo "== Second run over the same epoch volumes =="
compose down --remove-orphans
compose up --no-build -d
wait_for_workload_exit
assert_zero_exit_codes
second_logs="$(capture_logs)"
assert_every_party_returned "-10"
refute_preprocessing_reuse "${second_logs}" "second run"
assert_topology "${second_logs}"
second_ids="$(instance_ids)"
if [ "$(sort -u <<<"${second_ids}" | wc -l | tr -d ' ')" != "1" ]; then
    echo "The parties did not agree one instance_id in the second run:" >&2
    echo "${second_ids}" >&2
    exit 1
fi
# The restart is the point of this script. The roster, program and execution id
# are the same in both runs; only the persisted epoch (blocker B5), keyed by the
# roster digest, can make the second run's instance_id fresh.
if [ "$(head -n 1 <<<"${first_ids}")" = "$(head -n 1 <<<"${second_ids}")" ]; then
    echo "The second run reused the first run's instance_id $(head -n 1 <<<"${first_ids}"):" >&2
    echo "the epoch store did not advance across the restart." >&2
    exit 1
fi

echo "Coordinator restart test passed on ${TOPOLOGY}: no preprocessing reused, instance_id $(head -n 1 <<<"${first_ids}") -> $(head -n 1 <<<"${second_ids}")."
