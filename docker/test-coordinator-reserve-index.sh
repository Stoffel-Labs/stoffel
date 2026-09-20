#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-240}"
COMPOSE_BUILD_FLAG="${COMPOSE_BUILD_FLAG:---build}"
# client[0] - client[1] with the default inputs 15 and 25. The documented swap
# STOFFEL_CLIENT0_SLOT=1 STOFFEL_CLIENT1_SLOT=0 flips it to 10.
EXPECTED_OUTPUT="${EXPECTED_OUTPUT:--10}"
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

# The stack registers its client slots under open admission, so no client
# identity is configured anywhere and the clients bind their slots at runtime.
assert_open_admission() {
    local logs="$1"
    require_log "${logs}" "(open admission)" "open-admission registration"
}

# The coordinator is the only roster authority and the only place a client is
# admitted, so no party holds another node's certificate or any client's, and
# no container holds a key but its own (docs/design/bootnode-elimination.md
# §9.F.0, decision 3 of §9). Checked on the containers as they ran, from the
# identity files compose actually mounted.
assert_identity_mounts() {
    local service="$1"
    shift
    local container="$1"
    shift
    local allowed=("$@")
    local destination
    local found
    while IFS= read -r destination; do
        case "${destination}" in
            /app/ids/*|/run/secrets/*) ;;
            *) continue ;;
        esac
        found=0
        local entry
        for entry in "${allowed[@]}"; do
            if [[ "${destination}" == "${entry}" ]]; then
                found=1
                break
            fi
        done
        if [[ "${found}" != "1" ]]; then
            echo "${service} (${container}) holds identity material it must not: ${destination}" >&2
            return 1
        fi
    done < <(docker inspect -f '{{range .Mounts}}{{println .Destination}}{{end}}' "${container}")
}

assert_no_foreign_identity() {
    local index
    for index in 0 1 2 3 4; do
        assert_identity_mounts "party${index}" "stoffel-coord-party${index}" \
            /app/ids/server_cert.crt \
            "/app/ids/nodes/cert${index}.crt" \
            "/run/secrets/node${index}_key"
    done
    for index in 0 1; do
        assert_identity_mounts "client${index}" "stoffel-coord-client${index}" \
            /app/ids/server_cert.crt \
            "/app/ids/clients/cert${index}.crt" \
            "/run/secrets/client${index}_key"
    done
    # Open admission: the coordinator is told no client certificate either.
    assert_identity_mounts coordinator stoffel-coordinator-reserve-index \
        /app/ids/server_cert.crt \
        /app/ids/nodes/cert0.crt /app/ids/nodes/cert1.crt /app/ids/nodes/cert2.crt \
        /app/ids/nodes/cert3.crt /app/ids/nodes/cert4.crt \
        /run/secrets/coordinator_key
}

# The coordinator served the roster the parties and clients expected: its own
# startup line, and — since every container passed --expect-roster-digest — no
# container refused it.
assert_served_roster() {
    local logs="$1"
    require_log "${logs}" "Serving node roster n=5, t=1, digest=" "coordinator roster announcement"
    if [ -n "${EXPECT_ROSTER_DIGEST}" ]; then
        require_log "${logs}" "digest=${EXPECT_ROSTER_DIGEST}" "the expected roster digest"
    fi
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

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true
compose up "${COMPOSE_BUILD_FLAG}" -d
wait_for_workload_exit
assert_zero_exit_codes

logs="$(capture_logs)"
# client_sub_order sends neither client anything, so its slots are input-only
# and the value is the one every party reveals and prints
# (docs/design/bootnode-elimination.md §9.D.7 step 12, §9.F.2).
assert_every_party_returned "${EXPECTED_OUTPUT}"
assert_topology "${logs}"
assert_open_admission "${logs}"
assert_served_roster "${logs}"
assert_no_foreign_identity

echo "Coordinator reserve-index test passed on ${TOPOLOGY}: every party returned ${EXPECTED_OUTPUT}"
