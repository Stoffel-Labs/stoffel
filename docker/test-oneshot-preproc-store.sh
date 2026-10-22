#!/usr/bin/env bash
#
# WHAT THIS SCRIPT WITNESSES, AND WHAT IT DOES NOT.
#
# It drives the ONE-SHOT `--preproc-store` deployment: five one-shot parties,
# each with a named LMDB preprocessing volume that survives a `down`, across
# two sequential coordinator-minted executions. That is the only deployment
# that reaches `persist_preproc` — the commit path where the preprocessing
# reuse defect lived (design doc §9.1 stage V-0, §C.9 part 4, finding S12) —
# and until this script existed nothing in `docker/` or CI exercised it. Its
# sibling `docker/test-coordinator-preproc-store.sh` makes the parties STANDING
# and therefore cannot reach it at all; that script asserts the ABSENCE of a
# commit, and this one asserts the PRESENCE of the same marker on the same
# image, so the pair pins both directions.
#
# What it asserts:
#
#   1. Run 1 commits into a volume it found empty: the commit marker on every
#      party, and the load marker nowhere. Without the second half the third
#      assertion would be meaningless.
#   2. Run 2 draws what run 1 banked: the load marker on every party.
#   3. Run 2 finds that draw INSUFFICIENT and generates the shortfall. This is
#      the one assertion here that is more than liveness. Under the copy
#      semantics the fix replaced, run 1 banked its whole pool — including the
#      material it went on to use — so run 2's load covered its targets and
#      this line could not be emitted. It is a count comparison the engine
#      prints itself; no share byte is ever logged.
#   4. Both runs complete: no `NotEnoughPreprocessing`, every container exit 0,
#      the multiply reached and a share returned.
#   5. Neither run leaves a record under a CONDEMNED key prefix in the
#      preprocessing volume. It began as a check on one known writer — a
#      mask-index cursor the node persisted beside the mask shares — and that
#      writer is now gone along with its namespace, so what it still measures
#      is that nothing in the whole deployed binary writes a prefix this binary
#      is supposed to never write. It no longer stands alone either: a claimed
#      volume holding such a record is refused on open, so run 2 reopening run
#      1's volume at all is an independent fail-closed witness. The prefixes are
#      read out of `CondemnedNamespace`, not spelled in this script, so the set
#      cannot grow past the assertion again. It counts a key prefix; it reads no
#      share.
#
# What it CANNOT witness, and must not be cited for: "no preprocessing item
# ever serves two executions". That is a claim about item IDENTITY, and
# identity is observable only inside the process. Comparing run 1's items with
# run 2's from out here would mean printing share bytes to the container logs,
# which is the very disclosure the property exists to prevent. The witnesses
# are unit tests, where the items are in hand:
# `material_one_execution_used_is_never_handed_to_a_later_execution`
# (HoneyBadger) and
# `client_masks_one_execution_used_are_never_handed_to_a_later_execution`
# (AVSS) for the cross-execution case,
# `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`
# for two concurrent executions on one node, and
# `two_executions_never_receive_the_same_reservoir_item_content` plus
# `a_standing_reservoir_never_hands_two_executions_the_same_item` for the draw.
# All of them run in CI under `cargo test --workspace --all-features`.
#
# Usage:
#   STOFFEL_COORDINATOR_CONTEXT=/abs/path/to/stoffel-mpc-coordinator \
#   STOFFEL_NETWORK_CONTEXT=/abs/path/to/stoffel-networking \
#     docker/test-oneshot-preproc-store.sh
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=docker/preproc-log-markers.sh
. "${ROOT_DIR}/docker/preproc-log-markers.sh"
# Read before anything is built. These are the phrases every assertion below
# turns on, and they are not written here: they are read out of
# crates/stoffel-vm/src/storage/preproc.rs, which both engines interpolate. So
# rewording the human half of a message cannot make an assertion vacuous, and a
# renamed or deleted constant stops the run instead.
COMMIT_MARKER="$(read_preproc_log_marker PREPROC_COMMIT_LOG_MARKER)"
LOAD_MARKER="$(read_preproc_log_marker PREPROC_LOAD_LOG_MARKER)"
PARTIAL_LOAD_MARKER="$(read_preproc_log_marker PREPROC_PARTIAL_LOAD_LOG_MARKER)"
# The byte prefixes a volume is refused for holding, read from the same file for
# the same reason. This set is not a constant here because it has already grown
# once: `rsv:` joined `pp:` when the reservation registry stopped reaching disk.
CONDEMNED_PREFIXES="$(read_condemned_preproc_prefixes)"

BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
ONESHOT_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.oneshot-preproc.yml"
PROJECT_NAME="${PROJECT_NAME:-oneshot-preproc}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-300}"
# The only shipped program whose preprocessing targets include a Beaver triple;
# see the overlay's header for why that is a requirement and not a preference.
PROGRAM="${STOFFEL_PROGRAM:-/app/programs/client_mul.stflb}"
# No default: a sibling checkout is not necessarily the 0.3.0 the workspace
# requires, and a build context at another version is silently discarded by
# cargo rather than refused.
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:?Set STOFFEL_COORDINATOR_CONTEXT to a stoffel-mpc-coordinator 0.3.0 checkout}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
# Every container exits here, parties included: these are one-shot processes,
# unlike the standing override's.
WORKLOAD_CONTAINERS=(
    stoffel-coord-party0
    stoffel-coord-party1
    stoffel-coord-party2
    stoffel-coord-party3
    stoffel-coord-party4
    stoffel-coord-client0
    stoffel-coord-client1
)
PARTY_COUNT=5

compose() {
    STOFFEL_EXECUTION_ID="${EXECUTION_ID:-}" \
    STOFFEL_COORDINATOR_CONTEXT="${COORDINATOR_CONTEXT}" \
    STOFFEL_NETWORK_CONTEXT="${NETWORK_CONTEXT}" \
        docker compose \
        -p "${PROJECT_NAME}" \
        -f "${BASE_COMPOSE}" \
        -f "${ONESHOT_COMPOSE}" \
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
            status="$(docker inspect -f '{{.State.Status}}' "${container}" 2>/dev/null || echo missing)"
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
            capture_logs >&2 || true
            return 1
        fi
    done
}

capture_logs() {
    compose logs --no-color coordinator party0 party1 party2 party3 party4 client0 client1
}

# Each engine message reaches the container logs twice — `eprintln!` and
# `tracing::info!`, so that an operator's RUST_LOG cannot silence an assertion
# — so a per-party count is a FLOOR, never an equality.
require_log_count() {
    local haystack="$1"
    local needle="$2"
    local expected="$3"
    local description="$4"
    local actual
    actual="$(grep -Fc "${needle}" <<<"${haystack}" || true)"
    if (( actual < expected )); then
        echo "Missing ${description}: expected at least ${expected} occurrences of \"${needle}\", got ${actual}" >&2
        return 1
    fi
    echo "  ok: ${description} (${actual} line(s) matching \"${needle}\")"
}

refute_log() {
    local haystack="$1"
    local needle="$2"
    local description="$3"
    if grep -Fq "${needle}" <<<"${haystack}"; then
        echo "Unexpected ${description}:" >&2
        grep -F "${needle}" <<<"${haystack}" | head -5 >&2
        return 1
    fi
    echo "  ok: no ${description}"
}

# No record under a CONDEMNED key prefix may appear in a preprocessing volume.
#
# The subject of this assertion changed under it, which is worth stating rather
# than leaving a reader to infer. It began as a check on one known writer: the
# node-side masked-input registry persisted a mask-index cursor into the very
# volume holding the mask shares, and when that writer was deleted as
# unreachable the deletion rested on a call-graph argument, so this measured it.
# The registry now has no path to disk at all and the `rsv:` namespace is gone
# with it, so there is no writer left to catch. What this still measures is
# narrower and real: that nothing in the WHOLE DEPLOYED BINARY — entrypoint,
# runner, engines, store — leaves a record under a prefix this binary is
# supposed to never write. The unit tests
# `a_standing_engine_writes_nothing_into_the_volume_holding_its_preprocessing`
# and `the_condemned_prefixes_are_ones_this_binary_never_writes` drive one
# engine in process; this covers the deployment.
#
# Two mechanisms, because one of them is not sound for every prefix.
#
#   * THE GREP, below, for prefixes of at least four bytes. A k-byte needle
#     matches uniformly distributed bytes about once every 2^(8k) bytes, and
#     these volumes are tens to hundreds of kilobytes of serialized field
#     elements. At k=4 that is roughly one chance match in 10^5 per party per
#     run; at k=3 it is roughly one in 200, which over five parties and two
#     runs would make a nightly campaign fail for no reason. So a three-byte
#     prefix is reported and delegated rather than asserted on — the
#     alternative is a flaky assertion, which is worse than none.
#   * THE REFUSAL, which is exact and covers every prefix however short. A
#     claimed volume holding a condemned record is refused on open, so run 2
#     reopening run 1's volume at all is a fail-closed witness: if run 1 had
#     written one, run 2's parties would not have started and the run-2 load
#     assertion above could not have passed. That assertion is therefore doing
#     double duty, and this comment is where it is written down.
#
# The prefixes are read out of `CondemnedNamespace`, not spelled here, so the
# set cannot grow past this assertion again — it already grew once, when `rsv:`
# joined `pp:`. It counts a key prefix and reads nothing else, so it discloses
# no share.
assert_no_condemned_records() {
    local run_label="$1"
    local party prefix found counted=() delegated=()
    while IFS= read -r prefix; do
        [[ -n "${prefix}" ]] || continue
        if (( ${#prefix} >= 4 )); then
            counted+=("${prefix}")
        else
            delegated+=("${prefix}")
        fi
    done <<<"${CONDEMNED_PREFIXES}"
    if (( ${#counted[@]} == 0 )); then
        echo "${run_label}: no condemned prefix is long enough to count, so this" >&2
        echo "assertion would measure nothing. Rely on the refusal and say so, or" >&2
        echo "find a sound way to count a short prefix." >&2
        return 1
    fi
    for party in party0 party1 party2 party3 party4; do
        for prefix in "${counted[@]}"; do
            found="$(compose run --rm --no-deps -T --entrypoint /bin/sh "${party}" -c \
                "if [ -f /var/lib/stoffel-preproc/data.mdb ]; then grep -ac '${prefix}' /var/lib/stoffel-preproc/data.mdb || true; else echo missing; fi" \
                | tr -d '\r' | tail -1)"
            if [[ "${found}" == "missing" ]]; then
                echo "${run_label}: ${party} has no preprocessing volume to inspect" >&2
                return 1
            fi
            if [[ "${found}" != "0" ]]; then
                echo "${run_label}: ${party}'s preprocessing volume holds ${found} record(s) under the condemned prefix '${prefix}'." >&2
                echo "This binary writes no such record, so the volume predates the division" >&2
                echo "or another writer reached it. A node refuses such a volume on open." >&2
                return 1
            fi
        done
    done
    echo "  ok: no condemned record in any party's preprocessing volume (counted: ${counted[*]}${delegated[0]+; left to the open-time refusal: ${delegated[*]}})"
}

# The coordinator decides what runs, so it has to be running before anything
# can ask it. It mints the execution identity and publishes the execution to
# every party; the clients are not on the node roster, so they are handed the
# identity it printed. Open admission is legal here: only a STANDING node
# refuses it, because only a standing node holds a program catalog.
mint_execution() {
    compose up --no-build -d coordinator
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
        --program-file "${PROGRAM}" \
        --entry "${STOFFEL_ENTRY:-main}" \
        --client-slots "${STOFFEL_CLIENT_SLOTS:-1:1,1:1}" \
        --open-admission)"
    # Last non-empty line only: anything compose prints ahead of the id is
    # noise. Images are built before the first mint for the same reason.
    EXECUTION_ID="$(awk 'NF{last=$1} END{print last}' <<<"${submitted}" | tr -d '\r')"
    if ! [[ "${EXECUTION_ID}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "The coordinator did not mint an execution: ${submitted}" >&2
        return 1
    fi
    echo "Coordinator minted execution ${EXECUTION_ID}"
}

run_execution() {
    mint_execution
    export STOFFEL_EXECUTION_ID="${EXECUTION_ID}"
    compose up --no-build -d
    wait_for_workload_exit
    assert_zero_exit_codes
}

# Both runs must get this far, whatever the store held: a campaign where the
# program never ran cannot say anything about the material it would have used.
assert_execution_did_the_work() {
    local run_label="$1"
    local logs="$2"
    refute_log "${logs}" "NotEnoughPreprocessing" "${run_label} under-provisioned execution"
    require_log_count "${logs}" "Multiplication completed at node" "${PARTY_COUNT}" \
        "${run_label} multiply on every party"
    require_log_count "${logs}" "Program returned: share:v1[secret-int:64" "${PARTY_COUNT}" \
        "${run_label} secret-shared result on every party"
}

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== Run 1: one-shot parties commit the surplus of a fresh volume =="
# Build before the first mint, with progress on stderr: `compose run` writes
# build progress to STDOUT, so a build triggered by the mint would land inside
# what it parses and the id regex would read "#1" instead of an execution id.
if [[ "${STOFFEL_SKIP_BUILD:-0}" != "1" ]]; then
    compose build >&2
fi
run_execution
first_logs="$(capture_logs)"
require_log_count "${first_logs}" "${COMMIT_MARKER}" "${PARTY_COUNT}" \
    "run-1 commit on every party"
# The volumes were created by the `down -v` above, so nothing could be loaded.
# This is what makes run 2's load, and the shortfall it reveals, mean anything.
refute_log "${first_logs}" "${LOAD_MARKER}" "run-1 load from a volume that was created empty"
assert_execution_did_the_work run-1 "${first_logs}"
assert_no_condemned_records run-1

echo "== Run 2: a second process draws what run 1 banked, and finds it short =="
# `down` WITHOUT `-v`: the volumes are the experiment. A fresh execution
# identity, because an identity is single use.
compose down --remove-orphans
run_execution
second_logs="$(capture_logs)"
require_log_count "${second_logs}" "${LOAD_MARKER}" "${PARTY_COUNT}" \
    "run-2 load on every party"
# THE ASSERTION THAT IS MORE THAN LIVENESS.
#
# Measured on this stack at n=5, t=1 with client_mul.stflb: run 1 banks
# {beaver: 0, random: 2} — everything above the targets it declared — and run 2
# needs {beaver: 3, random: 4}, so `held.covers(targets)` is false and the
# engine says so. Replace the commit's `split_off` division with a copy and run
# 1 banks its whole generated pool instead, run 2's load covers its targets,
# and this line is never emitted. Those exact numbers depend on how
# `plan_preprocessing` bands targets up: if they change, this assertion needs
# re-measuring, not deleting — what it pins is that a banked surplus is
# strictly smaller than a generated pool.
if ! require_log_count "${second_logs}" "${PARTIAL_LOAD_MARKER}" "${PARTY_COUNT}" \
    "run-2 partial load, i.e. a banked surplus that is smaller than a pool"; then
    # What run 2 actually drew, so a maintainer can tell "the guard is gone"
    # from "the banding changed and the numbers need re-measuring". No share
    # byte is in these lines; they carry counts only.
    echo "What run 2 loaded instead:" >&2
    { grep -F "${LOAD_MARKER}" <<<"${second_logs}" | sort -u || true; } | head -5 >&2
    exit 1
fi
# Print what it measured, not just that it matched: the counts above are the
# evidence for "a banked surplus is strictly smaller than a generated pool",
# and a maintainer re-measuring the comment's numbers should not have to
# instrument the script to see them.
# `|| true` because this is a report, not an assertion, and the pipeline runs
# under `pipefail` where `head` closing the pipe early would otherwise abort a
# run that has already passed.
measured="$(grep -o "${PARTIAL_LOAD_MARKER} ([^)]*)" <<<"${second_logs}" | sort -u || true)"
sed -n '1,2p' <<<"${measured}" | sed 's/^/      measured: /'
assert_execution_did_the_work run-2 "${second_logs}"
assert_no_condemned_records run-2

echo "One-shot --preproc-store commit/load test passed."
