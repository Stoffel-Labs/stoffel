#!/usr/bin/env bash
#
# WHAT THIS CHECKS, AND WHY IT IS NOT A CAMPAIGN.
#
# The six `docker/test-*.sh` suites are the only live evidence this repository
# has for the preprocessing-privacy work (design doc §9.1 stage V-0). Each one
# needs a five-party deployment and ten to forty minutes, so none of them can
# run on every pull request. That left every live assertion operator-run, and
# an operator-run assertion rots silently: nobody notices a suite that stopped
# resolving, a constant an assertion greps for that was renamed, or a compose
# override whose per-party volumes collapsed onto one name.
#
# This script is the part of that evidence which costs nothing to check. It
# starts no container and builds no image, and it needs no Docker DAEMON at all
# — only the `docker compose` CLI, whose `config` is client-side resolution.
# (Measured: the whole script passes with DOCKER_HOST pointed at a socket that
# does not exist.) So it belongs on the pull-request path where the campaigns
# cannot. It guards the WIRING, which is precisely the class of breakage that
# makes a campaign vacuous rather than red:
#
#   1. every shell file under docker/ still parses;
#   2. both Python drivers still compile;
#   3. every log-marker constant the suites grep for still reads back, and an
#      unknown constant still fails closed;
#   4. every condemned preprocessing prefix still reads back, likewise;
#   5. the canonical example count the all-examples campaign refuses to start
#      without still matches the catalog on disk;
#   6. every compose project this repository ships still resolves, each override
#      inside its merge — and each override still does NOT resolve alone, so an
#      override that silently became a whole project is noticed rather than
#      half-validated;
#   7. every preprocessing-bearing project still gives each party its own
#      DISTINCT volume at the store path, and gives no client and no coordinator
#      one. This is the structural fact that makes `--preproc-store` reachable
#      at all, and one volume shared by two parties is the exact configuration
#      `LmdbPreprocStore`'s owner record exists to refuse.
#
# What it does NOT check: anything that requires running the code. It cannot
# tell you a suite passes; it can only tell you a suite would still run and
# still assert what its comments claim. The campaigns remain the evidence —
# .github/workflows/docker-e2e.yml schedules them.
#
# Usage:  docker/check-harness-wiring.sh
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=docker/preproc-log-markers.sh
. "${ROOT_DIR}/docker/preproc-log-markers.sh"

failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=1
}

# Context values that only have to RESOLVE. `docker compose config` substitutes
# them and never reads them, so a placeholder is honest here: this script
# validates the project's shape, not an operator's checkout.
export STOFFEL_COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-/nonexistent/coordinator}"
export STOFFEL_NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-/nonexistent/networking}"
export STOFFEL_STANDING_POOL_ID="${STOFFEL_STANDING_POOL_ID:-1}"
export STOFFEL_STANDING_STATE_DIR="${STOFFEL_STANDING_STATE_DIR:-/nonexistent/state}"

echo "== 1. shell files parse =="
shell_count=0
for script in "${ROOT_DIR}"/docker/*.sh; do
    if bash -n "${script}"; then
        shell_count=$((shell_count + 1))
    else
        fail "$(basename "${script}") does not parse"
    fi
done
if (( shell_count == 0 )); then
    fail "no shell file was checked, so this step asserted nothing"
else
    echo "  ok: ${shell_count} shell file(s) parse"
fi

echo "== 2. Python drivers compile =="
for driver in acceptance.py all_examples.py; do
    if python3 -m py_compile "${ROOT_DIR}/docker/standing-concurrency/${driver}"; then
        echo "  ok: ${driver} compiles"
    else
        fail "${driver} does not compile"
    fi
done
# py_compile writes bytecode beside the source; the campaigns do not need it.
rm -rf "${ROOT_DIR}/docker/standing-concurrency/__pycache__"

echo "== 3. log-marker constants =="
for name in PREPROC_COMMIT_LOG_MARKER PREPROC_LOAD_LOG_MARKER PREPROC_PARTIAL_LOAD_LOG_MARKER; do
    if value="$(read_preproc_log_marker "${name}" "${ROOT_DIR}")"; then
        echo "  ok: ${name} = \"${value}\""
    else
        fail "${name} is not readable, so every assertion that greps for it is vacuous"
    fi
done
# The helper's whole value is that it stops a run. An unknown constant must not
# return an empty string and a zero status.
if read_preproc_log_marker NO_SUCH_MARKER_CONSTANT "${ROOT_DIR}" >/dev/null 2>&1; then
    fail "read_preproc_log_marker accepted an unknown constant; it must fail closed"
else
    echo "  ok: an unknown marker constant fails closed"
fi

echo "== 4. condemned preprocessing prefixes =="
if condemned="$(read_condemned_preproc_prefixes "${ROOT_DIR}")"; then
    echo "  ok: $(wc -l <<<"${condemned}" | tr -d ' ') condemned prefix(es): $(tr '\n' ' ' <<<"${condemned}")"
else
    fail "the condemned prefixes are not readable, so the one-shot suite's volume count is vacuous"
fi
# A prefix this binary still writes must never be condemned, or every healthy
# volume would be refused. The Rust side asserts this over every key the binary
# can produce (`the_condemned_prefixes_are_ones_this_binary_never_writes`);
# here it is enough that the extraction stayed scoped to the condemned enum.
if grep -Fqx "standing-preproc-generation-v1:" <<<"${condemned}"; then
    fail "a live blob namespace was read as condemned; the extraction lost its scope"
else
    echo "  ok: no live blob namespace was read as condemned"
fi

echo "== 5. canonical example count =="
declared="$(sed -n 's/^CANONICAL_EXAMPLE_COUNT = \([0-9]*\)$/\1/p' \
    "${ROOT_DIR}/docker/standing-concurrency/all_examples.py")"
# The same expression the campaign counts with (`examples_dir.rglob("main.stfl")`),
# so this agrees with it by construction rather than by coincidence.
actual="$(find "${ROOT_DIR}/crates/stoffel-lang/examples" -name main.stfl | wc -l | tr -d ' ')"
if [[ -z "${declared}" ]]; then
    fail "CANONICAL_EXAMPLE_COUNT is not readable from all_examples.py"
elif [[ "${declared}" != "${actual}" ]]; then
    fail "all_examples.py declares ${declared} canonical examples; the catalog holds ${actual}.
docker/test-standing-all-examples.sh refuses to start on a mismatch, so adding an
example means raising that constant in the same change."
else
    echo "  ok: ${actual} canonical examples, matching all_examples.py"
fi

echo "== 6. compose projects resolve =="
BASE_RESERVE_INDEX="docker-compose.coordinator.reserve-index.yml"
# Whole projects: each must resolve on its own.
WHOLE_PROJECTS=(
    docker-compose.yml
    docker-compose.avss.yml
    docker-compose.benchmark.yml
    "${BASE_RESERVE_INDEX}"
    docker-compose.standing-concurrency.yml
)
# Overrides: each must resolve ON TOP of its base, and must NOT resolve alone.
OVERRIDES=(
    docker-compose.coordinator.reserve-index.preproc.yml
    docker-compose.coordinator.reserve-index.oneshot-preproc.yml
)
for project in "${WHOLE_PROJECTS[@]}"; do
    if ( cd "${ROOT_DIR}" && docker compose -f "${project}" config -q >/dev/null 2>&1 ); then
        echo "  ok: ${project} resolves"
    else
        fail "${project} does not resolve:
$( cd "${ROOT_DIR}" && docker compose -f "${project}" config -q 2>&1 | head -5 )"
    fi
done
for override in "${OVERRIDES[@]}"; do
    if ( cd "${ROOT_DIR}" && docker compose -f "${BASE_RESERVE_INDEX}" -f "${override}" config -q >/dev/null 2>&1 ); then
        echo "  ok: ${BASE_RESERVE_INDEX} + ${override} resolves"
    else
        fail "${BASE_RESERVE_INDEX} + ${override} does not resolve:
$( cd "${ROOT_DIR}" && docker compose -f "${BASE_RESERVE_INDEX}" -f "${override}" config -q 2>&1 | head -5 )"
    fi
    if ( cd "${ROOT_DIR}" && docker compose -f "${override}" config -q >/dev/null 2>&1 ); then
        fail "${override} resolves alone. It is listed here as an override, so either it
gained a base of its own — move it to WHOLE_PROJECTS — or a service lost the
build context the base supplies and this step is validating half a project."
    else
        echo "  ok: ${override} does not resolve alone, as an override should not"
    fi
done

echo "== 7. per-party preprocessing volumes =="
# The store path is not spelled here: it is read out of the resolved project,
# from each party's own `--preproc-store` argument or `STOFFEL_PREPROC_STORE`.
# That makes this the invariant that actually matters — the volume is mounted
# where the party was told to look — rather than a second copy of the path that
# could drift from the first. The two preprocessing overrides already disagree
# about it (/var/lib/stoffel-preproc vs /var/lib/stoffel/preproc), so a
# hard-coded path would have validated one project and asserted nothing about
# the other.
assert_preproc_volumes() {
    local label="$1"
    shift
    local -a files=()
    local file
    for file in "$@"; do
        files+=(-f "${file}")
    done
    local report
    if ! report="$( cd "${ROOT_DIR}" \
        && docker compose "${files[@]}" config --format json 2>/dev/null \
        | LABEL="${label}" python3 -I -c '
import json, os, re, sys

label = os.environ["LABEL"]
project = json.load(sys.stdin)
services = project.get("services", {})
parties = sorted(name for name in services if name.startswith("party"))
if len(parties) != 5:
    sys.exit(f"{label}: expected five party services, found {parties}")


def store_path(service):
    """Where this service was told its preprocessing store lives, or None.

    Two shapes, because both ship. The standing projects hand the whole node
    invocation to `/bin/sh -ec` as one string, so `command` is a one-element
    list holding a script and the flag has to be found inside it; the one-shot
    override instead sets the entrypoint hook `STOFFEL_PREPROC_STORE`.
    """
    paths = set()
    command = service.get("command") or []
    if isinstance(command, str):
        command = [command]
    paths.update(re.findall(r"--preproc-store\s+(\S+)", "\n".join(command)))
    environment = service.get("environment") or {}
    if environment.get("STOFFEL_PREPROC_STORE"):
        paths.add(environment["STOFFEL_PREPROC_STORE"])
    if len(paths) > 1:
        sys.exit(
            f"{label}: a service names more than one preprocessing store: "
            f"{sorted(paths)}. The flag and the environment hook must agree, or "
            "the party reads one path while the volume is mounted at the other."
        )
    return paths.pop() if paths else None


sources = {}
for party in parties:
    service = services[party]
    path = store_path(service)
    if path is None:
        sys.exit(
            f"{label}: {party} names no preprocessing store, so it reaches none. "
            "A suite asserting on a store would assert on nothing."
        )
    mounted = [
        mount.get("source")
        for mount in service.get("volumes", [])
        if mount.get("target") == path
    ]
    if len(mounted) != 1:
        sys.exit(
            f"{label}: {party} was told its store is {path} but has "
            f"{len(mounted)} volume(s) mounted there, expected one. Material "
            "written to a container-local path does not survive the process, "
            "which is the whole subject of these suites."
        )
    sources[party] = mounted[0]

if len(set(sources.values())) != len(sources):
    sys.exit(
        f"{label}: parties share a preprocessing volume: {sources}. A volume is "
        "owned by one node and LmdbPreprocStore refuses a second claimant, so "
        "this deployment would refuse to start - and a YAML anchor replacing "
        "five per-party blocks with one is how it happens."
    )

party_paths = {store_path(services[party]) for party in parties}
for name, service in services.items():
    if name in sources:
        continue
    if store_path(service) is not None:
        sys.exit(f"{label}: {name} is not a party but names a preprocessing store")
    if any(
        mount.get("target") in party_paths
        for mount in service.get("volumes", [])
    ):
        sys.exit(
            f"{label}: {name} is not a party but mounts a volume where a party "
            "keeps its preprocessing"
        )

print(" ".join(f"{party}={sources[party]}" for party in parties))
' 2>&1 )"; then
        fail "${report:-${label}: the project did not resolve}"
        return
    fi
    echo "  ok: ${label} - ${report}"
}
assert_preproc_volumes "one-shot --preproc-store" \
    "${BASE_RESERVE_INDEX}" docker-compose.coordinator.reserve-index.oneshot-preproc.yml
assert_preproc_volumes "standing reserve-index" \
    "${BASE_RESERVE_INDEX}" docker-compose.coordinator.reserve-index.preproc.yml
assert_preproc_volumes "standing concurrency" \
    docker-compose.standing-concurrency.yml

if (( failed )); then
    echo "Harness wiring check FAILED." >&2
    exit 1
fi
echo "Harness wiring check passed."
