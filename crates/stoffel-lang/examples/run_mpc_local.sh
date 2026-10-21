#!/usr/bin/env bash
set -euo pipefail

# Host-process MPC run of one compiled example: a coordinator and one
# `stoffel run-node` party per node, all on 127.0.0.1.
#
# The coordinator is the trusted party and decides what runs: this script asks
# it to run the example with `stoffel coord-ctl`, it mints the execution's
# identity, and it publishes that identity to every party. No party is given an
# identity and none invents one.
#
# Every party of a mesh takes its membership from a coordinator: the coordinator
# is the only roster authority, and `stoffel run-node` refuses `--peers` without
# `--off-chain-coord` (docs/design/bootnode-elimination.md section 9.D). The
# coordinator here is docker/coordinator-wrapper run as a host process — the
# only coordinator `main` this repository has, in its own Cargo workspace. It
# serves the node certificates below as the node roster; each party pins its
# certificate, fetches that roster once, and forms the mesh from it.
#
# `stoffel run --local` would start an in-process coordinator instead, but it
# requires every party to return the same value, and programs such as
# mpc_runtime_info deliberately return a per-party one. This script prints each
# party's own result.
#
# The identities are the committed development fixtures under ids/, and every
# listener binds 127.0.0.1 only.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VM_DIR="${STOFFEL_VM_DIR:-${WORKSPACE_DIR}}"
OUT_DIR="${STOFFEL_EXAMPLES_OUT:-${ROOT_DIR}/examples/dist}"
PROGRAM_NAME="${STOFFEL_PROGRAM_NAME:-mpc_runtime_info.stflb}"
ENTRY="${STOFFEL_ENTRY:-main}"
# The size of the coordinator's node roster, and its threshold. Each party
# passes the same pair as the expectation its served roster is checked against.
N_PARTIES="${STOFFEL_N_PARTIES:-5}"
THRESHOLD="${STOFFEL_THRESHOLD:-1}"
MPC_BACKEND="${STOFFEL_MPC_BACKEND:-honeybadger}"
MPC_CURVE="${STOFFEL_MPC_CURVE:-bls12-381}"
BASE_PORT="${STOFFEL_BASE_PORT:-19100}"
RPC_BASE_PORT="${STOFFEL_RPC_BASE_PORT:-$((BASE_PORT + 100))}"
COORD_PORT="${STOFFEL_COORD_PORT:-$((BASE_PORT + 99))}"
TIMEOUT_SECONDS="${STOFFEL_MPC_TIMEOUT_SECONDS:-90}"
IDS_DIR="${STOFFEL_IDS_DIR:-${VM_DIR}/ids}"
# A node roster has n >= 2t + 1 with t >= 1, so two parties cannot form one.
if [ "$N_PARTIES" -lt 3 ]; then
  echo "run_mpc_local.sh requires at least 3 parties (a node roster has n >= 2t + 1 with t >= 1); got STOFFEL_N_PARTIES=${N_PARTIES}" >&2
  exit 2
fi

NODE_CERTS=""
for ((party_id = 0; party_id < N_PARTIES; party_id++)); do
  cert="${IDS_DIR}/nodes/cert${party_id}.crt"
  key="${IDS_DIR}/nodes/key${party_id}.der"
  if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
    echo "Missing node identity for party ${party_id}: expected ${cert} and ${key}" >&2
    echo "Set STOFFEL_IDS_DIR, or lower STOFFEL_N_PARTIES to the number of shipped ids." >&2
    exit 2
  fi
  if [ -z "$NODE_CERTS" ]; then
    NODE_CERTS="$cert"
  else
    NODE_CERTS="${NODE_CERTS},${cert}"
  fi
done
COORD_CERT="${IDS_DIR}/server_cert.crt"
COORD_KEY="${IDS_DIR}/server_key.der"

# One binary: each party is `stoffel run-node`, and the operator's side of the
# coordinator's control plane is `stoffel coord-ctl`.
STOFFEL="${VM_DIR}/target/debug/stoffel"
if [ ! -x "$STOFFEL" ]; then
  echo "Building the stoffel CLI..."
  cargo build --quiet --manifest-path "${VM_DIR}/Cargo.toml" -p stoffel-cli --bin stoffel
fi
WRAPPER_DIR="${VM_DIR}/docker/coordinator-wrapper"
COORDINATOR="${WRAPPER_DIR}/target/debug/stoffel-coordinator-docker"
if [ ! -x "$COORDINATOR" ]; then
  echo "Building the coordinator wrapper..."
  cargo build --quiet --manifest-path "${WRAPPER_DIR}/Cargo.toml"
fi

PROGRAM="${OUT_DIR}/${PROGRAM_NAME}"
if [ ! -f "$PROGRAM" ]; then
  echo "Compiled program not found: ${PROGRAM}" >&2
  echo "Run examples/validate_examples.sh first." >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stoffel-mpc-local.XXXXXX")"
PIDS=""
COORD_PID=""

cleanup() {
  for pid in $PIDS $COORD_PID; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# The coordinator: the node roster, served and verified. It prints the digest
# every party could pin with --expect-roster-digest before anything connects.
echo "Starting coordinator on 127.0.0.1:${COORD_PORT}" >&2
"$COORDINATOR" \
  --bind-addr 127.0.0.1 \
  --port "$COORD_PORT" \
  --server-cert "$COORD_CERT" \
  --server-key "$COORD_KEY" \
  --node-roster "$NODE_CERTS" \
  --t "$THRESHOLD" \
  --operator-certs "${IDS_DIR}/operator/cert.crt" \
  >"${WORK_DIR}/coordinator.log" 2>&1 &
COORD_PID=$!

coord_deadline=$((SECONDS + 30))
until (exec 3<>"/dev/tcp/127.0.0.1/${COORD_PORT}") 2>/dev/null; do
  if ! kill -0 "$COORD_PID" >/dev/null 2>&1 || [ "$SECONDS" -ge "$coord_deadline" ]; then
    echo "The coordinator did not start listening on 127.0.0.1:${COORD_PORT}." >&2
    cat "${WORK_DIR}/coordinator.log" >&2
    exit 1
  fi
  sleep 0.2
done

# One submission, by the only identity the coordinator admits as an operator.
# The coordinator mints the execution's identity and publishes it to the roster;
# this script only needs to know that it succeeded.
echo "Submitting the execution to the coordinator" >&2
if ! SUBMITTED="$("$STOFFEL" coord-ctl submit \
  --coordinator "127.0.0.1:${COORD_PORT}" \
  --coord-cert "$COORD_CERT" \
  --cert "${IDS_DIR}/operator/cert.crt" \
  --key "${IDS_DIR}/operator/key.der" \
  --program-file "$PROGRAM" \
  --entry "$ENTRY" 2>"${WORK_DIR}/submit.log")"; then
  echo "The coordinator refused the submission." >&2
  cat "${WORK_DIR}/submit.log" >&2
  exit 1
fi
echo "Coordinator minted execution ${SUBMITTED%% *}" >&2

run_party() {
  local name="$1"
  shift
  echo "Starting ${name}: $*" >&2
  "$@" >"${WORK_DIR}/${name}.log" 2>&1 &
  PIDS="${PIDS} $!"
}

# Every other party's address. A pair is dialed from one end only, and which end
# is decided by a digest of the two certificates, so every party is given the
# full list rather than a guess at the covering half.
peers_for() {
  local self="$1"
  local list=""
  local party_id
  for ((party_id = 0; party_id < N_PARTIES; party_id++)); do
    [ "$party_id" -eq "$self" ] && continue
    if [ -z "$list" ]; then
      list="127.0.0.1:$((BASE_PORT + party_id))"
    else
      list="${list},127.0.0.1:$((BASE_PORT + party_id))"
    fi
  done
  echo "$list"
}

# All parties start at once. There is nothing for anyone to wait for: the mesh
# forms out of dials, and a party that is not up yet is simply redialed.
for ((party_id = 0; party_id < N_PARTIES; party_id++)); do
  party_port="$((BASE_PORT + party_id))"
  run_party "party${party_id}" \
    "$STOFFEL" run-node "$PROGRAM" "$ENTRY" \
    --party-id "$party_id" \
    --bind "127.0.0.1:${party_port}" \
    --peers "$(peers_for "$party_id")" \
    --n-parties "$N_PARTIES" \
    --threshold "$THRESHOLD" \
    --off-chain-coord "127.0.0.1:${COORD_PORT}" \
    --coord-cert "$COORD_CERT" \
    --rpc-bind "127.0.0.1:$((RPC_BASE_PORT + party_id))" \
    --cert "${IDS_DIR}/nodes/cert${party_id}.crt" \
    --key "${IDS_DIR}/nodes/key${party_id}.der" \
    --mpc-backend "$MPC_BACKEND" \
    --mpc-curve "$MPC_CURVE" \
    --local-store "${WORK_DIR}/party${party_id}.redb"
done

deadline=$((SECONDS + TIMEOUT_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  all_done=1

  for pid in $PIDS; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      all_done=0
    fi
  done

  if [ "$all_done" -eq 1 ]; then
    failed=0
    for pid in $PIDS; do
      if ! wait "$pid"; then
        failed=1
      fi
    done
    if [ "$failed" -ne 0 ]; then
      echo "One or more parties failed." >&2
      cat "${WORK_DIR}"/*.log >&2
      exit 1
    fi
    cat "${WORK_DIR}"/party*.log
    echo "Local MPC run complete."
    exit 0
  fi

  sleep 1
done

echo "Timed out waiting for local MPC run." >&2
cat "${WORK_DIR}"/*.log >&2
exit 1
