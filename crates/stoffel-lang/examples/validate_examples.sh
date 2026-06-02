#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="${ROOT_DIR}/examples"
WORKSPACE_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VM_DIR="${STOFFEL_VM_DIR:-${WORKSPACE_DIR}}"
COORDINATOR_DIR="${STOFFEL_COORDINATOR_DIR:-/Users/gabriel/RustroverProjects/stoffel-mpc-coordinator}"
NETWORK_DIR="${STOFFEL_NETWORK_DIR:-/Users/gabriel/RustroverProjects/stoffel-network}"
OUT_DIR="${STOFFEL_EXAMPLES_OUT:-${EXAMPLES_DIR}/dist}"
RUN_DOCKER_MPC=0
RUN_HOST_MPC=0

for arg in "$@"; do
  case "$arg" in
    --docker-mpc)
      RUN_DOCKER_MPC=1
      ;;
    --host-mpc)
      RUN_HOST_MPC=1
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: examples/validate_examples.sh [--docker-mpc] [--host-mpc]

Compiles every examples/**/main.stfl program to examples/dist.
Runs local-only examples through StoffelVM.
Optionally runs an MPC smoke test either through Docker Compose or through
five local StoffelVM host processes.

Environment:
  STOFFEL_VM_DIR          VM checkout path
  STOFFEL_COORDINATOR_DIR Coordinator checkout path used as Docker build context
  STOFFEL_NETWORK_DIR     Networking checkout path used as Docker build context
  STOFFEL_EXAMPLES_OUT   Output directory for .stflb files
  STOFFEL_PROGRAM_NAME   Compiled binary to run in docker compose
  STOFFEL_MPC_BACKEND    honeybadger or avss
  STOFFEL_MPC_CURVE      bls12-381, secp256k1, p-256, etc.
USAGE
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [ ! -d "$VM_DIR" ]; then
  echo "VM checkout not found: $VM_DIR" >&2
  exit 2
fi
if [ ! -d "$NETWORK_DIR" ]; then
  echo "Networking checkout not found: $NETWORK_DIR" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

echo "Building Stoffel compiler..."
cargo build --quiet --manifest-path "${ROOT_DIR}/Cargo.toml"
COMPILER="${ROOT_DIR}/target/debug/stoffellang"

echo "Compiling examples into ${OUT_DIR}..."
find "$EXAMPLES_DIR" -path "$OUT_DIR" -prune -o -name main.stfl -print | sort | while read -r source; do
  rel="${source#${EXAMPLES_DIR}/}"
  rel_dir="$(dirname "$rel")"
  binary_name="$(printf '%s' "$rel_dir" | tr '/ ' '__').stflb"
  output="${OUT_DIR}/${binary_name}"
  mpc_backend="honeybadger"
  case "$rel_dir" in
    avss_certificate/*|threshold_signatures/threshold_ecdsa_p256|threshold_signatures/threshold_ecdsa_secp256k1|threshold_signatures/threshold_schnorr_ed25519|threshold_signatures/threshold_eddsa_ed25519)
      mpc_backend="avss"
      ;;
  esac
  echo "  ${rel} -> ${binary_name} (${mpc_backend})"
  "$COMPILER" -b --mpc-backend "$mpc_backend" -o "$output" "$source" >/dev/null
done

run_vm() {
  local binary_name="$1"
  shift
  echo "Running local VM example: ${binary_name}"
  (
    cd "$VM_DIR"
    cargo run --quiet --manifest-path Cargo.toml -p stoffel-vm --bin stoffel-run -- \
      "${OUT_DIR}/${binary_name}" main "$@"
  )
}

run_vm local_control_flow.stflb
run_vm local_collections.stflb
run_vm local_nested_generics.stflb
run_vm language_policy_engine.stflb
run_vm local_text_processing.stflb
run_vm local_dynamic_workflow.stflb
run_vm local_closure_counter.stflb
run_vm language_mpc_schemas.stflb

LOCAL_STORE="$(mktemp -d "${TMPDIR:-/tmp}/stoffel-local-store.XXXXXX")"
trap 'rm -rf "$LOCAL_STORE"' EXIT
LOCAL_CERT="${VM_DIR}/ids/nodes/cert0.crt"
LOCAL_KEY="${VM_DIR}/ids/nodes/key0.der"
run_vm local_storage.stflb --local-store "${LOCAL_STORE}/example.redb" --cert "$LOCAL_CERT" --key "$LOCAL_KEY"
run_vm avss_share_auditor.stflb --local-store "${LOCAL_STORE}/auditor.redb" --cert "$LOCAL_CERT" --key "$LOCAL_KEY"

if [ "$RUN_DOCKER_MPC" -eq 1 ]; then
  docker_mpc_down() {
    (
      cd "$EXAMPLES_DIR"
      STOFFEL_VM_DIR="$VM_DIR" \
      STOFFEL_COORDINATOR_DIR="$COORDINATOR_DIR" \
      STOFFEL_NETWORK_DIR="$NETWORK_DIR" \
      STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
        docker compose -f docker-compose.mpc.yml down --remove-orphans >/dev/null 2>&1 || true
    )
  }

  run_docker_mpc() {
    local binary_name="$1"
    local backend="${2:-honeybadger}"
    local curve="${3:-bls12-381}"

    echo "Running docker compose MPC example: ${binary_name} (${backend}/${curve})"
    docker_mpc_down
    if ! (
      cd "$EXAMPLES_DIR"
      STOFFEL_VM_DIR="$VM_DIR" \
      STOFFEL_COORDINATOR_DIR="$COORDINATOR_DIR" \
      STOFFEL_NETWORK_DIR="$NETWORK_DIR" \
      STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
      STOFFEL_PROGRAM_NAME="$binary_name" \
      STOFFEL_MPC_BACKEND="$backend" \
      STOFFEL_MPC_CURVE="$curve" \
        docker compose -f docker-compose.mpc.yml up --build --abort-on-container-exit --exit-code-from party0
    ); then
      docker_mpc_down
      return 1
    fi
    docker_mpc_down
  }

  run_coordinator_example() {
    local binary_name="$1"
    shift

    echo "Running coordinator compose example: ${binary_name}"
    STOFFEL_VM_DIR="$VM_DIR" \
    STOFFEL_COORDINATOR_DIR="$COORDINATOR_DIR" \
    STOFFEL_NETWORK_DIR="$NETWORK_DIR" \
    STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
    STOFFEL_PROGRAM_NAME="$binary_name" \
      "$EXAMPLES_DIR/run_coordinator_compose.sh" "$@"
  }

  run_docker_mpc mpc_runtime_info.stflb
  run_docker_mpc mpc_share_arithmetic.stflb
  run_docker_mpc mpc_share_toolkit.stflb
  run_docker_mpc mpc_protocol_coordination.stflb
  run_docker_mpc threshold_signatures_threshold_bls_bls12381.stflb honeybadger bls12-381
  run_docker_mpc threshold_signatures_threshold_schnorr_ed25519.stflb avss ed25519
  run_docker_mpc threshold_signatures_threshold_eddsa_ed25519.stflb avss ed25519
  run_docker_mpc threshold_signatures_threshold_ecdsa_secp256k1.stflb avss secp256k1
  run_docker_mpc threshold_signatures_threshold_ecdsa_p256.stflb avss p-256
  run_docker_mpc avss_certificate_keygen.stflb avss p-256
  run_docker_mpc avss_certificate_sign.stflb avss p-256

  STOFFEL_CLIENT_INPUT_COUNT=1 \
  STOFFEL_COORDINATOR_N_INPUTS=2 \
  STOFFEL_OUTPUTS=1 \
  STOFFEL_CLIENT1_OUTPUTS=0 \
  STOFFEL_CLIENT0_INPUT=100 \
  STOFFEL_CLIENT1_INPUT=20 \
  STOFFEL_CLIENT0_INDEX=0 \
  STOFFEL_CLIENT1_INDEX=1 \
  EXPECTED_OUTPUT=320 \
  WAIT_TIMEOUT_SECS=420 \
    run_coordinator_example mpc_client_private_score.stflb

  STOFFEL_CLIENT_INPUT_COUNT=6 \
  STOFFEL_COORDINATOR_N_INPUTS=12 \
  STOFFEL_OUTPUTS=6 \
  STOFFEL_CLIENT1_OUTPUTS=0 \
  STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS=16 \
  STOFFEL_CLIENT0_INPUT='65536,131072,196608,262144,327680,393216' \
  STOFFEL_CLIENT1_INPUT='458752,524288,589824,655360,720896,786432' \
  STOFFEL_CLIENT0_INDEX=0 \
  STOFFEL_CLIENT1_INDEX=6 \
  EXPECTED_OUTPUT='8, 10, 12, 14, 16, 18' \
  WAIT_TIMEOUT_SECS=420 \
    run_coordinator_example mpc_client_federated_average.stflb
fi

if [ "$RUN_HOST_MPC" -eq 1 ]; then
  echo "Running host-process MPC example..."
  "${EXAMPLES_DIR}/run_mpc_local.sh"
fi

echo "Example validation complete."
