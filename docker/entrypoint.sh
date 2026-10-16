#!/bin/bash
set -e

# StoffelVM Docker Entrypoint Script
#
# Two roles: `party` and `client`. Every party is the same shape and starts in
# any order: it dials the addresses in STOFFEL_PEERS and forms the mesh its
# coordinator's roster defines. Membership is the certificate allowlist that
# roster installs, so no shared secret is configured here.

# A party is published the execution it runs by its coordinator. A client is
# told which execution to join: the operator who registered it reads the
# identity the coordinator minted and passes it on. Every client is a
# coordinator client — the coordinator is what tells it which nodes exist and
# which certificates they must prove — so STOFFEL_COORD_ADDR is required.
validate_env() {
    if [ "${STOFFEL_ROLE:-}" = "client" ]; then
        if [ -z "${STOFFEL_COORD_ADDR:-}" ]; then
            echo "ERROR: STOFFEL_COORD_ADDR is required for a client. A client is given its"
            echo "       node set, and the certificates those nodes must prove, by the"
            echo "       coordinator it pins; STOFFEL_SERVERS supplies only addresses."
            exit 2
        fi
        if [ -z "${STOFFEL_EXECUTION_ID:-}" ]; then
            echo "ERROR: STOFFEL_EXECUTION_ID is required for a client."
            exit 2
        fi
        if ! [[ "${STOFFEL_EXECUTION_ID}" =~ ^[0-9a-fA-F]{64}$ ]] \
            || [[ "${STOFFEL_EXECUTION_ID}" =~ ^0{64}$ ]]; then
            echo "ERROR: STOFFEL_EXECUTION_ID must be a nonzero 64-character hexadecimal value."
            exit 2
        fi
    fi
}

validate_env

if [ "${STOFFEL_ROLE}" = "party" ]; then
    /app/configure-peer-netem.sh
fi

# Resolve the IP address peers should use to connect to this node.
# STOFFEL_ADVERTISE_IP can be set explicitly; otherwise auto-detect from
# the primary network interface (works for ECS Fargate and docker-compose, but not for EC2!).
if [ -z "${STOFFEL_ADVERTISE_IP:-}" ]; then
    STOFFEL_ADVERTISE_IP=$(hostname -i | awk '{print $1}')
fi

echo "=========================================="
echo "StoffelVM Node Startup"
echo "=========================================="
echo "Role: ${STOFFEL_ROLE}"
    if [ "${STOFFEL_ROLE}" = "client" ]; then
        echo "Inputs: ${STOFFEL_INPUTS}"
        echo "Manifest Slot: ${STOFFEL_CLIENT_SLOT:-auto}"
        echo "Servers: ${STOFFEL_SERVERS}"
else
    echo "Party ID: ${STOFFEL_PARTY_ID}"
    echo "Bind Address: ${STOFFEL_BIND_ADDR}"
    echo "Peers: ${STOFFEL_PEERS:-N/A}"
    echo "Advertise IP: ${STOFFEL_ADVERTISE_IP}"
    echo "Expected Clients: ${STOFFEL_EXPECTED_CLIENTS:-none}"
fi
echo "N Parties: ${STOFFEL_N_PARTIES}"
echo "Threshold: ${STOFFEL_THRESHOLD}"
echo "Program: ${STOFFEL_PROGRAM}"
echo "Entry: ${STOFFEL_ENTRY}"
echo "Coordinator: ${STOFFEL_COORD_ADDR:-N/A}"
echo "Preproc Store: ${STOFFEL_PREPROC_STORE:-none}"
echo "Local Store: ${STOFFEL_LOCAL_STORE:-none}"
echo "Profiler: ${STOFFEL_PROFILE:-none}"
echo "=========================================="

# Wait for a host:port to be available (UDP check for QUIC)
wait_for_host() {
    local host=$1
    local port=$2
    local max_attempts=${3:-60}
    local attempt=1

    echo "Waiting for ${host}:${port} to be available (QUIC/UDP)..."

    # For QUIC (UDP), we can't easily check with nc, so we use a simple
    # connectivity test by trying to send a UDP packet and checking if
    # the host is reachable. The application has its own retry logic.
    while [ $attempt -le $max_attempts ]; do
        # Check if host is reachable via ping (basic network connectivity)
        if ping -c 1 -W 1 "$host" >/dev/null 2>&1; then
            # Try UDP connection test with nc -u
            if timeout 1 bash -c "echo '' | nc -u -w 1 $host $port" 2>/dev/null; then
                echo "${host}:${port} appears reachable!"
                return 0
            fi
            # If UDP check is inconclusive, just verify ping works and continue
            # The application will handle connection retries
            echo "Host ${host} is reachable, assuming it is starting..."
            sleep 2
            return 0
        fi
        echo "Attempt ${attempt}/${max_attempts}: ${host} not reachable, waiting..."
        sleep 1
        attempt=$((attempt + 1))
    done

    echo "ERROR: ${host}:${port} did not become available after ${max_attempts} attempts"
    return 1
}

# Resolve every comma-separated host:port in STOFFEL_PEERS to an address the
# transport can dial. Seed hints, not membership: a wrong address costs one
# failed, certificate-pinned handshake.
resolve_peer_list() {
    local list=$1
    local resolved=""
    local entry

    IFS=',' read -ra entries <<< "$list"
    for entry in "${entries[@]}"; do
        entry=$(echo "$entry" | tr -d '[:space:]')
        [ -z "$entry" ] && continue
        if [ -z "$resolved" ]; then
            resolved="$(resolve_socket_addr "$entry")"
        else
            resolved="${resolved},$(resolve_socket_addr "$entry")"
        fi
    done
    echo "$resolved"
}

resolve_socket_addr() {
    local addr=$1
    local host
    local port
    local resolved

    host=$(echo "$addr" | cut -d: -f1)
    port=$(echo "$addr" | cut -d: -f2)

    resolved=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')
    if [ -z "$resolved" ]; then
        resolved=$(ping -c 1 "$host" 2>/dev/null | sed -n 's/^PING [^(]*(\([^)]*\)).*/\1/p' | head -n 1)
    fi

    if [ -z "$resolved" ]; then
        echo "$addr"
    else
        echo "${resolved}:${port}"
    fi
}

# Build command based on role
build_command() {
    local cmd="/app/stoffel-run"

    if [ "${STOFFEL_ROLE}" = "client" ]; then
        # Client mode: connect to the coordinator and submit inputs. The
        # coordinator arguments are unconditional: there is no client that
        # reaches a node without one.
        cmd="${cmd} --client"
        cmd="${cmd} --inputs ${STOFFEL_INPUTS}"
        cmd="${cmd} --servers ${STOFFEL_SERVERS}"
        # A standing node serves clients on a listener separate from its mesh
        # bind, so a client needs both: --servers for the node RPC, and
        # --client-transport-servers for the client-facing socket. The mesh
        # admits only the coordinator's node roster, which is why a client key
        # never reaches it.
        if [ -n "${STOFFEL_CLIENT_TRANSPORT_SERVERS:-}" ]; then
            cmd="${cmd} --client-transport-servers ${STOFFEL_CLIENT_TRANSPORT_SERVERS}"
        fi
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
        cmd="${cmd} --threshold ${STOFFEL_THRESHOLD:-1}"
        if [ -n "${STOFFEL_PROGRAM:-}" ]; then
            cmd="${cmd} --program ${STOFFEL_PROGRAM}"
        fi
        if [ -n "${STOFFEL_CLIENT_SLOT:-}" ]; then
            cmd="${cmd} --client-slot ${STOFFEL_CLIENT_SLOT}"
        fi
        if [ "${STOFFEL_RAW_CLIENT_IO:-}" = "true" ]; then
            cmd="${cmd} --raw-client-io"
        fi
        if [ -n "${STOFFEL_OUTPUTS:-}" ]; then
            cmd="${cmd} --outputs ${STOFFEL_OUTPUTS}"
        fi
        if [ -n "${STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS:-}" ]; then
            cmd="${cmd} --output-fixed-point-fractional-bits ${STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS}"
        fi
        cmd="${cmd} --off-chain-coord ${STOFFEL_COORD_ADDR}"
        cmd="${cmd} --coord-cert ${STOFFEL_COORD_CERT:-/app/ids/server_cert.crt}"
        cmd="${cmd} --execution-id ${STOFFEL_EXECUTION_ID}"
        cmd="${cmd} --cert ${STOFFEL_CERT}"
        cmd="${cmd} --key ${STOFFEL_KEY}"
        if [ -n "${STOFFEL_MPC_BACKEND:-}" ]; then
            cmd="${cmd} --mpc-backend ${STOFFEL_MPC_BACKEND}"
        fi
        if [ -n "${STOFFEL_MPC_CURVE:-}" ]; then
            cmd="${cmd} --mpc-curve ${STOFFEL_MPC_CURVE}"
        fi
        echo "$cmd"
        return
    fi

    # Add program path and entry function for non-client modes
    cmd="${cmd} ${STOFFEL_PROGRAM} ${STOFFEL_ENTRY}"

    # Party mode. `--peers` is the switch that makes this a party of a mesh;
    # the coordinator serves the roster that mesh is formed from, and the
    # party count and threshold below are the expectation that roster is
    # checked against.
    RESOLVED_PEERS=$(resolve_peer_list "${STOFFEL_PEERS}")
    cmd="${cmd} --party-id ${STOFFEL_PARTY_ID}"
    cmd="${cmd} --peers ${RESOLVED_PEERS}"
    cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
    cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
    cmd="${cmd} --threshold ${STOFFEL_THRESHOLD}"
    BIND_PORT=$(echo "${STOFFEL_BIND_ADDR}" | awk -F: '{print $NF}')
    cmd="${cmd} --advertise ${STOFFEL_ADVERTISE_IP}:${BIND_PORT}"
    # The coordinator counts retirement acknowledgements per party and requires
    # n - t of them before an execution is evictable, so every party emits this.
    # No party is designated: an acknowledgement that arrives after the
    # execution was already forgotten is a success.
    if [ -n "${STOFFEL_ONE_OFF:-}" ]; then
        cmd="${cmd} --one-off"
    fi

    cmd="${cmd} --off-chain-coord ${STOFFEL_COORD_ADDR}"
    cmd="${cmd} --coord-cert ${STOFFEL_COORD_CERT:-/app/ids/server_cert.crt}"
    cmd="${cmd} --cert ${STOFFEL_CERT}"
    cmd="${cmd} --key ${STOFFEL_KEY}"

    if [ -n "${STOFFEL_RPC_ADDR:-}" ]; then
        cmd="${cmd} --rpc-bind ${STOFFEL_RPC_ADDR}"
    fi

    if [ -n "${STOFFEL_EXPECTED_CLIENTS:-}" ]; then
        cmd="${cmd} --expected-clients ${STOFFEL_EXPECTED_CLIENTS}"
    fi

    if [ -n "${STOFFEL_WAIT_FOR_CLIENTS:-}" ]; then
        cmd="${cmd} --wait-for-clients ${STOFFEL_WAIT_FOR_CLIENTS}"
    fi

    if [ -n "${STOFFEL_CLIENT_INPUT_COUNT:-}" ]; then
        cmd="${cmd} --client-input-count ${STOFFEL_CLIENT_INPUT_COUNT}"
    fi

    if [ -n "${STOFFEL_CLIENT_INPUT_TOTAL:-}" ]; then
        cmd="${cmd} --client-input-total ${STOFFEL_CLIENT_INPUT_TOTAL}"
    fi

    if [ -n "${STOFFEL_PREPROC_STORE:-}" ]; then
        cmd="${cmd} --preproc-store ${STOFFEL_PREPROC_STORE}"
    fi

    if [ -n "${STOFFEL_LOCAL_STORE:-}" ]; then
        cmd="${cmd} --local-store ${STOFFEL_LOCAL_STORE}"
    fi

    # Add MPC backend if specified
    if [ -n "${STOFFEL_MPC_BACKEND:-}" ]; then
        cmd="${cmd} --mpc-backend ${STOFFEL_MPC_BACKEND}"
    fi

    # Add MPC curve if specified
    if [ -n "${STOFFEL_MPC_CURVE:-}" ]; then
        cmd="${cmd} --mpc-curve ${STOFFEL_MPC_CURVE}"
    fi

    # Add optional trace flags
    if [ "${STOFFEL_TRACE_INSTR}" = "true" ]; then
        cmd="${cmd} --trace-instr"
    fi
    if [ "${STOFFEL_TRACE_REGS}" = "true" ]; then
        cmd="${cmd} --trace-regs"
    fi
    if [ "${STOFFEL_TRACE_STACK}" = "true" ]; then
        cmd="${cmd} --trace-stack"
    fi

    echo "$cmd"
}

run_command() {
    local cmd="$1"
    local profile="${STOFFEL_PROFILE:-}"
    local profile_party="${STOFFEL_PROFILE_PARTY_ID:-0}"
    local party_id="${STOFFEL_PARTY_ID:-client}"
    local out_dir="${STOFFEL_PROFILE_DIR:-/app/profiles}"
    local label="${STOFFEL_PROFILE_LABEL:-party${party_id}}"

    if [ -z "$profile" ] || [ "$profile" = "none" ] || [ "$party_id" != "$profile_party" ]; then
        exec $cmd
    fi

    mkdir -p "$out_dir"
    echo "Profiling party ${party_id} with ${profile}; output dir: ${out_dir}"

    case "$profile" in
        heaptrack)
            exec heaptrack -o "${out_dir}/${label}.heaptrack" $cmd
            ;;
        massif)
            exec valgrind \
                --tool=massif \
                --pages-as-heap=yes \
                --massif-out-file="${out_dir}/${label}.massif" \
                $cmd
            ;;
        perf)
            exec perf record \
                -F "${STOFFEL_PERF_FREQUENCY:-99}" \
                --call-graph dwarf,16384 \
                -o "${out_dir}/${label}.perf.data" \
                -- $cmd
            ;;
        *)
            echo "ERROR: unknown STOFFEL_PROFILE '${profile}' (expected heaptrack, massif, perf, or none)" >&2
            exit 2
            ;;
    esac
}

# Main execution logic
main() {
    # Handle client mode
    if [ "${STOFFEL_ROLE}" = "client" ]; then
        # Wait for servers to be ready
        # Parse the first server address to check connectivity
        FIRST_SERVER=$(echo "${STOFFEL_SERVERS}" | cut -d',' -f1)
        SERVER_HOST=$(echo "${FIRST_SERVER}" | cut -d: -f1)
        SERVER_PORT=$(echo "${FIRST_SERVER}" | cut -d: -f2)

        # Add startup delay to let servers complete preprocessing
        DELAY=${STOFFEL_CLIENT_DELAY:-30}
        echo "Client: waiting ${DELAY}s for servers to complete preprocessing..."
        sleep $DELAY

        # Wait for first server to be reachable
        if ! wait_for_host "$SERVER_HOST" "$SERVER_PORT" 120; then
            echo "Failed to connect to server at ${FIRST_SERVER}"
            exit 1
        fi

        # Build and execute the command
        CMD=$(build_command)
        echo ""
        echo "Executing: ${CMD}"
        echo "=========================================="
        echo ""

        run_command "$CMD"
    fi

    # A party starts immediately and waits for nothing: the parties are
    # symmetric, and the mesh re-dials every peer it is still missing on its own
    # schedule until the discovery budget runs out.

    # Build and execute the command
    CMD=$(build_command)
    echo ""
    echo "Executing: ${CMD}"
    echo "=========================================="
    echo ""

    run_command "$CMD"
}

main "$@"
