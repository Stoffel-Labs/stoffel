#!/bin/bash
set -e

# StoffelVM Docker Entrypoint Script
#
# Every non-client role is a member of a roster-pinned mesh: it binds, advertises
# the port it bound, and dials the other members. There is no bootstrap process
# and no shared bearer token — membership is the coordinator's node roster,
# fetched once over a connection pinned by STOFFEL_COORD_CERT and enforced per
# connection by mTLS (docs/design/bootnode-elimination.md §9.D).

validate_env() {
    # Stage 8 of docs/design/bootnode-elimination.md removed these. Each is
    # refused by name rather than ignored: a stack whose compose file still sets
    # one is a stack that was configured for a topology that no longer exists,
    # and silently starting anyway is how it turns into a debugging session.
    if [ -n "${STOFFEL_AUTH_TOKEN:-}" ]; then
        echo "ERROR: STOFFEL_AUTH_TOKEN was removed. Membership is now the certificate set:"
        echo "       set STOFFEL_COORD_ADDR, STOFFEL_COORD_CERT and STOFFEL_EXECUTION_ID"
        echo "       (plus STOFFEL_CERT/STOFFEL_KEY) instead."
        exit 2
    fi
    if [ -n "${STOFFEL_BOOTSTRAP_ADDR:-}" ]; then
        echo "ERROR: STOFFEL_BOOTSTRAP_ADDR was removed. There is no bootstrap process to"
        echo "       register with: set STOFFEL_PEERS to the other parties' addresses."
        exit 2
    fi
    if [ "${STOFFEL_ROLE}" = "bootnode" ]; then
        echo "ERROR: STOFFEL_ROLE=bootnode was removed. Run every node as 'party';"
        echo "       'leader' survives only as a label on a stack's first service."
        exit 2
    fi
    # Coordinator transitions are quorum-gated, so no party is the round driver
    # and STOFFEL_COORD_DRIVER designates nothing. Refuse it rather than ignore
    # it: a stack that still sets it was configured on the assumption that
    # exactly one party advances the rounds.
    if [ -n "${STOFFEL_COORD_DRIVER:-}" ]; then
        echo "ERROR: STOFFEL_COORD_DRIVER was removed. Coordinator transitions are"
        echo "       quorum-gated: every party proposes every Round and none is designated."
        exit 2
    fi
    if [ "${STOFFEL_ENABLE_NAT:-}" = "true" ] || [ -n "${STOFFEL_STUN_SERVERS:-}" ]; then
        echo "ERROR: the nat feature was removed (docs/design/bootnode-elimination.md §4)."
        echo "       Give every party a reachable STOFFEL_ADVERTISE_IP instead."
        exit 2
    fi
    if [ "${STOFFEL_ROLE}" != "client" ] && [ -z "${STOFFEL_PEERS:-}" ]; then
        echo "ERROR: STOFFEL_PEERS must list the other parties' addresses."
        echo "       A party forms its session by dialing them; there is nobody to ask."
        exit 2
    fi

    # docs/design/bootnode-elimination.md §9.D.3: the coordinator is the only
    # roster authority, and client participation is its per-execution
    # admission, so every variable that gave a container a roster, a party
    # count, a threshold, a timestamp or a client list of its own is refused by
    # name, in both roles, rather than ignored. stoffel-run refuses the matching
    # flags the same way.
    removed_variable_hint() {
        case "$1" in
            STOFFEL_NODE_ROSTER)
                echo "The coordinator serves the node roster: set STOFFEL_COORD_ADDR, STOFFEL_COORD_CERT and STOFFEL_EXECUTION_ID." ;;
            STOFFEL_EXPECTED_CLIENTS)
                echo "Client certificates no longer enter a node's transport allowlist: register clients with the coordinator (STOFFEL_CLIENT_IO, STOFFEL_CLIENT_CERTS or open admission)." ;;
            STOFFEL_WAIT_FOR_CLIENTS)
                echo "Clients no longer connect to the node mesh: they associate through the coordinator and reach the parties' STOFFEL_RPC_ADDR listeners." ;;
            STOFFEL_CLIENT_INPUT_COUNT)
                echo "The client slot layout is the coordinator's execution registration (STOFFEL_CLIENT_IO)." ;;
            STOFFEL_N_PARTIES|STOFFEL_THRESHOLD)
                echo "n and t come from the coordinator's node roster." ;;
            STOFFEL_TIMESTAMP)
                echo "No coordinator takes a timestamp; an execution's deadlines are part of its registration." ;;
            STOFFEL_CLIENT_INDEX)
                echo "The coordinator assigns each client's input range when it associates. Set STOFFEL_CLIENT_SLOT to ask for a specific slot." ;;
            STOFFEL_OUTPUTS)
                echo "A client's output count comes from its admission." ;;
            STOFFEL_PREPROC_STORE)
                echo "Preprocessing material is never stored between executions: a stored item could be drawn by a second execution (docs/design/bootnode-elimination.md §9.C.9). Remove the variable." ;;
        esac
    }
    for var in STOFFEL_NODE_ROSTER STOFFEL_EXPECTED_CLIENTS STOFFEL_WAIT_FOR_CLIENTS \
        STOFFEL_CLIENT_INPUT_COUNT STOFFEL_N_PARTIES STOFFEL_THRESHOLD STOFFEL_TIMESTAMP \
        STOFFEL_CLIENT_INDEX STOFFEL_OUTPUTS STOFFEL_PREPROC_STORE; do
        if [ -n "${!var:-}" ]; then
            echo "ERROR: ${var} was removed. $(removed_variable_hint "${var}")"
            exit 2
        fi
    done

    # A party proves it is one of the coordinator's roster nodes with its own
    # certificate and key; failing here names the variables to set.
    if [ -n "${STOFFEL_COORD_ADDR:-}" ] && [ "${STOFFEL_ROLE}" != "client" ] \
        && { [ -z "${STOFFEL_CERT:-}" ] || [ -z "${STOFFEL_KEY:-}" ]; }; then
        echo "ERROR: STOFFEL_COORD_ADDR requires STOFFEL_CERT and STOFFEL_KEY."
        echo "The coordinator's node roster names nodes by certificate, and a node proves it is"
        echo "one of them with its key."
        exit 2
    fi

    # The coordinator keys every RPC on an ExecutionId, so a coordinator-bearing
    # container must name the invocation it belongs to. There is no default:
    # guessing one would attach this node to whatever execution happened to
    # carry that id.
    if [ -n "${STOFFEL_COORD_ADDR:-}" ] && [ -z "${STOFFEL_EXECUTION_ID:-}" ]; then
        echo "ERROR: STOFFEL_COORD_ADDR requires STOFFEL_EXECUTION_ID (64 hex characters)."
        echo "It must match the coordinator service's --execution-id, and every party and"
        echo "client of one run must carry the same value."
        exit 2
    fi

    # Coordinator 0.3.0 has no connection without a pin: stoffel-run refuses
    # --off-chain-coord without --coord-cert, and failing here names the
    # variable the operator has to set (docs/design/bootnode-elimination.md §9.A).
    if [ -n "${STOFFEL_COORD_ADDR:-}" ] && [ -z "${STOFFEL_COORD_CERT:-}" ]; then
        echo "ERROR: STOFFEL_COORD_ADDR requires STOFFEL_COORD_CERT."
        echo "It is the path of the coordinator's DER certificate. Every coordinator"
        echo "connection pins its key, and a connection that does not accepts any server."
        exit 2
    fi

    # A mesh's membership is the coordinator's node roster, and nothing else;
    # stoffel-run refuses --peers without --off-chain-coord, and failing here
    # names the variables the operator has to set.
    if [ -n "${STOFFEL_PEERS:-}" ] && [ "${STOFFEL_ROLE}" != "client" ] \
        && { [ -z "${STOFFEL_COORD_ADDR:-}" ] || [ -z "${STOFFEL_COORD_CERT:-}" ]; }; then
        echo "ERROR: STOFFEL_PEERS requires STOFFEL_COORD_ADDR and STOFFEL_COORD_CERT."
        echo "A seed address is a hint; membership is the coordinator's node roster, fetched"
        echo "over a connection pinned to STOFFEL_COORD_CERT."
        exit 2
    fi

    # §9.E.3: direct client mode was removed. A client associates with an
    # execution through the coordinator and reaches the parties' RPC listeners.
    if [ "${STOFFEL_ROLE}" = "client" ] && [ -z "${STOFFEL_COORD_ADDR:-}" ]; then
        echo "ERROR: a client requires STOFFEL_COORD_ADDR, STOFFEL_COORD_CERT and STOFFEL_EXECUTION_ID."
        echo "Direct client mode was removed: a client associates with an execution through"
        echo "the coordinator, and STOFFEL_SERVERS names the parties' node RPC listeners."
        exit 2
    fi

    # A client is admitted by the identity it presents: the coordinator binds
    # its certificate to a slot, and every node RPC leg delivers masks and
    # outputs to that certificate only. stoffel-run requires both, and failing
    # here names the variables instead.
    if [ "${STOFFEL_ROLE}" = "client" ] \
        && { [ -z "${STOFFEL_CERT:-}" ] || [ -z "${STOFFEL_KEY:-}" ]; }; then
        echo "ERROR: a client requires STOFFEL_CERT and STOFFEL_KEY."
        echo "Its admission is keyed on the certificate it presents to the coordinator and"
        echo "to the parties' node RPC listeners. The certificate need not be configured"
        echo "anywhere else: under open admission any certificate holder may bind a free slot."
        exit 2
    fi
    if [ "${STOFFEL_ROLE}" = "client" ] && [ -z "${STOFFEL_SERVERS:-}" ]; then
        echo "ERROR: a client requires STOFFEL_SERVERS, the parties' node RPC listeners"
        echo "(their STOFFEL_RPC_ADDR). Every leg is pinned to the coordinator's node roster."
        exit 2
    fi
}

validate_env

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
        echo "Inputs: ${STOFFEL_INPUTS:-none}"
        echo "Client Slot: ${STOFFEL_CLIENT_SLOT:-unset}"
        echo "Invitation: ${STOFFEL_INVITATION:-none}"
        echo "Expected Program Hash: ${STOFFEL_EXPECT_PROGRAM_HASH:-none}"
        echo "Servers: ${STOFFEL_SERVERS}"
else
    echo "Party ID: ${STOFFEL_PARTY_ID}"
    echo "Bind Address: ${STOFFEL_BIND_ADDR}"
    echo "Advertise IP: ${STOFFEL_ADVERTISE_IP}"
    echo "Peers: ${STOFFEL_PEERS:-none}"
fi
echo "Program: ${STOFFEL_PROGRAM}"
echo "Entry: ${STOFFEL_ENTRY}"
echo "Coordinator: ${STOFFEL_COORD_ADDR:-N/A}"
echo "Coordinator Cert: ${STOFFEL_COORD_CERT:-N/A}"
echo "Expected Roster Digest: ${STOFFEL_EXPECT_ROSTER_DIGEST:-none}"
echo "Execution ID: ${STOFFEL_EXECUTION_ID:-N/A}"
echo "Local Store: ${STOFFEL_LOCAL_STORE:-none}"
echo "Epoch Store: ${STOFFEL_EPOCH_STORE:-none}"
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
            echo "Host ${host} is reachable, assuming the node is starting..."
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

# Resolve one peer's host:port, waiting for the name to appear.
#
# A name that falls through unresolved would reach `--peers`, which parses
# SocketAddrs and aborts the process on a hostname (`stoffel-run.rs`,
# `expect("Invalid --peers address")`). There is also no single address
# `depends_on` can order the stack around — every party names every other party
# — so this retry loop is what a mesh has instead. If the name never appears it
# fails loudly and names the entry rather than handing a hostname to the parser.
#
# Progress goes to stderr because the caller captures stdout as the resolved
# address.
resolve_peer_addr() {
    local addr=$1
    local attempts=${STOFFEL_PEER_RESOLVE_ATTEMPTS:-120}
    local host
    local port
    local resolved
    local attempt=1

    host=$(echo "$addr" | cut -d: -f1)
    port=$(echo "$addr" | cut -d: -f2)

    case "$host" in
        # A literal IPv4 address needs no lookup, and getent would answer for it
        # anyway; short-circuiting keeps the retry loop for names only.
        [0-9]*.[0-9]*.[0-9]*.[0-9]*)
            echo "${host}:${port}"
            return 0
            ;;
    esac

    while [ "$attempt" -le "$attempts" ]; do
        resolved=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')
        if [ -z "$resolved" ]; then
            resolved=$(ping -c 1 "$host" 2>/dev/null | sed -n 's/^PING [^(]*(\([^)]*\)).*/\1/p' | head -n 1)
        fi
        if [ -n "$resolved" ]; then
            echo "${resolved}:${port}"
            return 0
        fi
        if [ "$attempt" -eq 1 ]; then
            echo "Waiting for peer name ${host} to resolve..." >&2
        fi
        sleep 1
        attempt=$((attempt + 1))
    done

    echo "ERROR: peer ${addr} did not resolve after ${attempts} attempts." >&2
    echo "       Every STOFFEL_PEERS entry must be a literal address or a name this" >&2
    echo "       container can resolve; --peers is parsed as a SocketAddr and a" >&2
    echo "       hostname there aborts the node at startup." >&2
    return 1
}

# Resolve every host:port in a comma-separated list: compose service names have
# to become addresses before they reach stoffel-run, which parses --peers as
# SocketAddrs. A single unresolvable entry fails the whole list rather than being
# passed through.
resolve_peer_list() {
    local list=$1
    local resolved=""
    local entry
    local one

    local IFS=','
    for entry in $list; do
        [ -z "$entry" ] && continue
        one=$(resolve_peer_addr "$entry") || return 1
        if [ -z "$resolved" ]; then
            resolved="$one"
        else
            resolved="${resolved},${one}"
        fi
    done
    if [ -z "$resolved" ]; then
        echo "ERROR: STOFFEL_PEERS resolved to an empty list." >&2
        return 1
    fi
    echo "$resolved"
}

# Build command based on role
build_command() {
    local cmd="/app/stoffel-run"

    if [ "${STOFFEL_ROLE}" = "client" ]; then
        # Client mode: associate with the execution through the coordinator
        # (docs/design/bootnode-elimination.md §9.E). The client's slot, input
        # range and output count are the coordinator's admission; nothing here
        # sets them. A client of an output-only slot has no STOFFEL_INPUTS.
        cmd="${cmd} --client"
        if [ -n "${STOFFEL_INPUTS:-}" ]; then
            cmd="${cmd} --inputs ${STOFFEL_INPUTS}"
        fi
        cmd="${cmd} --servers ${STOFFEL_SERVERS}"
        if [ -n "${STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS:-}" ]; then
            cmd="${cmd} --output-fixed-point-fractional-bits ${STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS}"
        fi
        cmd="${cmd} --off-chain-coord ${STOFFEL_COORD_ADDR}"
        cmd="${cmd} --coord-cert ${STOFFEL_COORD_CERT}"
        # Which invocation this client's inputs belong to. The coordinator keys
        # every RPC on it, so it has to match the value the coordinator was
        # registered with and the parties were started with; there is no
        # default, and the all-zero value is rejected.
        cmd="${cmd} --execution-id ${STOFFEL_EXECUTION_ID}"
        # Optional: refuse a coordinator that serves any other node roster. The
        # client's node legs are pinned to whatever roster it is served.
        if [ -n "${STOFFEL_EXPECT_ROSTER_DIGEST:-}" ]; then
            cmd="${cmd} --expect-roster-digest ${STOFFEL_EXPECT_ROSTER_DIGEST}"
        fi
        # The client's own transport identity: its admission is keyed on it,
        # and so is every node RPC leg it opens (required, see validate_env).
        cmd="${cmd} --cert ${STOFFEL_CERT}"
        cmd="${cmd} --key ${STOFFEL_KEY}"
        # The client slot to bind. Under open admission this is how a client
        # picks its slot; without it the coordinator binds the client's
        # pre-registered slot, its invitation's slot, or under open admission
        # the first free one.
        if [ -n "${STOFFEL_CLIENT_SLOT:-}" ]; then
            cmd="${cmd} --client-slot ${STOFFEL_CLIENT_SLOT}"
        fi
        # Under invitation admission: the signed invitation (JSON) presented
        # when the client associates.
        if [ -n "${STOFFEL_INVITATION:-}" ]; then
            cmd="${cmd} --invitation ${STOFFEL_INVITATION}"
        fi
        # Optional: refuse to associate with an execution of any other program.
        if [ -n "${STOFFEL_EXPECT_PROGRAM_HASH:-}" ]; then
            cmd="${cmd} --expect-program-hash ${STOFFEL_EXPECT_PROGRAM_HASH}"
        fi
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

    # Mesh mode. Every node is spelled the same way: bind, advertise the port it
    # actually bound, and dial the seeds. There is no round-driver flag: the
    # coordinator applies a round once a quorum of roster members has proposed
    # it, so every party proposes every transition and none of them is
    # designated. STOFFEL_ROLE=leader is only a label on a stack's first
    # service.
    # STOFFEL_PARTY_ID names this container's volumes and nothing else. The
    # index this node is addressed by on the wire is its rank in the
    # coordinator roster's lexicographic SPKI order, and the shipped certificates do not sort into
    # the order they are numbered in, so the two routinely differ; the party
    # says so once after the join and carries on. The store itself is keyed by
    # this node's certificate, so a container always opens its own.
    cmd="${cmd} --party-id ${STOFFEL_PARTY_ID}"
    cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
    BIND_PORT=$(echo "${STOFFEL_BIND_ADDR}" | awk -F: '{print $NF}')
    # One listener, one port. The BIND_PORT+1000 offset this replaced belonged to
    # the leader/bootnode topology, where the bootnode held BIND_PORT and the
    # party listened above it; a mesh node advertises the port it binds.
    # docs/design/bootnode-elimination.md §7 lists all four homes of that
    # convention, and they had to go together: dropping it in the Rust sites
    # alone would have left every leader advertising a dead port.
    cmd="${cmd} --advertise ${STOFFEL_ADVERTISE_IP}:${BIND_PORT}"
    cmd="${cmd} --peers ${STOFFEL_RESOLVED_PEERS}"

    # Membership (docs/design/bootnode-elimination.md §9.D). The party fetches
    # the coordinator's node roster once, over a connection pinned to
    # STOFFEL_COORD_CERT, before it binds anything; the roster's certificates
    # become the transport's peer-certificate allowlist — nodes only — so
    # membership is enforced per connection by mTLS.
    cmd="${cmd} --off-chain-coord ${STOFFEL_COORD_ADDR}"
    cmd="${cmd} --coord-cert ${STOFFEL_COORD_CERT}"
    # Which invocation this party serves. The same value the coordinator
    # service registered; every party and client of one run shares it.
    cmd="${cmd} --execution-id ${STOFFEL_EXECUTION_ID}"
    cmd="${cmd} --cert ${STOFFEL_CERT}"
    cmd="${cmd} --key ${STOFFEL_KEY}"
    # Optional: refuse a coordinator that serves any other node roster.
    if [ -n "${STOFFEL_EXPECT_ROSTER_DIGEST:-}" ]; then
        cmd="${cmd} --expect-roster-digest ${STOFFEL_EXPECT_ROSTER_DIGEST}"
    fi

    if [ -n "${STOFFEL_RPC_ADDR:-}" ]; then
        cmd="${cmd} --rpc-bind ${STOFFEL_RPC_ADDR}"
    fi

    if [ -n "${STOFFEL_LOCAL_STORE:-}" ]; then
        cmd="${cmd} --local-store ${STOFFEL_LOCAL_STORE}"
    fi

    # Where this node keeps its monotone session epoch, keyed by the
    # coordinator's roster digest, which is what makes
    # instance_id fresh across runs of one roster (blocker B5,
    # docs/design/bootnode-elimination.md). It belongs on the same persistent
    # volume as STOFFEL_LOCAL_STORE and must NOT be shared between parties: an
    # epoch store that is wiped by a `docker compose down` resets to 0 and the
    # next run reuses the previous run's MPC session namespace.
    if [ -n "${STOFFEL_EPOCH_STORE:-}" ]; then
        cmd="${cmd} --epoch-store ${STOFFEL_EPOCH_STORE}"
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
                -g \
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

    # Resolve every peer name before building the command. There is no single
    # first service for compose's `depends_on` to order the stack around — every
    # party names every other party — so this retry loop is what replaces it.
    # Resolving here rather than inside `build_command` is what lets a failure
    # exit with a message: `build_command`'s stdout *is* the command, so anything
    # it prints would be swallowed into it.
    if [ "${STOFFEL_ROLE}" != "client" ]; then
        if ! STOFFEL_RESOLVED_PEERS=$(resolve_peer_list "${STOFFEL_PEERS}"); then
            exit 2
        fi
        export STOFFEL_RESOLVED_PEERS
        echo "Resolved peers: ${STOFFEL_RESOLVED_PEERS}"
    fi

    # Build and execute the command
    CMD=$(build_command)
    echo ""
    echo "Executing: ${CMD}"
    echo "=========================================="
    echo ""

    run_command "$CMD"
}

main "$@"
