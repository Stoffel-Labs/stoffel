# syntax=docker/dockerfile:1.4
# Multi-stage Dockerfile for StoffelVM
# Builds the stoffel-run binary and packages it for distributed MPC execution
#
# Example:
#   docker build -t stoffelvm:latest .

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN printf '%s\n' \
      '[net]' \
      'git-fetch-with-cli = true' \
      '' \
      > /build/.cargo/config.toml

# Configure git for private repos if using SSH
# For private GitHub repos, mount SSH keys during build:
#   docker build --ssh default .
RUN mkdir -p ~/.ssh && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# TEMPORARY — docs/design/bootnode-elimination.md §9.F.5. stoffel-mpc-coordinator 0.3.0 is
# not published, so the workspace's [patch.crates-io] names a path on the build
# host. The `coordinator` named build context is copied to exactly that path
# before cargo resolves the workspace. Delete with the patch.
COPY --from=coordinator . /Users/gabriel/RustroverProjects/stoffel-mpc-coordinator-roster-admission

# Build the release binary
# Note: If using private repos with SSH, run with: docker build --ssh default .
RUN --mount=type=ssh \
    cargo build --release --package stoffel-vm-runner --bin stoffel-run && \
    strip target/release/stoffel-run

# Compile the AES-128 secret-bit circuit example into VM bytecode for compose runs.
RUN cargo build --release --package stoffellang && \
    mkdir -p /build/crates/stoffel-lang/examples/mpc_aes128_circuit/target && \
    STOFFEL_INLINE_BUDGET=100000000 \
    STOFFEL_UNROLL_BUDGET=100000000 \
    STOFFEL_UNROLL_MAX_EXPANSION=100000000 \
    /build/target/release/stoffellang \
      --binary \
      --opt-level 3 \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/crates/stoffel-lang/examples/mpc_aes128_circuit/target/mpc_aes128_circuit.stflb \
      /build/crates/stoffel-lang/examples/mpc_aes128_circuit/main.stfl

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    netcat-openbsd \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/stoffel-run /app/stoffel-run

# Copy the test bytecode files
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/matrix_average_fixed_point.stflb /app/programs/matrix_average_fixed_point.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/client_mul.stflb /app/programs/client_mul.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/client_sub_order.stflb /app/programs/client_sub_order.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/avss_keygen.stflb /app/programs/avss_keygen.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/avss_certificate_keygen.stflb /app/programs/avss_certificate_keygen.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/avss_certificate_sign.stflb /app/programs/avss_certificate_sign.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_schnorr_ed25519.stflb /app/programs/threshold_schnorr_ed25519.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_eddsa_ed25519.stflb /app/programs/threshold_eddsa_ed25519.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_bls_bls12381.stflb /app/programs/threshold_bls_bls12381.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_ecdsa_secp256k1.stflb /app/programs/threshold_ecdsa_secp256k1.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_ecdsa_p256.stflb /app/programs/threshold_ecdsa_p256.stflb
COPY --from=builder /build/crates/stoffel-lang/examples/mpc_aes128_circuit/target/mpc_aes128_circuit.stflb /app/programs/mpc_aes128_circuit.stflb

# No identity material is baked in (docs/design/bootnode-elimination.md §9.F.0):
# each container receives its own private key as a compose secret and the public
# certificates as read-only per-file mounts under /app/ids.

# Copy the entrypoint script
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Default environment variables (can be overridden in docker-compose)
# No party count, threshold, roster or client list: every party takes them from
# the coordinator's node roster and execution registration, and the entrypoint
# refuses the removed variables by name (docs/design/bootnode-elimination.md §9.D.3).
ENV STOFFEL_BIND_ADDR="0.0.0.0:9000"
ENV STOFFEL_PROGRAM="/app/programs/mpc_aes128_circuit.stflb"
ENV STOFFEL_ENTRY="main"
ENV STOFFEL_ROLE="party"
ENV STOFFEL_PARTY_ID="0"
ENV STOFFEL_COORD_ADDR=""
ENV STOFFEL_COORD_CERT=""
ENV STOFFEL_EXPECT_ROSTER_DIGEST=""
ENV STOFFEL_RPC_ADDR=""
ENV STOFFEL_CERT=""
ENV STOFFEL_KEY=""

# Expose ports for party communication and RPC.
# Port 9000: this party's single QUIC listener, which is also the port it
#            advertises. The bind_port + 1000 pairing this replaced belonged to
#            the leader/bootnode topology, where a bootnode held 9000 and the
#            party listened on 10000; it was removed from all four of its homes
#            at once (docs/design/bootnode-elimination.md §7).
# Port 16180: node RPC server (mask distribution to clients)
EXPOSE 9000 16180

ENTRYPOINT ["/app/entrypoint.sh"]
