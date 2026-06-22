# syntax=docker/dockerfile:1.4
FROM rustlang/rust:nightly-bookworm AS chef

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

WORKDIR /build

FROM chef AS planner

COPY crates/stoffel-vm-types /StoffelVM/crates/stoffel-vm-types
COPY docker/coordinator-wrapper /build/coordinator-wrapper
COPY --from=coordinator . /stoffel-mpc-coordinator
COPY --from=network . /stoffel-network

RUN mkdir -p /build/.cargo && \
    printf '%s\n' \
      '[net]' \
      'git-fetch-with-cli = true' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git"]' \
      'stoffel-mpc-coordinator = { path = "/stoffel-mpc-coordinator" }' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/stoffel-networking.git"]' \
      'stoffelnet = { path = "/stoffel-network" }' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/StoffelVM.git"]' \
      'stoffel-vm-types = { path = "/StoffelVM/crates/stoffel-vm-types" }' \
      > /build/.cargo/config.toml

WORKDIR /build/coordinator-wrapper

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

WORKDIR /build

COPY --from=planner /build/coordinator-wrapper/recipe.json /build/coordinator-wrapper/recipe.json
COPY --from=planner /build/.cargo /build/.cargo
COPY --from=planner /StoffelVM/crates/stoffel-vm-types /StoffelVM/crates/stoffel-vm-types
COPY --from=planner /stoffel-mpc-coordinator /stoffel-mpc-coordinator
COPY --from=planner /stoffel-network /stoffel-network

WORKDIR /build/coordinator-wrapper

RUN --mount=type=cache,id=stoffel-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=stoffel-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=stoffel-coordinator-target,target=/build/coordinator-wrapper/target,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

COPY docker/coordinator-wrapper /build/coordinator-wrapper

RUN mkdir -p /build/.cargo && \
    printf '%s\n' \
      '[net]' \
      'git-fetch-with-cli = true' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git"]' \
      'stoffel-mpc-coordinator = { path = "/stoffel-mpc-coordinator" }' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/stoffel-networking.git"]' \
      'stoffelnet = { path = "/stoffel-network" }' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/StoffelVM.git"]' \
      'stoffel-vm-types = { path = "/StoffelVM/crates/stoffel-vm-types" }' \
      > /build/.cargo/config.toml

RUN --mount=type=cache,id=stoffel-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=stoffel-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=stoffel-coordinator-target,target=/build/coordinator-wrapper/target,sharing=locked \
    cargo build --release && \
    mkdir -p /build/artifacts && \
    cp target/release/stoffel-coordinator-docker /build/artifacts/stoffel-coordinator-docker

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/artifacts/stoffel-coordinator-docker /app/stoffel-coordinator
COPY ids /app/ids

ENTRYPOINT ["/app/stoffel-coordinator"]
