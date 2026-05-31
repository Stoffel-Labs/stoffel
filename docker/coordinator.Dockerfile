# syntax=docker/dockerfile:1.4
FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY .cargo /build/.cargo
COPY . /StoffelVM
COPY docker/coordinator-wrapper /build/coordinator-wrapper
COPY --from=coordinator . /stoffel-mpc-coordinator
COPY --from=network . /stoffel-network
RUN sed -i 's#path = "../StoffelVM/crates/stoffel-vm-types"#path = "/StoffelVM/crates/stoffel-vm-types"#' \
    /stoffel-mpc-coordinator/Cargo.toml

RUN printf '%s\n' \
      '[net]' \
      'git-fetch-with-cli = true' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git"]' \
      'stoffel-mpc-coordinator = { path = "/stoffel-mpc-coordinator" }' \
      '' \
      '[patch."https://github.com/Stoffel-Labs/stoffel-networking.git"]' \
      'stoffelnet = { path = "/stoffel-network" }' \
      > /build/.cargo/config.toml

WORKDIR /build/coordinator-wrapper
RUN cargo build --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/coordinator-wrapper/target/release/stoffel-coordinator-docker /app/stoffel-coordinator
COPY ids /app/ids

ENTRYPOINT ["/app/stoffel-coordinator"]
