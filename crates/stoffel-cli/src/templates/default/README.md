# Stoffel app

This is a runnable base project for building a Stoffel application. It gives you a private program, generated typed bindings, an ephemeral Rust client, and independently run coordinator and MPC services.

The included program doubles one private integer and returns the authorized output to the submitting client. Replace that small example with your application logic while keeping the same separation between clients and long-lived MPC infrastructure.

If this is your first Stoffel project, keep the [Stoffel documentation](https://docs.stoffelmpc.com) open alongside this README. The docs cover StoffelLang, the Rust SDK, MPC concepts, and deployment configuration in more depth.

## Validate the Stoffel program

```sh
stoffel check
```

## Run the local MPC network

Install the local MPC node runner once:

```sh
cargo install stoffel-vm-runner --version 0.1.2 --locked
```

Start the coordinator and the number of MPC nodes configured by `[mpc].parties` in `Stoffel.toml`:

```sh
./scripts/run-local.sh
```

The script validates and compiles `src/main.stfl`, builds the Rust binaries, starts the coordinator and MPC nodes, and waits for preprocessing to finish. It prints `Local Stoffel MPC services are ready for client input.` only after party 0 advances the coordinator to the input-mask reservation round. It does not run a client.

Local addresses are selected together when the network starts. If a default port is already occupied, the script records another available address set in `deploy/local/deployment.json` and uses it for the coordinator, nodes, and clients.

The script finds `stoffel-run` on `PATH`. Framework contributors can instead select a local build explicitly with `STOFFEL_RUN_BIN=/path/to/stoffel-run ./scripts/run-local.sh`.

## Run the sample client

In a second terminal, send the sample private input:

```sh
./scripts/run-client.sh 42
```

The client launcher waits for the coordinator's input-ready round before submitting anything, so starting it while preprocessing is still running is safe.

Expected output:

```text
Doubled result: 84
```

`src/client.rs` is the application entrypoint. Its short `main` function gets a configured `StoffelClient`, submits typed private input with `run_typed`, receives the typed result, and exits. `src/main.rs` holds the project-level SDK and deployment configuration so application code stays focused on inputs and outputs. The coordinator and MPC nodes continue running and can accept independently started clients.

## Build bytecode

```sh
stoffel build --output artifacts/program.stflb
```

`cargo build` then generates typed Rust bindings from that exact bytecode through `build.rs`.

## Project structure

```text
.
├── Cargo.toml                 # Client and service binaries
├── Stoffel.toml               # Program, party count, threshold, and build settings
├── build.rs                   # Typed binding generation
├── src/
│   ├── client.rs              # Participant-owned application entrypoint
│   ├── main.rs                # Shared SDK and deployment configuration
│   ├── server.rs              # One MPC node built with stoffel-rust-sdk
│   ├── coordinator.rs         # Off-chain coordinator and local identities
│   └── main.stfl              # Private computation
├── tests/                     # Stoffel and Rust tests
└── scripts/
    ├── run-local.sh           # Long-lived local coordinator and nodes
    ├── run-client.sh          # Ephemeral application client
    ├── docker-compose.yml     # Coordinator and five deployable MPC nodes
    └── Dockerfile             # Coordinator and node image
```

The application client, coordinator, and MPC nodes are separate processes. Private input goes from the participant-owned client directly to the MPC network; starting or stopping a client does not control the service lifecycle.

## Build your application from this template

Use this project as the starting point rather than treating the doubling example as a fixed application:

1. Write the private computation in `src/main.stfl`.
2. Run `stoffel check` and rebuild `artifacts/program.stflb`.
3. Run `cargo build` to regenerate typed Rust bindings from that bytecode.
4. Replace the sample input and output handling in `src/client.rs` with your application types and workflow.
5. Adjust `[mpc]` in `Stoffel.toml` and the deployment configuration for your topology.
6. Keep private values in participant-owned clients. The application client should submit directly to the MPC network, while coordinator and MPC nodes remain independently operated services.

For the full language, SDK, and deployment guides, continue with the [Stoffel documentation](https://docs.stoffelmpc.com).

## Run the tests

```sh
stoffel test
cargo test
```

## Run with Docker Compose

Build the program and prepare local development identities once:

```sh
stoffel build --output artifacts/program.stflb
cargo run --bin stoffel-coordinator -- prepare
docker compose -f scripts/docker-compose.yml up --build
```

The Compose stack runs one coordinator and five independently addressable MPC nodes. The `input-ready` service waits for preprocessing and exits successfully only when the coordinator can accept client input. Keep the client in your application and run `./scripts/run-client.sh 42` after Compose prints `MPC network is ready for client input`.

If readiness times out, inspect the coordinator and node logs before starting a client. The readiness command reconnects across coordinator startup and preprocessing resets, but cannot make progress if party 0 exits. An open port only means that a process is listening; it does not mean the MPC network has finished preprocessing. Party 0 must remain running and complete the transition from `Idle` through preprocessing to input-mask reservation.

For a real deployment, provide each service its own identity and persistent runtime environment, replace loopback addresses in the deployment configuration, and manage secrets with your deployment platform.
