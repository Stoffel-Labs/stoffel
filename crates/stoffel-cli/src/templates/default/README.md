# Stoffel app

This is a runnable base project for integrating Stoffel into a Rust application. It demonstrates the full boundary: a StoffelLang program becomes bytecode and typed Rust bindings, a participant-owned client submits private input, and independently run coordinator and MPC services execute the program.

The included example doubles one private integer and returns the authorized output to the submitting client. Replace that example with your application logic while preserving the separation between participant clients and long-lived MPC infrastructure.

The generated environment is a **single-host development deployment**: the coordinator, MPC parties, and participant client remain separate processes and trust roles even though they can all run on one development machine. It is not a separate in-process or simulated execution model. Moving to an operator-managed deployment changes endpoints, identities, secrets, persistence, and process supervision rather than the application boundary.

## How Stoffel fits into your application

```text
src/main.stfl
    ↓ stoffel build
artifacts/program.stflb
    ↓ cargo build / build.rs
Client0Inputs + Client0Outputs + ProgramManifest
    ↓ src/client.rs
participant-owned input → StoffelClient → MPC services → authorized output
```

The bytecode is the contract between your application clients and the MPC services. Both sides load the same artifact, and the generated Rust types describe its client input and output slots.

Read [Rust SDK app integration](https://docs.stoffelmpc.com/rust-sdk/app-integration) for the broader application pattern.

## Run the example

### 1. Validate the Stoffel program

```sh
stoffel check
```

`stoffel check` validates `src/main.stfl` and the MPC settings in `Stoffel.toml`. Start with the [StoffelLang overview](https://docs.stoffelmpc.com/stoffel-lang/overview) when changing the private computation.

### 2. Compile the Stoffel program

```sh
stoffel build --output artifacts/program.stflb
```

This compiles `src/main.stfl` into the exact bytecode artifact used by the client and MPC nodes. See [StoffelLang compilation](https://docs.stoffelmpc.com/stoffel-lang/compilation) for build and bytecode details.

### 3. Generate typed Rust bindings

```sh
cargo build
```

Cargo runs `build.rs`, which reads `artifacts/program.stflb` and generates `ProgramManifest`, `Client0Inputs`, and `Client0Outputs` into Cargo's `OUT_DIR`. If the Stoffel program's `ClientStore` or `MpcOutput` shape changes, rebuild the bytecode before rebuilding Rust.

Read [Typed client IO bindings](https://docs.stoffelmpc.com/developer-skills/stoffel-typed-client-io-bindings) for multi-client programs, ordered fields, and manifest-backed validation.

### 4. Start the development deployment

```sh
./scripts/run-local.sh
```

The script repeats validation and compilation, builds the Rust binaries, and starts the coordinator and the number of MPC nodes configured by `[mpc].parties` as separate processes on one development host. It prints `Development Stoffel deployment is ready for participant input.` only after the network reaches its input-ready round. It does not run a client.

Loopback endpoints are selected as one coherent set. If a default port is occupied, the script writes another available set to `deploy/local/deployment.json`, which the coordinator, nodes, and clients all consume. Here, `local` names the generated development environment; it does not indicate a different Stoffel execution model.

Read [Network and off-chain integration](https://docs.stoffelmpc.com/developer-skills/stoffel-app-network-and-offchain-integration) to understand the coordinator, node, and participant-client configuration.

### 5. Run the participant client

In a second terminal:

```sh
./scripts/run-client.sh 42
```

Expected output:

```text
Doubled result: 84
```

The client launcher waits for the network's input-ready round. `src/client.rs` maps the example's domain value into generated `Client0Inputs`, calls `StoffelClient::run_typed`, maps `Client0Outputs` back into an application value, and exits. Starting or stopping this client does not control the service lifecycle.

## Integrate Stoffel into your own app

Follow these steps in order. The comments marked `INTEGRATION STEP` in the generated source identify the corresponding code.

### 1. Define the private computation boundary

Decide which values remain in participant-owned software, what the MPC program computes, and which output may be revealed or sent to each client. Ordinary public application logic, persistence, authentication, and UI code should remain outside the Stoffel program.

Use the [privacy-boundary guide](https://docs.stoffelmpc.com/tutorials/privacy-boundary) before expanding the example.

### 2. Replace the example program

Edit `src/main.stfl`:

- Load each participant value from its assigned `ClientStore` slot.
- Perform only the logic that needs private computation.
- Send or reveal only the authorized output.

Then rerun:

```sh
stoffel check
stoffel build --output artifacts/program.stflb
```

### 3. Regenerate the Rust contract

Run `cargo build` after every change to the client input or output shape. Do not hand-edit generated bindings. Update Rust code to use the new generated structs and fields so mismatches fail at compile time.

### 4. Move the client boundary into participant-owned code

`src/client.rs` is a small executable example, not a required application architecture. In an existing Rust app:

1. Keep the `bindings` module and client builder from `src/main.rs` in an application module such as `stoffel.rs`.
2. Collect and validate private values in the participant-owned process.
3. Map domain values into generated `Client{slot}Inputs`.
4. Call `run_typed` on the configured `StoffelClient`.
5. Map generated outputs into your application's domain response.

The essential handoff is:

```rust
let inputs = Client0Inputs { input_0: private_value };
let outputs: Client0Outputs = app::client()?.run_typed(inputs).await?;
let application_value = outputs.output_0;
```

Do not route participant plaintext through an application backend just to reach the MPC network. The participant-owned client should submit directly to the separately operated MPC services.

### 5. Decide which infrastructure you operate

- `src/main.rs` contains the reusable client-side artifact, manifest, deployment, and identity wiring.
- `src/server.rs` is the MPC node process. Application feature code should not be added there.
- `src/coordinator.rs` prepares development identities and runs the off-chain coordinator. Treat it as deployment infrastructure, not the application's private-input endpoint.
- `deploy/local/deployment.json` is the generated development deployment configuration. Operator-managed environments should supply equivalent endpoints and identities through their deployment platform.

If another team operates the MPC services, your app may need only the bytecode, generated bindings, participant-client integration, and their deployment configuration. If you operate the services, use the [deployment runbook](https://docs.stoffelmpc.com/developer-skills/stoffel-deployment-runbook).

### 6. Keep build and deployment artifacts aligned

Deploy the same `artifacts/program.stflb` used to generate the client bindings. When the program changes, rebuild bytecode, regenerate bindings, rebuild clients and services, and deploy the set together.

## Project map

| Path | Role | What you normally change |
| --- | --- | --- |
| `src/main.stfl` | Private computation | Client slots, private logic, and authorized outputs |
| `Stoffel.toml` | Program and MPC build settings | Package name, backend, parties, threshold, and source path |
| `build.rs` | Exact-bytecode binding generation | Usually nothing; preserve the bytecode-first contract |
| `src/main.rs` | Shared Rust integration module | Deployment source, client slot, and app-specific wrapper organization |
| `src/client.rs` | Participant-client example | Domain input validation and input/output mapping |
| `src/server.rs` | Long-lived MPC node | Deployment/operator configuration only |
| `src/coordinator.rs` | Coordinator and development provisioning | Deployment/operator configuration only |
| `artifacts/program.stflb` | Compiled app contract | Regenerate from `src/main.stfl`; do not edit |
| `deploy/local/` | Generated development identities/config | Regenerate for development; do not commit identities |
| `scripts/run-local.sh` | Single-host development launcher | Extend only for development operations |
| `scripts/run-client.sh` | Sample client launcher | Replace with your app's participant-client entrypoint |

## Development loop

After changing the private program or client contract:

```sh
stoffel check
stoffel build --output artifacts/program.stflb
cargo build
stoffel test
cargo test
```

Then restart the development MPC services and rerun the participant client. This catches StoffelLang errors, stale bytecode, stale generated types, Rust integration errors, and topology regressions separately.

What each layer proves:

- `stoffel check` and `stoffel test` cover source validity and fast program logic.
- `cargo build` and `cargo test` cover generated bindings and Rust integration.
- `run-local.sh` plus `run-client.sh` proves the separate coordinator, MPC nodes, and participant client work together.

## Run with Docker Compose

Build the program and prepare generated development identities once:

```sh
stoffel build --output artifacts/program.stflb
cargo run --bin stoffel-coordinator -- prepare
docker compose -f scripts/docker-compose.yml up --build
```

The Compose stack runs one coordinator and five independently addressable MPC nodes. The `input-ready` service exits successfully only when preprocessing is complete and the coordinator can accept client input. Run `./scripts/run-client.sh 42` after Compose prints `MPC network is ready for client input`.

Each node sets `STOFFEL_BIND_ADDRESS` to its own Compose service name (for example `node-1:19202`). `src/server.rs` resolves that name at startup and binds the MPC listener to the container's own network address, because the bootnode on party 0 hands each node's bind address to the other parties. Binding `0.0.0.0` instead makes every peer dial itself, and `input-ready` times out. For any other topology, set `STOFFEL_BIND_ADDRESS` to an address the other nodes can reach; a container attached to more than one network needs an explicit numeric address. Party 0 serves the bootnode on its bind port and its party listener on the bind port + 1000.

An open port only means a process is listening. If readiness times out, inspect the coordinator and node logs. Party 0 must remain running and advance the coordinator through preprocessing to input-mask reservation.

For an operator-managed production deployment, provide each service its own identity and persistent runtime environment, replace loopback endpoints, manage secrets with your deployment platform, and follow the [Stoffel deployment runbook](https://docs.stoffelmpc.com/developer-skills/stoffel-deployment-runbook). For the container topology, see the [Docker network deployment guide](https://docs.stoffelmpc.com/deployment/docker-local-network).
