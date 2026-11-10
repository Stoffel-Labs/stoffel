# Stoffel MPC Coordinator Libraries

`stoffel-mpc-coordinator` provides coordinator primitives for Stoffel MPC workflows. It manages the full protocol lifecycle: preprocessing, input-mask reservation, input collection, MPC execution, and output distribution.

The workspace contains these libraries:

- [`stoffel-mpc-coordinator-shared`](https://crates.io/crates/stoffel-mpc-coordinator-shared): shared coordinator traits, execution identifiers, protocol rounds, RPC utilities, and test helpers.
- [`stoffel-mpc-coordinator-off-chain`](https://crates.io/crates/stoffel-mpc-coordinator-off-chain): secure JSON-RPC coordination over mutual TLS for local or non-chain deployments, plus an optional server-authenticated TLS listener for browser clients.
- `stoffel-mpc-coordinator-on-chain`: Ethereum smart-contract coordination via Alloy and the Stoffel Solidity bindings; currently workspace-only.
- `stoffel-mpc-coordinator-bins`: deployment and local-development binaries; currently workspace-only.

## Installation

Add the off-chain coordinator library with:

```toml
[dependencies]
stoffel-mpc-coordinator-off-chain = "0.2.1"
```

The shared crate is pulled in automatically. Depend on `stoffel-mpc-coordinator-shared = "0.2.1"` directly when implementing against transport-independent coordinator traits and types.

## Package status

Version `0.2.1` publishes the shared and off-chain libraries. The on-chain and binary crates remain excluded from crates.io because they depend on pinned Stoffel Solidity SDK binding crates from Git.

## Deploying the on-chain coordinator

Start Anvil using `anvil`.

Install a mock on-chain coordinator with:

```sh
DEPLOY_SK='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' \
cargo run --bin deploy-contract -- \
  --eth-node-addr ws://127.0.0.1:8545 \
  --program program.stflb \
  --t 1 \
  --initial-mpc-nodes 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 \
  --output-clients 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

`deploy-contract` takes:

| Flag | Description |
|---|---|
| `--eth-node-addr` | WebSocket URL of the Ethereum node. |
| `--program` | Compiled Stoffel program (`.stflb`). |
| `--t` | Threshold `t`. |
| `--initial-mpc-nodes` | Comma-separated Ethereum addresses of the MPC nodes. |
| `--output-clients` | Comma-separated Ethereum addresses of the output clients. Must match the number of output-bearing clients in the program's IO manifest. |

The deployer's private key is read from the `DEPLOY_SK` environment variable. The program hash
(Keccak-256 of the serialized bytecode) and the input count are derived from the program; the
minimum number of output shares is derived from `--t` and the manifest's MPC backend (`2t + 1`
for HoneyBadger, `t + 1` for AVSS). The deployed contract address is printed on success.

## Running the off-chain coordinator

### Identities

Generate self-signed P-256 identities with the `generate-ids` shell script in the repository root
(requires `openssl`):

```sh
./generate-ids ids 2 5   # output directory `ids`, 2 clients, 5 nodes
```

The output directory must not exist yet. Certificates are written to `ids/pub/{coord.crt,clients/clientN.crt,nodes/nodeN.crt}`
and DER private keys to `ids/priv/{coord.der,clients/clientN.der,nodes/nodeN.der}`.

The `generate-ids` Rust binary is a lower-level tool that creates a single certificate/key pair:
`cargo run --bin generate-ids -- --cert coord.crt --key coord.der --subject-alt-names coord`.

### Execution IDs

Every program invocation needs one nonzero 256-bit execution ID (64 hex characters) shared by its
coordinator, MPC nodes, and clients. The commands below use
`0000000000000000000000000000000000000000000000000000000000000001` as a readable example;
use a freshly generated value (for example, `openssl rand -hex 32`) for each real invocation.

### One-off coordinator

```sh
cargo run --bin run-coord -- \
  --one-off 0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000001 \
  --server-cert ids/pub/coord.crt --server-key ids/priv/coord.der \
  --n 5 --t 1 --n-inputs 2 \
  --initial-mpc-nodes ids/pub/nodes/node0.crt,ids/pub/nodes/node1.crt,ids/pub/nodes/node2.crt,ids/pub/nodes/node3.crt,ids/pub/nodes/node4.crt \
  --output-clients ids/pub/clients/client0.crt,ids/pub/clients/client1.crt
```

`--one-off <hash>,<execution-id>` registers that single execution (32-byte hex program hash and
execution ID) before listening. The coordinator exits once the designated party (the first
`--initial-mpc-nodes` entry) calls the
`request_shutdown` RPC method — stoffel-run's `--one-off` mode does this after confirming the
execution reached `ProgramFinished`; the coordinator does not shut down on the round transition by
itself. After the request it waits up to `--one-off-shutdown-grace-secs` for every MPC party to
acknowledge `ProgramFinished`, exiting sooner if all of them do.

Omit `--one-off` to run a standing coordinator that keeps listening and accepts further
executions via the `register_execution` RPC method. `--program`, `--client-bindings`,
`--n-inputs`, and `--backend` only take effect together with `--one-off`; a standing coordinator
ignores them.

### VM-backed client IO

For VM-backed client IO, pass a compiled `.stflb` with an IO manifest and bind logical VM slots to
off-chain client certificates:

```sh
cargo run --bin run-coord -- \
  --one-off 0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000001 \
  --server-cert ids/pub/coord.crt --server-key ids/priv/coord.der \
  --n 5 --t 1 \
  --initial-mpc-nodes ids/pub/nodes/node0.crt,ids/pub/nodes/node1.crt,ids/pub/nodes/node2.crt,ids/pub/nodes/node3.crt,ids/pub/nodes/node4.crt \
  --program program.stflb \
  --client-bindings 0=ids/pub/clients/client0.crt
```

With `--program`, the input count is derived from the bound clients' input counts and the output
clients are the bound clients that have outputs, so `--n-inputs` and `--output-clients` are not
used for that purpose. If `--client-bindings` is omitted, the `--output-clients` certificates are
bound to the manifest's client slots in ascending slot order, and their number must equal the
number of manifest clients. Every manifest slot must be bound, and each identity may be bound to
only one slot.

The off-chain coordinator also selects the MPC share backend from the `.stflb` manifest. Compile
programs with `stoffel --mpc-backend honeybadger -b program.stfl` or
`stoffel --mpc-backend avss -b program.stfl`. Without `--program`, the backend is chosen with
`--backend` (default `honeybadger`).

### Browser listener

A standing coordinator can additionally serve browser clients over ordinary server-authenticated
TLS (browsers cannot present TLS client certificates):

```sh
cargo run --bin run-coord -- \
  --server-cert ids/pub/coord.crt --server-key ids/priv/coord.der \
  --n 5 --t 1 \
  --initial-mpc-nodes ids/pub/nodes/node0.crt,ids/pub/nodes/node1.crt,ids/pub/nodes/node2.crt,ids/pub/nodes/node3.crt,ids/pub/nodes/node4.crt \
  --browser-addr 0.0.0.0 --browser-port 31416 \
  --browser-tls-cert-chain fullchain.pem --browser-tls-key privkey.pem \
  --webauthn-rp-id vote.example.com
```

The browser certificate chain should be CA-issued: browsers reject a self-signed certificate on a
WebSocket handshake without offering a prompt. `--browser-addr` is not yet supported together with
`--one-off`.

### `run-coord` flags

| Flag | Default | Description |
|---|---|---|
| `--server-cert` | required | DER certificate of the coordinator (mTLS listener). |
| `--server-key` | required | DER private key of the coordinator. |
| `--n` | required | Number of MPC nodes; must equal the number of `--initial-mpc-nodes`. |
| `--t` | required | Threshold; must be less than `--n`. |
| `--initial-mpc-nodes` | required | Comma-separated DER certificates of the MPC nodes; identities must be unique. |
| `--addr` | `127.0.0.1` | Bind address of the mTLS listener. |
| `--port` | `31415` | Port of the mTLS listener. |
| `--one-off` | — | `<hash>,<execution-id>`: run exactly one execution, then exit on `request_shutdown`. |
| `--one-off-shutdown-grace-secs` | `30` | Maximum wait for parties to acknowledge `ProgramFinished` after a shutdown request. |
| `--n-inputs` | — | Number of inputs; required with `--one-off` when `--program` is not given. |
| `--output-clients` | — | Comma-separated DER certificates of the output clients (see above for use with `--program`). |
| `--program` | — | Compiled `.stflb` whose IO manifest determines backend, inputs, and outputs (`--one-off` only). |
| `--client-bindings` | — | Comma-separated `<client_slot>=<cert>` pairs (`--one-off` with `--program` only). |
| `--backend` | `honeybadger` | `honeybadger` or `avss`; used with `--one-off` when `--program` is not given. |
| `--browser-addr` | — | Bind address of the browser listener; requires `--browser-tls-cert-chain`, `--browser-tls-key`, and `--webauthn-rp-id`. |
| `--browser-port` | `31416` | Port of the browser listener. |
| `--browser-tls-cert-chain` | — | PEM certificate chain (leaf first) for the browser listener. |
| `--browser-tls-key` | — | PEM private key for the browser listener. |
| `--webauthn-rp-id` | — | WebAuthn relying party ID: the site's hostname exactly as shown in the browser's URL bar (e.g. `vote.example.com`). |
| `--client-cert-dir` | — | Directory of registered clients' public-key files (`{client_name}.crt`). |
| `--client-credential-id-dir` | — | Directory of registered clients' WebAuthn credential IDs (`{client_name}.id`, raw `rawId` bytes). Together with `--client-cert-dir`, lets WebAuthn binding look a credential up directly instead of scanning the roster; if either is missing, the scan is used. |

## Library overview

This library is generic over the share type used by the underlying MPC protocol.

## Share Types

The coordinator is parameterized as `<F: FftField, S: ShareBound<F>>`, where `S` is the share type used throughout the protocol. `ShareBound<F>` bundles the constraints the coordinator places on a share:

- **`SecretSharingScheme<F>`**: exposes secret reconstruction (`recover_secret`) and share generation (`compute_shares`).
- **`CanonicalSerialize` / `CanonicalDeserialize`**: shares are transmitted as compressed bytes over JSON-RPC.
- **`Clone`, `Send`, `'static`**: required for use across async Tokio tasks.
- **`compute_masked_input`**: subtracts a mask share from a masked input while preserving any per-share metadata.
- **`min_shares(t)`**: the number of shares needed to reconstruct a secret.

Two concrete share types are provided. Off-chain startup selects between them from the running
program manifest when `--program` is provided:

| Manifest backend | Share type | `min_shares(t)` | Description |
|---|---|---|---|
| `honeybadger` | `RobustShare<F>` | `2t + 1` | Plain Shamir share used by HoneyBadger MPC |
| `avss` | `FeldmanShamirShare<F, G>` | `t + 1` | Shamir share with group-element commitments for verifiable secret sharing |

To add a new share type, implement `ShareBound<F>` for it, paying particular attention to `compute_masked_input` and `min_shares`.

## Protocol Rounds

Every protocol execution traverses these rounds in order:

```
Idle → Preprocessing → InputMaskReservation → InputCollection → MPCExecution → OutputDistribution → ProgramFinished
```

Clients and nodes subscribe to round notifications and receive them to stay in sync. In the
off-chain coordinator, round transitions are decided by vote (see below); on-chain, they are
driven by calls to the coordinator contract.

## The `Coordinator` Trait

Both on-chain and off-chain coordinators implement `Coordinator<F, S>`, which exposes:

- **Transitioning methods**: `start_preprocessing`, `reserve_input_masks`, `collect_inputs`, `start_mpc`, `send_output`, `finalize`
- **Node methods**: `wait_for_round`, `wait_for_indices`, `wait_for_inputs`, `send_output_shares`
- **Client methods**: `reserve_mask_index`, `reserve_mask_indices`, `send_masked_input`, `send_masked_inputs`, `obtain_outputs`

`reserve_mask_indices` and `send_masked_inputs` have default implementations that loop over their single-item counterparts; the off-chain coordinator overrides them with a single round trip.

## On-Chain Coordinator

`on_chain::OnChainCoordinator<P, F, S>` integrates with the `StoffelCoordinator` Ethereum smart contract via [Alloy](https://alloy.rs). Key behaviors:

- **Role management**: contract events and calls assign roles (party, designated party) to nodes.
- **Index reservation**: clients reserve input-mask indices via contract calls; the coordinator tracks ownership through `ReservedInputEvent` events.
- **Client authentication**: clients sign a nonce with their Ethereum private key; nodes verify the signature against the Ethereum address registered in the contract, binding the client's TLS identity to its Ethereum identity.
- **Input collection**: clients submit masked inputs (`x + m`) to the contract; nodes listen for `MaskedInputEvent` and compute a share of the unmasked input by subtracting their mask share.
- **Output distribution**: output shares are HPKE-encrypted for each client and delivered via the contract.

Client identities are Ethereum `Address` values. The on-chain node-side RPC server (`on_chain::node_rpc::NodeRPCServer`) watches for `ReservedInputEvent` from the contract to learn which client holds which mask index, then serves the corresponding mask share to the authenticated client.

## Off-Chain Coordinator

The off-chain coordinator operates over JSON-RPC (WebSockets) with mutual TLS, without any blockchain dependency. It consists of two components:

- **`OffChainCoordinatorServer<C>`**: the coordinator RPC server. It is generic over the connection type `C: RPCServerConnection`, so developers can extend both per-connection state and shared state. `CoordinatorRPCServerConnectionBase` implements the library-provided RPC methods, and `tests::fake_coord::CoordinatorConnection` (aliased as `HoneyBadgerCoordinatorConnection` and `AvssCoordinatorConnection`) is a ready-to-use connection type built on it.
- **`OffChainCoordinatorClient<F, S>`**: the RPC client used by both MPC nodes and MPC clients to communicate with the coordinator.

Key behaviors:

- **Executions**: one coordinator serves multiple concurrent executions, each identified by an `ExecutionId` that every RPC call carries. Executions are added with `register_execution` and removed with `retire_execution` (a one-off coordinator registers its single execution at startup).
- **Round management**: parties propose transitions by calling `transition(execution_id, round)` over RPC. The round advances once a quorum of distinct parties has voted for it (`2t + 1`, capped at `n - t` for liveness and never below `t + 1`), and all subscribers receive the corresponding event.
- **Index reservation**: clients call `reserve_mask_index(i)` or `reserve_mask_indices(indices)` during `InputMaskReservation`. The event is broadcast to all `sub_reserved_indices` subscribers, including MPC nodes.
- **Mask-share distribution**: each MPC node runs a `node_rpc::NodeRPCServer`. After learning a client's reserved index from the coordinator, the node delivers its mask share to the client over a dedicated WebSocket subscription authenticated by mTLS. The client collects `min_shares(t)` shares and reconstructs the mask locally.
- **Output distribution**: MPC nodes HPKE-encrypt their output shares under the client's P-256 public key and call `send_output_shares`. Once the execution's `min_output_shares` (`min_shares(t)` of its backend) have arrived at the coordinator, they are forwarded to the client's `obtain_output_shares` subscription.
- **Bound VM IO layout**: `.stflb` bytecode can carry a client IO manifest built from `ClientStore.take_share*` and client-output calls. Off-chain startup binds VM `client_slot` values to certificate public keys, derives input-mask capacity from bound input counts, and authorizes output clients from bound output counts. Scalar IO types stay with the SDK/VM manifest and are not interpreted by the coordinator. On-chain contracts/events do not yet carry this layout metadata; equivalent Solidity support is deferred.
- **Authentication**: all native connections use mutual TLS. The client's identity is the raw public key (the certificate's `subjectPublicKey` bytes), used consistently towards both the coordinator and node RPC servers.
- **Late-subscriber safety**: the coordinator keeps each execution's event history and replays it to subscribers that join after events have fired.
- **One-off shutdown**: `request_shutdown` lets the designated party stop a one-off coordinator after it has confirmed the execution finished; standing coordinators reject it.

### Browser clients

`browser_rpc` exposes polling JSON-RPC methods (`browser_round`, `browser_reserve_mask_indices`,
`browser_submit_masked_inputs`, `browser_output_shares`, ...) on a separate, server-authenticated
TLS listener started with `OffChainCoordinatorServer::start_coord_with_browser_tls`. Because a
browser cannot present a TLS client certificate, authenticated requests are signed individually
with an ephemeral P-256 key and carry a timestamp and a random nonce for replay protection. The
ephemeral key is bound to a registered client identity through a WebAuthn ceremony
(`browser_bind_webauthn_identity`), after which the browser acts with the same `ClientIdentity`
as a native client. MPC nodes expose corresponding browser methods for mask-share delivery.

### Extending the coordinator

The off-chain coordinator is split into two RPC trait layers:

1. **`StoffelCoordinatorRPC`**: the developer-facing interface containing only the round-transition methods (`start_preprocessing`, `reserve_input_masks`, etc.). Implement this on a custom connection type to embed application logic into each transition.
2. **`CoordinatorRPCBase`**: pre-implemented by the library, covering execution registration, round transitions, index reservation, input submission, output distribution, shutdown, and all subscriptions.

## Common Features

- **HPKE encryption**: output shares are encrypted.
- **Threshold**: secret reconstruction requires `min_shares(t)` shares (`2t + 1` for HoneyBadger, `t + 1` for AVSS); both the coordinator and clients enforce this before forwarding or accepting outputs.
- **Testing utilities**: `self_signed_certs` provides `server_cert()` / `client_cert()` helpers. `setup_test()` ensures a default `rustls` crypto provider is available before tests create TLS connections.
