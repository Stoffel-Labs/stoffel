# Stoffel
[![GitHub License](https://img.shields.io/github/license/Stoffel-Labs/stoffel)](LICENSE)
[![Static Badge](https://img.shields.io/badge/docs-stoffel-%23FDC448)](https://docs.stoffelmpc.com)
[![Static Badge](https://img.shields.io/badge/built%20by-Stoffel%20Labs-%232D39E0)](https://stoffelmpc.com)



Stoffel is a toolchain for writing, compiling, and running programs that compute
over private data using secure Multi-Party Computation (MPC). You write ordinary
looking code, mark the values that must stay secret, and Stoffel compiles and
executes it so that no single party ever sees the secret inputs in the clear.

This repository is the Stoffel monorepo. It contains everything from the
language and compiler down to the runtime and the networking/MPC layer:

| Product | Crate | What it is |
|---------|-------|------------|
| **Stoffel CLI** | `crates/stoffel-cli` | The Cargo-like `stoffel` command for creating, building, and running MPC projects |
| **StoffelLang** | `crates/stoffel-lang` | The `stoffel` language compiler (`.stfl` → `.stflb` bytecode) |
| **Stoffel SDK** | `crates/stoffel-rust-sdk` | The Rust SDK (`stoffel` crate) for embedding compilation, execution, and MPC config in apps |
| **Stoffel VM** | `crates/stoffel-vm` | The register-based VM runtime, networking, and MPC backends (HoneyBadger, AVSS), plus the C FFI |

Supporting crates:

- `crates/stoffel-vm-runner`: the `stoffel-run` binary — local runner and distributed MPC party/client node
- `crates/stoffel-vm-types`: shared VM types, the instruction set, runtime `Value`s, and the compiled bytecode format
- `crates/stoffel-bindgen`: build-time generation of typed Rust bindings for Stoffel programs
- `include/`: the public C header and FFI notes for embedding the VM from C-compatible environments

```
StoffelLang source (.stfl)
        │  stoffel build / stoffel-lang
        ▼
Compiled bytecode (.stflb)        ← stoffel-vm-types::compiled_binary
        │  stoffel run / stoffel-run / Stoffel SDK
        ▼
Stoffel VM  ── local execution  (clear or simulated MPC)
            └─ distributed MPC  (HoneyBadger / AVSS over QUIC)
```

## Installation

Install the released Stoffel CLI with the installer:

```bash
curl -fsSL https://get.stoffelmpc.com | sh
```

The installer places `stoffel` in `~/.local/bin` by default. Add it to your shell path if needed:

```bash
export PATH="$HOME/.local/bin:$PATH"
stoffel --help
```

Create and run a project:

```bash
stoffel init hello-mpc
cd hello-mpc
stoffel run --input a=40 --input b=2
```

> **Runner caveat:** local runs need the `stoffel-run` MPC runner. The installer
> drops it next to `stoffel`, and the CLI discovers it automatically. If you
> installed `stoffel` another way, Stoffel also looks for `stoffel-run` on your
> `PATH` (e.g. after `cargo install stoffel-vm-runner`), or
> you can point at a specific binary with `--runner <path>` or the
> `STOFFEL_RUN_BIN` environment variable.

To build from source instead, see [Build and Test](#build-and-test).

## Stoffel CLI

The `stoffel` binary is a Cargo-like project CLI built on top of `crates/stoffel-rust-sdk`.
It reads `Stoffel.toml`, defaults to `src/main.stfl`, and writes bytecode to
`target/debug/<package>.stflb` or `target/release/<package>.stflb`.

> **Local runner:** local execution (`stoffel run` without `--network`, and
> `stoffel dev`) drives the `stoffel-run` MPC runner. Stoffel resolves it in order:
> an explicit `--runner <path>`, the `STOFFEL_RUN_BIN` environment variable, a
> `stoffel-run` sitting next to the `stoffel` binary (where the installer puts it),
> a `stoffel-run` on your `PATH` (e.g. via `cargo install stoffel-vm-runner`),
> then a `stoffel-run` built in the current
> Cargo workspace. See [Build and Test](#build-and-test) to build one from source.

### Create a project

```bash
stoffel init my-lib --lib
stoffel init rust-app --template rust
stoffel init py-app --template python
```

Solidity/EVM project templates (`solidity-foundry`, `solidity-hardhat`) are
planned but not yet available — see [Roadmap](#roadmap).

### Build, check, and inspect

```bash
stoffel build
stoffel check
stoffel compile src/main.stfl -O2 --output target/debug/hello-mpc.stflb
stoffel compile --disassemble target/debug/hello-mpc.stflb
```

`build` and `compile` default to all `src/**/*.stfl` files when no source path is
provided. Use `--output` when compiling a single file.

### Run

```bash
stoffel run target/debug/hello-mpc.stflb --entry main --input a=40 --input b=2
stoffel run --input a=40 --input b=2
stoffel run program.stfl --local --client-input 0=42 --parties 5 --threshold 1
stoffel run program.stfl --local --expected-output-clients 2
stoffel run target/debug/program.stflb --network --config offchain-client.toml --input x=42
stoffel run target/debug/program.stflb --network --config party-network.toml --connect-timeout-ms 1000
```

`run` accepts `.stfl` source or `.stflb` bytecode. By default it runs through the
local MPC coordinator; `--local` is accepted as an explicit local mode selector.
Use `--client-input SLOT=VALUE` for `ClientStore` input providers, and
`--expected-output-clients N` to declare output-capable local client slots
`0..N-1` for dynamic output loops or output-only runs (this does not synthesize
client inputs). `--network --config` uses SDK network configuration: an off-chain
client config executes through the coordinator/node RPC path, while a network
config validates and connects to real node addresses.

Local runs form a **roster-pinned mesh**: every party is spawned symmetrically
with `--peers` seed addresses, the in-process coordinator's `--coord-cert`, and
its own `--epoch-store`, and fetches the node roster — the run's own node
certificates — from that coordinator once at startup. Nothing has to be
configured for it — the certificates and epoch stores are minted into the run's
temporary directory —
and `--mesh` is accepted as a no-op name for the default. There is no other
local topology: `--bootnode` was removed along with the bootnode itself, and an
invocation that still passes it fails to parse rather than quietly doing
something else.

### Develop with live reload

```bash
stoffel dev --parties 5 --threshold 1 --input a=40 --input b=2
```

`stoffel dev` runs once, watches `Stoffel.toml` and the configured source tree,
then rebuilds and reruns whenever a `.stfl` file or project config changes. Use
`stoffel dev --once` for one-shot behavior, or `--poll-ms <N>` to tune reload latency.

### Test and manage projects

```bash
stoffel test
stoffel test --test selected --verbose
stoffel status --verbose
stoffel clean
stoffel clean --all
stoffel update --check
stoffel update
```

`status` validates project config, checks detected dependency managers, compiles
configured sources, and reports local MPC network configuration. `clean` removes
the project `target/` directory and Stoffel build cache; `--all` also removes
known ecosystem caches such as `node_modules`, Foundry cache/output, and Python
test caches. `update` checks for CLI/project dependency updates and runs detected
project dependency update commands; use `--check` to inspect without changing files.

## StoffelLang

StoffelLang (`.stfl`) is the source language compiled by `crates/stoffel-lang`
into Stoffel VM bytecode. It is a Python-flavored, statically typed language: it
uses indentation and `def`, but values carry concrete types and the `secret`
qualifier marks data that must remain private under MPC.

```python
def main(a: secret int64, b: secret int64) -> secret int64:
  return a + b
```

Arithmetic, comparisons, and control flow work transparently on both clear and
`secret` values; the compiler and VM insert the MPC operations needed for secret
operands. Programs interact with the runtime through module-style builtins such
as `Share.*`, `Field.*`, and `Mpc.*` (see [Builtins](#standard-library-builtins)).

Many worked programs live in `crates/stoffel-lang/examples/`, including local
collections/control-flow demos, AES-128 (CTR/CBC/circuit) under MPC, and
threshold ECDSA / certificate-signing flows. See
`crates/stoffel-lang/examples/README.md` for an index.

The compiler can be driven directly (`stoffel compile`) or through the SDK; bump
the binary format version when serialization changes (see
`crates/stoffel-vm-types/src/compiled_binary/`).

## Stoffel SDK (Rust)

`crates/stoffel-rust-sdk` publishes the `stoffel` crate: the library entry point
for embedding Stoffel-Lang compilation, bytecode loading, VM execution, and MPC
participant configuration in Rust applications. The CLI itself is built on it.

```toml
# Cargo.toml
stoffel-rust-sdk = "=0.1.2"
```

```rust
use stoffel::prelude::*;

let result = Stoffel::compile(
    "def main(a: int64, b: int64) -> int64:\n  return a + b",
)?
.with_inputs(&[("a", 42_i64), ("b", 58_i64)])
.execute_clear()?;

assert_eq!(result[0].as_i64(), Some(100));
# Ok::<(), stoffel::Error>(())
```

For local MPC smoke runs, use the same builder and call `execute_local().await`.
This starts real localhost VM parties through `stoffel-vm`'s local coordinator
runner when a built `stoffel-run` binary is available:

```rust
use stoffel::prelude::*;

# async fn example() -> stoffel::Result<()> {
let result = Stoffel::compile(
    "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
)?
.parties(5)
.threshold(1)
.execute_local()
.await?;
# Ok(())
# }
```

`crates/stoffel-bindgen` complements the SDK by generating typed Rust bindings
for a Stoffel program at build time, so host code can call into compiled
programs with a checked interface.

## Stoffel VM

`stoffel-vm` is a register machine optimized for MPC. The register design keeps
execution predictable and maps cleanly onto optimized runtimes and physical MPC
backends. It supports basic values (integers, booleans, strings, floats) and
complex runtime types (objects, arrays, closures, foreign objects, and secret
shares), and has a closure system with true lexical scoping where functions
capture upvalues from their surrounding environment.

Stoffel supports Rust ⇆ Stoffel FFI out of the box, so you can extend the
runtime with native Rust functions and objects while keeping the execution model
intact. A configurable hook system can intercept instruction execution, register
access, stack events, object/array access, closure creation, and more for
debugging or instrumentation.

HoneyBadger and AVSS MPC backends are built by default. Distributed party runs
select the backend from the compiled `.stflb` program manifest.

### Embedding the VM directly

The most direct low-level use of the runtime is to embed it in a Rust program
and register `VMFunction` values. `VirtualMachine::new()` automatically registers
the standard library and MPC builtins. (Most applications should prefer the SDK
above; this is the raw API.)

```rust
use std::collections::HashMap;

use stoffel_vm::core_types::Value;
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;

fn main() -> Result<(), String> {
    let mut vm = VirtualMachine::new();

    let hello_world = VMFunction::new(
        "hello_world".to_string(),
        vec![],
        vec![],
        None,
        2,
        vec![
            Instruction::LDI(0, Value::String("Hello, World!".to_string())),
            Instruction::PUSHARG(0),
            Instruction::CALL("print".to_string()),
            Instruction::LDI(1, Value::Unit),
            Instruction::RET(1),
        ],
        HashMap::new(),
    );

    vm.try_register_function(hello_world)?;

    let result = vm.execute("hello_world")?;
    println!("Program returned: {:?}", result);

    Ok(())
}
```

Good places to explore next:

1. `crates/stoffel-vm-types/examples/generate_client_mul_program.rs` — a bytecode-generation example
2. `crates/stoffel-vm/src/tests/vm_mpc_integration.rs` — VM + MPC execution flows
3. `crates/stoffel-vm/src/tests/p2p_integration.rs` — QUIC transport coverage

### Instruction Set

**Memory Operations**

- `LD(dest_reg, stack_offset)`: Load a value from the current activation record into a register
- `LDI(dest_reg, value)`: Load an immediate value into a register
- `MOV(dest_reg, src_reg)`: Move a value from one register to another
- `PUSHARG(reg)`: Push a register value as a function argument

**Arithmetic Operations**

- `ADD`, `SUB`, `MUL`, `DIV`, `MOD` `(dest_reg, src1_reg, src2_reg)`

**Bitwise Operations**

- `AND`, `OR`, `XOR` `(dest_reg, src1_reg, src2_reg)`
- `NOT(dest_reg, src_reg)`
- `SHL`, `SHR` `(dest_reg, src_reg, amount_reg)`

**Control Flow**

- `JMP(label)`: Unconditional jump
- `JMPEQ`, `JMPNEQ`, `JMPLT`, `JMPGT` `(label)`: Conditional jumps
- `CMP(reg1, reg2)`: Compare two registers
- `CALL(function_name)`: Call a function
- `RET(reg)`: Return from the current function with the value in a register

### Values

```
Value::I64/I32/I16/I8   — signed integers
Value::U64/U32/U16/U8   — unsigned integers
Value::Float(F64)       — 64-bit floating point
Value::Bool(bool)       — boolean
Value::String(String)   — string
Value::Object(ObjectRef)        — object table reference
Value::Array(ArrayRef)          — array table reference
Value::Foreign(ForeignObjectRef) — foreign object reference
Value::Closure(Arc<Closure>)    — closure with captured environment
Value::Unit                     — unit/void/nil
Value::Share(ShareType, ShareData) — secret-shared value for MPC
```

### Standard Library Builtins

General runtime builtins registered by default:

- `print` / `type`: print values; get a value's type as a string
- `create_object` / `create_array`: create an object or array
- `get_field` / `set_field`: get/set a field on an object or array
- `array_length` / `array_push`: length of an array; append values
- `create_closure` / `call_closure`: create and invoke closures
- `get_upvalue` / `set_upvalue`: read/update captured upvalues
- `ClientStore.*`: client slot counts and `take_share` / `take_share_fixed`
- `MpcOutput.send_to_client`: send a share result to a client

MPC-focused, module-style builtins:

- `Share.*`: clear-to-share conversion, arithmetic on shares, opening, random share generation, client output, local interpolation, and commitment inspection
- `Mpc.*`: runtime MPC metadata such as party id, threshold, instance id, readiness, and randomness helpers
- `Rbc.*`: reliable broadcast helpers
- `Crypto.*`: hashing and curve/field conversion helpers
- `Bytes.*`: byte-array helpers
- `Avss.*`: AVSS-specific helper functions

### Compiled Bytecode

Stoffel ships a portable compiled binary format through
`stoffel-vm-types::compiled_binary::CompiledBinary`. The format uses the magic
bytes `STFL` and round-trips between `VMFunction` definitions and serialized binaries.

```rust
use stoffel_vm_types::compiled_binary::{utils::save_to_file, CompiledBinary};

// Assume `functions: Vec<VMFunction>` already exists.
let binary = CompiledBinary::from_vm_functions(&functions);
save_to_file(&binary, "program.stflb").unwrap();
```

## VM Runner CLI (`stoffel-run`)

`stoffel-vm-runner` provides `stoffel-run`, which executes a compiled Stoffel
bytecode file locally or as part of a distributed MPC session.

```bash
cargo build --release -p stoffel-vm-runner
cargo run -p stoffel-vm-runner --bin stoffel-run -- --help
```

Run a compiled program locally (default entry function is `main`):

```bash
./target/release/stoffel-run path/to/program.stflb
./target/release/stoffel-run path/to/program.stflb main --trace-instr
```

Run one party of a 3-party MPC session. Every party is spelled the same way:
its own certificate and key, the coordinator it pins and the execution it
serves, the other parties' addresses as seed hints, and a persistent epoch store
of its own. The coordinator is the only roster authority: the party fetches the
node roster (the node certificates and `t`) from it once, before it binds
anything, and refuses to run if its own certificate is not one of them.

```bash
COORD="--off-chain-coord 127.0.0.1:31415 --coord-cert coordinator.crt --execution-id $EXEC"

./target/release/stoffel-run path/to/program.stflb main \
  --party-id 0 \
  --bind 127.0.0.1:9001 \
  $COORD \
  --cert node0.crt --key node0.der \
  --rpc-bind 127.0.0.1:10001 \
  --peers 127.0.0.1:9002,127.0.0.1:9003 \
  --epoch-store /var/lib/stoffel/epochs-0
```

Join as another party — the same command line with its own identity, bind
address, peer list and epoch store:

```bash
./target/release/stoffel-run path/to/program.stflb main \
  --party-id 1 \
  --bind 127.0.0.1:9002 \
  $COORD \
  --cert node1.crt --key node1.der \
  --rpc-bind 127.0.0.1:10002 \
  --peers 127.0.0.1:9001,127.0.0.1:9003 \
  --epoch-store /var/lib/stoffel/epochs-1
```

Run in client mode to submit inputs: the client associates with the execution
through the coordinator, which decides its slot, input range and output count,
and its node legs — `--servers` are the parties' `--rpc-bind` listeners — are
pinned to the node roster the coordinator serves. The client's certificate need
not appear in any configuration: under open admission any certificate holder
that pins the coordinator may bind a free slot:

```bash
./target/release/stoffel-run --client \
  --inputs 10,20 \
  $COORD \
  --cert client0.crt --key client0.der \
  --servers 127.0.0.1:10001,127.0.0.1:10002,127.0.0.1:10003
```

AVSS output-client mode can reconstruct private field outputs; the output
count is the client's admission:

```bash
./target/release/stoffel-run --client \
  --mpc-backend avss \
  --mpc-curve secp256k1 \
  --inputs 0x<sha256-tbs-digest-hex> \
  $COORD \
  --cert client0.crt --key client0.der \
  --servers 127.0.0.1:10000,127.0.0.1:10001,127.0.0.1:10002,127.0.0.1:10003,127.0.0.1:10004
```

Notes:

- Membership is the coordinator's node roster (docs/design/bootnode-elimination.md §9.D). A party opens one connection to the coordinator, pinned to `--coord-cert`, fetches the roster exactly once before it binds anything, checks that its own `--cert` is one of the nodes (exit 2 otherwise), and installs the roster's certificates — nodes only — as its transport's peer-certificate allowlist, so membership is enforced per connection by mTLS. The same connection then drives the coordinator's rounds; nothing re-fetches the roster. `n` and `t` are the roster's. `--expect-roster-digest <64-hex>` (`STOFFEL_EXPECT_ROSTER_DIGEST`), `--expect-n-parties` and `--expect-threshold` refuse (exit 2) a coordinator that serves another roster; they carry no certificate and can only refuse, never supply, membership. `--roster`, `--n-parties`, `--threshold`, `--expected-clients`, `--wait-for-clients`, `--client-roster`, `--client-input-count`, `--client-input-slots`, `--client-input-total`, `--timestamp`, `--client-index` and `--outputs` fail by name (exit 2), and the entrypoint refuses `STOFFEL_NODE_ROSTER`, `STOFFEL_N_PARTIES`, `STOFFEL_THRESHOLD`, `STOFFEL_TIMESTAMP`, `STOFFEL_EXPECTED_CLIENTS`, `STOFFEL_WAIT_FOR_CLIENTS`, `STOFFEL_CLIENT_INPUT_COUNT`, `STOFFEL_CLIENT_INDEX` and `STOFFEL_OUTPUTS` by name. Clients are admitted per execution by the coordinator and reach a party's RPC listener, never the mesh, so no party's allowlist ever names a client, and a client nobody knew about when the parties started can still take part (§9, decision 3).
- `--execution-id <64-hex>` names the program invocation this process joins, and is required with `--off-chain-coord` (and refused without it). The coordinator keys rounds, admissions, reserved mask indices, masked inputs and output shares on it, so every party and client of one invocation passes the same value, and a standing coordinator registers a new value for each later invocation; the all-zero value is reserved and rejected. There is no round driver: the coordinator applies a round once a quorum of the roster has proposed it, so every party proposes every transition. `--coord-driver` and `--leader` both fail by name, as do `STOFFEL_COORD_DRIVER` in the Docker flows.
- `--peers <addrs>` is how a party forms its session: the parties dial each other directly and agree the session — program, entry, execution, `n`, `t` and `instance_id` — all-to-all, with no bootstrap process anywhere. It requires `--off-chain-coord`, `--coord-cert` and `--execution-id` (membership is the coordinator's node roster, since a seed address carries no identity) and an epoch store (`--epoch-store <dir>` or `STOFFEL_EPOCH_STORE`, a persistent per-node directory, keyed by the roster digest, that keeps `instance_id` fresh across runs of one roster). There is no alternative: `--bootnode`, `--bootstrap`, `--leader`, `--no-program-upload`, `--nat` and `--stun-servers` were all removed, and each now errors with the replacement named rather than being silently ignored.
- `--party-id` is not an identity. Every party index is the node's rank in the lexicographic order of the coordinator roster's DER SubjectPublicKeyInfo bytes, computed locally and identically by every party, and the join refuses to proceed unless the roster's rank for this node and the transport's agree. The flag survives as the *label* on this node's on-disk state — the `--local-store` path and the `party-N.redb` volumes the compose stacks mount are named by it. It is not the key to that state: persistent storage is keyed by this node's certificate, so a node holding `cert0` opens `cert0`'s store whatever number it is given. Because certificate file names carry no ordering, `--party-id` and the derived rank routinely differ (they do in every shipped compose stack); the mismatch is reported once after the join and the run continues on the derived index.
- The seed list is hints, not membership: every dial is pinned to a roster certificate, so a wrong or hostile address costs one failed handshake and nothing else. A **missing** address is not as cheap. A first mesh forms out of dials alone, and the peer book is exchanged inside the join handshake — after the mesh is already complete — so peer exchange cannot supply an address the mesh needs in order to form; it is what lets a later join in the same process start from less. The requirement is per pair: for every two parties, at least one of them must hold a hint for the other. Listing all `n-1` peers at every party always satisfies it, and is what every shipped stack does; a shorter list is accepted but warned about, because the parties it leaves out have to dial this node themselves.
- `--coord-cert <path>` is the coordinator's DER certificate, and is required with `--off-chain-coord` (and refused without it). Coordinator `0.3.0` pins its key on every connection and has no unpinned client; a server presenting another key is refused with exit 13. In the Docker flows it is `STOFFEL_COORD_CERT`, which the entrypoint requires whenever `STOFFEL_COORD_ADDR` is set. A coordinator client (docs/design/bootnode-elimination.md §9.E.1) reads the execution summary before it associates, since an association is irrevocable, and refuses (exit 2) an execution of another program than `--expect-program-hash <64-hex>` (`STOFFEL_EXPECT_PROGRAM_HASH`), a roster its backend cannot reconstruct at, a slot whose outputs cannot be sealed under the bound, and a slot that does not take its `--inputs`; a slot table past its bounds or an aborted execution exits 13. It then associates with a client slot — its pre-registered one, its invitation's (`--invitation <json>`, `STOFFEL_INVITATION`), the one `--client-slot` (`STOFFEL_CLIENT_SLOT`) names, or under open admission the first free one — and its input range and output count are that admission, never a flag: `--client-index` and `--outputs` fail by name. A client of an output-only slot passes no `--inputs`. The coordinator's admission policies and the Docker coordinator's flags are described under [Docker Flows](#docker-flows). `LocalCoordinatorRunner` offers the same choice as `LocalAdmission::{PreRegistered, Open}`: under `Open`, `start()` returns a running coordinator whose `client_endpoint()` any client can pass to `run_offchain_client`.
- A coordinated party trusts the coordinator's decisions but checks what it serves (docs/design/bootnode-elimination.md §9.D.6, §9.D.7). Before preprocessing it refuses an execution summary registered for another program than the one it loaded, a roster too small for its backend, a slot whose sealed outputs exceed the bound, or a slot table that contradicts the program's manifest (exit 13); the coordinator wrapper therefore takes `--program <path>` in every shipped stack, not a placeholder `--hash`. Mask count and preprocessing are sized from the registration. Every party then agrees the frozen client admissions, and later the masked inputs exactly as delivered, with every other party over the mesh (`STOFFEL_ADMISSIONS_AGREED_V1` / `STOFFEL_INPUTS_AGREED_V1` digest barriers) before it releases a mask share or unmasks an input, so a coordinator that tells parties different things stops the run. Inputs are stored and outputs sent by the agreed client slot; outputs come only from `send_to_client` — a returned share is revealed by the parties, not broadcast to clients — and every run finishes the coordinator's `ProgramFinished` round. `--client-input-total` and `--client-input-slots` fail by name: the slot layout is the registration.
- The images contain no identity material. Every compose stack mounts certificates read-only one file at a time under `/app/ids`, gives each service only its own private key as a compose secret at `/run/secrets/<name>` (`STOFFEL_KEY`, `--server-key`), and publishes every port on `127.0.0.1` only: the keys under `ids/` are committed development fixtures, so a pin to them authenticates nothing on a reachable port. `crates/stoffel-vm-runner/tests/deployment_key_material.rs` enforces this (docs/design/bootnode-elimination.md §9.F.0). A real deployment mints each key on the host that uses it and distributes only certificates.
- `STOFFEL_PEERS` is the Docker flows' spelling of `--peers`, and it is required for every non-client role. The entrypoint emits `--bind`, an advertise address on the *same* port it binds, `--peers`, `--off-chain-coord`, `--coord-cert`, `--execution-id`, `--cert` and `--key`; a party without `STOFFEL_COORD_ADDR` and `STOFFEL_COORD_CERT` is refused. `STOFFEL_ROLE=leader` is now only a label on a stack's first service: no party drives the coordinator's rounds. Every shipped compose stack runs a coordinator and forms a mesh: `docker-compose.yml`, `docker-compose.mesh.yml`, `docker-compose.avss.yml`, `docker-compose.benchmark.yml`, both `docker-compose.coordinator.reserve-index*.yml` files and the two `crates/stoffel-lang/examples/docker-compose.*.yml` stacks. `docker-compose.mesh.yml` is the fully symmetric one — every service is `STOFFEL_ROLE=party`, because nothing distinguishes one party from another. `docker-compose.nat.yml` was deleted with the `nat` feature (design doc §4), which never worked: nothing read the flags it set, and the topology it shipped required the leader to be publicly reachable anyway.
- The entrypoint refuses `STOFFEL_AUTH_TOKEN`, `STOFFEL_BOOTSTRAP_ADDR`, `STOFFEL_ROLE=bootnode`, `STOFFEL_COORD_DRIVER`, `STOFFEL_ENABLE_NAT` and `STOFFEL_STUN_SERVERS` by name, and requires `STOFFEL_EXECUTION_ID` whenever `STOFFEL_COORD_ADDR` is set. A compose file that still sets one was configured for a topology that no longer exists, and starting anyway would turn that into a debugging session.
- There is no `BIND_PORT + 1000` advertise convention any more. A party binds one socket and advertises the port it bound; the pairing existed only because a leader ran a bootnode on one port and its own listener on the other, and it was removed from all four of its homes at once (`stoffel-run`, the local runner, `docker/entrypoint.sh`, and the `Dockerfile`'s `EXPOSE`).

Direct client mode — a client dialing the node mesh — was removed (docs/design/bootnode-elimination.md §9.E.3): `stoffel-run --client` without `--off-chain-coord` exits 2 naming the flags to pass. A client associates with an execution through the coordinator, and every node leg it opens is pinned to a member of the node roster the pinned coordinator serves. It presents its certificate to the coordinator and to the nodes' RPC listeners, and no node lists it.
- The CLI accepts any file path; this repository conventionally stores compiled fixtures as `.stflb`
- `--mpc-backend` supports `honeybadger` and `avss` for client mode; `.stflb` party runs use the backend recorded in the program manifest and reject conflicting CLI overrides
- `--mpc-curve` supports `bls12-381`, `bn254`, `curve25519`, `ed25519`, `secp256k1`, and `p-256` (`secp256r1`) for AVSS

## Docker Flows

Every compose stack runs a coordinator — the `docker/coordinator-wrapper` binary, built by `docker/coordinator.Dockerfile` — beside five parties (docs/design/bootnode-elimination.md §9.F). The coordinator is the only trusted party: it serves the node roster (membership), registers the one execution the stack runs (program hash, client slot table, admission policy, deadlines) and decides which clients take part. Everything else is the parties' mesh.

| Stack | Program (default) | Client slots (default) | Admission (default) | Client services |
|---|---|---|---|---|
| `docker-compose.yml` | AES-128 circuit | none (`STOFFEL_CLIENT_IO`) | `STOFFEL_ADMISSION`, `pre-registered` | `client0`, `client1` under `--profile clients` |
| `docker-compose.mesh.yml` | AES-128 circuit | none | as above | as above |
| `docker-compose.avss.yml` | `avss_keygen` | none; `1:2` for certificate signing | as above | `client0` under `--profile clients` |
| `docker-compose.benchmark.yml` | AES-128 circuit | none | as above | none |
| `docker-compose.coordinator.reserve-index.yml` | `client_sub_order` | `1:0,1:0` | `open`, deadlines 600 s / 900 s | `client0`, `client1` |
| `docker-compose.coordinator.reserve-index.preproc.yml` | override of the above for a restart check | | | |
| `crates/stoffel-lang/examples/docker-compose.coordinator.yml` | `mpc_share_arithmetic` | `1:1,1:0` | `pre-registered` (client 0's and client 1's certificates) | `client0`, `client1` |
| `crates/stoffel-lang/examples/docker-compose.mpc.yml` | `mpc_runtime_info` | none | as `docker-compose.yml` | none |

The coordinator service registers the parties' own `STOFFEL_PROGRAM` (`--program`), so a party refuses to run anything else, and it logs the digest of the roster it serves (`Serving node roster n=5, t=1, digest=…`). Passing that digest as `STOFFEL_EXPECT_ROSTER_DIGEST` makes every party and client of the stack refuse a coordinator that serves any other roster; it is the only check that does not trust the coordinator's roster (§9 trust boundary). `docker/test-coordinator-reserve-index.sh` and `docker/test-coordinator-preproc-store.sh` pass the §9.B golden digest of `ids/nodes`.

**Admission.** A party is never told a client certificate, a client count or a slot. The coordinator's flags, set through these variables where a stack exposes them:

| Coordinator flag | Variable | Meaning |
|---|---|---|
| `--client-io <in:out,...>` | `STOFFEL_CLIENT_IO` | one client slot per entry, in slot order |
| `--admission <pre-registered\|open\|invitation>` | `STOFFEL_ADMISSION` | default `pre-registered`, never `open` |
| `--client-certs <paths>` | `STOFFEL_CLIENT_CERTS` | `pre-registered` only: the certificate bound to each slot, in slot order |
| `--invitation-issuer-cert <path>` | `STOFFEL_INVITATION_ISSUER_CERT` | `invitation` only: the key that signs invitations; refused if it is a roster node's or the coordinator's. Mount the certificate into the coordinator service. |
| `--association-deadline-secs`, `--input-deadline-secs` | `STOFFEL_ASSOCIATION_DEADLINE_SECS`, `STOFFEL_INPUT_DEADLINE_SECS` | seconds after the coordinator starts; required under `open` and `invitation`, after which an execution whose slots or inputs are missing is aborted |
| `--node-certs`, `--t` | `STOFFEL_THRESHOLD` for `--t` | the node roster; `n` is the number of certificates |
| `--max-connections` | | connections of identities that are neither roster nodes nor bound clients (default 4096) |

An empty value is the same as an absent flag, and a flag the chosen admission does not read makes the coordinator exit 2. Under `open`, a client whose certificate appears in no configuration at all binds a free slot (or the one `STOFFEL_CLIENT_SLOT` asks for) — this is how a computation takes clients that were not known in advance. For example, `docker-compose.yml`'s `client_mul` recipe, first pre-registered and then open:

```bash
STOFFEL_PROGRAM=/app/programs/client_mul.stflb STOFFEL_CLIENT_IO=1:0,1:0 \
STOFFEL_CLIENT_CERTS=/app/ids/clients/cert0.crt,/app/ids/clients/cert1.crt \
  docker compose --profile clients up --build

STOFFEL_PROGRAM=/app/programs/client_mul.stflb STOFFEL_CLIENT_IO=1:0,1:0 \
STOFFEL_ADMISSION=open STOFFEL_ASSOCIATION_DEADLINE_SECS=600 STOFFEL_INPUT_DEADLINE_SECS=900 \
  docker compose --profile clients up --build
```

A client container (`STOFFEL_ROLE=client`) needs `STOFFEL_COORD_ADDR`, `STOFFEL_COORD_CERT`, `STOFFEL_EXECUTION_ID`, `STOFFEL_SERVERS` (the parties' `STOFFEL_RPC_ADDR` listeners) and its own `STOFFEL_CERT` / `STOFFEL_KEY`; the entrypoint refuses it without them. `STOFFEL_INPUTS`, `STOFFEL_CLIENT_SLOT`, `STOFFEL_INVITATION`, `STOFFEL_EXPECT_PROGRAM_HASH` and `STOFFEL_EXPECT_ROSTER_DIGEST` are optional and map to the flags of the same names.

**Key material.** Certificates are mounted read-only, one file per mount, only where they are read: the coordinator gets the node certificates and, for the pre-registered recipes, the client certificates; a party gets the coordinator's certificate and its own; a client the same. Each service gets exactly its own private key as a compose secret, and every port is published on `127.0.0.1` only, because the keys under `ids/` are committed development fixtures. `crates/stoffel-vm-runner/tests/deployment_key_material.rs` enforces all of this, including that no party or client service is given another identity's certificate.

**Test scripts.** `docker/test-coordinator-reserve-index.sh` runs the open-admission stack and checks that every party reveals `client[0] - client[1]` (`-10`; `STOFFEL_CLIENT0_SLOT=1 STOFFEL_CLIENT1_SLOT=0 EXPECTED_OUTPUT=10` flips it), that the coordinator registered open admission and served the expected roster, and — from the containers' actual mounts — that no party or client held any identity but its own and the coordinator's pin. `docker/test-coordinator-preproc-store.sh` runs the same stack twice over the same per-party volumes and checks that no preprocessing material is persisted or loaded (no preprocessing item may serve two executions, §9.C.9) and that the second run's session `instance_id` differs from the first's (the persisted epoch, blocker B5). `crates/stoffel-lang/examples/run_coordinator_compose.sh` runs the examples coordinator stack and checks the client's output and the parties' mounts.

The AVSS stack covers AVSS curves and local share storage:

```bash
docker compose -f docker-compose.avss.yml up --build
```

`docker-compose.avss.yml` mounts a per-party local data volume and forwards `STOFFEL_LOCAL_STORE` to `stoffel-run`.

The AVSS threshold ECDSA examples mirror the threshold signature fixtures:

```bash
STOFFEL_PROGRAM=/app/programs/threshold_ecdsa_secp256k1.stflb \
STOFFEL_MPC_CURVE=secp256k1 \
docker compose -f docker-compose.avss.yml up --build

STOFFEL_PROGRAM=/app/programs/threshold_ecdsa_p256.stflb \
STOFFEL_MPC_CURVE=p-256 \
docker compose -f docker-compose.avss.yml up --build
```

The Stoffel source for these programs lives in `crates/stoffel-lang/examples/threshold_signatures/threshold_ecdsa_secp256k1/main.stfl` and `crates/stoffel-lang/examples/threshold_signatures/threshold_ecdsa_p256/main.stfl`. The VM only provides primitive helpers for field inversion, converting an opened curve point to `x mod q`, and formatting the final ECDSA output. The threshold ECDSA protocol itself is expressed in the Stoffel program. The returned layout is fixed-width big-endian `r(32) || s(32) || sec1_compressed_pk(33)`, so callers can DER-encode `(r, s)` directly.

For the AVSS certificate-signing path, run `/app/programs/avss_certificate_keygen.stflb` with `STOFFEL_MPC_CURVE=secp256k1` or `STOFFEL_MPC_CURVE=p-256` to persist each party's CA signing share. Keygen is idempotent: it loads the existing share if the storage key already exists and only generates on first use. Then run `/app/programs/avss_certificate_sign.stflb` with `STOFFEL_CLIENT_IO=1:2 STOFFEL_CLIENT_CERTS=/app/ids/clients/cert0.crt STOFFEL_CLIENT0_INPUT=0x<sha256-tbs-digest-hex>` and `--profile clients`: the coordinator registers client 0's slot (one input, two outputs), the parties are given no client certificate, and the `client0` service submits the digest through the coordinator and reconstructs fixed-width threshold ECDSA `r || s` material from the sealed outputs its admission grants. The corresponding Stoffel source lives in `crates/stoffel-lang/examples/avss_certificate/keygen/main.stfl` and `crates/stoffel-lang/examples/avss_certificate/sign/main.stfl`.

### Building the images before `stoffel-mpc-coordinator` 0.3.0 is published

The roster and admission contract lives in `stoffel-mpc-coordinator` `0.3.0`, which is not on crates.io yet. Until it is, the root `Cargo.toml` and `docker/coordinator-wrapper/Cargo.toml` carry a temporary `[patch.crates-io]` pointing at a local checkout of it, by absolute path (docs/design/bootnode-elimination.md §9.F.5). A Docker build context cannot see that path, so:

- Every image is built with a BuildKit named context `coordinator` that holds the `0.3.0` checkout, and every Dockerfile copies it to the patch path before cargo resolves the workspace (`Dockerfile`, `Dockerfile.benchmark`, `docker/coordinator.Dockerfile`). Every compose build block declares it from `STOFFEL_COORDINATOR_CONTEXT`, and compose refuses to start a stack without it:

  ```bash
  export STOFFEL_COORDINATOR_CONTEXT=/path/to/stoffel-mpc-coordinator   # the 0.3.0 checkout
  docker compose up --build
  ```

  The test scripts also accept `STOFFEL_COORDINATOR_DIR`. Outside compose, pass it yourself: `docker build --build-context coordinator=$STOFFEL_COORDINATOR_CONTEXT -f docker/coordinator.Dockerfile .`
- A plain `docker build .` without that context fails, and so does CI's `docker-build` job, which has no way to reach a checkout on a developer machine. The Rust CI jobs fail for the same reason: the patch path exists on one machine only. That is the expected state of an unreleased dependency, and it ends when `0.3.0` is published, the `[patch.crates-io]` tables and the `COPY --from=coordinator` lines are deleted, and both lockfiles are re-locked.
- `cargo publish` of `stoffel-vm-runner` and `stoffel-rust-sdk` fails for the same reason until then.

### Still open

- `stoffel-run --preproc-store` still persists HoneyBadger preprocessing material and loads it on the next run (stage V-0 of §9.1 is not done): a stored item could then serve a second execution. The entrypoint refuses `STOFFEL_PREPROC_STORE` and no stack sets it; do not pass the flag directly.
- The node binary still contains the branches for parties without a coordinator and for direct clients. Both are refused before they are reached, and their deletion (stage V-c) is not done.
- `crates/stoffel-lang/examples/run_mpc_local.sh` runs its host-process parties against the wrapper binary as a host-process coordinator rather than through `stoffel run --local` (§9.F.2), because the local runner requires every party to return the same value and that script's default program does not.
- Invitation admission has no shipped stack: a stack can register it (`STOFFEL_ADMISSION=invitation` with an issuer certificate mounted into the coordinator), and clients present an invitation with `STOFFEL_INVITATION`; the `issue-invitation` binary that signs one ships with the coordinator repository.

## C Foreign Function Interface

`stoffel-vm` builds as both an `rlib` and a `cdylib`, so the runtime can also be embedded from C-compatible environments.

Relevant files:

- `include/stoffel_vm.h`
- `include/README.md`

Platform-specific library names:

- Linux: `libstoffel_vm.so`
- macOS: `libstoffel_vm.dylib`
- Windows: `stoffel_vm.dll`

## Build and Test

Build everything:

```bash
cargo build
```

Run the test suite:

```bash
cargo test
cargo test -- --ignored
```

Build the runtime and CLI in release mode:

```bash
cargo build --release -p stoffel-vm -p stoffel-vm-runner
```

HoneyBadger and AVSS backend code is built by default. Distributed party runs
select the backend from the compiled `.stflb` program manifest.

## Roadmap

Stoffel is under active development. The following capabilities are planned or
in progress and are **not yet supported**:

- **Solidity / EVM integration** — `solidity-foundry` and `solidity-hardhat`
  project templates, and tooling for using Stoffel MPC outputs from on-chain
  smart contracts. Referenced in some docs, but not yet shipped.
- **Additional SDKs** — Python and TypeScript/WASM SDKs to complement the Rust
  SDK. The C FFI surface exists today; higher-level language bindings are still
  in progress.
- **Persistent / long-running MPC networks** — keeping nodes and the coordinator
  warm across runs with ahead-of-time preprocessing, so repeated runs pay only
  the online cost.
- **Hosted / managed deployment** — turnkey deployment of MPC party networks
  beyond the local runner and Docker Compose stacks.

Have a use case you don't see here? Open an issue or reach out — priorities are
shaped by what people are building.

## Learn More

To learn more about what you can build with Stoffel, visit
[stoffelmpc.com](https://stoffelmpc.com).
