# Eliminating the Bootnode: Roster-Pinned Mesh + Coordinator

Status: implemented in both repositories, except where §9.I says otherwise. §9.I is the
status of record; the rest of this document is the contract the code was built to, and the
few places where the code deliberately differs are listed there.
Branch: `claude/bootnode-elimination-mesh-146b80` (VM),
`claude/coordinator-roster-admission` (`stoffel-mpc-coordinator`).

Rule applied throughout: functionality that genuinely needs a trusted party moves to the
**coordinator**; everything else becomes **mesh** behavior in the VM nodes. Nothing is
kept under a new name.

## 1. What the bootnode actually is

The bootnode reaches production through exactly **one** function:
`register_and_wait_for_session` (`crates/stoffel-vm/src/net/discovery.rs:633`), called from
two sites in `crates/stoffel-vm-runner/src/bin/stoffel-run.rs` (`:4263` leader, `:4358` party).

Everything else that is bootnode-shaped has **zero production callers** and is deletable
without replacement:

- `bootstrap_with_bootnode` (`discovery.rs:205`)
- `agree_session_with_bootnode` (`session.rs:162`) — cannot even talk to this bootnode: it
  frames on `CONTROL_STREAM_ID` while the bootnode reader only reads the default stream
- `agree_and_sync_program` (`program_sync.rs:237`) and the whole `ProgramFetch` path
- the entire `nat` feature

### Why it exists at all

One technical reason. stoffelnet's accept path rejects an unknown inbound server peer under
`use_tls` unless a certificate allowlist is configured
(`stoffelnet-0.1.1` `quic.rs:3384-3402`), so the bootnode must relay `SessionInfo.tls_ids`
to pre-seed `self.nodes`.

**A single public API removes that need**, and it is currently unused:

| API | Location | Call sites in `crates/` |
|---|---|---|
| `install_expected_server_public_keys` | `quic.rs:1273` | **0** |
| `public_key_from_certificate_der` | `quic.rs:1268` | **0** |
| `connect_as_server_with_expected_public_key` | `quic.rs:2162` | **0** |
| `add_allowed_certificate_public_key` | `quic.rs:1442` | **0** |
| `is_party_connected` (reconnection) | `quic.rs:1605` | **0** |

Installing the allowlist makes the accept path take its allowlist branch, which
auto-registers the peer from its observed `remote_addr`. Addresses then stop being
security-relevant — a wrong address fails mTLS — so they become freely gossipable.
Party indices are already derived locally from sorted SPKIs (`assign_party_ids`,
`quic.rs:1922`); `stoffel-run.rs:4717-4719` explicitly *discards* the bootnode-assigned id.

## 2. Responsibility map

| Responsibility | Today | New home | Mechanism |
|---|---|---|---|
| TLS-id relay (`SessionInfo.tls_ids`) | `discovery.rs:86-90,672-683` | **deleted** | `install_expected_server_public_keys(roster)` |
| Admission control (`STOFFEL_AUTH_TOKEN`) | `discovery.rs:128-163` | **deleted** | membership *is* the cert allowlist, enforced per-connection by mTLS |
| Client admission | *no check today* | **mesh** | roster carries a `clients` SPKI set (see Blocker B1). *Superseded: the coordinator's per-execution admission (§9.C); client keys never enter the node allowlist.* |
| Peer address directory | `bootnode.rs:96-123` | **mesh** | unsigned `PeerRecord` gossip (PEX); forged address fails the cert check |
| Party index assignment | `discovery.rs:877-882` | **mesh** (already) | sorted SPKIs, unchanged |
| Quorum barrier | `bootnode.rs:150-227` | **mesh** | `net.is_fully_connected(n)` |
| Session params (n, t, entry, program) | `bootnode.rs:186-192` first-registrant-wins | **mesh** | all-to-all `JoinCommit` digest equality |
| `instance_id` freshness | `bootnode.rs:192` random nonce | **mesh** | LMDB monotone epoch, bounded `max(proposals)` |
| Program byte custody | `bootnode.rs:125-139` | **deleted** | provably dead (see §3) |
| Program↔execution binding | `bootnode.rs:161-162` | **coordinator** | `ExecutionRegistration.program_hash` |
| `SessionAnnounce` / `SessionAck` / `Heartbeat` | `bootnode.rs:304-330,674-691` | **deleted** | replaced by a real barrier generalizing `HB_PREPROCESSING_READY_PREFIX` |
| ICE signaling relay + `nat` feature | `bootnode.rs:332-350,409-449` | **deleted** | see §4 |
| Mesh formation choreography | `discovery.rs:743-882` | **mesh** | moved verbatim, re-anchored on SPKI rank |
| Peer dial + backoff (2 near-duplicates) | `discovery.rs:247-310`, `:484-545` | **mesh** | one `dial.rs` + reconnect supervisor |
| Roster (which SPKIs are the session) | *nothing — whoever has the token* | **coordinator** (opt-in) | `--roster` cert files by default. *Superseded: coordinator, required, `get_node_roster` (§9.B).* |

### The bootnode's program distribution is dead code

Party mode hard-exits without a local program (`stoffel-run.rs:4310-4314`), no client ever
constructs `ProgramFetchRequest`, and `program_id_matches_bytes` (`bootnode.rs:710-712`)
uses bare `blake3::hash` against a *domain-separated* id (`b"stoffel-program-v1"`,
`program_sync.rs:128-133`) — so every honest upload fails validation and is silently dropped.

Related: the untagged trial decode across three message enums (`bootnode.rs:352-360`) means
`DiscoveryMessage` variants 2/3 and `ProgramSyncMessage` variants 2/3 encode to byte-identical
bincode frames. `ProgramSyncMessage::ProgramFetchRequest` always dispatches to the
`DiscoveryMessage` arm; `bootnode.rs:659-665` is unreachable for that variant.

## 3. Trust boundary

*Rewritten by §9 revision 2 (2026-09-16). This section used to describe an optional
coordinator trusted for two statements beside an offline `--roster` path, to claim that a
malicious coordinator "cannot … make a node dial an impostor", and to call the change
"strictly better on every axis". §9 made the coordinator the only roster authority and
removed the offline path, so none of those claims holds any more, and they are not kept
here. §9.G is the trust table; this section is its summary.*

The coordinator — the process, whoever operates it, and an invitation issuer beside them
(§9) — is trusted for exactly three things, in every deployment, because every deployment
runs one:

1. **Membership** — the node roster: which SPKIs are the `n` parties, and `t` (§9.B).
2. **Executions** — which `ExecutionId`s exist and which program each runs (§9.C.1).
3. **Admission** — which client identities take part in each execution, in which slot
   (§9.C).

It is **not** trusted for: party indices (each node sorts SPKIs itself), addresses (a wrong
address is a liveness failure only), program bytes (nodes check the registered hash against
the program they loaded, §9.D.7), `instance_id` (a local epoch plus the roster digest,
§9.D.5), round advancement beyond its structural preconditions, any MPC message, or the
integrity of a client's inputs and outputs (clients sign their submissions and nodes sign
the output shares they seal, §9.C.7).

**Trusting the coordinator's roster is trusting it with client input privacy.** A
malicious coordinator can serve a node, or a client, a roster of its own keys. Nodes detect
a roster that differs between them only when they appear in each other's served roster,
because every agreement travels over the mesh a node formed from the roster it was served;
a coordinator that partitions the nodes and pads each part with keys of its own **does**
make a node dial an impostor. A client pins its node legs to whatever roster it was served,
so a coordinator that serves a client its own keys receives that client's inputs and can
forge its outputs. The only defence is a node or client that knows the intended roster and
passes `--expect-roster-digest` (§9.D.2), which turns a substituted roster into a refusal;
without it, the coordinator's roster is trusted with client input privacy and nothing in
this design detects otherwise.

**There is no offline path.** The `--roster` + `--epoch-store` mode that formed and ran a
session with no coordinator contact is removed (§9.D.2, §9.E.3). A deployment whose
coordinator is unreachable does not run.

**Against the bootnode it replaces**, the change is better on membership and admission, and
it concentrates a different power. Better: the bootnode's admission control was
`STOFFEL_AUTH_TOKEN`, a symmetric bearer string over a `use_tls: false` link
(`discovery.rs:190`) that `registration_token_is_valid` (`discovery.rs:145-151`) accepted
whenever the variable was unset — fail-open — and `handle_register` set `my_party_id` from
the client's own assertion (`bootnode.rs:496`); now every connection is authenticated by key
and every client leg against the served roster. Different: one authenticated service now
defines membership for every node and every client, which is why the coordinator's
certificate is pinned (§9.A), why its private key must exist only where it runs (§9.F.0), and
why `--expect-roster-digest` exists.

## 4. NAT decision: delete the feature

The `nat` feature has never worked and nothing depends on it.

- No code anywhere sets `QuicNetworkConfig.enable_nat_traversal` or `.stun_servers`, so
  `is_nat_traversal_enabled()` is always false.
- `--nat` / `--stun-servers` parse into `_enable_nat` / `_stun_servers`
  (`stoffel-run.rs:3630-3631`) with **zero read sites**; neither appears in `--help`.
- `Dockerfile:47` builds `--features nat`, but `crates/stoffel-vm-runner/Cargo.toml` has **no
  `[features]` table at all**. That build cannot succeed. (It sits inside an `ENABLE_NAT`
  conditional, which is presumably why nobody noticed.)
- The shipped path is not ICE: it discards `ufrag`/`pwd` (`discovery.rs:394-395`), runs no
  connectivity checks and no simultaneous-open punching.
- The bootnode relay is lossy by construction: a 256-slot `tokio::broadcast` drained with
  `try_recv`, treating `Lagged` identically to `Empty`.
- `docker-compose.nat.yml` requires the leader to be publicly reachable — the only NAT
  topology shipped is one where ICE is unnecessary.

**If consumer-NAT parties become real:** mesh-relayed signaling first. stoffelnet's *real*
ICE is already present and unused (`connect_p2p`, `handle_p2p_request`,
`connect_with_fallback`), and `connect_with_fallback` takes `signaling_connection` as an
explicit parameter — upstream never assumed a bootnode. Coordinator as cold-start fallback
only. **Never build a relay/TURN**: it would carry the full MPC data plane for the relayed
pair, a strictly stronger centralization position than the bootnode ever held.

## 5. Staged migration

Stages 0-8 deliver a fully bootnode-free deployment with **zero coordinator changes and zero
dependency bumps**. Coordinator work (9, 11) is last and optional. *(Stage 11 is no longer
optional; see §9.)*

| # | Stage | Repo | Net effect |
|---|---|---|---|
| 0 | Characterization harness + visibility fixes | VM | no behavior change |
| 0a | Bootnode session-replay fix (`send_ready_session_if_waiting`) | VM | **behavior change**, independently revertible |
| 1 | `SessionJoin` seam; bootnode becomes one impl | VM | no behavior change |
| 2 | Extract mesh formation; real connectivity barrier | VM | dedupe + `tls_id` downgrade fix |
| 3 | **Roster pinning** — cert identity replaces the bearer token | VM | security win, no dep bump |
| 4 | Mesh wire + PEX + `MeshRouter` in **both** backends | VM | gossip + reconnection |
| 5 | `join_mesh` — first bootnode-free path, side by side | VM | both paths exercised |
| 6 | Split `--leader` into its two unrelated meanings | VM | **pure rename, no deletion** |
| 7 | Flip every deployment surface to the mesh | VM | no code deletion |
| 8 | **Delete the bootnode** | VM | -2327 lines |
| 9 | Bump coordinator pin `=0.1.0` → `=0.2.0`; drop round-driver | VM | breaking — **done**, see below |
| 10 | Delete legacy in-VM QUIC stack (`net/p2p.rs`) | VM | -1164 lines — **done**; the close-out also deleted `net/mesh/form_mesh.rs` and the `PeerDialer` / `DirectDialer` / `PinnedDialer` seam, whose only caller was the bootnode's announced-party-list formation |
| 11 | Coordinator-issued node roster and client admission — **required since 2026-09-16, contract in §9** (was *optional*: coordinator-issued roster and session start) | both | every deployment (was: dynamic deployments only) |

### What Stage 7 flipped, and what Stage 8 inherits

Stage 7 is done when a default `docker compose up`, a default `stoffel run --local`
and a default SDK local run all form a mesh. That is now true, with two recorded
exceptions Stage 8 owns:

| Surface | State after Stage 7 | Why |
|---|---|---|
| 6 compose stacks + `docker-compose.yml` | mesh by default, `STOFFEL_PEERS=` falls back | — |
| `docker-compose.mesh.yml` | mesh only, no fallback | the symmetric reference |
| `docker-compose.nat.yml` | **bootnode by default** | its peer addresses are public IPs with no defaultable value, and a one-sided seed list cannot form a tournament-dialed mesh (below). §4 deletes this stack rather than flipping it. |
| `stoffel run --local`, `stoffel dev`, `stoffel test --local` | mesh by default, `--bootnode` opts out | — |
| `LocalTopology::default()` (CLI + SDK `execute_local_*`) | `RosterMesh` | the runner mints the roster and epoch stores itself, so the flip costs a caller nothing |
| `ServerTopology::default()` (`stoffel-rust-sdk/src/server.rs`) | **`LeaderBootnode`** | a mesh server needs `--roster` and an epoch store the caller must supply, so flipping the default is a hard break — which §8 rules out for the SDK. Stage 8 removes the variant instead, at which point the SDK's required arguments change with the rest of its break. |

### A pair is dialed from one end only

Stage 5's mesh let both ends of a pair dial, and stoffelnet resolves the
resulting duplicate by closing one connection — including one a peer is already
streaming its join handshake over (`quic.rs:2262-2288` dialer side,
`:3411-3441` acceptor side). A five-party mesh failed about one run in three on
that. `net::mesh::join::dials_towards` makes the dial partition a tournament on
`NodePublicKey::derive_id`, the same order the transport's own tie-breaker uses,
so the surviving connection is the one that would have survived anyway and no
duplicate is ever created between roster members.

There is no timed escape hatch for the losing side. One was tried
(`dial_grace`: dial out of turn after a rank had been missing 15s) to keep the
seed-coverage requirement stated over pairs rather than directions, and it
re-created the same duplicate in the shape deployments actually produce — a
party gated behind another's healthcheck is grace-dialed by peers that gave up
waiting at the same moment it dials them. The rule is therefore absolute, and
the cost is a narrowed contract:

> **Seed coverage is directional.** For every pair, the member with the higher
> transport-derived id must hold a hint for the other. Derived ids are BLAKE3
> digests, so pass every party the full `n - 1` peer list unless you have worked
> the direction out; `build_session_join` warns on a short list and discovery's
> timeout names which half of the requirement was unmet.

Stage 0a exists because Stage 0's harness cannot assert blocker B5 against a bootnode that
replays its previous announcement, and because that replay is itself an `instance_id` reuse.
It is carved out of Stage 0 rather than folded into it so that Stage 0's "no behavior change"
stays literally true and the fix can be reverted on its own.

Stage 0 is non-negotiable: **no regression cover exists today.** `.github/workflows/ci.yml`
skips `leader_bootnode_integration`, `p2p_integration`, `vm_mesh_integration`,
`vm_mpc_integration` and `mpc_multiplication_integration` — every bootstrap-adjacent test.
And `leader_bootnode_integration.rs` contains no bootnode code at all: it hardcodes
`instance_id = 77779` at `:283` and builds the mesh directly.

Stage 6 before Stage 8 is also non-negotiable. `--leader` means two unrelated things, and its
*second* meaning — the coordinator round driver (25 `as_leader` sites) — is the only caller of
`start_preprocessing` / `collect_inputs` / `start_mpc`. Published coordinator `0.1.0`'s
`transition` is hard leader-gated (`0.1.0/src/lib.rs:1513-1526`, `NotDesignatedParty`);
quorum transitions exist only in `0.2.0` (`transition_quorum`, `:1186`). Deleting `--leader`
before the bump hangs every coordinator run at `Round::Idle`.

## 6. Blockers — must be handled or the migration silently breaks

**B1. The cert allowlist rejects MPC clients, not just unknown nodes.**
`extract_and_verify_peer_public_key` runs at `quic.rs:3292`, *before* the
`match connection_role` branch at `:3352`, and `allowed_peer_public_keys` is an
`Arc<DashSet>` shared across `net.clone()`. `setup_hb_party_for_curve`
(`stoffel-run.rs:2353`) and `setup_avss_party_for_curve` (`:2810`) clone the mesh manager, so
a node-only roster rejects **every client**. The roster must carry a `clients` set.
*Reversed by §9: client keys never enter the node allowlist, and the start of §9 records why
that is also a transport-security requirement.*

**B2. SPKI byte-shape mismatch.** stoffelnet builds `NodePublicKey` from
`cert.public_key().raw` (full SPKI DER, `quic.rs:1768`); the VM's `extract_pubkey_from_cert`
(`stoffel-run.rs:209-217`) returns `subject_public_key.data` (the bare BIT STRING). *Different
bytes from the same certificate.* Use `public_key_from_certificate_der`, never the VM helper.
This also means the coordinator's existing `--initial-mpc-nodes` is already in the wrong shape
for Stage 11 — a schema change, not an added method.

**B3. An empty allowlist silently disables enforcement.**
`verify_peer_public_key_allowed` (`quic.rs:1791-1796`) returns `Ok(())` when the set is empty.
A roster-parse bug yields a mesh with *no* peer authorization rather than a loud failure.
Assert non-empty and `>= nodes.len()` after install — **not** `== nodes + clients`:
`set_allowed_certificate_public_keys` clears first (`:1445-1448`) and
`install_expected_server_public_keys` dedupes by `derive_id()`, so exact cardinality fails
whenever a client SPKI equals a node SPKI (the `local_runner` single-host dev case).

**B4. The node must authenticate the coordinator.** `SelfSignedServerVerifier::verify_server_cert`
in the coordinator's `self_signed_certs.rs` accepts **any** server certificate. Stage 11 would
elevate that channel to *the* authenticated statement of membership; a fake coordinator has no
`mpc_nodes` roster to be bounded by and could serve a roster of attacker SPKIs that every node
then installs as its allowlist. Stage 11 requires `--coord-cert` SPKI pinning. *Specified in
§9.A.*

**B5. `instance_id` must not derive from the roster digest alone.** Roster and program are
constant across runs, so `instance_id` would be constant — and it is the MPC session namespace
(`net/mpc/protocol_ids.rs:5-14`). Today's `random_instance_id` gives 64 bits of per-run
freshness. Use an LMDB monotone epoch, and **bound** `max(proposals)` by
`last + MAX_EPOCH_JUMP` or one Byzantine member proposing `u64::MAX` permanently bricks every
honest store.

**B6. AVSS does not use `spawn_receive_loops_split`.** It calls `try_handle_wire_message`
directly at `avss_server.rs:703` and `:821` in its own loops. `MeshRouter` must be installed
there too, and at `hb_server.rs:216`/`:321` as well as `:466`/`:616` — four HB sites, not two.
Also `avss_server.rs:348-352` `add_peer` returns `()` and **silently no-ops after start**
(unlike `hb_server.rs:143-157`, which returns `AlreadyStarted`); PEX-learned peers would vanish
without error.

**B7. `MESH_CTRL_PREFIX` must be disjoint from four existing in-band prefixes** on the same
framed stream: `OPN1`, `XOP1`, `AXOP`, `AXG2` (`net/open_registry/wire.rs:6,12,14,16`) plus
`HB_PREPROCESSING_READY_PREFIX` (`stoffel-run.rs:198`). State and test the invariant.

**B8. The local coordinator checkout is a divergent fork, not a newer version.**
`/Users/gabriel/RustroverProjects/stoffel-mpc-coordinator` is on branch
`codex/persistent-execution-coordination` (`5e66dea`), crates still at version `0.1.0`, with
`InputAssignment {input_slots}` versus published `0.2.0`'s `{clients, ranges}`, plus
uncommitted `Cargo.toml`/`Cargo.lock`. **Design Stage 9 against published `0.2.0` only.**

## 7. Coverage gaps found by the completeness critic

These are files and behaviors the first-pass plan missed. They are part of the work.

- **`docker/coordinator-wrapper/`** is **its own workspace** (`[package]` + `[workspace]`, own
  lockfile). `cargo build --workspace` cannot see it; only `docker compose build` catches it.
  It implements `CoordinatorConnection` over `0.1.0`'s *generic*
  `CoordinatorRPCServerSharedBase<S::ValueType>`; `0.2.0`'s is non-generic (`:1021`), so
  Stage 9 is a rewrite there, not a version bump.
- **`crates/stoffel-cli/`** — `stoffel run --local`, `stoffel dev`, `stoffel test` all ride
  `local_runner`'s `PartyRole::Leader{bootnode}` (`main.rs:903,1262,1282,1344`). Stage 8
  deletes the flags that path emits. **No stage currently covers it.**
- **Root `tests/p2p_integration.rs`** (326 lines) imports the `net/mod.rs:126-129` re-export
  Stage 10 deletes. Orphaned by the virtual manifest, so no build break — but Stage 10's
  `rg 'net::p2p' crates/` misses it. **Resolved in Stage 10: deleted**, not retargeted — its
  transport cover now lives in `crates/stoffel-vm/src/tests/p2p_integration.rs`, which runs
  against stoffelnet's `QuicNetworkManager` and is compiled and run by CI.
- **8 compose files, not 7.** `docker-compose.coordinator.reserve-index.preproc.yml` is a
  change target too. There is no top-level `examples/` directory; the path is
  `crates/stoffel-lang/examples/docker-compose.coordinator.yml`.
- **`Dockerfile:128-132`** carries a *fourth* copy of the `bind_port + 1000` convention
  (`EXPOSE 9000 10000` + comment) alongside `stoffel-run.rs:4231`, `local_runner.rs:1443`, and
  `docker/entrypoint.sh:154`. All four must change in one commit or ports go silently wrong.
- **`STOFFEL_AUTH_TOKEN` also appears in** `run_coordinator_compose.sh:12,27`,
  `docker/test-coordinator-reserve-index.sh:6,23`, `docker/test-coordinator-preproc-store.sh:8,23`
  — the latter two are *used as stage verification* but never edited.
- **README bootnode lines:** 398, 400, 409, 412, 423, 441, 451, 458, 467, 472.
- **`--advertise` has no owner.** `docker/entrypoint.sh:154-161` computes the leader's
  advertise port as `BIND_PORT+1000`. Removing +1000 from the Rust sites without redefining
  `ADVERTISE_PORT` makes every leader advertise a dead port.
- **`--party-id` is undecided.** Under SPKI-sorted indexing it is meaningless, but it selects
  party mode (`stoffel-run.rs:4303`), is passed by the SDK (`server.rs:752`), and **keys
  on-disk state** (`STOFFEL_LOCAL_STORE: /app/local-store/party-0.redb`). Keep as cross-check,
  remove, or keep as the storage key — must be decided.
- **Clients do not authenticate nodes.** The client manager
  (`stoffel-run.rs:1744 QuicNetworkManager::new()`) installs no allowlist, and the check is
  fail-open on empty. A client accepts *any* node certificate — and that is the leg carrying
  secret inputs. The roster fixes node↔node; this leg needs its own fix.
  *Resolved in Stage 3:* `run_as_client` now installs `--cert`/`--key` on its own manager and,
  given `--roster`, pins the node certificates through `Roster::install_for_client`, so the
  client refuses an unlisted node (`a_client_pinned_to_the_roster_refuses_a_node_outside_it`)
  and is itself nameable in a node's `--expected-clients`
  (`a_roster_pinned_node_refuses_a_client_that_brings_no_certificate`).
  *Superseded by §9.E: direct client mode and `Roster::install_for_client` are removed, and
  coordinator-mediated clients pin their node legs to the coordinator's roster.*
- **`request_shutdown` is an invented requirement.** Stage 9 keeps `--coord-driver` alive
  solely because `0.2.0` still gates it on `mpc_nodes[0]` — but
  `grep -rn request_shutdown crates docker` returns **zero hits**. The VM never calls it.
  Either add the call or let the flag die outright.
  *Resolved in Stage 9:* re-checked, still zero hits, so the flag died outright. Nothing in
  this repository uses `request_shutdown`, `start_coord_one_off` or
  `watch_for_shutdown_request`; the shipped coordinator is a standing listener that
  `docker compose down` stops. `--coord-driver`, `STOFFEL_COORD_DRIVER` and the SDK's
  party-0 special case are all gone, and `--coord-driver` now fails by name.
- **`receive_mask` does not exist in `0.2.0`** (only `0.1.0/src/lib.rs:203`), and `NodeRPCServer`
  is non-generic there. Stage 9 also touches `local_runner.rs:913,939,951,1021,1046,1058` and
  `stoffel-rust-sdk/src/client.rs:1158,1181,1191`, none of which the plan listed.
- **Stage 3 breaks the SDK's non-coordinator path.** `stoffel-rust-sdk/src/server.rs:727-748`
  passes `--cert`/`--key` **only when an off-chain coordinator is configured**. A roster-mesh
  SDK server without a coordinator would have no certificate and could not join.
  *Resolved in Stage 3:* `ServerBuilder::identity_files` carries the certificate independently
  of the coordinator (the two must agree when both are set) and `ServerBuilder::roster_certs`
  emits `--roster`; `an_sdk_server_presents_its_identity_and_roster_without_a_coordinator`
  spawns the runner and reads the argv back.
- **`net/mod.rs:169` is left dangling.** Stage 8 deletes `agree_and_sync_program` and
  `ProgramSyncMessage`, which are re-exported at `:169` — inside the `program_sync` block the
  plan says to *keep*. Compile error.
- **`cargo fmt --all -- --check` is a hard CI gate** (no `continue-on-error`, unlike clippy).
  No stage's verification runs it.
- **Stage 8's residue grep false-positives** on
  `crates/stoffel-lang/examples/mpc_boolean_circuit/README.md:3` ("bootstraps boolean gates").
  Anchor on `bootnode|--bootstrap` with word boundaries.
- **`crates/stoffel-vm` is `publish = true`, version `0.1.2`.** Removing the `net/mod.rs`
  re-exports is a published-crate semver break, in the same release train as the SDK break.
- **The epoch store has no home in the image.** `heed` is already a dependency
  (`Cargo.toml:62`), but no stage names a path, env var, or compose volume. The
  `docker compose down/up` cycle in `test-coordinator-preproc-store.sh` will fail without one.
- **Stage 11's hash check breaks every shipped stack.** `docker-compose.yml:44-45` passes
  `--hash 0000…0`; making `run-coord` verify `blake3(--program) == --hash` fails startup in all
  four coordinator-bearing compose files.
  *Resolved by §9.C.1, §9.D.7 and §9.F.1: nodes check the registered hash against the
  program they loaded, and every stack's coordinator registers the hash of that program
  (`--program`) instead of a placeholder.*

### What Stage 9 actually changed

The pin moved to `=0.2.0` in `crates/stoffel-vm-runner`, `crates/stoffel-rust-sdk` and
`docker/coordinator-wrapper` (its own workspace, its own lockfile, built by
`docker/coordinator.Dockerfile` and by no `cargo build --workspace`). Five API shapes changed
and each one is a call-site edit, not a rename:

| `0.1.0` | `0.2.0` | Why it matters here |
|---|---|---|
| `start_rpc_client` | `start_rpc_client_for_execution` | every RPC is keyed on an `ExecutionId` |
| `NodeRPCServer::start` + `<F, S>` | `NodeRPCServer::start_for_execution`, non-generic | mask shares are bytes; one listener serves both backends |
| `receive_mask()` | `receive_assigned_masks(start, count)` | a client names the reserved-index window it owns |
| `reset_coord()` | *gone* | a fresh `ExecutionId` is what makes a run fresh |
| `transition` gated on `mpc_nodes[0]` | `transition_quorum()` vote | no party is designated |

Three consequences the plan did not list, found by reading the published source:

- **A client gets exactly one reservation call.** `reserve_mask_indices` rejects a second one
  as `ClientAlreadyReserved` (`0.2.0/src/lib.rs:2214`), so every `for index { reserve_mask_index }`
  loop — two in `stoffel-run`, two in `local_runner`, one in the SDK client — became a single
  batched call. Left as loops, every client past its first index fails at run time.
- **`0.2.0` rejects a zero program hash** (`CoordinatorExecutionState::new`), and all four
  coordinator-bearing compose stacks passed `--hash 0000…0`. They now pass a documented
  non-zero placeholder, overridable as `STOFFEL_PROGRAM_HASH`. Verifying it against program
  bytes is still Stage 11.
- **The wrapper lost its type parameters entirely**, and with them its `ark-*` and
  `stoffelcrypto` dependencies and its `--mpc-curve`/`--mpc-backend` flags (removed from the
  compose files in the same change, since clap refuses an unknown flag).

`--execution-id <64-hex>` is the new required input wherever `--off-chain-coord` appears:
`stoffel-run` (party *and* client mode), `STOFFEL_EXECUTION_ID` in `docker/entrypoint.sh` and
every coordinator-bearing compose stack, `OffChainServerConfig`/`OffChainClientConfig` in the
SDK, and a per-run minted id in `local_runner`. It is refused *without* a coordinator, and the
all-zero value is refused everywhere, because a defaulted id would silently attach a client's
secret input to whatever execution happened to carry it.

### Resolved during Stage 7: the client leg stays an open gap, loudly

Doc §7 lists "Clients do not authenticate nodes" as a gap with no home. Stage 3 closed it for
**direct** clients via `Roster::install_for_client` (`stoffel-run.rs:1883`). It could NOT be
closed for coordinator-mediated clients: `run_hb_coordinator_client_for_field` and
`AvssOffchainCoordinatorClientArgs` build their node legs through the published coordinator
crate's own RPC client (`HbOffChainNodeRpcClient::start_rpc_client`) and never construct a
`QuicNetworkManager`, so there is no allowlist to install. Both shipped client-bearing stacks
are coordinator-mediated.

`--roster` in coordinator client mode is therefore **rejected with an explicit error**, not
accepted and ignored. An accepted-and-ignored flag on the leg carrying shares of a client's
secret input is worse than no flag, because `verify_peer_public_key_allowed` is fail-open on an
empty allowlist — it would read as pinned while authenticating nothing.

Closing this properly requires an allowlist hook on the coordinator crate's RPC client, which
lives outside this repository. Until then: `docker-compose.coordinator.reserve-index.yml` and
`crates/stoffel-lang/examples/docker-compose.coordinator.yml` do not pin their client legs, and
say so in a comment rather than carrying a no-op `STOFFEL_NODE_ROSTER`.

*Closed by §9.A and §9.E.1: `NodeRPCClient` pins every node leg to the roster served by the
pinned coordinator — the allowlist hook on the coordinator crate's RPC client that this
section said was missing.*

## 8. Open decisions

| Question | Recommendation |
|---|---|
| Static `--roster` from cert files, or coordinator-issued? | **DECIDED (2026-09-16): coordinator-issued, and the coordinator is the only roster authority.** Membership (nodes and clients) is fixed once the network is up, so the roster is fetched once at startup and installed once. Nodes no longer carry `--roster` cert lists. This reverses the earlier static-by-default recommendation, and it makes a coordinator a required service for every deployment. **Contract: §9.A (the pin that makes a fetched roster authenticated), §9.B (`get_node_roster`), §9.D (node startup), §9.F (every stack runs a coordinator).** Under the next row client participation is admission, not membership, so the fetched roster carries nodes only. |
| Clients known in advance, or arbitrary? | **REQUIREMENT (2026-09-16): plan for arbitrary clients whose identities are not known in advance.** Today's clients are pre-provisioned, but the design must not rely on that. Consequence: the coordinator-served roster should carry **nodes only**. Client participation becomes per-execution admission at the application layer, not an entry in the node transport allowlist. **Contract: §9.C (`AdmissionPolicy`, `associate_client`, the gates), §9.E (client flow; direct client mode retired), §9.G (what an unknown client can and cannot do).** |
| `instance_id` freshness source? | **LMDB monotone epoch** by default (matches the repo's existing persistent-network design record), coordinator `ExecutionId` when `--coord-roster` is used. Commit-reveal costs a round and still needs the membership set. **Updated by §9.D.5:** there is no `--coord-roster` mode — the coordinator roster is the only roster — and `ExecutionId` is not a freshness source, because shipped stacks reuse one across `docker compose down`/`up`. The epoch stays, keyed by the coordinator's roster digest, and `derive_instance_id` now mixes that digest in. |
| Full `--peers` list, or partial seed + PEX gossip? | **Ship PEX, but keep it independently revertible.** Every compose file *could* supply a full list, so PEX is not strictly required — but the reconnect supervisor it brings fixes a real gap: there is currently **no reconnection logic anywhere in the VM**. The coordinator serves keys, never addresses (§9.B), so address discovery stays a mesh concern. |
| SDK: hard break or deprecation shim? | **Shim.** `stoffel-rust-sdk/tests/sdk_usage.rs` is the only bootnode-shaped contract CI actually enforces (not in the skip list). A shim lets those assertions be relaxed rather than rewritten. ~10 lines. **Superseded by §9.E.2 and §9.F:** the coordinator `0.3.0` train is a hard break for the SDK — a pinned coordinator, no `node_roster`, no `expected_client_certs`, input ranges assigned by the coordinator — and a shim cannot default any of them. |
| Flip `hb_server.rs:101 use_tls: false` in scope? | **Out of scope, file as follow-up.** It is a genuine gap — with TLS off there is no peer authentication on that path — but `stoffel-run` never constructs `HoneyBadgerQuicServer`, and bundling it would turn Stage 3 from a pure env addition into a semantics change. |

## 9. Coordinator roster and client admission — contract

Status: **binding contract** for both repositories, **revision 2**. Implementers in
`stoffel-mpc-coordinator` (worktree `stoffel-mpc-coordinator-roster-admission`, branch
`claude/coordinator-roster-admission`, based on tag `v0.2.0`) and in this repository
build exactly what is written here; a deviation is a change to this section first.
This is Stage 11 of §5, and it is no longer optional: §8 made the coordinator the only
roster authority, so every deployment runs one.

It implements three decisions (2026-09-16) and gives way on none of them:

1. **The coordinator is the only roster authority.** Nodes fetch the node roster once at
   startup and install it once. Nodes carry no roster certificate list of their own,
   and there is no join, leave or rotation.
2. **No node is trusted more than any other.** Bootstrap, membership and admission are
   the coordinator's; everything else is the mesh's.
3. **Clients may be arbitrary.** A client's identity need not be known before it
   associates with an execution. Client certificates therefore never enter a node's
   transport allowlist. Client participation is a per-execution **admission** the
   coordinator decides and the application layer enforces: mask reservations are owned
   by admitted identities, and node-side delivery is keyed on the caller's certificate.

"The coordinator" means the coordinator process **and whoever operates it**: the operator
registers executions in-process (§C.1), so the operator sits inside the coordinator's
trust boundary and nowhere else. An invitation issuer (§C.3) is an admission authority
and sits inside the same boundary: under rule 2 it must not be run by any node's
operator.

The coordinator is trusted for bootstrap, membership and admission — which executions
exist, which program each runs, and who is admitted to it — and for nothing it does not
need for those. Since revision 2 that excludes the integrity of client inputs and outputs:
clients sign their masked inputs and nodes sign the output shares they seal (§C.7), so a
coordinator that alters either is detected rather than believed (§G).

References: `coord:<crate>/src/<file>:<line>` is the coordinator worktree, which is
byte-identical to published `0.2.0`; `quic.rs:<line>` is `stoffelnet-0.1.1`;
`stoffelcrypto-0.1.1/<file>:<line>`, `jsonrpsee-<crate>-0.26.0/<file>:<line>`,
`ring-0.17.14/<file>:<line>`, `hpke-0.13.0/<file>:<line>` and
`rustls-0.23.41/<file>:<line>` are those crates' registry sources; everything else is a
path in this repository.

### Revision 1 (2026-09-16): where each review finding went

Three read-only reviews — security (S1–S11), coordinator feasibility (C1–C12) and VM
integration (V1–V16), numbered here in the order each review listed them — raised 39
findings against the first version of this section (revision 0). Every one is resolved
in place. The parts that were declined, or whose evidence did not hold, carry
their rationale in the section named. Revision 2 changed three of these resolutions
again, and its own table says where: S11 and C7 (output shares are now delivered per
node, so `min_output_shares` is gone), C2 and C11 (the assigned event streams are
deleted rather than chunked), and V7's dependents paragraph (which described an edit to
`mpc_share_arithmetic` as if it had been made).

| # | Finding | Resolved in |
|---|---|---|
| S1 | Committed fixture keys make the coordinator pin worthless | §F.0 (new); §G rows hold only under it |
| S2, C1 | One node registers an execution and picks its admission policy | `register_execution` RPC deleted, registration is in-process and operator-only (§C.1); nodes check the summary against their own program (§D.7 step 1). *Declined:* a per-node cap on pending registrations — nothing remote can register any more (§C.1) |
| S3 | Event subscriptions are ungated and unbounded | every subscription gated (§C.6); parked sinks bounded per caller, listener connection limit (§A "Server side", §C.6) |
| S4 | Invitations replay across registrations, programs and rosters | signing bytes bind the registration nonce, program, roster and an expiry (§C.3) |
| S5 | `Open` squatting and absent invitees stall an execution forever | association and input deadlines, terminal `Round::Aborted` (§C.8); what `Open` is for (§C.2) |
| S6 | Masked inputs are not agreed across nodes | `InputsAgreed` digest barrier (§D.6, §D.7 step 9) |
| S7 | Roster equivocation claimed detectable | §G rewritten; optional `--expect-roster-digest` (§D.2, §E.1) |
| S8 | The invitation issuer key may be a node's or the coordinator's | `IssuerIsRosterNode`, `IssuerIsCoordinatorKey` (§C.1, §C.3) |
| S9 | The caller identity and the handshake key come from two parsers | one derivation with an algorithm allowlist (§A "Server side") |
| S10 | `t = 0` is accepted; the VM checks `n`, `t` more weakly | `ZeroThreshold` everywhere, VM enforces `n >= 2t + 1` (§B, §D.4). *Declined:* a client `--min-threshold` (§D.4) |
| S11, C7 | `min_output_shares` below reconstruction makes clients fail | revision 1: bounds and backend checks. *Superseded by revision 2 (C18):* outputs arrive one node at a time and the client reconstructs when it can, so the field is deleted (§C.1, §C.7) |
| C2 | jsonrpsee's 10 MiB caps make the slot bound unreachable | measured bounds (§C.1), records without `execution_id` (§C.7). *Revision 2:* re-measured at the new per-input and per-output byte bounds; the assigned streams are deleted instead of chunked (§C.6) |
| C3 | The on-chain crate has no roster source | explicit decision (§A "The on-chain crate") |
| C4 | The one-off drain can start mid-execution | drain gated on a terminal round; nodes retire (§C.10, §D.7) |
| C5 | Idempotent association promised after retirement | claim narrowed, output retention added (§C.4, §C.10) |
| C6 | Round skips are not tied to the slot table | structural skip preconditions (§C.8) |
| C8 | There is no per-execution state lock | wording, verification before the lock, the binding sequence (§C.4 steps 4–10) |
| C9 | A verified-on-deserialize roster loses its typed error over jsonrpsee | the RPC returns `NodeRosterWire` (§B) |
| C10 | Client-side Rust API unspecified | `OffChainCoordinatorClient` methods (§C.7) |
| C11 | Submit-side assigned events; `available_input_masks` | `available_input_masks` deleted (§C.10). *Revision 2:* both assigned streams deleted (§C.6) |
| C12 | `n_inputs` allocation is unbounded | per-slot and total input bounds (§C.1) |
| V1 | No VM build order | §9.1 (new) |
| V2 | `ExecutionId` is a coordinator type; `JoinRequest` has no execution | `SessionExecutionId` (§D.5) |
| V3 | Removing `Roster::new` strands key-based callers | `Roster::from_node_keys`, callers and retargets listed (§D.4, §H) |
| V4 | Barrier frames cannot carry a body | `DigestBarrier` (§D.6) |
| V5 | Preprocessing is sized before the summary is read | summary first, `mask_count` (§D.7 step 1) |
| V6 | Output-only and sparse slots cannot be registered | slot-table construction (§F.4) |
| V7 | The returned-share broadcast disagrees with admissions | broadcast deleted (§D.7 step 12); its dependents are corrected in revision 2 (V17, V18) |
| V8 | Coordinator-less party paths and `run_mpc_local.sh` | §E.3, §F.2 |
| V9 | `entrypoint.sh` and compose still emit `n` and `t` | §D.3, §F.1 |
| V10 | SDK surfaces and tests missing | §E.2, §H |
| V11 | `stoffel-cli` not mentioned | §E.2. *Evidence corrected:* three of the four cited `cli.rs` fixtures are project-config fixtures and do not change (§E.2) |
| V12 | `start()` lifetimes; `run()` under `Open` | §F.4 |
| V13 | Named-context `COPY` placement; CI `docker-build` | §F.5 |
| V14 | `input_ordinal` and typed storage undefined | §D.7 steps 7 and 10 |
| V15 | Runner dependencies; VM-side pin test | §9.0, §H |
| V16 | Golden vector verified; one line reference drifted | §B kept; `:883` (§E.2) |

### Revision 2 (2026-09-16): where each review finding went

The same three reviews read revision 1 and raised 41 findings, numbered here after
revision 1's: security S12–S22, coordinator feasibility C13–C27, VM integration V17–V31,
each in the order its review listed them. Every one was checked against the source before
it was resolved. Where the resolution differs from the fix the review proposed, or a
piece of its evidence did not hold, the section named says why.

| # | Finding | Resolved in |
|---|---|---|
| S12 | Mask shares and triples come back in a later execution through the preprocessing store | §C.9 part 4 (new rule: no preprocessing item serves two executions), §D.7 steps 2 and Abort, §9.1 V-0, §H. *Differs:* the write path is deleted rather than made cursor-exact, because triples are drawn inside `stoffelcrypto` where no commit can precede the draw, and the only material a finished run leaves unused is banding slack (§C.9) |
| S13 | Share ids are not tied to roster positions; reconstruction stops at the first `min_shares` answers | `ShareBound::reconstruct` over position-bound shares, Feldman verification, per-node output items (§9.0, §A, §C.7), §G. *Refined:* reconstruction returns as soon as it is conclusive, which is already correct with at most `t` corrupt positions, and otherwise waits for every leg; the position inside the sealed plaintext is not added — the share-id check and the node's signature already bind it (§C.7) |
| S14 | One connection pool, no per-source or per-identity bound, no idle timeout, no capacity for nodes; summaries cloned under the state mutex; no reconnection | `RpcServerLimits` (§A "Server side"), rate limit and summary snapshot (§C.6, §C.7), a lost link exits the node (§D.1 step 10), residual stated (§G) |
| S15 | §F.0 rule 1 is not enforced and `ids/` keys may back compose secrets | every compose stack in this repository is loopback-only, enforced by a fourth check (§F.0). *Declined:* a key-minting init service (§F.0) |
| S16 | `Invitation.client_index: None` lets an invitee take any role, including a slot another invitation names | `client_index` required, signing bytes v3 (§C.3, §C.4 step 7, §E.1). *Declined:* a shape-scoped wildcard (§C.3) |
| S17, C23 | One P-256 key has several SPKI encodings, so byte comparisons are not key comparisons | canonical SPKI layouts, `PinError::NonCanonicalPublicKey` (§A) |
| S18 | HoneyBadger reconstructs only at `n >= 3t + 1`, but only `n >= 2t + 1` is checked | `ShareBound::min_parties`; nodes (§D.7 step 1), `associate_client` (§C.7), every client surface (§E.1 step 1, §E.2) |
| S19 | A malicious coordinator can shift a client's input and substitute its outputs | clients sign masked inputs, nodes sign sealed outputs (§C.7), nodes verify at §D.7 step 9, clients at §E.1 step 7; §G |
| S20 | The local runner writes node keys under the shared temp directory with default modes | run directory `0700`, key files `0600` (§F.4) |
| S21 | §3 still claims the coordinator cannot make a node dial an impostor | §3 rewritten |
| S22 | The issuer checks compare keys, not operators | issuer placed inside the coordinator's trust boundary (§9 preamble, §C.3, §G); checks kept as misconfiguration guards |
| C13 | The state mutex is held across WebSocket sends on replay and on `reserve_mask_indices` | no send under the state mutex; sequence-numbered replay; live broadcasts never wait (§C.6) |
| C14 | Aborts race the take-and-return sink paths and post-accept parking | lock order and aborted re-checks (§C.6, §C.8) |
| C15 | The input deadline aborts an execution whose inputs are all present | the input deadline needs a missing input (§C.8) |
| C16 | `start_coord_one_off` spawns no sweeper | one private helper for both starts, owned by the handle (§C.8, §C.10) |
| C17 | `masked_input` length is unchecked, so an event can exceed the client's cap | `MAX_MASKED_INPUT_BYTES`, code 36, re-measured (§C.1, §C.5, §C.6) |
| C18 | One output snapshot per client can exceed the cap, and one node can make it undeliverable | one message per node, `MAX_SEALED_OUTPUT_BYTES`, code 39, size checks on nodes and clients; `min_output_shares` deleted (§C.1, §C.7, §D.7, §E.1) |
| C19 | Tombstones are forgotten at unanimity, so an aborted id re-registers at once | `EndedExecutions`, not cleared by acknowledgements (§C.8) |
| C20 | `validate` needs state it is not given | a pure `validate` and ordered state checks (§C.1). *Order differs:* validation runs before the capacity check, so a refused registration never evicts |
| C21 | `watch_for_retirement_quorum` has no trigger | a `Notify` signalled from every path that changes the condition (§C.10) |
| C22 | A concurrent removal panics `deliver_ready_output_waiters` | every post-release re-lock returns quietly (§C.10) |
| C24 | `server_spki` is not tied to the certificate the listener serves | all three starts refuse a mismatch, `ServerCertificateMismatch` (§B, §C.10) |
| C25 | The `MAX_INPUTS` memory bound is about ten times too low | per-slot storage, restated bound (§C.1) |
| C26 | `wait_for_indices` unwraps a rejected subscription | subscribe rejections decode like method errors (§C.7) |
| C27 | Manifests miss `ring`, `serde_json` and an on-chain signature | §9.0 |
| V17 | `mpc_share_arithmetic` sends nothing to its client | the program is edited, and listed (§D.7 step 12, §9.1 V-b, §F.1) |
| V18 | `client_sub_order` sends nothing to either client | the stack registers input-only slots and the scripts assert the parties' revealed value (§F.1, §F.2) |
| V19 | `NodeCertificateDer` and `RosterDigest` have no accessors | constructors, accessors, `FromStr`, `Display` (§B) |
| V20 | V-a cannot keep the legacy roster API and retarget its tests at once | distinct V-a variant names; exact V-a and V-c test lists (§9.1, §D.4, §H) |
| V21 | An execution without captured outputs never reaches `ProgramFinished` | finalize from `MPCExecution` (§D.7 step 12) |
| V22 | Between V-b and V-c a direct client runs unpinned | the refusal lands in V-b (§9.1, §E.3) |
| V23 | V-b has no gate for the wrapper, the lockfiles or the runner's re-exports | V-b done criteria (§9.1), §9.0 |
| V24 | Existing refusal hints point at flags this section removes | every site listed with a new hint (§D.3, §F.1). *Evidence corrected:* the coordinator-client `--roster` refusal is `stoffel-run.rs:4434-4443`; `:5669` is usage text, which §D.3 lists separately |
| V25 | Party signatures that carry the link are unlisted; the AVSS path maps execution errors to 13 | new signatures and `CoordinatedRunError` (§D.7) |
| V26 | The unassigned `add_reserved_index(es)_for_execution` remain | deleted (§C.10), and V-b removes both VM call sites (§D.7 step 7) |
| V27 | `build()` check order; SDK local runs | order fixed (§F.4); SDK behaviour change listed (§E.2, §H). *Evidence corrected:* the SDK forwards per-slot output counts (`crates/stoffel-rust-sdk/src/vm.rs:263-265`), so only a runtime without them changes behaviour |
| V28 | SDK `parties` and `threshold` silently stop meaning anything | refusal-only `--expect-n-parties` / `--expect-threshold` (§D.2, §E.2) |
| V29 | `--timestamp` is emitted but never parsed | removed everywhere, fails by name (§D.2, §D.3, §E.2, §F.1, §F.4) |
| V30 | The runner and SDK import coordinator `tests::fake_coord` | `OffChainCoordinatorConnection` promoted; both `fake_coord` modules stay public (§C.10) |
| V31 | Module docs that D.5 makes wrong; the `n == 1` join branch | listed under V-a; the branches are deleted in V-c (§D.5, §9.1) |

### Rule 3 is a transport-security requirement, not only a product one

stoffelnet authorizes a peer certificate at `quic.rs:3292`, *before* it looks at the
connection's ALPN role (`:3355` client, `:3376` server), and once the allowlist is
non-empty it is the only authorization on the server branch. A key admitted "as a
client" that dials with the server ALPN is therefore accepted as a **server peer**: it
is inserted into `peer_public_keys` (`:3407`), counts toward `is_fully_connected`
(`:1976`), and is ranked by `get_sorted_public_keys` (`:1856`), which *is* the
party-index order. Stage 3's `--expected-clients` put exactly such keys into every
node's allowlist. The allowlist is also frozen once the manager is shared —
`add_allowed_certificate_public_key` takes `&mut self` (`:1452`) — so it could never
admit a client that arrives after startup anyway. B1's "the roster must carry a
`clients` set" is reversed by this section: the node allowlist holds nodes and nothing
else, and clients never touch the mesh transport.

### 9.0 Where each piece lives

The coordinator crates move to **`0.3.0`** (`[workspace.package] version`, and
`stoffel-mpc-coordinator-shared = { version = "0.3.0", path = … }` in the coordinator
workspace). `ClientIdentity` stays `Vec<u8>` holding the certificate's
`subject_public_key` BIT STRING (`coord:coord-shared/src/rpc.rs:103-109`): it is also
the HPKE key output shares are sealed to (`coord:off-chain/src/lib.rs:3013`), so its
form cannot change without changing output encryption. Since §A admits only canonical
encodings, its length names its algorithm: 65 bytes is a P-256 point, 32 an Ed25519 key.

| Item | Crate, file | Section |
|---|---|---|
| `SpkiDer`, `KeyAlgorithm`, `ServerPin`, `RosterKeys`, `PinError` | `stoffel-mpc-coordinator-shared`, `src/pin.rs` (new) | A |
| `PinnedServerVerifier`, `PinnedClient`, `setup_client`, TLS 1.3-only configs | shared, `src/self_signed_certs.rs` (replaces `SelfSignedServerVerifier`) | A |
| `caller_identity`, `RpcServerLimits`, `RPCServerConnection::capacity_class`, `CapacityClass`, `start_coord` (new signature) | shared, `src/rpc.rs` | A |
| `NodeRoster`, `NodeRosterWire`, `NodeCertificateDer`, `RosterDigest`, `RosterDigestParseError`, `RosterError` | shared, `src/roster.rs` (new) | B |
| `ShareBound::{min_parties, share_id_of_position, share_id, share_degree, serialized_share_len, reconstruct}`, `PositionedShare`, `Reconstruction` | shared, `src/lib.rs` (`ShareBound`, `:100-143`) | A, C.7 |
| `SignatureError`, `sign_with_pkcs8`, `verify_identity_signature`, `masked_inputs_signing_bytes`, `sealed_output_signing_bytes` | shared, `src/signing.rs` (new) | C.7 |
| `ClientIdentity` (moved from `coord:off-chain/src/lib.rs:51`, re-exported there), `ClientIndex`, `ClientSlotSpec`, `ClientSlotTable`, `InputRange`, `OutputRights`, `UnixSeconds`, `ExecutionDeadlines`, `RegistrationNonce`, `AdmissionPolicy`, `AdmissionPolicyKind`, `InvitationIssuer`, `Invitation`, `SignedInvitation`, `AssociationRequest`, `ClientAdmission`, `ClientAdmissionRecord`, `ClientAdmissionSet`, `AbortReason`, `ExecutionOutcome`, `AdmissionError`, `SubmissionError`, `InvitationRejection`, `RegistrationError`, `InvitationSigningError`, `program_hash_of`, the `MAX_*` bounds | shared, `src/admission.rs` (new) | C |
| `Round::Aborted`; new `CoordinatorError` variants; `RpcRefusal` | shared, `src/lib.rs:145`, `:257` | A, C |
| reshaped `ExecutionRegistration`, `ExecutionSummary`, `CoordinatorLink`, `MaskedInputSubmission`, `SealedOutput`, `SealedOutputShares`, `Event::ExecutionAborted`, `EndedExecutions`, new and deleted RPC methods, new `CoordinatorRPCBaseError` codes, `OffChainCoordinatorServer::state`, `OffChainCoordinatorConnection`, deadline sweeper | `stoffel-mpc-coordinator-off-chain`, `src/lib.rs` | B, C |
| `issue-invitation` binary; `run-coord` flags | `stoffel-mpc-coordinator-bins`, `src/bin/` | C.3, F.3 |
| on-chain `NodeRPCClient::start_rpc_client` and `start_rpc_client_from_cert` taking a `&NodeRoster` (both lose `n` and `t`, `coord:on-chain/src/lib.rs:113-160`); `Round::Aborted` handling | `stoffel-mpc-coordinator-on-chain`, `src/lib.rs` | A |
| `serde_json = "1.0"` in `[workspace.dependencies]`; `ring` and `serde_json` in `crates/bins` `[dependencies]` (`issue-invitation` signs with `EcdsaKeyPair` and writes JSON); `serde_json` in `crates/coord-shared` `[dev-dependencies]` (the wire-bound test); `blake3 = "1.8"` in `[workspace.dependencies]` and `coord-shared` | coordinator `Cargo.toml`, `crates/{bins,coord-shared}/Cargo.toml` | B, C.1, C.3, H |
| the preprocessing store is never written with material an execution may still draw: `persist_preproc` deleted in both engines | `crates/stoffel-vm/src/net/mpc/{honeybadger,avss}/preprocessing.rs` | C.9 |
| `Roster` (nodes only), `Roster::from_node_keys`, `Roster::from_coordinator` | `crates/stoffel-vm/src/net/mesh/roster.rs` | D.4 |
| `SessionExecutionId`, `derive_instance_id` (v2) | `crates/stoffel-vm/src/net/session.rs` | D.5 |
| `JoinRequest.execution_id`, `JoinProposal.execution_id`, `SessionField::ExecutionId`, `session_digest` (v2) | `crates/stoffel-vm/src/net/mesh/{mod,join,wire}.rs` | D.5 |
| `DigestBarrier`, `DigestBarrierTag`, `ADMISSIONS_AGREED_PREFIX`, `INPUTS_AGREED_PREFIX`, `MeshError::{AdmissionDivergence, InputDivergence, DigestBarrierUnannounceable, DigestBarrierIncomplete}` | `crates/stoffel-vm/src/net/mesh/{barrier,wire,mod}.rs` | D.6 |
| `check_execution_summary`, `admission_agreement_digest`, `inputs_agreement_digest`, `reservations_matching_admissions`, `submissions_matching_admissions`, `SummaryMismatch`, `ReservationMismatch`, `MaskedInputMismatch` | `crates/stoffel-vm-runner/src/admissions.rs` (new) | D.6, D.7 |
| `CoordinatedRunError` | `crates/stoffel-vm-runner/src/bin/stoffel-run.rs` | D.7 |
| `blake3 = "=1.8.5"` in `[dependencies]`, `rcgen = "=0.14.8"` in `[dev-dependencies]` | `crates/stoffel-vm-runner/Cargo.toml` | D.6, H |
| party and client flags | `crates/stoffel-vm-runner/src/bin/stoffel-run.rs`, `docker/entrypoint.sh` | D.2, E.2 |
| `LocalAdmission`, `LocalCoordinatorRunner::start`, `RunningLocalCoordinator`, `LocalClientEndpoint`, `LocalClientRun`, `run_offchain_client` | `crates/stoffel-vm-runner/src/local_runner.rs` | F.4 |
| `CoordinatorClientConfig`, `CoordinatorEndpoint`, `PendingAssociation` + `BindableSlots` (step 2 via `inspect`, step 3 via `associate`), `AdmittedClient` (steps 4–7), `CoordinatorClientRun`, `CoordinatorClientError` (with `exit_code`): the E.1 flow, once, for `stoffel-run --client` on both backends, `run_offchain_client` and the SDK client | `crates/stoffel-vm-runner/src/coordinator_client.rs` (new) | E.1 |
| re-exports of `LocalAdmission`, `LocalClientEndpoint`, `LocalClientRun`, `RunningLocalCoordinator`, `run_offchain_client` beside today's (`crates/stoffel-vm-runner/src/lib.rs:3-7`) | `crates/stoffel-vm-runner/src/lib.rs` | F.4 |
| `OffChainServerConfig`, `OffChainClientConfig`, `ClientBuilder::connect` | `crates/stoffel-rust-sdk/src/{server,client,runtime}.rs` | E.2 |
| off-chain client TOML, `--client-id` | `crates/stoffel-cli/src/main.rs` | E.2 |
| `MpcOutput.send_to_client(0, [product])` in the client branch | `crates/stoffel-lang/examples/mpc_share_arithmetic/main.stfl` | D.7, F.1 |
| wrapper flags; its own `CoordinatorConnection` (`:78-137`) replaced by `OffChainCoordinatorConnection` | `docker/coordinator-wrapper/src/main.rs` | C.10, F.3 |
| key-material rule | `Dockerfile`, `docker/coordinator.Dockerfile`, every compose file, `crates/stoffel-vm-runner/tests/deployment_key_material.rs` (new) | F.0 |

### 9.1 Build order

Neither repository may be left unbuildable between steps, and parallel implementers
work to this order.

**Coordinator worktree first.** In order, each step building and testing on its own:
(C-a) `coord-shared`: `pin.rs` with the canonical key layouts, `roster.rs`,
`admission.rs`, `signing.rs`, the `ShareBound` additions, `Round::Aborted`,
`caller_identity`, `RpcServerLimits`, TLS 1.3-only configs, `setup_client` with a pin, and
the manifest entries of §9.0; (C-b) `off-chain`: registration, admission RPCs, gates,
submissions and sealed outputs, the delivery discipline of §C.6 — no send under the state
mutex, sequence-numbered replay, `reserve_mask_indices` moved off the mutex — deadlines and
the sweeper for both starts, ended executions, retention, client methods,
`OffChainCoordinatorConnection`; (C-c) `on-chain` and `bins`. The coordinator's
`cargo build --workspace` and `cargo test --workspace --no-run` must pass at version
`0.3.0` before V-b below starts.

**VM, four sub-stages.**

- **V-0 — no preprocessing item serves two executions (§C.9 part 4).** Independent of the
  coordinator and of every other stage, and first because it closes a live hole in the
  `docker-compose.coordinator.reserve-index.preproc.yml` stack. `stoffel-vm`: delete
  `persist_preproc` and its call in both engines. `stoffel-run`: `--preproc-store` fails
  by name (§D.3), and its plumbing goes with it — `configure_hb_preproc_store`
  (`stoffel-run.rs:670-689`), every `preproc_store_path` site
  (`rg -n preproc_store_path crates/stoffel-vm-runner` lists them) and the usage line
  (`:5678`). `docker/entrypoint.sh`
  refuses `STOFFEL_PREPROC_STORE` (`:128`, `:371-373`). The preproc override stops setting
  it, and `docker/test-coordinator-preproc-store.sh` is retargeted (§F.2).
  `README.md:473` stops naming the flag. The test of §H lands with it.
- **V-a — additive, before the pin bump.** `stoffel-vm`: `Roster::from_node_keys` and
  `Roster::from_coordinator` with the §B digest; the new `RosterError` variants
  `ZeroThreshold`, `ThresholdTooLarge { n, threshold }`, `DigestMismatch { served,
  computed }` and `ServedCertificateUnderivable { index, reason }` (§D.4), added under
  those names beside the legacy ones; `derive_instance_id` v2, `SessionExecutionId` and
  `JoinRequest.execution_id` / `JoinProposal.execution_id`; `DigestBarrier` with both
  tags; and the module documentation §D.5 makes wrong. `Roster` stores the digest it
  was built with, so the old `Roster::new(nodes, clients, t)`, `from_cert_paths`,
  `install_for_client`, their `CertUnreadable { path }`, `CertUnderivable { path }`,
  `ThresholdOutOfRange` and `AllowlistDisabled { nodes, clients }`, today's
  `stoffel-mesh-roster-digest-v1` layout and the `t < n` bound all stay exactly as they
  are until V-c, and the legacy path changes no behaviour beyond the value of its instance
  ids (§D.5). Test callers of `Roster::new`
  that build **node-only** rosters move to `from_node_keys` here, and only those (the
  exact list is §D.4's); tests of the client set, of certificate files and of the
  `t < n` bound exercise APIs that exist until V-c and are retargeted there (§H). In the
  runner, apart from its binary test, only the one `JoinRequest` literal
  (`stoffel-run.rs:4736`) changes: it gains `execution_id` — the coordinator's id, or
  `SessionExecutionId::UNUSED` for a coordinator-less run.
- **V-b — one atomic change, gated on the coordinator building at `0.3.0`.** The
  `[patch.crates-io]` table and the `=0.2.0` → `=0.3.0` pin in both workspaces (§F.5);
  `stoffel-run` (party and client, including the §E.3 refusal of direct client mode),
  `local_runner.rs`, the runner's `lib.rs` re-exports, `admissions.rs`, the SDK,
  `stoffel-cli`, the wrapper, `docker/entrypoint.sh`, every compose file, every
  Dockerfile, the scripts of §F.2, `crates/stoffel-lang/examples/mpc_share_arithmetic/main.stfl`
  and `README.md`. Six call graphs break at once when the pin moves (`stoffel-run.rs`,
  `local_runner.rs`, SDK `client.rs`/`server.rs`/`coordinator/mod.rs`, `stoffel-cli`
  through the SDK, and the wrapper's separate workspace), so this is not splittable.
  **Done when**, from the repository root:
  `cargo build --workspace && cargo test --workspace --no-run` passes;
  `cargo build --manifest-path docker/coordinator-wrapper/Cargo.toml` passes — the
  wrapper is its own workspace and neither `--workspace` nor CI sees it
  (`.github/workflows/ci.yml:45`, `:49` build the root workspace only); and both
  `Cargo.lock` and `docker/coordinator-wrapper/Cargo.lock` are re-locked
  (`cargo update -p stoffel-mpc-coordinator-shared -p stoffel-mpc-coordinator-off-chain`,
  once with and once without `--manifest-path docker/coordinator-wrapper/Cargo.toml`) and
  name `0.3.0` from the patch path.
- **V-c — deletion.** The now-dead `Roster::new(nodes, clients, t)`, `from_cert_paths`,
  `install_for_client`, `clients()`, `admits_client`, the legacy `RosterError` variants
  (`AllowlistDisabled` loses its `clients` field); both `n == 1` branches of the join
  (`join.rs:559-561`, `:1098-1112`), unreachable once every roster has `n >= 2t + 1` with
  `t >= 1`; the body of direct client mode and the uncoordinated party branches (§E.3);
  and the retargets of the legacy tests (§H).

### A. Server pinning

**Today.** `setup_client` (`coord:coord-shared/src/self_signed_certs.rs:199`) installs
`SelfSignedServerVerifier`, whose `verify_server_cert` returns
`ServerCertVerified::assertion()` for any certificate (`:95-104`). Every coordinator
connection (`OffChainCoordinatorClient::start_rpc_client_for_execution`,
`coord:off-chain/src/lib.rs:2648`) and every client→node RPC connection
(`NodeRPCClient::start_rpc_client_for_execution`, `:205`) goes through it. That is B4,
and under this section it would be fatal: the coordinator connection becomes the
authenticated source of membership, and an impostor could hand every node a roster of
its own keys.

A pin authenticates a *key*. It is worth exactly as much as the secrecy of the matching
private key, which is why §F.0 is part of this section and not a deployment footnote.

**Types** (`coord-shared/src/pin.rs`):

```rust
/// DER SubjectPublicKeyInfo: exactly `X509Certificate::public_key().raw`, the bytes
/// stoffelnet authorizes against (quic.rs:1768) — never the inner BIT STRING (B2).
/// Always in the canonical layout of its algorithm (below), so two values are equal
/// exactly when they are the same key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpkiDer(Vec<u8>);

/// The only key algorithms any certificate in this system may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// `id-ecPublicKey` (1.2.840.10045.2.1) with `namedCurve` `prime256v1` (1.2.840.10045.3.1.7).
    EcdsaP256,
    /// `id-Ed25519` (1.3.101.112).
    Ed25519,
}

impl KeyAlgorithm {
    /// The algorithm a canonical `ClientIdentity` names: 65 bytes starting `0x04` is
    /// `EcdsaP256`, 32 bytes is `Ed25519`, anything else `None`.
    pub fn of_client_identity(identity: &[u8]) -> Option<Self>;
}

impl SpkiDer {
    /// The one derivation. Refuses unparseable input, trailing bytes after the
    /// certificate, any key algorithm other than `KeyAlgorithm`'s, and any encoding of an
    /// admitted key other than its canonical layout.
    pub fn from_certificate_der(cert_der: &[u8]) -> Result<Self, PinError>;
    pub fn as_bytes(&self) -> &[u8];
    pub fn key_algorithm(&self) -> KeyAlgorithm;
    /// The coordinator identity form of the same key (`subject_public_key.data`).
    pub fn client_identity(&self) -> ClientIdentity;
}

/// Which server keys a caller accepts. No variant accepts every key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPin {
    /// The coordinator: exactly one key.
    Exact(SpkiDer),
    /// A node RPC listener: any one member of the node roster.
    RosterNode(RosterKeys),
}

/// Non-empty by construction: the field is private and the only constructor is
/// `ServerPin::roster_node`, which reads a verified `NodeRoster`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterKeys(BTreeSet<SpkiDer>);

impl ServerPin {
    pub fn roster_node(roster: &NodeRoster) -> Self;
    pub fn admits(&self, spki: &SpkiDer) -> bool;
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinError {
    #[error("not a DER X.509 certificate: {reason}")]
    UnparseableCertificate { reason: String },
    #[error("{trailing} bytes follow the certificate")]
    TrailingBytes { trailing: usize },
    #[error("key algorithm {algorithm} is not ECDSA P-256 or Ed25519")]
    UnsupportedKeyAlgorithm { algorithm: String },
    #[error("the {algorithm:?} public key is not in its canonical SubjectPublicKeyInfo encoding")]
    NonCanonicalPublicKey { algorithm: KeyAlgorithm },
}
```

`from_certificate_der` is `X509Certificate::from_der` (x509-parser `0.18.1`); a non-empty
remainder is `TrailingBytes`; the algorithm test compares
`public_key().algorithm.algorithm` with oid-registry's `OID_KEY_TYPE_EC_PUBLIC_KEY` (whose
`parameters` must be the named-curve OID `OID_EC_P256` — another curve, or explicit
curve parameters, is not this algorithm) or `OID_SIG_ED25519`, and
`UnsupportedKeyAlgorithm.algorithm` is the dotted OID. Then the canonical-layout check
below runs. Every
certificate this system handles goes through it: server pins, roster certificates (§B),
invitation issuers (§C.3) and callers (below). `key_algorithm` and `client_identity`
are infallible because the constructor already refused everything else.

**Canonical layouts.** An admitted algorithm is necessary but not sufficient. One P-256
key has an uncompressed (`0x04`), a compressed (33-byte) and a hybrid (`0x06`/`0x07`)
point encoding, and an Ed25519 SPKI may carry a stray `NULL` parameter; each is a
different `SpkiDer` and a different `ClientIdentity` for the same key. Every identity comparison in this section —
`DuplicateKey`, `IssuerIsRosterNode`, `IssuerIsCoordinatorKey`, `invitee == caller`,
`by_identity`, reservation ownership, the node RPC delivery gate — is a byte comparison,
so each of them could be evaded by re-encoding a key. `from_certificate_der` therefore
requires `public_key().raw` to be byte for byte one of:

```text
EcdsaP256   3059301306072a8648ce3d020106082a8648ce3d030107034200 || point     91 bytes
            point: 65 bytes, point[0] == 0x04, and p256::PublicKey::from_sec1_bytes(point) is Ok
Ed25519     302a300506032b6570032100 || key                                   44 bytes
            key: 32 bytes
```

and refuses anything else with the algorithm's `NonCanonicalPublicKey`. The prefixes are
the DER of the two `AlgorithmIdentifier`s and the BIT STRING header with zero unused
bits; `openssl pkey -pubin -outform DER` produces exactly them, and every certificate
under `ids/` has the 91-byte form (§B's golden vector). `p256` is already a
`coord-shared` dependency with its default `arithmetic` feature. Nothing that works today
is refused: ring verifies ECDSA only over uncompressed points
(`ring-0.17.14/src/ec/suite_b/ecdsa/verification.rs:109`, which refuses any first byte
but `0x04` at `src/ec/suite_b/public_key.rs:39-43`), and HPKE's P-256 key parser accepts
only the uncompressed length (`hpke-0.13.0/src/dhkex/ecdh_nistp.rs:73-83`), so a
compressed client key could never have received outputs. The VM checks no encoding
itself: every certificate reaches `Roster::from_coordinator` (§D.4) only after
`NodeRoster::try_from` ran this derivation on it (§D.1 steps 3 and 5).

**Verifier and client** (`coord-shared/src/self_signed_certs.rs`;
`SelfSignedServerVerifier` is deleted):

```rust
#[derive(Debug)]
pub struct PinnedServerVerifier { pin: ServerPin }

pub struct PinnedClient {
    pub client: jsonrpsee::async_client::Client,
    /// The key the server proved possession of in this handshake. Always admitted by the pin.
    pub server_spki: SpkiDer,
}

pub async fn setup_client(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    pin: &ServerPin,
) -> Result<PinnedClient, CoordinatorError>;
```

1. `verify_server_cert` derives `SpkiDer` from `end_entity`. Any `PinError` is
   `rustls::Error::InvalidCertificate(CertificateError::BadEncoding)`; a key the pin does
   not admit is `InvalidCertificate(CertificateError::ApplicationVerificationFailure)`.
   `intermediates`, `server_name` and the validity period are not consulted: the identity
   is the key, exactly as it is for stoffelnet.
2. `verify_tls12_signature` / `verify_tls13_signature` keep today's ring-provider
   verification (`:106-134`). rustls checks the handshake signature against the same
   end-entity certificate step 1 admitted, which is what binds the connection to the
   pinned *key* rather than to a copy of a public certificate.
3. After the handshake `setup_client` re-reads `peer_certificates()[0]` from the
   `tokio_rustls::client::TlsStream` (`get_ref().1`), re-derives the `SpkiDer`, re-checks
   `pin.admits`, and returns it as `server_spki`.
4. tokio-rustls surfaces a rustls failure as `io::Error::new(InvalidData, rustls::Error)`.
   A connect error that downcasts to `InvalidCertificate(ApplicationVerificationFailure)`
   becomes **`CoordinatorError::ServerPinMismatch { address }`**; every other failure stays
   `ConnectError`. A caller can therefore tell "wrong server" from "no server", and must
   never retry the former.
5. **TLS 1.3 only.** `server_tls_config` and `client_tls_config` (`:167-192`) build with
   `ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])` and
   `ServerConfig::builder_with_protocol_versions(…)`
   (`rustls-0.23.41/src/client/client_conn.rs:316`, `src/server/server_conn.rs:476`)
   instead of `builder()`, which also enables TLS 1.2. §C.7 signs application data with
   node and client certificate keys; under TLS 1.3 those keys sign only
   `CertificateVerify` content, which begins with 64 bytes of `0x20`, whereas a TLS 1.2
   `ServerKeyExchange` signature begins with a 32-byte random the *peer* chooses. Every
   §C.7 layout begins with an ASCII context, so no handshake signature can be replayed
   as one. The QUIC mesh transport is TLS 1.3 by protocol.

**Callers** (`coord:off-chain/src/lib.rs`):

```rust
/// One pinned coordinator connection plus the node roster it served, fetched and
/// verified exactly once, at connect. Not generic over the share type, so a node can
/// open it before it knows its backend and curve.
pub struct CoordinatorLink { /* rpc: Client, node_roster: NodeRoster, own_spki: SpkiDer, key_der: Vec<u8> */ }

impl CoordinatorLink {
    /// `expected_roster_digest` is `--expect-roster-digest` (§D.2): a served digest that
    /// differs is `CoordinatorError::UnexpectedRosterDigest { served, expected }`.
    pub async fn connect(addr: &str, port: u16, coordinator: &SpkiDer,
                         expected_roster_digest: Option<RosterDigest>,
                         cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, CoordinatorError>;
    pub fn node_roster(&self) -> &NodeRoster;
}

impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    pub fn from_link(link: CoordinatorLink, execution_id: ExecutionId) -> Self;
    /// `connect` + `from_link`. Loses 0.2.0's `t`, `n_parties` and `n_outputs` parameters:
    /// the roster supplies `n` and `t`, the client's admission supplies its output count.
    pub async fn start_rpc_client_for_execution(addr: &str, port: u16, coordinator: &SpkiDer,
        expected_roster_digest: Option<RosterDigest>, execution_id: ExecutionId,
        cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, CoordinatorError>;
    pub fn node_roster(&self) -> &NodeRoster;
}

impl<F: FftField, S: ShareBound<F>> node_rpc::NodeRPCClient<F, S> {
    /// Loses 0.2.0's `n` and `t` parameters; both come from `roster`.
    pub async fn start_rpc_client_for_execution(roster: &NodeRoster, addrs: Vec<(String, u16)>,
        execution_id: ExecutionId, cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, CoordinatorError>;
}
```

`NodeRPCClient` pins every address with `ServerPin::roster_node(roster)` and keeps, for
each leg, the roster position of the `server_spki` it answered with
(`roster.position_of`). It requires those positions to be pairwise distinct —
`CoordinatorError::DuplicateNodeIdentity { address }` otherwise, because two addresses
answering as one node would count one node's share twice — and refuses more addresses
than the roster has nodes (`TooManyNodeAddresses { given, n }`).

**Reconstruction is bound to positions.** `0.2.0`'s `receive_assigned_masks` pushes each
share into its index's list in arrival order, stops at the first `S::min_shares(t)`
entries per index, and interpolates with whatever ids and degree those shares carry
(`coord:off-chain/src/lib.rs:280-297`, `:311`). One node — at most `t` are corrupt — could
therefore relabel its share with another node's id, which makes HoneyBadger's robust
decoding refuse the duplicate id for the whole index
(`stoffelcrypto-0.1.1/src/honeybadger/robust_interpolate/robust_interpolate.rs:118-131`),
or, under AVSS, send a wrong value that `FeldmanShamirShare::recover_secret` interpolates
without consulting the commitments (`stoffelcrypto-0.1.1/src/common/share/feldman.rs:230-270`)
— a mask off by an amount that node chooses, and so a client input shifted by it. In
`0.3.0` the client:

1. Attributes every share on a leg to that leg's roster position, and ignores a second
   answer from the same leg, an answer for another index range, and a share that does not
   deserialize — each such leg counts as answered and contributes nothing.
2. Calls `S::reconstruct` (§C.7, `ShareBound`) for each index after every answer. It
   ignores a share whose `share_id()` is not `S::share_id_of_position(position)` — the
   HoneyBadger FFT-domain index is the position itself, since RanSha refuses a share whose
   id is not its holder's party id
   (`stoffelcrypto-0.1.1/src/honeybadger/share_gen/share_gen.rs:386-392`); AVSS ids are
   `1..=n` in party order
   (`stoffelcrypto-0.1.1/src/avss_mpc/share_gen/share_gen_avss.rs:63-67`), so position
   plus one — or whose `share_degree()` is not the roster's `t`.
3. Returns as soon as every index reconstructs, and fails with
   `MaskReconstructionFailed { index }` once every leg has answered or ended without that.
   It does not stop at the first `min_shares` answers, and it takes no timeout of its own:
   a conclusive reconstruction is already correct while at most `t` positions are corrupt
   (§C.7), and a caller that wants a bound wraps the call, as every client surface already
   does with its `timeout`.

The coordinator relays output shares under the same rule, one node per message with the
node's position and signature (§C.7).

**The on-chain crate.** `stoffel-mpc-coordinator-on-chain` is a workspace member whose
`NodeRPCClient::start_rpc_client(n, t, addrs, cert_der, key_der)` and
`start_rpc_client_from_cert(n, t, addrs, client_cert)`
(`coord:on-chain/src/lib.rs:113-160`) call `setup_client`, so they must take a pin to
compile. The crate cannot get a *served* roster: its coordinator is the `StoffelCoordinator`
contract, which identifies clients by Ethereum `Address` (`:34`) and nodes by address
(`ids_and_addrs`, `:264-272`) and carries no TLS identity at all. Serving one needs a
contract and bindings change in `Stoffel-solidity-SDK` (pinned by git revision in the
coordinator workspace), which is outside both worktrees. **Decision:** the on-chain
crate is outside the roster authority in `0.3.0`, explicitly. Both constructors take
`roster: &NodeRoster` in place of `n` and `t` — a roster their *caller* builds with
`NodeRoster::new(t, certificates)` from node certificates it obtained out of band — and
`receive_mask` reconstructs by position exactly as above. This does not
bend rule 1: rule 1 governs deployments of this repository, every one of which runs the
off-chain coordinator, and the on-chain crate is `publish = false` with no consumer here
(no `Cargo.toml` in this repository names it). The follow-up that would bring it under
rule 1 is a roster digest stored in the contract, against which the caller's roster is
compared. `Round` gains `Aborted` (§C.8), which the contract has no counterpart for:
`OnChainCoordinator::trigger_round(Round::Aborted)` returns the new
`CoordinatorError::RoundNotProposable { round }` — the same error the off-chain client
returns locally for that round — and its `wait_for_round(Round::Aborted)` returns it too.

**No insecure escape hatch** — not a variant, not a cargo feature, not `#[cfg(test)]`:

- every test already holds the certificate it started its listener with
  (`self_signed_certs::server_cert()` returns the `CertifiedKey`, which
  `start_coord_from_cert` consumes), so pinning costs a test one argument;
- cargo features are unified across the dependency graph, so one crate enabling an
  "accept any server" feature for its tests would switch it on in every production build
  that shares the graph;
- `#[cfg(test)]` is invisible to `tests/` integration tests and to downstream crates, so
  it would not even reach the tests that would want it.

There is no constructor for a verifier without a pin, so the client fails closed.

**Server side** (`coord-shared/src/rpc.rs`). `SelfSignedClientVerifier` (`:30`) is
unchanged: it accepts any client certificate and verifies the handshake signature. That
is correct under rule 3 — a client's certificate is not known in advance, the handshake
proves possession of the presented key, and authorization happens per RPC (§C) — but it
means the *identity* that authorizes each RPC and the key rustls verified must come from
one derivation. Today they do not: `start_coord` parses the certificate a second time
with x509-parser, discards the remainder and ignores the algorithm
(`coord:coord-shared/src/rpc.rs:103-114`). `0.3.0`:

```rust
/// The caller identity every RPC is authorized on. `SpkiDer::from_certificate_der`
/// followed by `client_identity`, so trailing bytes, unsupported algorithms and
/// non-canonical encodings are refused.
pub fn caller_identity(cert_der: &[u8]) -> Result<ClientIdentity, PinError>;

pub trait RPCServerConnection {
    type Internal: 'static + Send;
    fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self;
    fn into_rpc(self) -> RpcModule<Self> where Self: Sized;
    /// Which connection pool `id` draws on. Default `Unreserved`.
    fn capacity_class(_internal: &Self::Internal, _id: &ClientIdentity) -> CapacityClass {
        CapacityClass::Unreserved
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityClass {
    /// A roster node: bounded only by `max_connections_per_identity`, so by `n` times it.
    Node,
    /// A client bound to a slot of a live execution (coordinator), or holding a registered
    /// reservation (node RPC listener).
    BoundClient,
    /// Everyone else.
    Unreserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcServerLimits {
    /// Accepted TCP connections whose TLS handshake has not finished, all sources (default 1024).
    pub max_pending_handshakes: usize,
    /// The same, from one source IP address (default 16).
    pub max_pending_handshakes_per_ip: usize,
    /// A connection whose TLS handshake has not finished by then is closed (default 10 s).
    pub handshake_timeout: Duration,
    /// Established connections of `CapacityClass::Unreserved` identities (default 4096).
    pub max_connections: usize,
    /// Established connections of `CapacityClass::BoundClient` identities (default 1024).
    pub max_bound_client_connections: usize,
    /// Established connections of one identity, whatever its class (default 8).
    pub max_connections_per_identity: usize,
    /// An unreserved connection with no call in progress, no live subscription and no call
    /// started for this long is closed (default 30 s).
    pub idle_timeout: Duration,
    /// jsonrpsee's per-connection subscription bound (default 64; jsonrpsee's own default is 1024).
    pub max_subscriptions_per_connection: u32,
    /// Messages a connection may have queued before its subscriptions stop receiving
    /// (default 16; jsonrpsee's own default is 1024).
    pub message_buffer_capacity: u32,
}

impl Default for RpcServerLimits { /* the defaults above */ }

pub async fn start_coord<T: RPCServerConnection>(addr: &str, port: u16, cert_der: Vec<u8>,
    key_der: Vec<u8>, rpc_server_data: Arc<Mutex<T::Internal>>, limits: RpcServerLimits)
    -> Result<RPCServerHandle, CoordinatorError>;
```

- A caller certificate `caller_identity` refuses is logged and its connection closed
  before any RPC module is built. The coordinator listener and both node RPC listeners
  (`off-chain` `NodeRPCServer` and `on-chain` `NodeRPCServer`) share this path, so a
  reservation and the mask delivery keyed on it always compare one derivation's output.
- **Before the handshake**, the accept loop counts each accepted stream against
  `max_pending_handshakes` and against its peer address's `max_pending_handshakes_per_ip`
  (`listener.accept()` returns the address, `:70`), and drops the stream at once when
  either is full. The handshake runs under `tokio::time::timeout(handshake_timeout, …)`;
  both counts are released when it ends either way. Holding the pending pool takes
  `max_pending_handshakes / max_pending_handshakes_per_ip` = 64 source addresses, each
  reopening a stream every `handshake_timeout`; nothing before the handshake can tell a
  node from anyone else, so that residual belongs to the deployment's reachability
  controls (§C.2, §G).
- **After the handshake**, the identity is known, and `T::capacity_class` decides its
  pool. The coordinator answers `Node` for a roster node and `BoundClient` for an
  identity bound to a slot of a live execution — an index that `associate_client` (C.4
  step 10) and every removal path maintain, so the check is one lookup under the state
  mutex, taken only to read it. The node RPC listener, which no node dials, answers
  `BoundClient` for an identity it holds a registered reservation for. A connection is
  refused when its identity already has `max_connections_per_identity` connections, or
  when its class's pool is full: `max_connections` for `Unreserved`,
  `max_bound_client_connections` for `BoundClient`; `Node` has no pool beyond the
  per-identity bound, because there are only `n` node identities. So a flood of fresh
  certificates can fill the unreserved pool, and certificates bound under `Open` can fill
  the bound-client pool, but neither touches what a node needs to connect. The class is
  decided at connection time: a client connects unreserved, associates, and its next
  connection is a bound client's.
- **Idle unreserved connections are closed.** Each per-connection service is built with
  an RPC middleware (`TowerServiceBuilder::set_rpc_middleware`,
  `jsonrpsee-server-0.26.0/src/server.rs:634`) that stamps call starts and ends and counts
  live subscriptions; the connection task stops the connection
  (`ServerHandle::stop`, `jsonrpsee-server-0.26.0/src/future.rs:83`, on the handle
  `stop_channel` returns, `rpc.rs:116`) when an unreserved identity has had no call in
  progress, no live subscription and no call started for `idle_timeout`. Every
  subscription is gated to nodes and admitted clients (§C.6), so an identity that holds
  neither can keep a connection only by calling, and those calls are rate limited (§C.6).
  Honest clients are unaffected: association is one call, every wait after it is a
  subscription, which is never idle, and a later connection of the bound identity is a
  bound client's.
- The per-connection service is built with
  `Server::builder().set_config(ServerConfig::builder().max_subscriptions_per_connection(limits.max_subscriptions_per_connection).set_message_buffer_capacity(limits.message_buffer_capacity).build())`
  (`server.rs:661`, `:406`, `:466`). jsonrpsee queues outgoing messages in one channel of
  that capacity per connection (`jsonrpsee-server-0.26.0/src/transport/ws.rs:442`), so a
  connection that stops reading holds at most `message_buffer_capacity` messages of
  memory; §C.6's live broadcasts use `try_send` and drop such a subscriber rather than
  wait for it.
- jsonrpsee's own `max_connections` does not help with any of this: `start_coord`
  builds a fresh `Server::builder().to_service_builder()` per connection (`:116-119`),
  and each gets a fresh `ConnectionGuard`
  (`jsonrpsee-server-0.26.0/src/server.rs:837-846`).
- `start_coord` keeps refusing a caller that presents no certificate (`:96-100`).

Every `start_coord` caller passes `RpcServerLimits::default()` unless configured
(`--max-connections` on the wrapper and `run-coord`, §F.3).

**A node's coordinator link is not re-established.** A node opens its link once (§D.1
step 2) and never reconnects: its place in §D.7 — mask shares provisioned, reservations
registered, masked inputs agreed — is not something a fresh connection could resume, and
a replacement process cannot rejoin a mesh that has already formed (rule 1: membership is
fixed once the network is up). A transport failure on the link — a call that cannot reach
the coordinator, or a subscription that ends without its item — exits the node 13 (§D.3),
and the execution continues without it as without any crashed party. The node class
above is what keeps a connection flood from causing that in the first place: a node
connects once, at startup, into capacity no other identity can use.

### B. The node roster RPC

**Types** (`coord-shared/src/roster.rs`):

```rust
/// Unverified bytes: a certificate is checked when a `NodeRoster` is built from it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeCertificateDer(Vec<u8>);

impl NodeCertificateDer {
    pub fn from_der(der: Vec<u8>) -> Self;
    pub fn as_bytes(&self) -> &[u8];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RosterDigest([u8; 32]);

impl RosterDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}

/// Lowercase hexadecimal, 64 characters: what every message and flag of this section shows.
impl std::fmt::Display for RosterDigest { /* … */ }

/// Exactly 64 hexadecimal characters, either case; `--expect-roster-digest` parses with it.
impl std::str::FromStr for RosterDigest { type Err = RosterDigestParseError; /* … */ }

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RosterDigestParseError {
    #[error("expected 64 hexadecimal characters, got {length}")]
    WrongLength { length: usize },
    #[error("character {position} is not hexadecimal")]
    NotHex { position: usize },
}

/// Every value is canonical and verified: the fields are private, and deserializing
/// goes through `TryFrom<NodeRosterWire>`, which runs the full receiver check below.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NodeRosterWire", into = "NodeRosterWire")]
pub struct NodeRoster {
    n: u64,
    t: u64,
    node_certificates: Vec<NodeCertificateDer>,
    digest: RosterDigest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRosterWire {
    pub n: u64,
    pub t: u64,
    pub node_certificates: Vec<NodeCertificateDer>,
    pub digest: RosterDigest,
}

impl NodeRoster {
    /// Coordinator side: certificates in any order in, canonical order out.
    pub fn new(t: u64, certificates: Vec<NodeCertificateDer>) -> Result<Self, RosterError>;
    pub fn n(&self) -> u64;
    pub fn t(&self) -> u64;
    pub fn digest(&self) -> RosterDigest;
    /// Canonical order, which is party-index order.
    pub fn node_certificates(&self) -> &[NodeCertificateDer];
    pub fn node_spkis(&self) -> Vec<SpkiDer>;
    /// Coordinator identity form, same order; this is the coordinator's `mpc_nodes`.
    pub fn node_identities(&self) -> Vec<ClientIdentity>;
    pub fn position_of(&self, spki: &SpkiDer) -> Option<usize>;
    pub fn to_wire(&self) -> NodeRosterWire;
}

// `#[error("…")]` attributes are elided in this section's error enums; every variant carries one.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RosterError {
    Empty,
    /// `t == 0`: every single node could reconstruct every client mask.
    ZeroThreshold,
    UnparseableCertificate { index: usize, reason: PinError },
    /// Two certificates share an SPKI, or share a `subject_public_key` BIT STRING. With the
    /// canonical layouts of §A, either means the same key.
    DuplicateKey { first: usize, second: usize },
    /// `n < 2t + 1`, the rule `validate_topology` enforces today (coord:off-chain/src/lib.rs:1353-1394).
    ThresholdTooLarge { n: u64, t: u64 },
    CountMismatch { n: u64, certificates: usize },
    NotCanonical { index: usize },
    DigestMismatch,
}
```

**Canonical order** is ascending bytewise order of each certificate's `SpkiDer`. That is
`QuicNetworkManager::get_sorted_public_keys` (`quic.rs:1856-1872`) and `Roster::index_of`,
so `node_certificates()[i]` is party `i` everywhere. The order is total: `new` refuses two
certificates with the same SPKI, and also two with the same BIT STRING, so the
coordinator's identities are unique as well.

**Digest**, byte-exact. Both repositories implement it and both assert the golden vector
below:

```text
hasher = blake3::Hasher::new_derive_key("stoffel-coordinator-node-roster-v1")
hasher.update( n as u64, 8 bytes little-endian )
hasher.update( t as u64, 8 bytes little-endian )
for each certificate, in canonical order:
    spki = X509Certificate::from_der(certificate).public_key().raw
    hasher.update( spki.len() as u64, 8 bytes little-endian )
    hasher.update( spki )
digest = hasher.finalize()                                   // 32 bytes
```

The digest covers keys, not certificate bytes: re-issuing a node certificate for the same
key is the same membership and the same digest, and — since the epoch store is keyed by
it (D.5) — the same epoch counter. The coordinator adds `blake3 = "1.8"` to
`[workspace.dependencies]` and to `coord-shared` (it is already in that lock graph, at
1.8.7).

**Golden vector.** This repository's `ids/nodes/cert{0..4}.crt` with `t = 1` sort into
party order `cert3, cert0, cert1, cert2, cert4` (each SPKI is 91 bytes: a P-256 key with a
65-byte point) and digest to

`da7fa2fee0f97aaef9e77aa8534a2be721fbaf3ab26a52b5c2fd560f41a8e00d`

Recomputed independently during review (blake3 `1.8.5`, x509-parser `0.18.1`): same order,
same lengths, same digest. The vector reads certificates only — no private key — so it
stays valid under §F.0. The coordinator repository copies the five certificate files, and
nothing else from `ids/`, byte-for-byte to `crates/coord-shared/tests/fixtures/ids/nodes/`.

**Receiver check** (`TryFrom<NodeRosterWire>`), in order: non-empty (`Empty`); `t >= 1`
(`ZeroThreshold`); `n` equals the certificate count (`CountMismatch`); `n >= 2t + 1`
(`ThresholdTooLarge`); every certificate passes `SpkiDer::from_certificate_der`, canonical
layout included (`UnparseableCertificate`, whose `reason` is the `PinError`); SPKIs
strictly ascending (`NotCanonical`, which also rules out a repeated SPKI); BIT STRINGs
unique (`DuplicateKey`); recomputed digest equals the served one (`DigestMismatch`). A
receiver never re-sorts: a roster in any other order was not produced by
`NodeRoster::new`. `NodeRoster::new` runs the same checks, except that it
sorts instead of refusing an order and computes the digest instead of comparing one.

**RPC** (`coord:off-chain/src/lib.rs`, trait `CoordinatorRPCBase`, `:864`):

```rust
#[method(name = "get_node_roster")]
async fn get_node_roster(&self) -> RpcResult<NodeRosterWire>;
```

The method returns the *wire* form on purpose. Had it returned `NodeRoster`, the check
would run inside serde while the jsonrpsee proc-macro client decodes the response, and
every client call site maps that failure to a string (`e.to_string()`, e.g.
`coord:off-chain/src/lib.rs:2678-2680`) — `DigestMismatch` would be indistinguishable
from a transport decode error. `CoordinatorLink::connect` instead receives
`NodeRosterWire` and calls `NodeRoster::try_from(wire)` itself, mapping the failure to
`CoordinatorError::Roster(RosterError)`. `NodeRoster` keeps `#[serde(try_from)]` for every
other deserialization path, so no unverified `NodeRoster` value exists anywhere.

- **Scope:** process-wide, not execution-scoped. It fails only when the caller exceeds its
  rate (§C.6).
- **Access:** any caller that completed the mTLS handshake. The caller does not have to be
  a node, pre-registered or admitted: a client nobody has heard of needs exactly this
  response to pin the nodes it is about to take masks from (§E).
- **Immutable for the process lifetime.** `CoordinatorRPCServerSharedBase` holds
  `node_roster: NodeRoster` and `server_spki: SpkiDer`, set by its constructor and never
  again:

  ```rust
  /// `server_spki` is the key of the certificate the operator serves this state with;
  /// registration validation refuses it as an invitation issuer (§C.1).
  pub fn new(node_roster: NodeRoster, server_spki: SpkiDer) -> Self;   // replaces new(n, t, initial_mpc_nodes), :1157
  pub fn new_for_execution(node_roster: NodeRoster, server_spki: SpkiDer,
      registration: ExecutionRegistration) -> Result<Self, CoordinatorError>;   // replaces the eight-argument form, :1201
  ```

  `n`, `t` and `mpc_nodes` (`:1022-1024`) become derived views of it, `mpc_nodes` in
  canonical order; `validate_topology` (`:1353`) moves into `NodeRoster::new`. No method
  and no RPC changes it. A different roster is a different coordinator process, and nodes
  are restarted against it (rule 1). The state also keeps the roster's wire form in an
  `Arc<NodeRosterWire>` built once by the constructor; `get_node_roster` clones that `Arc`
  under the state mutex and serializes after releasing it.

  **The served key is the pinned key.** Nothing in `0.2.0` ties the state to the
  certificate its listener presents: `OffChainCoordinatorServer::start_coord` receives
  `cert_der` separately from the state (`coord:off-chain/src/lib.rs:2552-2568`). So
  `IssuerIsCoordinatorKey` could be checked against a key the listener does not serve.
  `start_coord`, `start_coord_from_cert` and `start_coord_one_off` therefore derive
  `SpkiDer::from_certificate_der(&cert_der)` before binding, and refuse to start with
  `CoordinatorError::ServerCertificateMismatch` when it differs from the state's
  `server_spki`, or with `CoordinatorError::Pin` when the certificate itself is refused.

**Why serving node certificates to anyone is acceptable.** A certificate carries a public
key and nothing that authorizes its holder; impersonating a node takes its private key,
which the TLS handshake proves. And every node already hands its certificate to anyone who
dials it: the QUIC listener completes the handshake, sending its certificate, before its
allowlist check runs (`quic.rs:3292` follows `incoming.await`), and the node RPC listener
accepts any client certificate while presenting its own. What the roster adds is the set,
its order and `t`, and every client needs those to reconstruct its masks and outputs
(`NodeRPCClient` reconstructs with both, `coord:off-chain/src/lib.rs:295` and `:311`). The
residual disclosure is that these keys belong to one deployment; operators must keep
anything sensitive out of node certificate subjects.

### C. Client admission

#### C.1 Registration: immutable, operator-only, bounded

```rust
// coord:off-chain/src/lib.rs — replaces :131-140
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRegistration {
    pub execution_id: ExecutionId,
    /// `program_hash_of` the compiled program bytes (below).
    pub program_hash: [u8; 32],
    pub client_slots: ClientSlotTable,
    pub admission: AdmissionPolicy,
    /// Required under `Open` and `Invitation`, optional under `PreRegistered` (C.8).
    pub deadlines: Option<ExecutionDeadlines>,
}

// coord-shared/src/admission.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSlotSpec { pub input_count: u64, pub output_count: u64 }

/// One entry per client slot. The position is the slot's `ClientIndex`, which is the
/// program's `client_slot` (`ClientIoSchema::client_slot`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientSlotTable(Vec<ClientSlotSpec>);

impl ClientSlotTable {
    pub fn new(slots: Vec<ClientSlotSpec>) -> Self;
    pub fn slots(&self) -> &[ClientSlotSpec];
    /// The rows of the validation table below that need neither a roster nor a policy.
    /// Nodes and clients run it on a served `ExecutionSummary` as well (§D.7, §E.1).
    pub fn check_bounds(&self) -> Result<(), RegistrationError>;
    // Meaningful once `check_bounds` has passed:
    pub fn capacity(&self) -> u32;
    pub fn n_inputs(&self) -> u64;
    /// Slot `i` owns `[sum of input_count over slots j < i, + input_count_i)`; `None` when 0.
    pub fn input_range(&self, slot: ClientIndex) -> Option<InputRange>;
    pub fn output_rights(&self, slot: ClientIndex) -> OutputRights;
    pub fn has_output_slots(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientIndex(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixSeconds(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDeadlines {
    /// Every slot is bound by then, or the execution is aborted (C.8).
    pub association: UnixSeconds,
    /// Every masked input is submitted by then, or the execution is aborted (C.8).
    pub input: UnixSeconds,
}

/// 32 bytes the coordinator draws from `ring::rand::SystemRandom` when it registers an
/// execution. Not secret: it names one registration of one `ExecutionId` (C.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RegistrationNonce([u8; 32]);

/// `blake3::Hasher::new()`, `update(b"stoffel-program-v1")`, `update(program_bytes)`,
/// `finalize()` — byte for byte the VM's `program_id_from_bytes`
/// (`crates/stoffel-vm/src/net/program_sync.rs:78-83`).
pub fn program_hash_of(program_bytes: &[u8]) -> [u8; 32];

pub const MAX_CLIENT_SLOTS: u32 = 16_384;
pub const MAX_INPUTS_PER_SLOT: u64 = 32_768;
pub const MAX_OUTPUTS_PER_SLOT: u64 = 1_024;
pub const MAX_INPUTS: u64 = 1 << 20;
/// One masked input's encoding. Every `ShareBound::ValueType` in use is a 32-byte
/// compressed scalar; 64 leaves room for a wider field without re-measuring C.1.
pub const MAX_MASKED_INPUT_BYTES: u64 = 64;
/// One node's sealed output ciphertext for one client (§C.7).
pub const MAX_SEALED_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
```

**The program hash** is the one both sides use: the coordinator registers
`program_hash_of(bytes)`, and every node compares it with `program_id_from_bytes` of the
program it loaded (§D.7 step 1). Golden vector, asserted by
`crates/stoffel-vm/src/net/program_sync.rs`, `coord-shared/src/admission.rs` and the
wrapper:

`program_hash_of(b"stoffel golden program")` = `fe9f7bf29eff22b4631f8468a32aff7761e78aba67a0ba19724779f0768179ee`

**Deleted:** the fields `n_inputs`, `output_clients`, `input_assignment` and
`min_output_shares`, and the types `InputAssignment`, `InputClientRange`,
`InputSlotAssignment` (`:95-128`) with `expand_input_ranges` and `input_slot_client`. The
layout is per slot and names nobody because it is the program's shape
(`ClientIoManifest.clients`), fixed before anyone associates. Identities are the only late
part. `min_output_shares` only delayed an output client's first snapshot until that many
node ciphertexts had arrived (`:1722`, `:2435-2437`); §C.7 delivers each node's ciphertext
on its own and the client decides when it can reconstruct, so the field has nothing left
to decide.

**Registration is in-process and operator-only.** The `register_execution` RPC method
(`:865-866`, implemented at `:1765-1781`) and `OffChainCoordinatorClient::register_execution`
(`:2685-2692`) are **deleted**:

- The RPC is gated only on `mpc_nodes.contains(&self.id)`, and registration is
  first-writer-wins (`:1231-1239`). Any single node could therefore fix an unregistered
  execution's program hash, slot table and policy — `Open`, or an issuer it controls —
  and every later registration of that id would fail as a conflict. That is admission
  authority in one node, which rule 2 forbids, and §D.6's barrier cannot see it: every
  node reads the same bad registration.
- A registration becomes evictable only after a retirement quorum (`:1246-1260`), so the
  same node could also fill `DEFAULT_MAX_CONCURRENT_EXECUTIONS` with registrations nobody
  retires and lock honest ones out for good.
- The alternative — apply a registration once `transition_quorum()` nodes proposed it
  byte-identically — would make nodes carry the slot table, policy and program hash as
  configuration again, which §D.2 removes.
- Nothing here uses the RPC: `local_runner.rs:143` and the wrapper
  (`docker/coordinator-wrapper/src/main.rs:169`) register through `new_for_execution`.
  Standing `run-coord` registered nothing at startup and relied on it
  (`coord:bins/src/bin/run-coord.rs:309-375`); §F.3 makes it register at startup.

With no remote registration left, the per-node cap on pending registrations the review
proposed guards nothing, and is not added.

```rust
impl CoordinatorRPCServerSharedBase {
    /// The checks below, in their order; draws the nonce and registers.
    pub fn register_execution(&mut self, registration: ExecutionRegistration)
        -> Result<RegistrationNonce, CoordinatorError>;
}

impl ExecutionRegistration {
    /// The rows of the validation table that read no coordinator state.
    pub fn validate(&self, roster: &NodeRoster, server_spki: &SpkiDer, now: UnixSeconds)
        -> Result<(), RegistrationError>;
}

impl<C: RPCServerConnection<Internal = CoordinatorRPCServerSharedBase>> OffChainCoordinatorServer<C> {
    /// The state this listener serves, for an embedding operator that registers
    /// further executions while it runs.
    pub fn state(&self) -> Arc<Mutex<CoordinatorRPCServerSharedBase>>;
}
```

**Validation.** `register_execution` runs, strictly in this order — replacing the string
errors at `:1231-1270` and `:1414-1455`:

1. `execution_id` is live and its registration is identical → return its existing nonce.
   First, so that re-registering a running execution after its association deadline
   answers its nonce rather than `DeadlineElapsed`.
2. `execution_id` is in `EndedExecutions` (C.8) → `ExecutionIdRetired { execution_id }`.
3. `execution_id` is live with a different registration → `ConflictingRegistration
   { execution_id }`.
4. `registration.validate(&self.node_roster, &self.server_spki, now)` — the pure rows of
   the table below, in table order.
5. `DEFAULT_MAX_CONCURRENT_EXECUTIONS` live: evict one evictable execution (a quorum-retired
   one, `:1240-1266`, or an aborted one, C.8), recording it in `EndedExecutions`; none
   evictable → `ExecutionCapacityReached { capacity }`. After step 4 on purpose: a
   registration that is refused anyway never evicts anything.
6. Draw the nonce, build the state (below) and insert it.

| Rule (`validate`, in order) | `RegistrationError` variant |
|---|---|
| `execution_id` nonzero | `ZeroExecutionId` |
| `program_hash` nonzero | `ZeroProgramHash` |
| `client_slots.len() <= MAX_CLIENT_SLOTS` | `TooManyClientSlots { slots, max }` |
| no slot has `input_count == 0 && output_count == 0` | `EmptyClientSlot { client_index }` |
| every `input_count <= MAX_INPUTS_PER_SLOT` | `TooManyInputsInSlot { client_index, input_count, max }` |
| every `output_count <= MAX_OUTPUTS_PER_SLOT` | `TooManyOutputsInSlot { client_index, output_count, max }` |
| `n_inputs() <= MAX_INPUTS` | `TooManyInputs { n_inputs, max }` |
| `PreRegistered`: exactly one identity per slot | `PreRegisteredCountMismatch { slots, clients }` |
| `PreRegistered`: every identity is a canonical key (`KeyAlgorithm::of_client_identity` is `Some`, §A) — a P-256 one for a slot with `output_count > 0` | `UnsupportedPreRegisteredKey { client_index }` |
| `PreRegistered`: identities unique | `DuplicatePreRegisteredClient { client_index }` |
| `Invitation`: the issuer SPKI's `key_algorithm()` is `EcdsaP256` | `UnsupportedIssuerKey` |
| `Invitation`: the issuer SPKI is no roster node's (`roster.node_spkis()`) | `IssuerIsRosterNode { position }` |
| `Invitation`: the issuer SPKI is not `server_spki` | `IssuerIsCoordinatorKey` |
| `Open` and `Invitation` carry `deadlines` | `DeadlinesRequired` |
| `deadlines.association <= deadlines.input` | `DeadlinesOutOfOrder { association, input }` |
| both deadlines later than `now` | `DeadlineElapsed { deadline, now }` |

`ConflictingRegistration`, `ExecutionIdRetired` and `ExecutionCapacityReached` are
`RegistrationError` variants too; they come from steps 2, 3 and 5, which read the
coordinator state `validate` is not given.

**The bounds are sized from the wire.** jsonrpsee defaults request and response bodies
to 10 MiB on the server (`jsonrpsee-server-0.26.0/src/server.rs:362-363`, used by
`coord:coord-shared/src/rpc.rs:117`), turns an oversized response into an error object
(`jsonrpsee-core-0.26.0/src/server/method_response.rs:176-203`), and the client caps a
received message at 10 MiB (`jsonrpsee-client-transport-0.26.0/src/ws/mod.rs:111-112`,
`:509`; `coord:coord-shared/src/self_signed_certs.rs:224` uses the default). A
subscription message is not checked at all on the way out
(`SubscriptionSink::send`, `jsonrpsee-core-0.26.0/src/server/subscription.rs:333-343`):
an oversized one reaches the client and fails there, on every replay. `u32::MAX` slots
was never reachable: a response over the cap fails only at the freeze, after clients
have associated and taken masks. Worst cases, measured with `serde_json` 1.0 over the
exact shapes of this section, every number at its largest, every byte `0xff`, every
identity a 65-byte P-256 point and every signature 72 bytes (the longest DER ECDSA P-256
signature). Subscription messages include jsonrpsee's notification envelope
(`{"jsonrpc":"2.0","method":…,"params":{"subscription":…,"result":…}}`) with a 20-digit
subscription id:

| Message | At | Bytes | Of 10 MiB |
|---|---|---|---|
| `get_client_admissions` records (C.7) | 16,384 records of 389 bytes | 6,389,918 | 60.9 % |
| `client_slots` of `get_execution_summary` | 16,384 slots | 688,129 | 6.6 % |
| `submit_masked_inputs` parameters (C.7) | 32,768 inputs of `MAX_MASKED_INPUT_BYTES`, one signature | 8,454,575 | 80.6 % |
| one `Event::MaskedInputEvent` (one per slot, C.7) | same | 8,454,899 | 80.6 % |
| one `Event::ReservedInputEvent` | 32,768 indices | 262,568 | 2.5 % |
| `send_output_shares` parameters (C.7) | a `MAX_SEALED_OUTPUT_BYTES` ciphertext | 8,389,350 | 80.0 % |
| one `SealedOutputShares` item of `obtain_output_shares` (C.7) | same | 8,389,357 | 80.0 % |

Without `MAX_MASKED_INPUT_BYTES`, `submit_masked_inputs` stored and rebroadcast any bytes
(`coord:off-chain/src/lib.rs:2006-2058`, recorded at `:2074-2078`, replayed at
`:1515-1531`), so a request just under the server's 10 MiB request cap became an event over
the client's 10 MiB receive cap, recorded for good: every node's `sub_masked_inputs`
would fail on every retry. At 1,024-byte inputs the same slot is 134,283,908 bytes. The
submission is refused instead (C.5 code 36).

Without `MAX_SEALED_OUTPUT_BYTES`, `send_output_shares` accepted any `enc_shares`
(`:2390-2437`), and `obtain_output_shares` sent each client one snapshot holding every
node's ciphertext (`:1705-1727`, `:1747-1748`). An honest AVSS registration inside the
slot bounds already overflowed it: a `FeldmanShamirShare<Fr, G1>` over BLS12-381 carries
`t + 1` compressed commitments and is 344 bytes at `t = 5` (measured with
`CanonicalSerialize::serialized_size`), so 1,024 outputs are 352,280 bytes of ciphertext —
about 1.26 MB of JSON per node at the 3.57 characters an average random byte takes — and
from nine nodes on the snapshot crosses the cap. One node could also send one
oversized ciphertext and make every later snapshot for that client undeliverable. In
`0.3.0` each node's ciphertext is its own message (C.7) and is refused above the bound
(code 39). At the bound one HoneyBadger ciphertext of 1,024 outputs is 49,176 bytes
(48-byte shares); an AVSS one over BLS12-381 fits up to `t = 40` (2,072,600 bytes) and
not at `t = 41`. Neither the coordinator nor the registration knows the share encoding,
so the nodes check it before preprocessing (§D.7 step 1) and clients before associating
(§E.1 step 2): `8 + output_count × S::serialized_share_len(t) + 16` — the vector's length
prefix and the AES-GCM tag — must not exceed `MAX_SEALED_OUTPUT_BYTES` for any slot.

The registration — program binding, slot layout, policy, deadlines — is **immutable**,
and `register_execution` snapshots it once as an `Arc`: `get_execution_summary` clones that
`Arc` and the round under the state mutex, and builds and serializes the summary after
releasing it, so a summary read never copies the slot table while the mutex is held. The
client→slot binding is **separate mutable per-execution state**:

```rust
// inside CoordinatorExecutionState (:1079); replaces output_clients (:1110),
// input_assignments (:1112), n_reserved, reserved_indices and masked_inputs (:1099-1101),
// and the four event logs with their sink lists (:1088-1095)
registration_nonce: RegistrationNonce,
registration: Arc<ExecutionRegistration>,
admissions: ClientAdmissions,

struct ClientAdmissions {
    slots: Vec<Option<AdmittedClient>>,               // indexed by ClientIndex
    by_identity: HashMap<ClientIdentity, ClientIndex>,
    /// Slot order of successful reservations and submissions, for replay (C.6).
    reservation_order: Vec<ClientIndex>,
    submission_order: Vec<ClientIndex>,
}

struct AdmittedClient {
    client: ClientIdentity,
    admission: ClientAdmission,
    /// The request that bound or first claimed the slot. `None` only for a
    /// pre-registered slot whose client has not called `associate_client` yet.
    request: Option<AssociationRequest>,
    /// The slot's reservation (C.6): its whole `input_range`, made in one call.
    reserved: bool,
    submission: Option<Arc<MaskedInputSubmission>>,
}
```

A binding is only ever added — never removed and never moved to another slot (C.9).

**Memory.** Revision 1 counted only `reserved_indices` and `masked_inputs` (48 bytes an
entry, about 48 MiB at `MAX_INPUTS`). `0.2.0` also stores, per index, a heap copy of the
owner's identity in `reserved_indices` and another in each `AssignedMaskReservation`, and
each masked input three times — `masked_inputs`, `masked_input_events` and
`assigned_masked_input_events`, the last with a further identity copy
(`coord:off-chain/src/lib.rs:1088-1101`, `:2058-2080`, `:2271-2290`): several hundred
bytes an input, hundreds of MiB per execution at the bound. `0.3.0` keeps an index's
owner implicitly — the slot's admitted identity, stored once — and a masked input once,
inside its slot's `Arc<MaskedInputSubmission>`, which a live broadcast and every replay
send without copying; the reservation and submission histories are `reservation_order` and
`submission_order`, one `ClientIndex` per event, and events are rebuilt from the slot when
sent (C.6); and the assigned streams are gone (C.10). An execution at the bounds therefore holds
at most `MAX_INPUTS × 104` bytes of inputs (a 24-byte `Vec` header and at most 80 bytes of
allocation for a 64-byte input) plus, per slot, an identity, an admission and an
association request with any invitation (under 1 KiB) — about 100 MiB and 16 MiB — and the
coordinator holds up to `DEFAULT_MAX_CONCURRENT_EXECUTIONS` (1,024) of them. Registration
is operator-only, so that product is the operator's to size; nothing remote can create an
execution.

#### C.2 Admission policies

```rust
// coord-shared/src/admission.rs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicy {
    /// Today's behaviour: `clients[i]` is bound to slot `i` at registration.
    PreRegistered { clients: Vec<ClientIdentity> },
    /// Any certificate holder may bind a free slot, first come, first served.
    Open,
    /// Only the invitee named by a valid `SignedInvitation` from `issuer` may bind the slot
    /// that invitation names.
    Invitation { issuer: InvitationIssuer },
}

/// What a non-node may learn about the policy: never the pre-registered identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicyKind { PreRegistered, Open, Invitation { issuer: InvitationIssuer } }
```

| Policy | A slot is bound | By whom | Capacity | Deadlines |
|---|---|---|---|---|
| `PreRegistered` | at registration: every `AdmittedClient` exists before the first RPC | nobody else; `associate_client` returns the existing admission | `client_slots.len()`, all bound from the start | optional |
| `Open` | at `associate_client` | any caller | `client_slots.len()` | required |
| `Invitation` | at `associate_client` | the invitee of a valid invitation, in the slot it names | `client_slots.len()` | required |

`Open` deliberately has **no `capacity` field**. The slot table already is the capacity: a
compiled program has exactly `client_slots.len()` client slots, and a second number could
only disagree with it. Smaller would leave a slot nobody may bind, so `InputCollection`
never opens (C.8); larger would admit clients with no input range and no output rights.
A program generic over its client count (`ClientStore.get_number_clients()`, as in
`crates/stoffel-lang/examples/mpc_client_federated_average`) takes the count from the
registration's slot table, so "how many clients may join" is chosen per execution by
choosing the table.

**`Open` is for networks where association is already access-controlled.** Certificates
cost nothing to mint and association is first come, first served, so anyone who can reach
the coordinator can bind every slot of an `Open` execution the moment it is registered —
then never reserve, which holds `InputCollection`, or reserve and never submit, which holds
`MPCExecution` (`:1603-1618`). Deadlines turn that from a permanent stall into an abort
(C.8), but such an attacker can still abort every `Open` execution it can reach. Use
`Open` on a private network, behind an authenticating front end, or in tests. **For
arbitrary clients on a reachable network, use `Invitation`**: the issuer decides who may
bind, and an invitee who never shows is bounded by the same deadlines.

#### C.3 Signed invitations

```rust
/// An ECDSA P-256 issuer key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvitationIssuer(SpkiDer);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub execution_id: ExecutionId,
    /// One registration of `execution_id`: a coordinator restart, or a later
    /// registration of the same id, draws a new nonce and orphans the invitation.
    pub registration_nonce: RegistrationNonce,
    pub program_hash: [u8; 32],
    /// The coordinator's node roster. The nodes are part of what the issuer vouches for.
    pub roster_digest: RosterDigest,
    /// Coordinator time after which association with this invitation is refused.
    pub not_after: UnixSeconds,
    /// The invitee's key in coordinator identity form, compared with the caller's mTLS identity.
    pub invitee: ClientIdentity,
    /// The slot the issuer assigns. Required: a slot is a program role, with its own input
    /// range and output rights.
    pub client_index: ClientIndex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInvitation {
    pub invitation: Invitation,
    /// ASN.1 DER ECDSA P-256 / SHA-256 signature over `invitation.signing_bytes()`.
    pub signature: Vec<u8>,
}
```

`Invitation::signing_bytes()`, byte-exact:

```text
b"stoffel-coordinator-invitation-v3"            33 bytes, ASCII, no terminator
execution_id                                    32 bytes
registration_nonce                              32 bytes
program_hash                                    32 bytes
roster_digest                                   32 bytes
not_after as u64                                 8 bytes little-endian
invitee.len() as u64                             8 bytes little-endian
invitee                                         invitee.len() bytes
client_index as u32                              4 bytes little-endian
```

- **The slot is required (v3).** Revision 1's `client_index: None` let the invitee bind any
  free slot. Slots are program roles — each has its own input range and `OutputRights` —
  so an invitee meant for an input-only role could take the slot that receives outputs,
  or the slot another invitation names, leaving the rightful invitee `SlotTaken` and the
  execution to abort at its association deadline. The coordinator cannot see that
  conflict, because invitations are not registered. "Admit this identity" had become
  "admit this identity to any role". A shape-scoped wildcard (`AnyOfShape(ClientSlotSpec)`)
  is **not** added: an issuer that wants interchangeable invitees already decides how
  many invitations it issues, so it can number them itself, and a wildcard invitee could
  still take the slot an exact invitation of the same shape names — the same squat,
  narrowed but not removed, and still invisible to the coordinator.
- **Why each field.** Revision 0 bound only `execution_id`, the invitee and the slot, and
  justified having no expiry and no nonce by the execution id bounding the invitation's
  life. It does not: shipped stacks reuse one `ExecutionId` across `docker compose
  down`/`up` (§8 row 3), and every coordinator-bearing compose file defaults
  `STOFFEL_EXECUTION_ID` to the same constant (`docker-compose.yml:102`,
  `docker-compose.mesh.yml:88`, `docker-compose.benchmark.yml:98`,
  `docker-compose.coordinator.reserve-index.yml:118`), so such an invitation stayed valid
  for every later program registered under that id, on every coordinator that trusted
  the issuer. The nonce scopes an invitation to one registration, the program hash to one
  program, the roster digest to one node set, and `not_after` to a window inside that
  registration. There is no revocation list: a short `not_after` is the tool. Presenting
  the same invitation twice is C.4's idempotent case, not a replay.
- **Verify:** `ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1,
  issuer_point).verify(&signing_bytes, &signature)`, where `issuer_point` is the issuer
  SPKI's `subject_public_key` BIT STRING. `ring` is already a `coord-shared` dependency.
- **Sign:** `SignedInvitation::sign(invitation: Invitation, issuer_pkcs8_der: &[u8]) ->
  Result<SignedInvitation, InvitationSigningError>`, via
  `ring::signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &SystemRandom::new())`.
  `InvitationSigningError` is `UnsupportedIssuerKey | SigningFailed`.
- **The issuer is an admission authority, inside the coordinator's trust boundary.** It
  decides who may associate, which is one of the functions rules 1–2 give the
  coordinator, so it is trusted exactly as the coordinator's operator is, and rule 2
  requires that **no node's operator runs it**: a node operator who also held the issuer
  key would control admission for its node alone, more trust than its peers. Registration
  refuses an issuer whose key is a roster node's (`IssuerIsRosterNode`) or the
  coordinator's own server key (`IssuerIsCoordinatorKey`). Those checks compare keys, not
  operators — a node operator can hold a second, unrelated key — so they guard against
  misconfiguration, such as reusing a node or server identity as the issuer, and do not
  by themselves enforce rule 2; who holds the issuer key is a deployment decision rule 2
  constrains. Generate the issuer key for that purpose and nothing else,
  on the issuer's machine — never reuse a `generate-ids` node or server identity.
  `generate-ids` run once for the issuer does produce a usable pair (rcgen's
  `generate_simple_self_signed` makes a P-256 key, `rcgen-0.14.7/src/key_pair.rs:85-87`,
  and `signing_key.serialize_der()` is PKCS#8); its certificate goes to the operator as
  `--invitation-issuer-cert`, its key stays with the issuer.
- **Tooling:** `crates/bins/src/bin/issue-invitation.rs`:
  `--coordinator <host:port> --coord-cert <path> --execution-id <64-hex>
  --expect-program-hash <64-hex> --issuer-key <pkcs8.der> --invitee-cert <cert.der>
  --client-index <u32> --valid-for-secs <u64> --out <invitation.json>`, every flag
  required. It connects
  with a certificate it mints for the call, pinned to `--coord-cert`, reads
  `get_node_roster` and `get_execution_summary`, and exits 2 without signing when the
  summary's `program_hash` differs from `--expect-program-hash`, when the policy is not
  `Invitation` with this key as its issuer (the issuer SPKI's BIT STRING against
  `EcdsaKeyPair::public_key()`), or when the execution is past association
  (`round` beyond `InputMaskReservation`, or `Aborted`), or when `--client-index` is not
  below the summary's `capacity()`. `not_after` is now plus `--valid-for-secs`. The
  output is `serde_json` of `SignedInvitation`; `crates/bins/Cargo.toml` gains `ring` and
  `serde_json` for it (§9.0).

#### C.4 `associate_client`

```rust
// coord-shared/src/admission.rs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationRequest {
    /// `None` binds the lowest-numbered free slot under `Open`, and the invitation's slot
    /// under `Invitation`.
    pub slot: Option<ClientIndex>,
    /// Required by `Invitation`, refused by every other policy.
    pub invitation: Option<SignedInvitation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRange { pub start: u64, pub count: NonZeroU64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputRights { None, Receive { output_count: NonZeroU64 } }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAdmission {
    pub execution_id: ExecutionId,
    pub client_index: ClientIndex,
    pub input_range: Option<InputRange>,
    pub output_rights: OutputRights,
}

// coord:off-chain/src/lib.rs, trait CoordinatorRPCBase
#[method(name = "associate_client")]
async fn associate_client(&self, execution_id: ExecutionId, request: AssociationRequest)
    -> RpcResult<ClientAdmission>;
```

Keyed on the caller's mTLS identity (`CoordinatorRPCServerConnectionBase::id`, `:1016`).
There is no per-execution state lock: `execution_state` maps a guard of the one
coordinator-wide `Mutex<CoordinatorRPCServerSharedBase>` (`:1139-1153`). So the
signature check and key parse run **outside** that mutex, and the binding runs in the
sequence `transition` and `submit_masked_inputs` already use (`:2343-2372`,
`:1959-1970`). Strictly in this order:

*Snapshot, under the coordinator state mutex, then released.*

1. Read `transition_quorum()` and `mpc_nodes[0]` — both functions of the immutable roster.
   The execution is not registered, or was removed → `ExecutionNotFound` (16), or
   `ExecutionAborted` (35) for an id `EndedExecutions` remembers as aborted (C.8); it is
   aborted → `ExecutionAborted` (35). Clone the `Arc` of its immutable registration
   (C.1), its `registration_nonce`, and the execution's `delivery` handle (C.6).

*Pure checks, no lock held.* Each yields a verdict that is **not** returned yet.

2. The policy is `Invitation` and `request.invitation` is `Some`: check, in order,
   `execution_id` (`WrongExecution`), `registration_nonce` (`WrongRegistration`),
   `program_hash` (`WrongProgram`), `roster_digest` against the coordinator's roster
   (`WrongRoster`), `not_after` against the coordinator's clock
   (`Expired { not_after, now }`), `invitee == caller` (`WrongInvitee`), then the
   signature (`BadSignature`).
3. Whether the caller identity is a P-256 point
   (`KeyAlgorithm::of_client_identity(caller) == Some(EcdsaP256)`, §A), the only form
   output shares can be sealed to (`<DhP256HkdfSha256 as Kem>::PublicKey::from_bytes`,
   `:3013`).

*Binding: take the `delivery` guard, re-map the execution state under the
mutex.*

4. The execution is gone → `ExecutionNotFound` (16); aborted → `ExecutionAborted` (35);
   its nonce differs from step 1's → `ExecutionNotFound` (16) — it was removed and
   registered again while steps 2–3 ran.
5. **Idempotency.** The caller already holds a slot:
   - its recorded `request` equals this `request` → return the stored `ClientAdmission`,
     whatever steps 2–3 found: the binding already exists;
   - its recorded `request` is `None` (a pre-registered slot, first call) → apply the
     pre-registered check — an `invitation` → `UnexpectedInvitation`; `slot: Some(i)` for
     another slot → `PreRegisteredSlotMismatch { registered, requested }` — then record
     `request` and return the stored admission;
   - otherwise → `AlreadyAssociated { execution_id, admission }`.

   This answers in every round **until the execution is removed** — not "in every round":
   unanimous retirement removes an execution and its output shares (`:1324-1327`), after
   which this step, like every method, is `ExecutionNotFound` (`obtain_output_shares`
   included, `:2451-2452`). §C.10's output retention is what keeps a restarted client's
   range and outputs recoverable for a bounded time after the nodes finish.
6. The round is not `Idle`, `Preprocessing` or `InputMaskReservation` →
   `AssociationClosed { execution_id, current }`.
7. Policy:
   - `PreRegistered` → `NotPreRegistered { execution_id }` (every pre-registered identity
     was answered in step 5);
   - `Open`: an `invitation` → `UnexpectedInvitation { execution_id }`. It is refused, not
     ignored, so a client that believes it was invited learns that this execution is not
     invitation-gated;
   - `Invitation`: no `invitation` → `InvitationRequired { execution_id }`; step 2's
     verdict is a rejection → `InvitationRejected { reason }`; `request.slot` is
     `Some(j)` with `j != invitation.client_index` →
     `InvitationRejected { reason: SlotMismatch { invited, requested } }`. The slot asked
     for is `invitation.client_index`, never `None`.
8. Slot: `Some(i)` with `i >= capacity()` → `SlotOutOfRange { execution_id, requested, slots }`;
   `Some(i)` already bound → `SlotTaken { execution_id, requested }`; `None` (only under
   `Open`) and no free slot → `CapacityExhausted { execution_id, capacity }`.
9. The slot has `output_count > 0` and step 3 found no uncompressed P-256 point →
   `UnsupportedClientKey { client_index }`. Refused at association rather than failing
   every node's `send_output_shares` after the program already ran.
10. Bind and record `request`; add the identity to the coordinator-wide index of bound
    identities (§A "Server side"); `try_advance(quorum, roster_head)` (`:1638`) with step
    1's values; drop the state guard; `deliver_transitions`; release the delivery guard.
    This binding may be the last one `InputCollection` was held for (C.8).

A caller that is also a roster node is not refused; its node key buys it nothing a fresh
certificate would not.

#### C.5 Errors

```rust
// coord-shared/src/admission.rs — `#[error("…")]` attributes elided, as in §B
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionError {
    AssociationClosed { execution_id: ExecutionId, current: Round },
    CapacityExhausted { execution_id: ExecutionId, capacity: u32 },
    SlotOutOfRange { execution_id: ExecutionId, requested: ClientIndex, slots: u32 },
    SlotTaken { execution_id: ExecutionId, requested: ClientIndex },
    NotPreRegistered { execution_id: ExecutionId },
    PreRegisteredSlotMismatch { registered: ClientIndex, requested: ClientIndex },
    InvitationRequired { execution_id: ExecutionId },
    InvitationRejected { reason: InvitationRejection },
    UnexpectedInvitation { execution_id: ExecutionId },
    UnsupportedClientKey { client_index: ClientIndex },
    AlreadyAssociated { execution_id: ExecutionId, admission: ClientAdmission },
    NotAdmitted { execution_id: ExecutionId },
    ReservationOutsideAdmission { admitted: Option<InputRange> },
    AdmissionsNotFrozen { execution_id: ExecutionId, current: Round },
    NoOutputRights { execution_id: ExecutionId },
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationRejection {
    WrongExecution,
    WrongRegistration,
    WrongProgram,
    WrongRoster,
    Expired { not_after: UnixSeconds, now: UnixSeconds },
    WrongInvitee,
    BadSignature,
    SlotMismatch { invited: ClientIndex, requested: ClientIndex },
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionError {
    MaskedInputTooLarge { reserved_index: u64, len: u64, max: u64 },
    SubmissionOutsideAdmission { admitted: Option<InputRange> },
    BadMaskedInputSignature,
    SealedOutputTooLarge { len: u64, max: u64 },
    BadOutputSignature,
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    AssociationDeadline { deadline: UnixSeconds, unbound_slots: u32 },
    /// `missing_inputs` is never 0 (C.8).
    InputDeadline { deadline: UnixSeconds, missing_inputs: u64 },
}

/// How an execution this process no longer serves ended (C.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcome { Finished, Aborted(AbortReason) }

/// Returned in-process by `register_execution` and `new_for_execution`; never on the wire.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationError { /* exactly the variants of the C.1 table */ }
```

Each admission failure is returned as
`ErrorObjectOwned::owned(code, error.to_string(), Some(&error))`: the JSON-RPC `code` is the
stable number in this table (`ErrorCode::ServerError(code).code()` is `code`, jsonrpsee-types
`error.rs:210`), and `data` is the serde form of the typed error. `OffChainCoordinatorClient`
decodes `data` by `code` into `CoordinatorError::Admission(AdmissionError)`,
`CoordinatorError::Submission(SubmissionError)` or `CoordinatorError::ExecutionAborted`,
which retires the string matching callers do today
(`crates/stoffel-vm-runner/src/local_runner.rs:1201`, `coordinator_wrong_round`). A
subscription refused before `accept` carries the same `code` and `data`, and the client
decodes it the same way (§C.7).

| Code | `CoordinatorRPCBaseError` (`coord:off-chain/src/lib.rs:969`) | Typed error in `data` | Raised by |
|---|---|---|---|
| 2 | `WrongRound` | — (unchanged) | reserve, submit |
| 5 | `MaskedInputAlreadySubmitted` | — (unchanged) | submit (a second submission for the slot) |
| 6 | `IndexNotReserved` | — (unchanged) | submit (the slot has not reserved) |
| 8 | `OutputSharesAlreadySent` | — (unchanged) | `send_output_shares` |
| 9 | `OutputSharesAlreadyRequested` | — (unchanged) | `obtain_output_shares` |
| 10 | `NotParty` | — (unchanged) | `get_client_admissions`, `send_output_shares`, `transition` (and its `StoffelCoordinatorRPC` façade), `retire_execution`, `sub_reserved_indices`, `sub_masked_inputs` |
| 12 | `NotOutputClient` | `AdmissionError::NoOutputRights` | `send_output_shares`, `obtain_output_shares` |
| 14 | `ClientAlreadyReserved` | — (unchanged) | reserve |
| 16 | `ExecutionNotFound` | — (unchanged) | every execution-scoped method |
| 20 | `AssociationClosed` | `AdmissionError::AssociationClosed` | `associate_client` |
| 21 | `CapacityExhausted` | `AdmissionError::CapacityExhausted` | `associate_client` |
| 22 | `SlotOutOfRange` | `AdmissionError::SlotOutOfRange` | `associate_client` |
| 23 | `SlotTaken` | `AdmissionError::SlotTaken` | `associate_client` |
| 24 | `NotPreRegistered` | `AdmissionError::NotPreRegistered` | `associate_client` |
| 25 | `PreRegisteredSlotMismatch` | `AdmissionError::PreRegisteredSlotMismatch` | `associate_client` |
| 26 | `InvitationRequired` | `AdmissionError::InvitationRequired` | `associate_client` |
| 27 | `InvitationRejected` | `AdmissionError::InvitationRejected` | `associate_client` |
| 28 | `UnexpectedInvitation` | `AdmissionError::UnexpectedInvitation` | `associate_client` |
| 29 | `UnsupportedClientKey` | `AdmissionError::UnsupportedClientKey` | `associate_client` |
| 30 | `AlreadyAssociated` | `AdmissionError::AlreadyAssociated` | `associate_client` |
| 31 | `NotAdmitted` | `AdmissionError::NotAdmitted` | `reserve_mask_indices`, `submit_masked_inputs`, `sub_round` |
| 32 | `ReservationOutsideAdmission` | `AdmissionError::ReservationOutsideAdmission` | `reserve_mask_indices` |
| 33 | `AdmissionsNotFrozen` | `AdmissionError::AdmissionsNotFrozen` | `get_client_admissions` |
| 35 | `ExecutionAborted` | `AbortReason` | every execution-scoped method on an aborted execution except `get_execution_summary` and `retire_execution`; every execution-scoped method but `retire_execution`, on an id `EndedExecutions` remembers as aborted (C.8) |
| 36 | `MaskedInputTooLarge` | `SubmissionError::MaskedInputTooLarge` | `submit_masked_inputs` |
| 37 | `SubmissionOutsideAdmission` | `SubmissionError::SubmissionOutsideAdmission` | `submit_masked_inputs` |
| 38 | `BadMaskedInputSignature` | `SubmissionError::BadMaskedInputSignature` | `submit_masked_inputs` |
| 39 | `SealedOutputTooLarge` | `SubmissionError::SealedOutputTooLarge` | `send_output_shares` |
| 40 | `BadOutputSignature` | `SubmissionError::BadOutputSignature` | `send_output_shares` |
| 41 | `RateLimited` | — | `get_node_roster`, `get_execution_summary` (§C.6) |

Codes 1 (`NotDesignatedParty`), 15 (`UnauthorizedClientIo`), 17
(`ExecutionAlreadyRegistered`, whose only raiser was the deleted `register_execution`
RPC) and 18 (`ShutdownNotAccepted`) lose their last raiser (C.6, C.10) and are
**retired, never reused**. So are the codes the exact-range rules subsume — 3
(`IndexOutOfBounds`), 4 (`BadID`), 7 (`IndexAlreadyReserved`), 13
(`MismatchedBatchLengths`, whose parameter pair is gone) and 19 (`EmptyBatch`): a
reservation or submission that names anything but the caller's admitted range is 32 or
37 — and 11 (`SendingFailed`), which has no raiser in `0.2.0` either. 34 is not allocated:
registration errors never cross the wire.

`CoordinatorError` (`coord:coord-shared/src/lib.rs:257`) gains `ServerPinMismatch { address:
String }`, `ServerCertificateMismatch` (§B), `DuplicateNodeIdentity { address: String }`,
`TooManyNodeAddresses { given: usize, n: u64 }`, `UnexpectedRosterDigest { served:
RosterDigest, expected: RosterDigest }`, `NotAssociated` (an `OffChainCoordinatorClient`
asked for outputs, or submitted, before `associate_client` succeeded),
`TopologyUnsupportedByBackend { n: u64, t: u64, required: u64 }` (§C.7),
`SealedOutputsExceedBound { client_index: ClientIndex, bytes: u64, max: u64 }` (§C.7),
`OutputReconstructionFailed { output: u64 }` (§C.7), `RoundNotProposable { round: Round }`,
`ExecutionAborted { execution_id: ExecutionId, reason: AbortReason }`, and transparent
`Pin(PinError)`, `Roster(RosterError)`, `Admission(AdmissionError)`,
`Submission(SubmissionError)`, `Registration(RegistrationError)`,
`Signature(SignatureError)`, and `Refused { refusal: RpcRefusal, message: String }` for a
refusal whose code carries no typed `data`:

```rust
/// The codes of the table above without a typed error in `data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcRefusal {
    WrongRound, MaskedInputAlreadySubmitted, IndexNotReserved, OutputSharesAlreadySent,
    OutputSharesAlreadyRequested, NotParty, ClientAlreadyReserved, ExecutionNotFound,
    RateLimited,
}
```

`MaskReconstructionFailed(usize)` (`0.2.0`, a share count, `coord:coord-shared/src/lib.rs:261-262`)
becomes `MaskReconstructionFailed { index: u64 }`. All inner types derive `Clone, Serialize,
Deserialize`, as `CoordinatorError` requires. The client-side string wrappers that remain
(`JSONError`, `SubscriptionError`) are for transport failures only.

#### C.6 What each RPC and subscription is gated on

Revision 0 listed gates for the new methods only. Every existing subscription checked
nothing but that the execution exists (`sub_round`, `:1840-1896`;
`sub_assigned_reserved_indices` and `sub_assigned_masked_inputs`, `:1903-1941`;
`sub_reserved_indices` and `sub_masked_inputs`, `:2139-2177`), and the coordinator
accepts any client certificate (§A), so any stranger could read every admitted identity,
its reserved indices and masked inputs — contradicting `AdmissionPolicyKind`'s promise and
`get_client_admissions`' node gate. The complete surface:

| Method | `0.2.0` gate | `0.3.0` gate |
|---|---|---|
| `register_execution` (`:865`) | node | **deleted**; in-process only (C.1) |
| `request_shutdown` (`:878`) | `mpc_nodes[0]` | **deleted** (C.10) |
| `available_input_masks` (`:906`) | execution exists | **deleted** (C.10) |
| `sub_assigned_reserved_indices`, `sub_assigned_masked_inputs` (`:894`, `:901`) | execution exists | **deleted** (below) |
| `reserve_mask_index`, `submit_masked_input` (`:911`, `:928`) | as their batch forms | **deleted**: one call covers a slot's whole range (below) |
| `retire_execution` (`:868`) | node | node (10), any round (the drain is gated instead, C.10) |
| `transition` and the `StoffelCoordinatorRPC` façade (`:949`, `:847-859`) | node | node (10), unchanged |
| `sub_round` (`:882`) | execution exists | node, or a client holding an admission (31) |
| `sub_reserved_indices`, `sub_masked_inputs` (`:885`, `:888`) | execution exists | node (10) |
| `reserve_mask_indices` (`:2183`) | round; free index; the assigned owner when `input_assignments` is non-empty, **anyone otherwise** | round `InputMaskReservation` (2); caller admitted (31); one call per client (14); `indices` is exactly the admitted `input_range`, ascending (32). The unassigned "anyone reserves any free index" mode is gone |
| `submit_masked_inputs` (`:1953`) | every index reserved by the caller | round `InputCollection` (2); caller admitted (31); its slot reserved (6) and not yet submitted (5); `first_index` and the input count are exactly the admitted `input_range` (37); every input at most `MAX_MASKED_INPUT_BYTES` (36); the signature verifies (38, C.7) |
| `send_output_shares` (`:2390`) | node; `client_id` in `output_clients` (`:2409`) | node (10); `client_index` admitted with `OutputRights::Receive` (12); once per node and client (8); ciphertext at most `MAX_SEALED_OUTPUT_BYTES` (39); the signature verifies against the caller's roster key (40, C.7) |
| `obtain_output_shares` (`:2441`) | caller in `output_clients` (`:2453`) | caller admitted with `OutputRights::Receive` (12); one live subscription per client (9), as today |
| `get_node_roster` (new) | — | any mTLS caller; rate (41) |
| `get_execution_summary` (new) | — | any mTLS caller; `ExecutionNotFound` (16); rate (41) |
| `associate_client` (new) | — | C.4 |
| `get_client_admissions` (new) | — | node (10); frozen (33) |

On an aborted execution every execution-scoped method except `get_execution_summary` and
`retire_execution` answers `ExecutionAborted` (35); acknowledging an aborted execution is
what lets a one-off coordinator drain it (C.10). A gated subscription is refused with
`PendingSubscriptionSink::reject` before `accept`, so a refused caller parks nothing.

**The two read methods are rate limited.** `get_node_roster` and `get_execution_summary`
are the only calls an unbound identity can make repeatedly, and a summary is up to
688,129 bytes (C.1) for a request of a few dozen. The coordinator keeps a token bucket
per caller identity — `SUMMARY_READS_PER_MINUTE = 60` tokens a minute, a burst of
`SUMMARY_READ_BURST = 10` — shared by both methods, and answers an empty bucket with
`RateLimited` (41). Buckets live in a least-recently-used map bounded at
`SUMMARY_READ_BUCKETS = 65_536` identities, so reconnecting does not refill one. Identities
cost nothing, so the bucket bounds one identity's reads, not a flood's; what bounds a
flood's is the unreserved connection pool and the idle timeout (§A). An honest node or
client reads the roster once and a summary once per execution.

**The assigned streams are deleted.** `sub_assigned_reserved_indices` and
`sub_assigned_masked_inputs`, which revision 1 kept and chunked, have no consumer in either
repository (no call site in `crates/`, in `docker/coordinator-wrapper` or in
`coord:off-chain/tests/off_chain.rs`), and in `0.3.0` they carry nothing a node cannot
compute: every index's owner and `input_ordinal = reserved_index - input_range.start`
follow from the agreed admission set a node already reads (C.7, §D.7 step 7). Keeping
them would keep two more event logs per execution (C.1 "Memory"), two more sink lists
for the abort to reach, and two more replays to keep off the state mutex. They go with
`AssignedMaskedInputEvent`; `AssignedMaskReservation` stays, as the node RPC listener's
registration type.

**One submission per slot.** A client reserves its whole `input_range` in one call
(code 14, unchanged) and now submits it in one call too:

```rust
#[method(name = "submit_masked_inputs")]
async fn submit_masked_inputs(&self, execution_id: ExecutionId, first_index: u64,
    masked_inputs: Vec<Vec<u8>>, signature: Vec<u8>) -> RpcResult<()>;
```

That is what lets one client signature cover a slot's inputs (C.7), and it is what a
client does already: `send_masked_inputs` submits all its pairs in one request
(`coord:off-chain/src/lib.rs:2872-2895`). The singular `reserve_mask_index` and
`submit_masked_input` RPC methods are deleted; the shared `Coordinator` trait keeps
`reserve_mask_index` and `send_masked_input`, and `OffChainCoordinatorClient` implements
them as one-element calls of the batch forms, which succeed exactly when the slot's range
has one index.

**Parked subscriptions are bounded per caller.** A subscription that waits parks its sink
in per-execution state (`d.sinks.entry(round).or_default().push(sink)`, `:1880`; the event
lists at `:1511`, `:1531`; output waiters at `:2491`). The sink holds one of its
connection's jsonrpsee subscription permits
(`jsonrpsee-core-0.26.0/src/server/subscription.rs:292-304`), but nothing prunes it when
the connection closes, so a caller could reconnect and park again without end. `0.3.0`
keys every parked list by caller identity. Parking first drops the list's closed sinks
(`SubscriptionSink::is_closed`, `subscription.rs:381`); a caller that already has
`MAX_PARKED_SUBSCRIPTIONS_PER_CALLER = 4` sinks in the same list — for `sub_round`, for
the same round — has its oldest one dropped. Output waiters are already one per client
(`output_sinks`, `:1108`; code 9). Only nodes and admitted clients may subscribe, so an
execution parks at most `4 × (n + capacity())` sinks per list, and no number of
certificates crowds a node out. The node RPC listener's `assigned_sinks` (`:622`) is
already one sink per identity; it now drops closed sinks before inserting, so it is
bounded by live connections, and those by `RpcServerLimits` (§A).

**No send under the state mutex.** Revision 1 kept `C.4`'s rule — never hold the
coordinator-wide mutex across I/O — for the new paths only. `0.2.0` breaks it on the paths
this section gates to nodes: every `subscribe_*` replay runs inside `execution_state()`'s
mapped guard of the one `Mutex<CoordinatorRPCServerSharedBase>`
(`coord:off-chain/src/lib.rs:2153-2156`, `:2173-2176`, the guard at `:1139-1153`), sending
each replayed event under `SUBSCRIPTION_SEND_TIMEOUT` (2 s, `:56`; sends at `:1495-1512`,
`:1515-1531`, `:1541-1556`, `:1565-1580`), and `reserve_mask_indices` broadcasts to every
sink while holding the same guard (`:2188`, `:2297-2327`). One node reading each message
just under 2 s would hold the coordinator — every execution, `associate_client` and the
deadline sweeper — for as long as it liked. `0.3.0`:

- **Nothing awaits a send, an `accept` or a `reject` while holding the state mutex.** The
  mutex is taken to read or change state and released before any WebSocket I/O.
- **Each execution has one delivery guard,** `delivery: Arc<Mutex<()>>` — `0.2.0`'s
  `masked_input_delivery` (`:1098`), renamed because it now serializes every broadcast
  of the execution. Lock order is always delivery guard, then state mutex, as
  `submit_masked_inputs` and `transition` already take them (`:1963-1970`,
  `:2367-2372`).
- **Replay is sequence-numbered.** Every event stream of an execution — the round events,
  reservation events, submission events and output items — has an append-only history
  whose length is its sequence number; reservation and submission events are rebuilt
  from the slots in `reservation_order` / `submission_order` (C.1), output items are the
  stored ciphertexts in arrival order. A subscription, after its gates and `accept`:
  (1) locks, reads the aborted flag and the history up to its current length `k` as
  `Arc`s, and unlocks; (2) sends those, each with `send_timeout(SUBSCRIPTION_SEND_TIMEOUT)`
  (`subscription.rs:346`), dropping the sink on a failure; (3) locks again: if the
  execution is gone it unlocks and drops the sink; if it is aborted it unlocks, sends
  `Event::ExecutionAborted { reason }` on an `Event`-typed stream (`sub_round`,
  `sub_reserved_indices`, `sub_masked_inputs`) and drops the sink; if the history grew
  past `k` it takes the new entries, unlocks and returns to (2); otherwise it parks the
  sink and unlocks. A broadcaster appends before it takes the parked sinks, so a
  subscriber either parks before that append and is sent the event live, or sees it in
  step 3: nothing is lost and nothing is sent twice.
- **Live broadcasts never wait on a subscriber.** A broadcast takes the delivery guard,
  locks, appends the event, takes the parked sinks, unlocks, and sends with
  `SubscriptionSink::try_send` (`subscription.rs:368`), which fails at once when the
  connection's queue (`RpcServerLimits::message_buffer_capacity`, §A) is full; then it
  locks again and, unless the execution is gone, re-parks each sink whose send succeeded —
  or, if the execution was aborted meanwhile, unlocks and sends it `ExecutionAborted`
  instead of re-parking it — and releases the delivery guard. `reserve_mask_indices`
  moves to this pattern, as `submit_masked_inputs` (`:1963-2127`) almost is. A
  subscriber whose connection falls `message_buffer_capacity` messages behind loses its
  subscription and sees its stream end, which a node treats as a lost link (§A); nothing
  it does can hold another subscriber, another execution or the mutex.
- A method's own response is built from `Arc`s cloned under the mutex and serialized
  after it is released: `get_node_roster` from the roster's wire form (§B),
  `get_execution_summary` from the registration (C.1), and `get_client_admissions` from an
  `Arc<ClientAdmissionSet>` built once, when the set freezes (C.7), rather than from the
  slots on every call.

#### C.7 How nodes learn admissions, and how inputs and outputs are authenticated

Every node applies the same rule to the same data; no node reads anything another node
cannot.

**The admission set is one read of a frozen value.**

```rust
// coord-shared/src/admission.rs
/// A `ClientAdmission` without its `execution_id`, which the set carries once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAdmissionRecord {
    pub client: ClientIdentity,
    pub client_index: ClientIndex,
    pub input_range: Option<InputRange>,
    pub output_rights: OutputRights,
}

impl ClientAdmissionRecord {
    pub fn admission(&self, execution_id: ExecutionId) -> ClientAdmission;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAdmissionSet {
    pub execution_id: ExecutionId,
    /// One record per slot, ascending `client_index`.
    pub records: Vec<ClientAdmissionRecord>,
}

// coord:off-chain/src/lib.rs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSummary {
    pub execution_id: ExecutionId,
    pub registration_nonce: RegistrationNonce,
    pub program_hash: [u8; 32],
    pub client_slots: ClientSlotTable,
    pub admission: AdmissionPolicyKind,
    pub deadlines: Option<ExecutionDeadlines>,
    pub round: Round,
}

/// One slot's masked inputs exactly as its client submitted them and the coordinator
/// delivered them, before any node unmasks them. `Event::MaskedInputEvent` carries one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskedInputSubmission {
    pub client: ClientIdentity,
    pub first_index: u64,
    pub masked_inputs: Vec<Vec<u8>>,
    /// The client's signature over `masked_inputs_signing_bytes` (below).
    pub signature: Vec<u8>,
}

/// `send_output_shares`' parameter: one node's sealed output shares for one client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOutput {
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// The sending node's signature over `sealed_output_signing_bytes` (below).
    pub signature: Vec<u8>,
}

/// `obtain_output_shares`' item: one node's `SealedOutput`, with the roster position of
/// the node that sent it. One message per node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOutputShares { pub node_position: u32, pub sealed: SealedOutput }

// trait CoordinatorRPCBase
#[method(name = "get_execution_summary")]
async fn get_execution_summary(&self, execution_id: ExecutionId) -> RpcResult<ExecutionSummary>;

#[method(name = "get_client_admissions")]
async fn get_client_admissions(&self, execution_id: ExecutionId) -> RpcResult<ClientAdmissionSet>;

#[method(name = "send_output_shares")]
async fn send_output_shares(&self, execution_id: ExecutionId, client_index: ClientIndex,
    sealed: SealedOutput) -> RpcResult<()>;

#[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = SealedOutputShares)]
async fn obtain_output_shares(&self, execution_id: ExecutionId) -> SubscriptionResult;
```

The set **freezes** when the execution enters `InputCollection` — or `MPCExecution`, for
an execution with no inputs (C.8's structural skip) — and C.8's precondition makes it
complete at that moment: one record per slot. A node reads it **once**, after
`wait_for_round` has shown it that round. Because the set cannot change afterwards, every
node reads the same value with no subscription, no "that was the last one" marker, and no
race between two streams. That is why this is a method and not a `sub_*` subscription.

Before using it, all nodes agree on it all-to-all (§D.6), so a coordinator that serves
different sets to nodes of one mesh aborts the run before any of them acts on either set.
"One mesh" is load-bearing: the agreement travels over the mesh, and nodes that were
served disjoint rosters are in different meshes (§G).

**Mask shares are released against the agreed set.** A node's RPC listener serves mask
share `i` to caller `C` iff the node has registered a reservation naming `C` for `i`
(`index_to_client`, `coord:off-chain/src/lib.rs:620`, compared with the caller's
certificate identity at `:719-721`). That serving rule is unchanged. What changes is
*when* a node registers a reservation. Today both node paths register every reservation
straight off the coordinator's stream, as soon as `wait_for_indices` returns and before
`InputCollection` (`stoffel-run.rs:5331-5345`, `:3590-3606`). That trusts each node's copy
of the stream: a malicious coordinator that names a different owner for index `i` to
disjoint node subsets hands both the client and itself `min_shares(t)` shares of the same
mask — possible whenever `n >= 2 * min_shares(t)`, that is AVSS at `n >= 2t + 2` and
HoneyBadger at `n >= 4t + 2` — and then unmasks the client's input. That hole exists in
`0.2.0` already. In `0.3.0` a node registers reservations only after the admission set is
frozen, agreed (§D.6), and every reservation it received matches the agreed range for that
identity; one that does not aborts the node before any share is released (§D.7). Clients
see only latency: `receive_assigned_masks` already waits until a share and its reservation
are both present, and now returns after `InputCollection` has begun.

**Masked inputs are agreed before they are used.** The same equivocation works one step
later: the coordinator delivers each node its own copy of the masked-input stream
(`sub_masked_inputs`, `:888`), so it can hand some nodes `x + r` and others `x' + r`. Honest
nodes would then hold an inconsistent sharing of the client's input, and whether robust
decoding fails, or what comes out, would depend on the secret — a selective-failure
channel. Nodes therefore agree on the raw submissions all-to-all (§D.6, `InputsAgreed`)
before any node unmasks or stores one (§D.7 step 9).

**Masked inputs are signed by their client.** Agreement makes every node use the same
submission; it does not make that submission the client's. A coordinator that changed
`x + r` to `x + r + δ` for every node alike would pass `InputsAgreed` and shift the
client's input by an offset it chose — a power none of the coordinator's roles (bootstrap,
membership, admission) needs. `0.3.0` removes it. The client signs its slot's submission
with its certificate key:

```text
masked_inputs_signing_bytes:
b"stoffel-masked-inputs-v1"                    24 bytes, ASCII, no terminator
execution_id                                   32 bytes
registration_nonce                             32 bytes
client_index as u32                             4 bytes little-endian
first_index as u64                              8 bytes little-endian
masked_inputs.len() as u64                      8 bytes little-endian
per masked input, ascending index:
    len as u64                                  8 bytes little-endian
    bytes                                       len bytes
```

`signing.rs` provides both halves: `sign_with_pkcs8(algorithm: KeyAlgorithm, pkcs8: &[u8],
message: &[u8]) -> Result<Vec<u8>, SignatureError>` — ECDSA P-256 / SHA-256 with an ASN.1
DER signature through `ring::signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, …)`,
Ed25519 through `Ed25519KeyPair::from_pkcs8_maybe_unchecked` — and
`verify_identity_signature(identity: &ClientIdentity, message: &[u8], signature: &[u8]) ->
Result<(), SignatureError>`, which takes the algorithm from
`KeyAlgorithm::of_client_identity` and verifies with `UnparsedPublicKey` over
`ECDSA_P256_SHA256_ASN1` or `ED25519`. `SignatureError` is
`UnsupportedKey | SigningFailed | BadSignature`. The coordinator verifies the submission
against the caller's identity before recording it (code 38), so a client bug surfaces to
the client; nodes verify it again against the identity the **agreed** admission set names
for that slot, with the agreed summary's nonce (§D.7 step 9), because the coordinator's
check is worth nothing against the coordinator. The nonce binds a submission to one
registration, so one run's signed submission cannot be replayed into a later run of a
reused `ExecutionId`.

**Output shares are signed by their node, and delivered one node at a time.** `0.2.0`
seals output shares in HPKE Base mode (`single_shot_seal` with `OpModeS::Base`,
`coord:off-chain/src/lib.rs:3020-3030`), which authenticates no sender: anyone holding the
client's public key can seal shares to it, so a coordinator could substitute a client's
outputs. And it sends each client one snapshot of every node's ciphertext
(`:1705-1727`), with no node attribution — which C.1 shows can exceed the client's receive
cap, and which leaves a client unable to tell which node sealed which share. In `0.3.0`:

1. A node seals its output shares for a client exactly as today, then signs, with its
   certificate key and its own roster position:

   ```text
   sealed_output_signing_bytes:
   b"stoffel-sealed-output-v1"                 24 bytes, ASCII, no terminator
   execution_id                                32 bytes
   registration_nonce                          32 bytes
   client_index as u32                          4 bytes little-endian
   node_position as u32                         4 bytes little-endian
   encapsulated_key.len() as u64, encapsulated_key
   ciphertext.len() as u64, ciphertext
   ```

   and calls `send_output_shares(execution_id, client_index, sealed)`.
2. The coordinator refuses a ciphertext over `MAX_SEALED_OUTPUT_BYTES` (39) and a signature
   that does not verify against the caller's own roster key at the caller's position
   (40), stores the item under `(client_index, position)`, and sends it to the client's
   output waiter as one `SealedOutputShares` message, live and on replay (C.6). The
   coordinator's check keeps junk out of storage; it is not what the client relies on.
3. The client (`Coordinator::obtain_outputs`) ignores an item whose `node_position` is not
   below `n`, a second item for a position, and an item whose signature does not verify
   against `roster.node_certificates()[node_position]`'s key; decrypts the rest, ignores
   one that fails to decrypt, to deserialize, or to hold exactly `output_count` shares —
   where `0.2.0` failed the whole call (`:2951-2962`) — and attributes each share to
   `node_position`. After each item it runs `S::reconstruct` (below) for every output,
   and returns once every output is a `Secret`. If the subscription ends first, it reads
   the summary: an aborted execution is `ExecutionAborted`; otherwise
   `OutputReconstructionFailed { output }` names the first output still pending.

The signature binds the position; the share-id check in `reconstruct` binds each share to
that position. A node that re-sends another node's ciphertext under its own position
decrypts to shares carrying the other node's ids and contributes nothing, so the node's
position inside the sealed plaintext — which the review proposed — adds nothing and is
not added. The nonce, again, stops replay into a later registration of the same id.
Signatures use node certificate keys, which is safe because every listener and client of
this crate is TLS 1.3 only (§A step 5).

**Reconstruction by position** (`coord-shared/src/lib.rs`, `ShareBound`):

```rust
pub struct PositionedShare<S> { pub position: usize, pub share: S }

pub enum Reconstruction<V> {
    /// Correct whenever at most `t` of the positions supplied corrupt shares.
    Secret(V),
    /// Not conclusive yet; more positions may make it so.
    Pending,
}

pub trait ShareBound<F: FftField>: /* unchanged supertraits */ {
    type ValueType: /* unchanged */;
    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError>;   // unchanged
    fn min_shares(t: usize) -> usize;                                                                  // unchanged
    /// Smallest `n` this backend reconstructs at: HoneyBadger `3t + 1`, AVSS `2t + 1`.
    fn min_parties(t: usize) -> usize;
    /// The share id roster position `position` holds: HoneyBadger `position`, AVSS `position + 1`.
    fn share_id_of_position(position: usize) -> usize;
    fn share_id(&self) -> usize;
    fn share_degree(&self) -> usize;
    /// `CanonicalSerialize` length of one share at degree `t`, compressed.
    fn serialized_share_len(t: usize) -> usize;
    /// At most one share per position; the caller refuses a second.
    fn reconstruct(shares: &[PositionedShare<Self>], n: usize, t: usize) -> Reconstruction<Self::ValueType>;
}
```

`reconstruct` first ignores every share whose `share_id()` is not
`share_id_of_position(position)` or whose `share_degree()` is not `t`. Then:

- **HoneyBadger:** with at least `2t + 1` remaining, `RobustShare::recover_secret(remaining,
  n, t)`; `Ok` is `Secret`, anything else `Pending`. A success is correct: it requires
  `2t + 1` shares on one degree-`t` polynomial
  (`stoffelcrypto-0.1.1/src/honeybadger/robust_interpolate/robust_interpolate.rs:253-259`
  for the optimistic path, `:614-620` for error correction), at least `t + 1` of them
  honest, and `t + 1` honest points fix the polynomial. The decode succeeds once every
  position that is not faulty has answered: with `f` silent
  and `e` wrong positions, `f + e <= t`, the `n - f` shares hold at least `2t + 1` that
  agree, and error correction over all of them (`:589-623`) corrects `e`.
- **AVSS:** shares are grouped by their `commitments` vector, compared byte for byte; a
  share that does not satisfy `share · G == Σⱼ commitmentsⱼ · idʲ` for its *own*
  commitments is ignored (`stoffelcrypto` `0.1.1` has no public check; `reconstruct`
  computes it with `ark-ec`); the first group with `t + 1` verified shares is interpolated
  (`FeldmanShamirShare::recover_secret`) and is `Secret`; otherwise `Pending`. A group
  forms around the vector its members *present*, and an honest node presents the honest
  one, so a vector the at most `t` corrupt nodes present never reaches `t + 1` members —
  even though a forged vector can be chosen to accept up to `t` honest shares, those
  shares were never presented with it. Every honest node presents the same vector: the
  dealer's commitments reach all of them through RBC, and the arithmetic on shares
  (`coord:coord-shared/src/lib.rs:136-138`, `stoffelcrypto-0.1.1/src/common/share/feldman.rs:92-207`)
  applies to commitments deterministically.
- **`min_parties`** is the roster check nothing performed: HoneyBadger's robust decoding
  refuses `n < 3t + 1` outright
  (`stoffelcrypto-0.1.1/src/honeybadger/robust_interpolate/robust_interpolate.rs:100-105`),
  and a HoneyBadger node refuses it at engine setup (`validate_honeybadger_topology`,
  `crates/stoffel-vm/src/net/mpc/helpers.rs:112-123`), but the roster accepts
  `n >= 2t + 1` (§B), so a client on a `2t + 1 <= n < 3t + 1` roster would pass every
  check, bind its slot irrevocably, and only then fail to reconstruct.

**Client-side Rust API.** The shared `Coordinator` trait (`coord:coord-shared/src/lib.rs:182-254`)
is unchanged, and `on-chain` implements it as today. `OffChainCoordinatorClient` loses its
`t`, `n_parties` and `n_outputs` fields (`coord:off-chain/src/lib.rs:2523-2531`), holds the
link's `NodeRoster`, its own `SpkiDer`, an `Option<(ClientAdmission, RegistrationNonce)>`
and — on a node — the `ClientAdmissionSet` its `get_client_admissions` returned, and gains:

```rust
impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    pub async fn get_execution_summary(&self) -> Result<ExecutionSummary, CoordinatorError>;
    /// Reads the summary first and returns, without sending the association:
    /// `TopologyUnsupportedByBackend` when `n < S::min_parties(t)`;
    /// `SealedOutputsExceedBound` when a slot's `8 + output_count × S::serialized_share_len(t)
    /// + 16` exceeds `MAX_SEALED_OUTPUT_BYTES`. Stores the returned admission with the
    /// summary's nonce; `send_masked_inputs` and `obtain_outputs` take both from it.
    pub async fn associate_client(&mut self, request: AssociationRequest)
        -> Result<ClientAdmission, CoordinatorError>;
    pub fn admission(&self) -> Option<&ClientAdmission>;
    /// Stores the set; `send_output_shares` maps an identity to its slot through it.
    pub async fn get_client_admissions(&mut self) -> Result<ClientAdmissionSet, CoordinatorError>;
    /// Every submission, ascending `first_index`, once their input counts sum to `n_inputs`.
    pub async fn wait_for_masked_input_submissions(&self, n_inputs: u64)
        -> Result<Vec<MaskedInputSubmission>, CoordinatorError>;
    /// Unmasks `submissions` with this node's mask shares; `mask_shares[i]` is index `i`'s.
    pub fn unmask_submissions(submissions: &[MaskedInputSubmission], mask_shares: &[S])
        -> Result<Vec<(u64, ClientIdentity, S)>, CoordinatorError>;
    pub async fn retire_execution(&self) -> Result<(), CoordinatorError>;   // unchanged
}
```

- `Coordinator::send_masked_inputs(&self, inputs)` returns `NotAssociated` without a stored
  admission, and `Submission(SubmissionOutsideAdmission)` — without an RPC — unless the
  indices are exactly the admitted range; it serializes, signs with the client's key and
  calls `submit_masked_inputs`.
- `Coordinator::send_output_shares(&self, client_id, key, output_shares)` returns
  `Admission(NotAdmitted)` for an identity the stored set does not name, and otherwise
  seals, signs with the node's own position (`roster.position_of(own SPKI)`) and the
  agreed nonce, and sends by `client_index`.
- `Coordinator::obtain_outputs(&self)` returns `NotAssociated` without a stored admission
  and `Admission(NoOutputRights)` for `OutputRights::None`, both without an RPC, and
  follows the three steps above with the roster's `n` and `t`.
- `Coordinator::wait_for_inputs` stays for the trait: it verifies each submission's
  signature against the identity its event names and unmasks. The VM does not call it:
  a node needs the agreement between delivery and unmasking (§D.7 steps 8–10).
- **A refused subscription is an error, not a panic.** `0.2.0`'s `wait_for_indices`
  unwraps the subscribe call (`:2764-2766`), and in `0.3.0` every subscription can be
  refused (C.6). That `unwrap` goes, and every subscribe call site decodes a refusal —
  `jsonrpsee::core::client::Error::Call(ErrorObjectOwned)` — by `code` and `data` exactly as
  C.5 decodes a method error, so a 35 is `CoordinatorError::ExecutionAborted` and a 10 is
  `CoordinatorError::Refused { refusal: RpcRefusal::NotParty, .. }`. `wait_for_round`,
  `wait_for_indices`, `wait_for_inputs` and
  `wait_for_masked_input_submissions` also end with `CoordinatorError::ExecutionAborted`
  when their stream delivers `Event::ExecutionAborted` (C.8).

**Client grouping and outputs.** A node also uses the agreed set (§D.7) to store each
reserved index's share under its `ClientIndex` instead of ordering clients by their lowest
reserved index (`stoffel-run.rs:465`, `store_reserved_client_inputs`); to set the VM client
roster to `0..capacity()`; and to choose the identity each output record is sealed to,
replacing `--expected-clients` (`stoffel-run.rs:5092-5096`, `:3484-3487`).

#### C.8 Rounds, deadlines and aborts

| Round | `associate_client` binds a new slot | reserve | submit | `get_client_admissions` |
|---|---|---|---|---|
| `Idle` | yes | — | — | `AdmissionsNotFrozen` |
| `Preprocessing` | yes | — | — | `AdmissionsNotFrozen` |
| `InputMaskReservation` | yes | yes | — | `AdmissionsNotFrozen` |
| `InputCollection` | `AssociationClosed` | — | yes | the frozen set |
| `MPCExecution`, `OutputDistribution`, `ProgramFinished` | `AssociationClosed` | — | — | the frozen set |
| `Aborted` | `ExecutionAborted` | `ExecutionAborted` | `ExecutionAborted` | `ExecutionAborted` |

Re-asking for an existing binding (C.4 step 5) answers in every round but `Aborted`, until
the execution is removed. `obtain_output_shares` stays unconstrained by round, as today.

**`Round::Aborted`** is a new terminal variant of the shared `Round`
(`coord:coord-shared/src/lib.rs:145-154`): `round_index(Aborted) = 7`, above every other
round, so no round compares as after it; `round_before(Aborted) = None`, so `transition`
refuses it as a target exactly as it refuses `Idle` (`:2359-2365`); it is not in
`ORDERED_ROUNDS`, so no quorum reaches it; and a proposal for any round on an aborted
execution answers `ExecutionAborted` (35, C.6). Only the deadline sweeper (below) enters it.
`OffChainCoordinatorClient::trigger_round` and `wait_for_round` refuse `Aborted` locally with
`CoordinatorError::RoundNotProposable { round }`: an abort reaches a waiter through
whatever round it is waiting for.

**Preconditions** in `blocking_precondition` (`:1603`). Each is a wait, not a rejection:
proposals are recorded, and a round applies inside whichever call makes it legal.

1. *(existing)* `MPCExecution` while any slot with inputs has no submission.
2. *(new)* `InputCollection`, and the skip from `Preprocessing` straight to `MPCExecution`,
   while any slot is unbound: "`{k} of {capacity} client slots are unbound`". Under
   `PreRegistered` it always holds. It never holds back an honest node's own progress:
   honest nodes propose `InputCollection` only after every input index is reserved, so what
   it can hold is an unbound **output-only** slot — the point, since the set freezes at that
   transition and an output slot bound later could never be delivered to.
3. *(new)* the skip from `Preprocessing` to `MPCExecution` while `n_inputs() > 0`:
   "`the registration has {n} inputs; the input rounds cannot be skipped`". Today
   `skips_empty_input_rounds` looks only at the round pair (`:1585-1587`) and switches off
   precondition 1 on that path (`:1604`), so a quorum could skip input collection for an
   execution that has inputs.
4. *(new)* the skip from `MPCExecution` to `ProgramFinished` while any slot has
   `output_count > 0`: "`{k} client slots have output rights; OutputDistribution cannot be
   skipped`" (`:1591-1593` looks only at the round pair). A registration without output
   slots takes this skip; §D.7 step 12 is how nodes reach `ProgramFinished` on it.

**Deadlines.** One deadline sweeper runs per listener. `OffChainCoordinatorServer::start_coord`
and `start_coord_one_off` both spawn it, through one private helper
`spawn_deadline_sweeper(state: Arc<Mutex<CoordinatorRPCServerSharedBase>>) ->
JoinHandle<()>`: revision 1 put it in `start_coord` alone, but `start_coord_one_off` builds
its own listener and never calls `start_coord` (`coord:off-chain/src/lib.rs:2585-2607`), and
`run-coord --one-off` goes through it (`coord:bins/src/bin/run-coord.rs:219-232`), so a
one-off coordinator would never abort an `Open` or `Invitation` execution — S5's permanent
stall — and would never expire retention. The server owns the handle: `OffChainCoordinatorServer`
stores it beside its `RPCServerHandle`, `shutdown` aborts it, and `start_coord_one_off`
aborts it after the drain; its `Drop` aborts it too. Both starts therefore require
`C: RPCServerConnection<Internal = CoordinatorRPCServerSharedBase>`, as
`start_coord_one_off` already does (`:2594-2597`). `register_execution` wakes the sweeper
through a `tokio::sync::Notify`. It sleeps until the earliest pending deadline or retention
expiry (C.10), then collects the executions due under the state mutex and releases it; for
each, it takes the execution's `delivery` guard, locks the state again — the order every
other path uses (C.6), so the sweeper never waits for a delivery guard while holding the
mutex — re-checks the condition, and acts:

- **association deadline** passed, the round is `Idle`, `Preprocessing` or
  `InputMaskReservation`, and a slot is unbound → abort with
  `AssociationDeadline { deadline, unbound_slots }`;
- **input deadline** passed, the round is before `MPCExecution`, and at least one slot with
  inputs has no submission → abort with `InputDeadline { deadline, missing_inputs }`,
  `missing_inputs` being the input count of those slots. Revision 1 required only
  `n_inputs() > 0`, which aborted a fully submitted, honest execution whose nodes were
  still running the `InputsAgreed` barrier (§D.7 step 9) when the deadline passed. Once
  every input is present only node liveness is left, which retirement and the drain's
  grace already bound;
- retention expired → remove the execution (C.10).

**Aborting** sets the round to `Aborted`; takes every parked sink of the execution;
releases the state mutex; sends `Event::ExecutionAborted { reason }` to the `sub_round`,
`sub_reserved_indices` and `sub_masked_inputs` sinks and drops the output waiters; and
releases the delivery guard. Holding the delivery guard throughout is what closes the two
races revision 1 left open:

- `submit_masked_inputs` and every other broadcast take the parked sinks out of the state,
  release the mutex to send, and put them back (`coord:off-chain/src/lib.rs:2085-2091`,
  `:2109-2127`). An abort in that window — during `InputCollection`, exactly when an input
  deadline fires — found the lists empty, and the sinks were re-parked on an aborted
  execution: those nodes' `wait_for_inputs` never ended, never retired, and a one-off
  drain never started. Now the abort waits for the broadcast's delivery guard, and a
  broadcaster that re-locks and finds the execution aborted sends `ExecutionAborted`
  instead of re-parking (C.6).
- Every subscription checks the execution, calls `accept` with no lock held, then re-locks
  and parks (`:1861-1880`, `:1908-1920`, `:1928-1940`, `:2144-2156`, `:2164-2176`). An abort
  between `accept` and the re-lock parked a sink that never received the event. Now the
  re-lock checks the round, and a subscription that finds `Aborted` sends
  `ExecutionAborted` (on an `Event` stream) and drops the sink instead of parking (C.6).

An aborted execution is evictable at once under capacity pressure, without any retirement
acknowledgement, which is what returns its `DEFAULT_MAX_CONCURRENT_EXECUTIONS` slot.

**Ended executions are remembered, and acknowledgements do not erase that.** Revision 1
said an aborted id is refused "while this process remembers it", relying on
`RetiredExecutions`. In the normal case that memory lasts moments: §D.7 makes every node
retire on abort, and unanimous retirement removes the execution without a tombstone
(`:1319-1327`) or forgets an existing tombstone (`RetiredExecutions::acknowledge`,
`:1061-1071`), and `register_execution` never consults `retired` (`:1231-1270`). The id
could then be registered again at once — exactly what a compose stack's constant
`STOFFEL_EXECUTION_ID` does (C.3) — and a client's summary read after that was
`ExecutionNotFound`, not the abort. `0.3.0` adds, beside `RetiredExecutions` (which keeps
its job of letting stragglers acknowledge):

```rust
/// Bounded, insertion-ordered: the last `DEFAULT_MAX_ENDED_EXECUTIONS` (4096) executions
/// that left `executions`, by any path — unanimous retirement, retention expiry, eviction
/// of a quorum-retired or an aborted execution. Acknowledgements never remove an entry;
/// only the bound does, oldest first.
struct EndedExecutions {
    outcomes: HashMap<ExecutionId, ExecutionOutcome>,
    order: VecDeque<ExecutionId>,
}
```

An id it holds is refused by `register_execution` (`ExecutionIdRetired`, C.1 step 2). A
call naming an id it holds as `Aborted(reason)` answers `ExecutionAborted` (35) with that
reason — `get_execution_summary` included, so a client arriving late learns why — and one
it holds as `Finished` answers `ExecutionNotFound` (16), as a removed execution does
today. `retire_execution` is the exception for both: acknowledging an execution that is
gone stays a success (`:1319-1323`), so a node's best-effort retirement never fails.
The bound makes the memory finite, so an id can be registered again once 4,096 later
executions have ended. That is safe for two reasons that do not depend on this
memory: a new registration draws a new nonce, which orphans every invitation and every
signed submission and sealed output of the old one (C.3, C.7), and no node ever provisions
a mask share or triple it provisioned for an earlier execution (C.9 part 4).

Deadlines are optional under `PreRegistered`, where the operator chose every identity; set
them anyway to bound how long an absent pre-registered client can hold a capacity slot.
Size them to the run: preprocessing time counts against the input deadline.

#### C.9 Capacity versus preprocessing

Association cannot over-commit masks, and no mask serves twice. The checks are
structural, in four parts:

1. **A mask exists for every index an admission can name.** `n_inputs()` is fixed at
   registration and every slot's range is a function of it (C.1). Every node reads the same
   `n_inputs()` from `get_execution_summary` **before** it sizes preprocessing (§D.7 step 1),
   and provisions exactly that many mask shares, at indices `0..n_inputs()`, before it
   proposes `InputMaskReservation` — where today it derived the count from its own flags
   (`stoffel-run.rs:2655-2656`, `--client-input-total` or `--expected-clients` ×
   `--client-input-count`). A node that cannot preprocess them exits before proposing: the
   execution stalls until its input deadline, and nobody is ever pointed at a mask that does
   not exist. A node also refuses a served table that fails `check_bounds`, so a
   coordinator cannot size a node's preprocessing past `MAX_INPUTS`.
2. **Admissions partition the index space.** Slot `i`'s range is a fixed function of the
   registration (C.1); the ranges of distinct slots are disjoint and together are exactly
   `[0, n_inputs())`; each slot is bound at most once. So the admitted input counts sum to
   at most `n_inputs()` by construction rather than by a counter that could drift, and the
   only runtime check is whether a free slot exists (`CapacityExhausted`, `SlotTaken`).
3. **Within an execution, no mask is handed to two clients.** Bindings are never removed
   or moved, and nodes release a mask only to the owner the agreed admission set names
   (C.7). This is also why a stalled client's slot is never evicted and rebound: the
   stalled client may already hold its mask, and a second client in that slot would be
   submitting `input + mask` to someone who can subtract. A squatter therefore costs the
   execution, not the mask: it is aborted at its deadline (C.8).
4. **No preprocessing item serves two executions** — not a mask share, not a Beaver
   triple, not a PRandBit or PRandInt share, not an AVSS triple or random share; not across
   a restart of the node, and not after an abort. Part 3 alone did not give this, because
   the node's preprocessing store handed the same material to consecutive executions:

   - After fresh preprocessing, `HoneyBadgerMpcEngine::preprocess` calls `persist_preproc`
     (`crates/stoffel-vm/src/net/mpc/honeybadger/preprocessing.rs:82`), which takes every
     item out of the pool, writes a copy to the LMDB store with its consumed cursor at 0,
     and puts the same items back (`prep.add(restore_*)`, `:270-347`, `:344`). The
     execution then draws its masks from memory (`take_random_shares`,
     `crates/stoffel-vm-runner/src/bin/stoffel-run.rs:5253-5280`) and its triples inside
     `stoffelcrypto` (`take_beaver_triples`, `stoffelcrypto-0.1.1/src/honeybadger/mod.rs:612-616`),
     and nothing ever rewrites the store. On the next start `try_load_preproc` loads that
     blob (`preprocessing.rs:90-160`), keyed only by program hash, field, `n`, `t` and node
     identity (`PreprocKeyScope`, `crates/stoffel-vm/src/storage/preproc.rs:146-153`) —
     nothing that changes between executions. The AVSS engine does the same
     (`crates/stoffel-vm/src/net/mpc/avss/preprocessing.rs:53`, `:140-190`).
   - `docker-compose.coordinator.reserve-index.preproc.yml:26` turns the store on for the
     stack §F.1 makes the `Open` stack, and `docker/test-coordinator-preproc-store.sh:162`
     asserts that the second run loads the first run's material.
   - The attack: under `Open`, an attacker binds slot 0 in run 1 and reconstructs its mask
     `r₀`. After `down`/`up`, an honest client in slot 0 of run 2 is given the same `r₀`,
     and any single node reads `x + r₀` from `sub_masked_inputs` and learns `x`; so does the
     coordinator, with no node at all. Reused triples leak the same way through the opened
     values of a multiplication.

   **The rule:** a node's preprocessing store never holds an item unconsumed while any
   execution may still draw it. Concretely, in both engines:

   - **Loading consumes before use.** `try_load_preproc` already advances the stored cursor
     past everything it loads with `reserve_at` — one LMDB write transaction, committed by
     the store's actor (`crates/stoffel-vm/src/storage/preproc.rs:489-529`) — and deletes the
     blob before any loaded item enters the pool (`honeybadger/preprocessing.rs:138-160`,
     `avss/preprocessing.rs:95-119`). That stays, and is the only store access an execution
     makes.
   - **Generation never writes.** `persist_preproc` and its calls are deleted in both
     engines. Material generated for an execution exists only in that process.
   - **An abort needs no record.** The mask shares an aborted execution provisioned, and
     any triples it drew, were never in the store: they die with the process and with the
     node RPC listener's retired execution (§D.7 "Abort").
   - `stoffel-run --preproc-store` fails by name (§D.3). With the write path gone nothing in
     this repository writes the store, so the flag could only ever load nothing.

   **Why not persist what an execution leaves unused.** The review proposed storing only
   unconsumed items and rewriting the store after every take. Two facts make that the wrong
   trade here. First, a take cannot be committed before its use: triples are drawn inside
   `stoffelcrypto`'s multiplication (`honeybadger/mod.rs:612-616`, `:1122-1126`), where the
   VM has no hook, so a cursor-exact store needs a change to that crate. Second, the only
   material a finished execution leaves unused is `plan_preprocessing`'s banding slack —
   an eighth of an octave per count, an extra octave for a dynamic program, and two random
   shares (`stoffel-run.rs:100-127`, `:148-183`) — and persisting even that would need every
   node to agree which slack it holds: a node that crashed or aborted mid-run holds a
   different one, and HoneyBadger preprocessing is interactive, so nodes that disagree about
   whether to load hang. Everything the store saved beyond that slack was material the
   previous execution had already used. Ahead-of-time material — a pool of whole
   executions' worth, the persistent-network design's — must meet the same rule: every draw
   advances a committed cursor before the item leaves the engine, and nothing is ever
   written back with its cursor rewound.

#### C.10 Wire compatibility: `0.3.0` is a breaking release

`0.2.0` and `0.3.0` peers do not interoperate in either direction, and no compatibility
shim is offered.

- **New methods:** `get_node_roster`, `get_execution_summary`, `associate_client`,
  `get_client_admissions`.
- **Deleted methods:** `register_execution` (C.1), `request_shutdown` (below),
  `available_input_masks` (`:904-907`), which its own comment calls racy and which has no
  meaning once every slot's range is fixed; `sub_assigned_reserved_indices` and
  `sub_assigned_masked_inputs` (C.6); and the singular `reserve_mask_index` and
  `submit_masked_input` (C.6). Nothing in this repository calls any of them.
- **Changed shapes:** `ExecutionRegistration` loses `n_inputs`, `output_clients`,
  `input_assignment` and `min_output_shares`, gains `client_slots`, `admission` and
  `deadlines`, and no longer crosses the wire. `InputAssignment`, `InputClientRange`,
  `InputSlotAssignment` and `AssignedMaskedInputEvent` are deleted. `Round` gains
  `Aborted`; `Event` gains `ExecutionAborted { reason }`, and `Event::MaskedInputEvent`
  carries one `MaskedInputSubmission`. `submit_masked_inputs` takes `first_index` and a
  signature; `send_output_shares` takes a `ClientIndex` and a `SealedOutput`;
  `obtain_output_shares` yields one `SealedOutputShares` per node (C.7).
- **Node RPC listener:** the unassigned `NodeRPCServer::add_reserved_index_for_execution`
  and `add_reserved_indices_for_execution` (`coord:off-chain/src/lib.rs:467-498`) are
  deleted. They register a reservation with `input_ordinal = reserved_index` and no
  admission behind it, and both VM node paths call them today (`stoffel-run.rs:5331-5345`,
  `:3590-3606`); leaving them would leave a way around "release only against agreed
  admissions" for the next caller. `add_assigned_reserved_index(es)_for_execution` stay as
  the incremental registration path, and `register_admitted_reservations_for_execution`
  is added: it registers an execution's complete admitted set and **seals** it (§D.7 step
  7). After sealing, any further registration is `NodeRPCError::ReservationsSealed`; every
  parked mask request that can no longer complete — from an identity holding no
  reservation, or over an index no one holds — is dropped (its stream closes); and such a
  request is refused at subscribe time (`RangeNotAssignedToCaller = 3`). Without the seal a
  certificate holding no reservation could park a request indefinitely.
  No listener await on a caller's socket runs under an execution's state lock, completed
  answers are sent on their own tasks with the subscription send timeout, and a parked
  subscription holds no reference to its execution's state, so retiring the execution
  frees the state and closes the parked stream.
- **Clients:** reserving without an admission (31), or reserving anything other than the
  admitted range (32), fails — so a `0.2.0` client that chooses its own window
  (`--client-index`) fails. A submission must cover the admitted range in one signed call
  (C.6, C.7). Output delivery follows admissions, not `output_clients`, one node per
  message. `InputCollection` and the zero-input skip wait for every slot to be bound.
  Every subscription is gated (C.6).
- **Transport:** every client-side connection (coordinator and node RPC) requires a pin;
  an unpinned `0.2.0` client cannot be built against `0.3.0` at all. Every connection is
  TLS 1.3. Listeners refuse caller certificates with trailing bytes, other key algorithms
  or non-canonical encodings, and bound connections before and after the handshake (§A).
- **Rust API:** `setup_client` takes `&ServerPin` and returns `PinnedClient`;
  `SelfSignedServerVerifier` is deleted; `coord_shared::rpc::start_coord` takes
  `RpcServerLimits`, and `RPCServerConnection` gains `capacity_class` with a
  default; `ShareBound` gains the methods of C.7; `OffChainCoordinatorServer::start_coord`,
  `start_coord_from_cert` and `start_coord_one_off` drop the unused `_t`, take
  `RpcServerLimits`, require `Internal = CoordinatorRPCServerSharedBase`, check the served
  certificate against the state (§B) and own the deadline sweeper (C.8), and the server
  gains `state()`; `OffChainCoordinatorClient::start_rpc_client_for_execution` and
  `NodeRPCClient::start_rpc_client_for_execution` take their new shapes (A);
  `CoordinatorRPCServerSharedBase::new(NodeRoster, SpkiDer)` and
  `new_for_execution(NodeRoster, SpkiDer, ExecutionRegistration)` (B); `ClientIdentity`
  moves to `coord-shared`, re-exported from `off-chain`, so paths through `off-chain` keep
  compiling.
- **`OffChainCoordinatorConnection`.** The connection type that merges the
  `StoffelCoordinatorRPC` façade with `CoordinatorRPCBase` exists today only as
  `tests::fake_coord::CoordinatorConnection` (`coord:off-chain/src/tests/fake_coord.rs:33-56`,
  aliased `HoneyBadgerCoordinatorConnection`, its façade impl from `:58`) and as the
  wrapper's private copy (`docker/coordinator-wrapper/src/main.rs:78-137`), and
  `local_runner.rs:11-13`, `:156` names the test one. `0.3.0` adds
  `stoffel_mpc_coordinator_off_chain::OffChainCoordinatorConnection` — the same type, `Internal = CoordinatorRPCServerSharedBase` — for embedders; the
  wrapper and `local_runner` use it. `off-chain`'s `tests::fake_coord` and
  `coord-shared`'s `tests::fake_coord` stay public, updated to the new constructors, with
  `CoordinatorConnection` and its aliases pointing at the promoted type, so
  `crates/stoffel-rust-sdk/tests/sdk_usage.rs:4267-4268` keeps compiling.
- **Canonical `mpc_nodes`.** `mpc_nodes[0]` is now the lowest SPKI, not the operator's
  first `--initial-mpc-nodes` entry. Every field that names it is informational
  (`:1657-1659`) except `request_shutdown`'s designated-party gate (`:1805-1812`), which
  rule 2 removes: **`request_shutdown` is deleted**.
- **One-off drain.** `start_coord_one_off` (`:2585`) takes its trigger from
  `CoordinatorRPCServerSharedBase::watch_for_retirement_quorum(execution_id)`, which
  replaces `watch_for_shutdown_request` and resolves once
  `absent || (terminal && acks >= retirement_quorum())` holds for the execution — absent
  meaning removed after being registered, which `retirement_progress` already treats as
  drained (`:1339-1350`), terminal meaning `ProgramFinished` or `Aborted`. The round gate is
  what `request_shutdown` had (`:1820-1826`) and a bare acknowledgement count would lose:
  `retire_execution` accepts an acknowledgement in any round (`:1302-1329`), so `n - t`
  early acknowledgements would otherwise start the drain mid-execution and drop output
  clients. `retire_execution` itself stays round-agnostic — honest nodes acknowledge only a
  terminal round (§D.7), so a pre-terminal quorum needs honest nodes that never send one —
  which keeps `retirement_drains_healthy_stragglers_without_pinning_capacity` meaningful.
  **The trigger:** the state holds `retirement_changed: Arc<tokio::sync::Notify>`, and every
  path that can change the condition calls `notify_waiters()` after changing it —
  `retire_execution`, `try_advance` when it applies `ProgramFinished`, the sweeper's abort,
  and every removal (unanimity, retention expiry, eviction). The watcher evaluates the
  condition under the state mutex, and if it does not hold creates the `Notified` future
  and calls `Notified::enable` (`tokio-1.52.3/src/sync/notify.rs:1006`) *before* releasing
  the mutex, so a notification sent between the check and the wait is not lost; revision
  1's oneshot fired from one RPC could not see the other three paths. The drain then waits,
  as today, until the execution is removed or `grace` has passed (`:2611-2624`).
  `run-coord`'s doc comments that still name a `stoffel-run --one-off` bootnode
  (`coord:bins/src/bin/run-coord.rs:26-30`, `:197-199`) are rewritten. A standing
  coordinator (the wrapper, and `run-coord` without `--one-off`) never drains.
- **Output retention.** Unanimous acknowledgement removes an execution at once
  (`:1324-1327`), and with it `output_shares` and `output_sinks`: a client subscribing to
  `obtain_output_shares` after the last node retired gets `ExecutionNotFound`
  (`:2451-2452`). `0.2.0` never met this because nothing in this repository retires; §D.7
  makes nodes retire. `0.3.0` removes an execution **whose slot table has output slots**
  `output_retention` after its unanimous acknowledgement — `DEFAULT_OUTPUT_RETENTION` is
  60 s, set with `CoordinatorRPCServerSharedBase::with_output_retention(Duration)` — through
  the deadline sweeper; one without output slots is removed at once, as today.
  Quorum-retired executions stay evictable under capacity pressure (`:1240-1266`). A
  one-off coordinator whose execution has output slots therefore exits `output_retention`
  after unanimity, or when its drain's `grace` runs out, whichever comes first.
- **Removal is concurrent, so no re-lock assumes the execution survived.** Retention
  expiry and eviction add removers that run while RPCs are between their unlock and
  re-lock. `deliver_ready_output_waiters` re-locks after `send_output_shares` or
  `obtain_output_shares` dropped the guard (`:2436-2437`, `:2493-2494`) and `.expect`s the
  execution to be registered (`:1736-1745`), which panics that connection's task on a
  removal in the gap; the race exists with unanimous retirement today, and the sweeper
  makes it routine. In `0.3.0` that path, and every other path that re-locks after
  releasing — the broadcasts and subscriptions of C.6, `associate_client` step 4 — treats
  an execution that is gone as the end of its work and returns quietly.
- **Error codes:** 35 through 41 added; 1, 3, 4, 7, 11, 13, 15, 17, 18 and 19 retired (C.5).
- **Binaries:** `run-coord` and the wrapper flags change (§F.3); `issue-invitation` is new
  (C.3).

### D. VM node behavior

#### D.1 Startup order

Party mode (`stoffel-run <program> --peers …`), in this order and no other:

1. **Own identity.** Read `--cert` and `--key` (already read for the storage identity,
   `required_storage_identity`). Read `--coord-cert` and derive its `SpkiDer`; a missing
   file, a non-certificate, a refused key algorithm or a non-canonical key exits 2 before
   any network I/O. Parse `--expect-roster-digest` (`RosterDigest::from_str`, §B),
   `--expect-n-parties` and `--expect-threshold` if given.
2. **Pinned coordinator.** `CoordinatorLink::connect(host, port, &coordinator,
   expected_roster_digest, cert_der, key_der)`. A transport failure exits 13, as
   coordinator connection failures do today; compose stacks gate parties on the
   coordinator's healthcheck. `ServerPinMismatch` exits 13 with its own message (D.3).
3. **Roster, once.** Inside `connect`: one `get_node_roster`, verified by
   `NodeRoster::try_from(wire)` (§B) — a failure exits 13 — and compared with
   `--expect-roster-digest` when given — a mismatch exits 2. Then, outside it, `n` and `t`
   are compared with `--expect-n-parties` and `--expect-threshold` when given — a mismatch
   exits 2. Nothing re-fetches the roster for the life of the process.
4. **Membership.** `node_roster.position_of(&SpkiDer::from_certificate_der(cert_der)?)` is
   `None` → exit 2. It is checked here, before a socket is bound, so the failure names the
   coordinator's roster instead of surfacing as stoffelnet's "local certificate is absent
   from the server certificate roster" (`quic.rs:1301-1305`) from inside the join.
5. **VM roster.** `Roster::from_coordinator` (D.4) over the served certificate DERs, `t`
   and digest. stoffelnet re-derives every SPKI, the VM refuses compact-id collisions and
   the rosters §B refuses, and it recomputes the §B digest and refuses a mismatch — so a
   drifted digest implementation can never be installed.
6. **Transport.** `QuicNetworkManager::with_node_id(party-id label)`,
   `set_local_certificate_der(cert, key)`, `listen(--bind)`.
7. **Peer book.** `MeshRouter::pinned_to(roster.nodes().iter().cloned(), PexLimits::default())`.
8. **Epoch store.** `EpochStore::open(epoch_store_path(--epoch-store))`.
9. **Join.** `MeshJoin::new(roster, seeds, epochs).with_router(router)` →
   `join_mesh`, which installs the allowlist before touching anything else
   (`crates/stoffel-vm/src/net/mesh/join.rs:366`, nodes only), proposes
   `epochs.propose(&roster.digest())` (`:376`) and commits under the same digest (`:433`).
   The epoch store is thereby keyed by the fetched roster digest. `JoinRequest.n_parties`
   and `threshold` are the roster's, and `JoinRequest.execution_id` is `--execution-id`
   (D.5).
10. **Rounds.** The same link becomes the round driver once the backend and curve are
    resolved: `OffChainCoordinatorClient::<F, S>::from_link(link, execution_id)`. No second
    connection and no second roster fetch. The link is moved into the coordinated party
    function (§D.7 "Signatures"), and the next thing it does is §D.7 step 1. It is never
    re-established: a transport failure on it exits 13 (§A, "A node's coordinator link is
    not re-established").

#### D.2 Flags

| Flag / environment | `0.3.0` status |
|---|---|
| `--off-chain-coord <host:port>` / `STOFFEL_COORD_ADDR` | required in party and client mode |
| `--coord-cert <path>` / `STOFFEL_COORD_CERT` | **new**; required wherever `--off-chain-coord` is |
| `--expect-roster-digest <64-hex>` / `STOFFEL_EXPECT_ROSTER_DIGEST` | **new**, optional, party and client mode |
| `--expect-n-parties <u64>`, `--expect-threshold <u64>` | **new**, optional, party and client mode; no environment variable — the SDK emits them (§E.2), compose stacks do not |
| `--execution-id <64-hex>` / `STOFFEL_EXECUTION_ID` | required (unchanged, §7) |
| `--cert`, `--key` / `STOFFEL_CERT`, `STOFFEL_KEY` | required (unchanged); in compose, the key is a per-service secret (§F.0) |
| `--peers`, `--bind`, `--advertise`, `--epoch-store`, `--rpc-bind`, `--party-id` (a label), `--mpc-backend`, `--mpc-curve`, `--local-store` | unchanged |
| `--roster` / `STOFFEL_NODE_ROSTER` | **removed**, fails by name |
| `--expected-clients` / `STOFFEL_EXPECTED_CLIENTS` | **removed**, fails by name |
| `--wait-for-clients` / `STOFFEL_WAIT_FOR_CLIENTS` | **removed** with direct clients (§E.3) |
| `--client-roster`, `--client-input-slots`, `--client-input-count` (`STOFFEL_CLIENT_INPUT_COUNT`), `--client-input-total` | **removed**; the layout is `get_execution_summary`'s |
| `--n-parties`, `--threshold` / `STOFFEL_N_PARTIES`, `STOFFEL_THRESHOLD` | **removed** in party and client mode — `--peers` now always comes with `--off-chain-coord` — so `n` and `t` have exactly one source |
| `--preproc-store` / `STOFFEL_PREPROC_STORE` | **removed** (§C.9 part 4, stage V-0) |
| `--timestamp` / `STOFFEL_TIMESTAMP` | **removed**. Emitted by the entrypoint (`docker/entrypoint.sh:274`, `:342`), the SDK server (`crates/stoffel-rust-sdk/src/server.rs:1039-1040`) and `local_runner` (`local_runner.rs:589-590`), but `stoffel-run` has no parser arm for it (`stoffel-run.rs:4045-4250` falls to `_ => {}`), so its value only ever landed among the positional arguments (`:4033-4036`), and no coordinator version takes a timestamp |

`--expect-roster-digest`, `--expect-n-parties` and `--expect-threshold` are defense in
depth, not a second roster authority: they carry no certificate and can only refuse what
the coordinator served, never supply membership, so rule 1 holds. The digest is what lets
an operator who knows the intended node set detect a coordinator that serves this node a
different one (§G); the two counts are what keep the SDK's configured `parties` and
`threshold` meaningful (§E.2).

#### D.3 Exact messages

Removed flags use the existing `fail_removed_flag` (`stoffel-run.rs:960`), which prints
``Error: `{flag}` was removed. {hint}`` and exits 2:

| Flag | Hint |
|---|---|
| `--roster` | `Membership is the coordinator's node roster, fetched once at startup. Pass --off-chain-coord, --coord-cert and --execution-id instead.` |
| `--expected-clients` | `Client certificates no longer enter a node's transport allowlist. Clients associate with an execution through the coordinator, and nodes read the admissions from it.` |
| `--wait-for-clients` | `Clients no longer connect to the node mesh. They associate through the coordinator and fetch their masks from the nodes' --rpc-bind listeners.` |
| `--client-roster`, `--client-input-slots`, `--client-input-count`, `--client-input-total` | `The client slot layout is the coordinator's execution registration.` |
| `--n-parties`, `--threshold` | `n and t come from the coordinator's node roster. To refuse a roster of another size, pass --expect-n-parties and --expect-threshold.` |
| `--preproc-store` | `Preprocessing material is never stored between executions: a stored item could be drawn by a second execution (docs/design/bootnode-elimination.md §9.C.9). Remove the flag.` |
| `--timestamp` | `No coordinator takes a timestamp; an execution's deadlines are part of its registration. Remove the flag.` |

The existing refusals whose hints name flags this section removes are rewritten, so an
operator is never sent from one refusal to the next:

| Site | Today's hint | `0.3.0` hint |
|---|---|---|
| `--client-id` (`stoffel-run.rs:3960-3964`) | `Client IDs are now transport-derived. Remove --client-id.` | `A client's slot is requested with --client-slot <index> and granted by the coordinator's admission.` |
| `--expected-client-count` (`:3965-3969`) | `Use --expected-clients <cert-paths-or-addrs> instead.` | `The client slot layout is the coordinator's execution registration.` |
| `--bootnode` (`:3985-3991`, flag at `:3987`) | `… give every node --roster <cert-paths>, --peers <addrs> and --epoch-store <dir> …` | `The bootnode is gone. Every node passes --off-chain-coord <host:port>, --coord-cert <path>, --execution-id <64-hex>, --peers <addrs> and --epoch-store <dir>, and runs no bootstrap process.` |
| `--bootstrap` (`:3992-3997`, flag at `:3994`) | `… Pass --peers <addrs> (seed hints) and --roster <cert-paths> (membership) instead.` | `There is no bootstrap process to register with. Pass --peers <addrs> (seed hints); membership is the coordinator's node roster (--off-chain-coord, --coord-cert).` |
| `--coord-driver` (`:4005-4011`) | names `0.2.0` | `Coordinator transitions are quorum-gated: every party proposes every round and none is designated. Drop the flag.` |
| `build_session_join` without a roster (`:282-286`) | `--peers forms a mesh, so membership must come from --roster …` | the `--peers` refusal of the next table, which the flag check reaches first; the function then takes the `Roster` built at §D.1 step 5, not an `Option` |
| `--roster` in coordinator client mode (`:4434-4443`) | `… use direct client mode … where the roster is installed and enforced.` | deleted: `--roster` fails by name (above) before client mode is reached, and direct client mode is refused (§E.3) |
| usage text (`print_usage_and_exit`, `:5619`; `--n-parties` "required … without --roster" at `:5650-5651`, `--party-id` naming `--preproc-store` at `:5643-5644`, `--roster` at `:5699-5704`, "Multi-Party Execution" at `:5707-5727`) | describes `--roster` membership | rewritten to the flags of §D.2 and §E.2 |

The rest exit with these exact messages:

| Condition | Exit | Message |
|---|---|---|
| `--off-chain-coord` without `--coord-cert` | 2 | `Error: --off-chain-coord requires --coord-cert <path>. The coordinator is the roster authority, and a connection that does not pin its certificate accepts any server.` |
| `--peers` without `--off-chain-coord` | 2 | `Error: --peers forms a mesh whose membership only the coordinator defines. Pass --off-chain-coord <host:port>, --coord-cert <path> and --execution-id <64-hex>.` |
| `--coord-cert` unreadable | 2 | `Error: cannot read --coord-cert {path}: {reason}` |
| `--coord-cert` not a certificate, a refused key algorithm or a non-canonical key | 2 | `Error: --coord-cert {path} is not a usable DER X.509 certificate: {reason}` |
| `--expect-roster-digest` does not parse | 2 | `Error: --expect-roster-digest: {error}` — `{error}` is the `RosterDigestParseError` (§B) |
| `--expect-n-parties` or `--expect-threshold` not a `u64` | 2 | `Error: {flag} must be a non-negative integer: {reason}` |
| `ServerPinMismatch` | 13 | `Error: the coordinator at {host}:{port} presented a key that --coord-cert {path} does not pin. Refusing to fetch a roster from it.` |
| served roster fails the receiver check | 13 | `Error: the coordinator at {host}:{port} served a node roster that fails verification: {error}` |
| `UnexpectedRosterDigest` | 2 | `Error: the coordinator serves roster digest {served}, not the --expect-roster-digest {expected}; refusing to install it.` |
| served `n` or `t` differs from `--expect-n-parties` / `--expect-threshold` | 2 | `Error: the coordinator serves a roster of n = {n}, t = {t}, not the expected {flag} {expected}; refusing to install it.` |
| own certificate not in the roster | 2 | `Error: this node's certificate (--cert {path}) is not one of the {n} nodes in the coordinator's roster (digest {first 8 bytes, hex}). A node cannot join a session it is not a member of.` |
| VM digest disagrees with the served digest | 2 | `Error: the coordinator's roster digest {served} does not match its certificates ({computed}); refusing to install it.` |
| lost coordinator link (§A) | 13 | `Error: lost the link to the coordinator at {host}:{port}: {error}. A node does not reconnect mid-execution.` |
| summary names another program (D.7 step 1) | 13 | `Error: execution {id} is registered for program {served}, but this node loaded {local}; refusing to run it.` |
| roster too small for the backend (D.7 step 1) | 13 | `Error: {backend} needs at least {required} nodes for threshold {t}, and the coordinator's roster has {n}; refusing to run execution {id}.` |
| a slot's outputs exceed the sealed-output bound (D.7 step 1) | 13 | `Error: execution {id} gives client slot {i} {k} outputs, {bytes} bytes sealed under {backend}, above the {max}-byte bound; refusing to run it.` |
| summary's slot table fails its bounds or the program manifest (D.7 step 1) | 13 | `Error: execution {id} has a client slot table this node refuses: {reason}` |
| `AdmissionDivergence` (D.6) | 13 | `Error: party {party_id} agreed different client admissions for execution {id}; refusing to release mask shares.` |
| `ReservationMismatch` (D.7 step 7) | 13 | `Error: the coordinator's reservation for index {i} does not match the agreed client admissions; refusing to release mask shares.` |
| `MaskedInputMismatch` (D.7 step 9) | 13 | `Error: the coordinator delivered masked inputs for client slot {i} that the agreed admissions do not match: {reason}; refusing to use any input.` — `{reason}` is the variant: another identity, another range, or a signature the slot's client did not make |
| `InputDivergence` (D.6) | 13 | `Error: party {party_id} received different masked inputs for execution {id}; refusing to use any of them.` |
| `ExecutionAborted` | 13 | `Error: execution {id} was aborted by the coordinator: {reason}` |
| output to a slot without output rights (D.7 step 12) | 4 | `Execution error in '{entry}': the program sent output to client slot {i}, which the registration gives no output rights` |
| output count differs from the admission (D.7 step 12) | 4 | `Execution error in '{entry}': the program sent {k} outputs to client slot {i}, which the registration gives {m}` |

`docker/entrypoint.sh` refuses removed variables by name, in its existing style, e.g.
`ERROR: STOFFEL_NODE_ROSTER was removed. The coordinator serves the node roster: set STOFFEL_COORD_ADDR, STOFFEL_COORD_CERT and STOFFEL_EXECUTION_ID.`
— and likewise `STOFFEL_EXPECTED_CLIENTS`, `STOFFEL_WAIT_FOR_CLIENTS`, `STOFFEL_CLIENT_INDEX`,
`STOFFEL_CLIENT_INPUT_COUNT`, `STOFFEL_OUTPUTS`, `STOFFEL_N_PARTIES`, `STOFFEL_THRESHOLD`,
`STOFFEL_PREPROC_STORE` and `STOFFEL_TIMESTAMP` (each when non-empty, in both roles). Every
site of the entrypoint that names them changes in the same edit:

| `docker/entrypoint.sh` | Today | `0.3.0` |
|---|---|---|
| `:6-9` header | "membership is STOFFEL_NODE_ROSTER, enforced per connection by mTLS" | membership is the coordinator's node roster, pinned by `STOFFEL_COORD_CERT` |
| `:16-19` | `STOFFEL_AUTH_TOKEN` refusal says "set STOFFEL_NODE_ROSTER (plus STOFFEL_CERT/STOFFEL_KEY) instead" | "set STOFFEL_COORD_ADDR, STOFFEL_COORD_CERT and STOFFEL_EXECUTION_ID (plus STOFFEL_CERT/STOFFEL_KEY) instead" |
| `:51-58` | `STOFFEL_NODE_ROSTER requires STOFFEL_CERT and STOFFEL_KEY` | becomes `STOFFEL_COORD_ADDR requires STOFFEL_CERT and STOFFEL_KEY` |
| `:60-72` | `STOFFEL_WAIT_FOR_CLIENTS requires STOFFEL_EXPECTED_CLIENTS …` | deleted; both variables are refused by name |
| `:78-83` | `STOFFEL_COORD_ADDR` without `STOFFEL_EXECUTION_ID` refused | unchanged, and `STOFFEL_COORD_ADDR` without `STOFFEL_COORD_CERT` refused beside it |
| `:85-94` | "`STOFFEL_PEERS` requires `STOFFEL_NODE_ROSTER`" | "`STOFFEL_PEERS` requires `STOFFEL_COORD_ADDR` and `STOFFEL_COORD_CERT`" |
| `:112` banner | `Client Index` | `Client Slot` |
| `:118-123`, `:128` banner (`N Parties` at `:122`) | `N Parties`, `Threshold`, `Expected Clients`, `Node Roster`, `Preproc Store` | no longer printed; `Coordinator Cert` is |
| `:389-392` | emits `--cert`/`--key` when there is no coordinator | deleted: a party without `STOFFEL_COORD_ADDR` is refused before this point, and the coordinator branch (`:333-343`) already emits both |

#### D.4 `Roster` becomes nodes only

`crates/stoffel-vm/src/net/mesh/roster.rs`, as it stands after V-c (during V-a and V-b the
legacy `clients` field and its API sit beside it, §9.1):

```rust
pub struct Roster { nodes: Vec<NodePublicKey>, n: usize, t: usize, digest: [u8; 32] }

impl Roster {
    /// Sorts, then refuses, in this order: an empty set (`Empty`), compact-id collisions
    /// (`DuplicateNode`), `t == 0` (`ZeroThreshold`) and `n < 2t + 1`
    /// (`ThresholdTooLarge`); computes the §9.B digest from the key bytes. That is §9.B
    /// exactly, because §9.B digests SPKIs, not certificate bytes — so a roster built from
    /// keys needs no certificate.
    pub fn from_node_keys(keys: Vec<NodePublicKey>, threshold: usize) -> Result<Self, RosterError>;
    /// Derives every key with QuicNetworkManager::public_key_from_certificate_der (B2) —
    /// a certificate it cannot derive is `ServedCertificateUnderivable { index, reason }` —
    /// calls `from_node_keys`, and refuses a served digest that differs
    /// (`DigestMismatch { served, computed }`).
    pub fn from_coordinator(certificates: &[&[u8]], threshold: u64, served_digest: [u8; 32])
        -> Result<Self, RosterError>;
    pub fn nodes(&self) -> &[NodePublicKey];
    pub fn n(&self) -> usize;
    pub fn t(&self) -> usize;
    pub fn digest(&self) -> [u8; 32];
    pub fn index_of(&self, key: &NodePublicKey) -> Option<PartyId>;
    pub fn key_of(&self, rank: PartyId) -> Option<&NodePublicKey>;
    /// install_expected_server_public_keys(nodes), then the B3 read-back. Nothing else.
    pub fn install_into(&self, net: &mut QuicNetworkManager) -> Result<(), RosterError>;
}
```

- **The bounds are the coordinator's.** Today the VM refuses only `threshold >= n`
  (`roster.rs:165`), and nothing refuses `t = 0` — with `t = 0`, `min_shares` is 1 and
  every single node can reconstruct every client mask. `from_node_keys` refuses both
  exactly as `NodeRoster::new` does, so a drifted or forged served roster is checked no
  more weakly here than there. The comment that justified `t < n` alone cites "the shipped
  two-party NAT stack runs `n=2, t=1`" (`roster.rs:161-166`); §4 deleted that stack. The
  VM does not repeat §A's canonical-encoding check: every certificate reaches
  `from_coordinator` only after `NodeRoster::try_from` ran it (§D.1 step 3), so its key
  bytes are already the one encoding of that key.
- **Error variants, by stage.** The legacy constructors keep their variants until they are
  deleted, and the new ones cannot share their names, so V-a *adds* four variants and V-c
  *removes* the legacy ones:

  | `RosterError` variant | V-a | V-c |
  |---|---|---|
  | `ZeroThreshold` | added, raised by `from_node_keys` | kept |
  | `ThresholdTooLarge { n, threshold }` (`n < 2t + 1`) | added, raised by `from_node_keys` | kept |
  | `DigestMismatch { served, computed }` | added, raised by `from_coordinator` | kept |
  | `ServedCertificateUnderivable { index, reason }` | added, raised by `from_coordinator` | kept |
  | `ThresholdOutOfRange { n, threshold }` (`t >= n`, `:96`) | unchanged, raised by `Roster::new` | removed |
  | `CertUnreadable { path, reason }`, `CertUnderivable { path, reason }` (`:79`, `:82`) | unchanged, raised by `from_cert_paths` | removed: file I/O moves to the runner's `--cert` and `--coord-cert` handling |
  | `AllowlistDisabled { nodes, clients }` (`:109`) | unchanged; `install_into` (`:302`) and `install_for_client` (`:342`) build it, with `clients: 0` for a node-only roster | becomes `AllowlistDisabled { nodes }` |
  | `Empty`, `DuplicateNode { compact_id }`, `InstallRejected { reason }` | unchanged | kept |

- **The `clients` field is removed** (in V-c, §9.1), with `clients()`, `admits_client`,
  `install_for_client` (`:333-349`), `from_cert_paths` (`:184-202`), the three-argument
  `Roster::new`, and `install_into`'s client loop (`:293-295`).
- `ROSTER_DIGEST_CONTEXT` (`:72`) becomes `"stoffel-coordinator-node-roster-v1"` for
  rosters built by `from_node_keys`, whose `digest()` implements §B. `stoffel-vm` does not
  depend on the coordinator crates, so it takes certificates as bytes and implements the
  digest itself; the shared golden vector keeps the two implementations equal, and step 5
  of D.1 keeps a drifted one from being installed.
- **Callers that move to `from_node_keys` in V-a** are exactly those that build a
  node-only roster; each keeps its assertions. Some use synthetic key bytes no certificate
  could carry, which is why the key-based constructor exists:
  - `roster.rs` tests `an_empty_node_roster_is_refused_before_the_transport_is_touched`
    (`:493`), `a_repeated_node_certificate_is_refused_rather_than_shrinking_the_mesh`
    (`:501`; `DuplicateNode` is checked before either threshold rule, so its two-entry
    roster still fails as it does today), `index_of_follows_the_lexicographic_spki_order_the_transport_uses`
    (`:535`, four identities) and `a_node_outside_its_own_roster_cannot_install_it`
    (`:1003`, three identities);
  - `roster.rs` `an_installed_roster_admits_a_member_and_refuses_an_outsider` (`:609`)
    builds its roster from **three** identities instead of two — a two-node roster no
    longer exists — and still dials only `identities[0]` and `identities[1]`;
  - `join.rs:1520` (`roster_of`, keys `vec![tag; 32]`); `avss_server.rs:1060-1068` (keys
    `vec![1u8; 32]`, three nodes, `t = 1`); `mesh_join_harness.rs:474`, `:1152`, `:1457`,
    `:1568`, `:1729`; `stoffel-run.rs:5820` (binary tests);
  - two of those change shape for the same reason: the tournament tests
    `the_mesh_dial_partition_is_a_tournament` and
    `discovery_only_ever_dials_its_half_of_the_tournament` (`join.rs:1533`, `:1592`) iterate
    sizes `3..=8` instead of `2..=8`, and the harness tests at `mesh_join_harness.rs:1561` and
    `:1722` (`a_party_proposing_a_different_session_is_refused_by_name`,
    `a_party_proposing_a_wildly_advanced_epoch_is_refused`) run three identities instead of
    two, the third being the divergent one.
- **Tests that stay on the legacy API until V-c,** because what they test exists until then,
  and are retargeted there (§H): `a_threshold_at_or_above_the_party_count_is_refused`
  (`:517`, which also asserts `n = 2, t = 1` is accepted),
  `the_digest_ignores_input_order_but_not_membership_or_parameters` (`:551`, which builds
  rosters with clients), the client-set tests
  `a_roster_admits_its_clients_alongside_its_nodes` (`:582`),
  `a_roster_pinned_node_admits_its_clients_and_refuses_an_unlisted_one` (`:666`),
  `a_roster_pinned_node_refuses_a_client_that_brings_no_certificate` (`:723`),
  `a_client_pinned_to_the_roster_refuses_a_node_outside_it` (`:778`),
  `a_listed_client_still_exchanges_bytes_through_an_allowlisted_node` (`:849`) and
  `a_clone_taken_before_the_install_still_enforces_the_roster_for_clients` (`:923`), and the
  file tests `a_missing_certificate_file_names_itself` (`:1025`) and
  `a_file_that_is_not_a_certificate_names_itself` (`:1038`). V-a adds the new tests of §H
  for `from_node_keys` and `from_coordinator` beside them.
  `adding_a_client_before_the_nodes_freezes_the_node_install_out` (`:984`) calls no `Roster`
  API — it pins stoffelnet's refusal of a roster install over a non-empty allowlist
  (`quic.rs:1310-1321`) — and stays through V-c; only its doc comment, which explains the
  order of `install_into`'s client loop, is rewritten to say it is one more reason no
  non-node key may enter the allowlist.
- **No client `--min-threshold`.** The review suggested one as an option; it is not
  added. Against a malicious coordinator it guards nothing: that coordinator can serve a
  roster of its own keys at any `t` (§G), and a client that knows what it expects pins the
  whole roster, `t` included, with `--expect-roster-digest`. Against an honest but
  misconfigured coordinator, `ZeroThreshold`, `n >= 2t + 1` and the backend's
  `min_parties` (§C.7) already refuse the degenerate rosters.

#### D.5 Session namespace

- **`derive_instance_id` takes the roster digest.** New signature
  `derive_instance_id(roster_digest: &[u8; 32], program_id: &[u8; 32], epoch: u64) -> u64`
  in `crates/stoffel-vm/src/net/session.rs`, replacing `:23-32` (re-exported from
  `net/mod.rs:187`, so a published-API change, §7):
  `blake3::Hasher::new_derive_key("stoffel-session-instance-v2")`, then `update(roster_digest)`,
  `update(program_id)`, `update(&epoch.to_le_bytes())`, and the first 8 bytes of the hash
  read little-endian. The epoch counter is kept per roster digest (`epoch.rs:227-261`), so
  it is only fresh *within* one digest, and the namespace has to say which digest.
  Without it, (a) this release's digest change restarts every store at epoch 1 and
  re-issues, for the same program, the instance ids the old digest issued at epoch 1 —
  B5's reuse through the back door, on every upgraded node — and (b) two rosters that
  share a node reuse ids for the same program and epoch. In V-a the legacy path calls it
  with its legacy digest, so a legacy run's instance ids change value and stay fresh per
  epoch; nothing else about that path changes.
- **The join agrees on the execution.** `ExecutionId` is a coordinator type and
  `stoffel-vm` has no coordinator dependency, so the mesh carries it as its own newtype:

  ```rust
  // crates/stoffel-vm/src/net/session.rs
  /// The coordinator's `ExecutionId`, as the bytes the mesh agrees on. `stoffel-vm-runner`
  /// converts with `SessionExecutionId::from_bytes(*execution_id.as_bytes())`.
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
  #[serde(transparent)]
  pub struct SessionExecutionId([u8; 32]);

  impl SessionExecutionId {
      /// All zeros: what a coordinator-less run carries until V-c deletes that path (§9.1).
      pub const UNUSED: Self = Self([0u8; 32]);
      pub const fn from_bytes(bytes: [u8; 32]) -> Self;
      pub const fn as_bytes(&self) -> &[u8; 32];
  }
  ```

  `JoinRequest` (`net/mesh/mod.rs:258-274`) gains `pub execution_id: SessionExecutionId`,
  and `MeshMessage::JoinProposal` (`wire.rs:167`) gains `execution_id: SessionExecutionId`.
  Its construction sites — `rg 'JoinRequest \{' crates` finds five, not the six the
  review counted — are `net/mesh/mod.rs:325` (unit test), `tests/mesh_join_harness.rs:525`,
  `:1606`, `:1784`, and `stoffel-vm-runner/src/bin/stoffel-run.rs:4736`.
  `session_digest` (`join.rs:168-185`) gains an `execution_id` parameter after
  `roster_digest` and hashes its 32 bytes immediately after the roster digest (fixed
  width, so no length prefix), with `SESSION_DIGEST_CONTEXT` (`:134`) bumped to
  `"stoffel-mesh-session-v2"`. `SessionField` (`:142-148`) gains `ExecutionId`, displayed
  as `execution id` and compared right after `RosterDigest`, so a divergence is
  `MeshError::SessionDivergence { field: SessionField::ExecutionId }`. Every party now
  carries `--execution-id`, and a party joined under a different one would pass the join
  and then wait forever on rounds of an execution no other party is in.
- **Documentation this makes wrong, rewritten in V-a with the code:**
  `crates/stoffel-vm/src/net/mesh/epoch.rs:15-20`, which says `derive_instance_id` "is not
  touched" and spells the session id as `blake3(b"stoffel-session-v1" || program_id ||
  nonce)`; the `SESSION_DIGEST_CONTEXT` doc at `crates/stoffel-vm/src/net/mesh/join.rs:128-133`,
  which lists the domain contexts it is separated from — `stoffel-mesh-roster-digest-v1`,
  `stoffel-program-v1`, `stoffel-session-v1` — and must name
  `stoffel-coordinator-node-roster-v1` and `stoffel-session-instance-v2` beside the legacy
  roster context until V-c; and the module and function docs of
  `crates/stoffel-vm/src/net/session.rs:1-21`, which describe the one-argument-nonce
  derivation.
- **The `n == 1` join branches go in V-c.** `discover_peers` returns early for `n == 1`
  (`join.rs:559-561`) and the agreement short-circuits it (`:1098-1112`, calling
  `derive_instance_id` with no peers). A legacy `Roster::new` can still build a one-node
  roster (`t = 0 < 1`), so both stay reachable through V-b; once V-c deletes the legacy
  constructors every roster has `t >= 1` and `n >= 2t + 1 >= 3`, and both branches are
  deleted rather than kept as dead code. No test exercises them (`rg 'generate_identities\(1\)'`
  finds only a transport test that builds no roster, `mesh_join_harness.rs:756`).

#### D.6 Agreement barriers: admissions and masked inputs

Revision 0 reused `MeshBarrier` for a frame with a body, and that cannot work.
`BarrierTag::classify` accepts only frames of exactly `prefix + 8` bytes
(`crates/stoffel-vm/src/net/mesh/barrier.rs:153-166`), so a frame carrying a digest never
classifies; `MeshBarrier::record` consumes a same-tag frame from another namespace without
error (`:293-296`), so a divergent value could only ever time out; and nothing stored what
each peer announced, although a peer's frame can arrive before this node has computed its
own digest. A separate type:

```rust
// crates/stoffel-vm/src/net/mesh/barrier.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestBarrierTag {
    /// The frozen admission set and the summary it was provisioned from (§9.C.7).
    AdmissionsAgreed,
    /// The masked inputs the coordinator delivered (§9.C.7).
    InputsAgreed,
}

impl DigestBarrierTag {
    pub const ALL: [Self; 2] = [Self::AdmissionsAgreed, Self::InputsAgreed];
    pub fn prefix(self) -> &'static [u8];
    /// `prefix || namespace (u64 LE) || digest (32 bytes)` at exactly that length, else `None`.
    pub fn classify(payload: &[u8]) -> Option<(Self, u64, [u8; 32])>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Announced { Digest([u8; 32]), Conflicting }

#[derive(Debug)]
pub struct DigestBarrier {
    tag: DigestBarrierTag,
    namespace: u64,
    n: usize,
    local: PartyId,
    /// A peer's first digest, or `Conflicting` once it has announced two different ones.
    announced: DashMap<PartyId, Announced>,
    wakeups_tx: mpsc::UnboundedSender<()>,
    wakeups_rx: Mutex<mpsc::UnboundedReceiver<()>>,
}

impl DigestBarrier {
    pub fn new(tag: DigestBarrierTag, namespace: u64, n: usize, local: PartyId) -> Self;
    /// Receive-loop half. `true` for any frame of this tag (the loop drops it); a frame in
    /// this namespace is stored whether or not `wait` has started.
    pub fn record(&self, sender: PartyId, payload: &[u8]) -> bool;
    /// Announces `own` to every peer, then waits for every peer's announcement. The first
    /// peer that announced a different digest, or two digests, fails the wait with the
    /// tag's divergence error naming it.
    pub async fn wait<T: BarrierTransport + ?Sized>(&self, net: &T, own: [u8; 32],
        timeout: Duration) -> MeshResult<()>;
}
```

- **Frame.** `ADMISSIONS_AGREED_PREFIX = b"STOFFEL_ADMISSIONS_AGREED_V1"` and
  `INPUTS_AGREED_PREFIX = b"STOFFEL_INPUTS_AGREED_V1"`, followed by `instance_id (u64 LE)`
  and the 32-byte digest. They are the only barrier frames with a body: every other
  namespace is not chosen by an adversary, but these values are computed from data the
  coordinator chooses, and a 64-bit value an adversary can steer falls to a 2^32 birthday
  search. `ReservedPrefix` (`wire.rs:101`) gains `AdmissionsAgreedBarrier` and
  `InputsAgreedBarrier`, so `ReservedPrefix::ALL` becomes `[Self; 10]` (`:122`) and the B7
  disjointness test (`every_reserved_prefix_is_disjoint_from_every_other`, `:323`) covers
  both. `BarrierTag::ALL` (`barrier.rs:137`) is unchanged.
- **Errors.** `MeshError::AdmissionDivergence { party_id }`,
  `MeshError::InputDivergence { party_id }`,
  `MeshError::DigestBarrierUnannounceable { tag: DigestBarrierTag, party_id, reason }` and
  `MeshError::DigestBarrierIncomplete { tag: DigestBarrierTag, reached, expected, waited }`.
  A node exits 13 on any of them (D.3).
- **Wiring.** Both barriers are created as soon as the join has returned the
  `instance_id` — **before** `setup_hb_party_for_curve` and `setup_avss_party_for_curve`
  spawn their receive loops — and both setups take them (a `DigestBarriers { admissions,
  inputs }` field on `HbPartySetup` and `AvssPartySetup`). The HoneyBadger processing loop
  offers every frame to them beside its preprocessing barrier (`stoffel-run.rs:2767`). The
  AVSS per-peer loop, which today offers frames to the mesh router and nothing else before
  the engine (`:3251`), offers every frame to them right after the router, so an agreement
  frame never reaches the AVSS engine as a protocol message.
- **Admission digest**, `admission_agreement_digest(summary: &ExecutionSummary, set:
  &ClientAdmissionSet) -> [u8; 32]` in `crates/stoffel-vm-runner/src/admissions.rs` (new;
  the barrier carries the digest as opaque bytes). All integers little-endian:

  ```text
  hasher = blake3::Hasher::new_derive_key("stoffel-admission-agreement-v1")
  update( execution_id )                                        32 bytes
  update( registration_nonce )                                  32 bytes
  update( program_hash )                                        32 bytes
  update( policy tag as u8 )     0 PreRegistered, 1 Open, 2 Invitation
      Invitation only: update( issuer_spki.len() as u64 ), update( issuer_spki )
  deadlines:     update( 0x00 )  or  update( 0x01 ), update( association as u64 ), update( input as u64 )
  update( client_slots.len() as u64 )
      per slot: update( input_count as u64 ), update( output_count as u64 )
  update( records.len() as u64 )
      per record, ascending client_index:
          update( client_index as u32 )
          update( client.len() as u64 ), update( client )
          input_range:   update( 0x00 )  or  update( 0x01 ), update( start as u64 ), update( count as u64 )
          output_rights: update( 0x00 )  or  update( 0x01 ), update( output_count as u64 )
  ```

  It covers the `ExecutionSummary` each node provisioned its masks from (all of it but
  `round`) as well as the admission set, so a coordinator that served different slot
  tables, nonces or policies to nodes of one mesh is caught here too.
- **Input digest**, `inputs_agreement_digest(execution_id: ExecutionId, submissions:
  &[MaskedInputSubmission]) -> [u8; 32]`, same file, over the submissions exactly as
  delivered — signatures included — before any node applies its own mask share. The
  layout changed from revision 1's per-record form, which was never implemented, so the
  context keeps its name:

  ```text
  hasher = blake3::Hasher::new_derive_key("stoffel-inputs-agreement-v1")
  update( execution_id )                                        32 bytes
  update( submissions.len() as u64 )
      per submission, ascending first_index:
          update( first_index as u64 )
          update( client.len() as u64 ), update( client )
          update( masked_inputs.len() as u64 )
              per masked input: update( len as u64 ), update( bytes )
          update( signature.len() as u64 ), update( signature )
  ```

- **When.** `AdmissionsAgreed` immediately after `get_client_admissions`, before the node
  registers any reservation with its RPC listener, stores any client input or seals any
  output share (D.7 step 6). `InputsAgreed` immediately after the submissions arrive and
  pass their checks, before any is unmasked or stored (D.7 step 9). Both run over the
  mesh, so they detect equivocation between nodes that share a roster and a mesh — not
  between nodes the coordinator partitioned into different rosters (§G).

#### D.7 Client inputs and outputs on a node

Both coordinated paths — HoneyBadger (`stoffel-run.rs:5065-5360`) and AVSS
(`run_avss_coordinated_party_for_curve`, `:3464`) — run this order. What moves is the
reservation registration: today it runs between steps 4 and 5.

1. **The summary, before any preprocessing.** Right after `from_link` (D.1 step 10) — before
   `start_preprocessing` (HoneyBadger `:5162`, AVSS `:3521`) and before
   `setup_*_party_for_curve` — `get_execution_summary`, then
   `check_execution_summary(&summary, &expectations) -> Result<(), SummaryMismatch>`
   (`admissions.rs`), where the expectations are this node's program id, program manifest,
   backend and the roster's `n` and `t`:
   - `summary.client_slots.check_bounds()` passes;
   - `summary.program_hash == program_id_from_bytes(loaded program)` — the one hash both
     sides use (§C.1);
   - `n >= S::min_parties(t)`: `3t + 1` for HoneyBadger, `2t + 1` for AVSS (§C.7);
     `SummaryMismatch::TopologyUnsupported { backend, n, t, required }`. A HoneyBadger node
     would refuse the roster at engine setup anyway (`validate_honeybadger_topology`,
     `crates/stoffel-vm/src/net/mpc/helpers.rs:112-123`); checking it here refuses before
     the node proposes anything, with the D.3 message;
   - for every slot with `output_count > 0`, `8 + output_count × S::serialized_share_len(t)
     + 16 <= MAX_SEALED_OUTPUT_BYTES` (§C.1), or
     `SummaryMismatch::SealedOutputsTooLarge { client_index, bytes, max }`: such a slot's
     outputs could never be delivered, so the node refuses before running the program;
   - for every slot that both the registration and the program's `ClientIoManifest`
     declare, the registered `input_count` equals the declared input count and the
     registered `output_count` is at least the declared output count. A manifest slot the
     registration lacks is not an error: a program may use clients only when
     `ClientStore.get_number_clients()` is non-zero (§F.1).

   A mismatch exits 13 (D.3). `mask_count = summary.client_slots.n_inputs()` sizes
   preprocessing: it replaces `HbPartySetup`'s `expected_client_count`,
   `coordinator_client_count_hint` and `client_input_count` (`:2523-2525`, set at
   `:5215-5217`) and `AvssPartySetup`'s `expected_client_count` and `client_input_count`
   (`:2967-2968`, passed as `None` and `1` at `:3528-3540`); `plan_preprocessing` receives
   `n_client_random = mask_count` (today `:2655-2656`). Read after setup, as revision 0 had
   it, the count would come from the flags §D.2 removes.
2. Take `mask_count` random shares from the pool — which holds no item any store still
   holds unconsumed (§C.9 part 4) — and provision them at indices `0..mask_count` with
   `add_mask_shares_for_execution` (C.9). The AVSS path takes `mask_count` random shares,
   not one per expected client (`:3553-3571`).
3. Propose `InputMaskReservation`; `wait_for_round`.
4. `wait_for_indices(mask_count)`: the complete reservation map. It is **not** registered yet.
5. Propose `InputCollection`; `wait_for_round`. The coordinator holds the round until every
   slot is bound (C.8).
6. `get_client_admissions`, then the `AdmissionsAgreed` barrier over
   `admission_agreement_digest(&summary, &set)` (D.6).
7. `reservations_matching_admissions(&set, &reserved) -> Result<Vec<AssignedMaskReservation>,
   ReservationMismatch>`: every identity's reserved indices must be exactly its agreed
   `input_range`, every agreed range must be reserved, and each reservation's
   `input_ordinal` is `reserved_index - input_range.start` (`wait_for_indices` returns only
   identities and indices, `coord:off-chain/src/lib.rs:2759-2762`). On success,
   `register_admitted_reservations_for_execution` — which is what releases the mask shares,
   seals the execution's reservations (§C.10), and is the only reservation registration a
   node makes: V-b deletes both calls of the
   unassigned `add_reserved_index_for_execution` (HoneyBadger `stoffel-run.rs:5331-5345`,
   AVSS `:3590-3606`), and `0.3.0` deletes the method (§C.10). On failure, exit 13 (D.3).
8. `wait_for_masked_input_submissions(mask_count)` (§C.7).
9. `submissions_matching_admissions(&summary, &set, &submissions) -> Result<(),
   MaskedInputMismatch>` (`admissions.rs`): the submissions' ranges
   `[first_index, first_index + masked_inputs.len())` must partition `0..mask_count`; each
   must be exactly the agreed `input_range` of one slot, and its `client` that slot's agreed
   identity; and its signature must verify —
   `verify_identity_signature(&record.client, &masked_inputs_signing_bytes(execution_id,
   summary.registration_nonce, record.client_index, first_index, &masked_inputs), &signature)`
   (§C.7) — against the **agreed** identity and nonce, never the coordinator's say-so.
   `MaskedInputMismatch` is `MissingSubmission { client_index }`,
   `RangeMismatch { client_index }`, `UnexpectedClient { client_index }` or
   `BadSignature { client_index }`; any of them exits 13 (D.3). Then the `InputsAgreed`
   barrier over `inputs_agreement_digest(execution_id, &submissions)` (D.6).
10. `unmask_submissions(&submissions, &mask_shares)`; group the shares by agreed
    `ClientIndex` in `input_ordinal` order; store each slot with
    `vm.try_store_client_input_with_types(client_index, shares, types)` when the manifest
    declares types for that slot (`client_input_types`, as `stoffel-run.rs:552-556` does
    today) and `vm.try_store_client_input(client_index, shares)` otherwise — the AVSS path
    the Feldman variants, as `store_reserved_client_inputs_feldman` (`:567`) does; set the
    VM client roster to `0..capacity()`.
11. Propose `MPCExecution`; run the program.
12. **Outputs come only from `send_to_client`, and every run reaches `ProgramFinished`.**
    The HoneyBadger party's broadcast of the program's returned share to every output
    client (`coordinator_output_share_bytes`, `:1109`, pushed onto every client's list at
    `:5538-5559` before the captured records) is **deleted**. Kept, it would make every
    output client receive one share more than its admission's `output_count`, and
    `obtain_outputs` ignores a node whose share count differs (§C.7), so the client would
    never reconstruct; counting it into `output_count` instead would tie a static
    registration to whether the entry function happens to return a share. It gave clients
    nothing the parties do not already open: a coordinated party reveals and prints a
    returned share (`print_vm_result`, `:5604`, `:967-996`). Then, on both backends:
    - **The registration has no output slots.** The node proposes `finalize` straight from
      `MPCExecution` — the skip §C.8 precondition 4 allows exactly then — and
      `wait_for_round(ProgramFinished)`. Today both paths call `send_output`/`finalize`
      only when there is something to send (HoneyBadger `stoffel-run.rs:5548`, AVSS
      `:3640`), so an execution without outputs — the AES circuit and `avss_keygen`, the
      default programs of the main and AVSS stacks, and the `client_mul` recipe — never
      reached `ProgramFinished`, step 13 never retired it, and a one-off coordinator never
      drained.
    - **The registration has output slots.** For every slot the captured records name, the
      slot must have `OutputRights::Receive { output_count }` and the program must have
      sent it exactly `output_count` shares, or the node exits 4 (D.3). A slot with output
      rights the program sends nothing to is not a node error; its client's
      `obtain_outputs` ends when the execution is removed (C.10). Then `send_output`,
      `wait_for_round(OutputDistribution)`, for each slot with captured shares
      `send_output_shares` — sealed, and signed with this node's position and the agreed
      nonce (§C.7) — then `finalize` and `wait_for_round(ProgramFinished)`. With output
      slots and no captured record at all the node still goes through
      `OutputDistribution`, sending nothing: precondition 4 refuses the skip.

    Dependents: `crates/stoffel-lang/examples/mpc_share_arithmetic/main.stfl` is the
    default program of `crates/stoffel-lang/examples/docker-compose.coordinator.yml`, whose
    `run_coordinator_compose.sh` asserts the client log line `outputs: [315]`
    (`:21`, `:117`). Its header comment (`:3-4`) says client 0 "receives the product
    through coordinator output distribution", but its client branch (`:13-15`) sends
    nothing: that product only ever reached the client through the broadcast this step
    deletes. Revision 1 described the edit below as if it existed. V-b **makes** it — in the
    client branch, after `product = client_left.mul(right)`:

    ```text
    MpcOutput.send_to_client(0, [product])
    ```

    which the compiler records in the manifest as one output for slot 0
    (`crates/stoffel-lang/tests/rust/compiler_phase_tests.rs:3011`, the same form), so the
    stack's `--client-io 1:1,1:0` matches it (§F.1). The branch runs only when
    `ClientStore.get_number_clients()` is non-zero, so `docker-compose.mpc.yml`, which
    runs the same program with no client, is unaffected. `client_sub_order`, the
    reserve-index stacks' program, returns `client[0] - client[1]` and sends nothing either
    (`crates/stoffel-vm-types/examples/generate_client_sub_order_program.rs:17-34`, no
    manifest at `:46`); its stacks register input-only slots instead and assert the
    parties' revealed value (§F.1, §F.2). The `client_mul` recipe (§F.1) stops expecting a
    client output. No local-runner or SDK test depends on the broadcast: every coordinator
    run in `crates/stoffel-vm-runner/tests/local_coordinator_e2e.rs` returns a clear value
    (`:121`, `:155`, `:189`, `:269`), and both coordinator examples `validate_examples.sh`
    runs (`mpc_client_private_score`, `mpc_client_federated_average`) deliver through
    `send_to_client`.
13. **Retire.** After `ProgramFinished`, `retire_execution` — best effort: a failure is
    logged, not fatal. A node acknowledges only a terminal round it has observed, which is
    what §C.10's drain gate relies on.

An execution with no inputs skips steps 2–5 and 7–10 and proposes `MPCExecution` straight
after preprocessing; its set freezes when `MPCExecution` begins (C.7), so the node runs
step 6 after that `wait_for_round` and before it runs the program.

**Abort.** Any coordinator call or wait that ends in `CoordinatorError::ExecutionAborted` —
a proposal answered with code 35, a subscription refused with it, or a wait that receives
`Event::ExecutionAborted` — makes the node `retire_execution` (best effort), retire the
execution on its RPC listener — which drops every mask share it provisioned
(`NodeRPCServer::retire_execution`, `coord:off-chain/src/lib.rs:376-378`) — and exit 13
(D.3). Nothing about the aborted execution's preprocessing needs recording: no store ever
held its items unconsumed (§C.9 part 4).

**Signatures.** The link opened at §D.1 step 2 is moved into the coordinated party; no
coordinated path connects to the coordinator itself any more, and none takes `n`, `t` or a
client list as an argument:

```rust
/// Everything a coordinated party needs, gathered once after the join.
struct CoordinatedParty<'a> {
    vm: &'a mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    instance_id: u64,
    link: CoordinatorLink,            // n and t: link.node_roster()
    execution_id: ExecutionId,
    rpc_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    agreed_entry: &'a str,
    mesh_router: Arc<MeshRouter>,
    barriers: DigestBarriers,          // §D.6
}

async fn run_hb_coordinated_party_for_field<F: SupportedMpcField>(party: CoordinatedParty<'_>)
    -> Result<(), CoordinatedRunError>;
async fn run_avss_coordinated_party(curve_config: MpcCurveConfig, party: CoordinatedParty<'_>)
    -> Result<(), CoordinatedRunError>;
async fn run_avss_coordinated_party_for_curve<F, G>(party: CoordinatedParty<'_>)
    -> Result<(), CoordinatedRunError>;

#[derive(Debug, thiserror::Error)]
enum CoordinatedRunError {
    #[error(transparent)] Coordinator(#[from] CoordinatorError),
    #[error(transparent)] Summary(#[from] SummaryMismatch),
    #[error(transparent)] Reservation(#[from] ReservationMismatch),
    #[error(transparent)] MaskedInput(#[from] MaskedInputMismatch),
    #[error(transparent)] Agreement(#[from] MeshError),
    #[error("Execution error in '{entry}': {source}")]
    Execution { entry: String, source: VirtualMachineError },
    #[error("Execution error in '{entry}': {violation}")]
    OutputRights { entry: String, violation: OutputRightsViolation },
}

impl CoordinatedRunError {
    /// 4 for `Execution` and `OutputRights`, 13 for everything else (D.3).
    fn exit_code(&self) -> i32;
}
```

`run_avss_coordinated_party_for_curve` today takes `coord_addr`, `n`, `t` and
`expected_clients` and connects with `start_rpc_client_for_execution` itself
(`stoffel-run.rs:3464-3501`), and its dispatcher `run_avss_coordinated_party` (`:3668`)
forwards them; the HoneyBadger party connects inline, after the join, through a
BLS12-381-only `coord_opt` (`:5073-5089`). All three lose those parameters. The AVSS
path also maps a VM execution error to a `String` (`:3638`) that its caller turns into
exit 13 (`:5436-5437`), where D.3 requires exit 4 for `Execution error in …`; with
`CoordinatedRunError::exit_code` both backends exit 4 for an execution or output-rights
error and 13 for the rest. `OutputRightsViolation` is `NoOutputRights { client_index }` or
`CountMismatch { client_index, sent, admitted }`, the two exit-4 messages of D.3.

The HoneyBadger coordinated party becomes generic over `SupportedMpcField` in the same
change — today it is `HbOffChainCoordinator<ark_bls12_381::Fr>` (`:5075`) behind a
BLS12-381-only branch (`:5200`). HoneyBadger client IO over bn254, curve25519 and ed25519
exists today only through direct clients, which §E.3 retires; the client half
(`run_hb_coordinator_client_for_field<F>`, `:2278`) is already generic.

### E. VM client behavior

#### E.1 The flow — the only one there is

Every client surface does this, in this order:

1. **Pinned coordinator, roster once.** `CoordinatorLink::connect` with `--coord-cert` and
   `--expect-roster-digest`; the served `NodeRoster` gives `n` and `t`, compared with
   `--expect-n-parties` / `--expect-threshold` when given. Failures exit as in §D.3. The
   link is never re-established: a transport failure on it exits 13.
2. **Know what you are joining, before associating** — an association is irrevocable
   (C.9). `get_execution_summary`, then:
   - `client_slots.check_bounds()` fails → exit 13:
     `Error: execution {id} has a client slot table this client refuses: {reason}`
   - the round is `Aborted` → exit 13:
     `Error: execution {id} was aborted by the coordinator: {reason}`
   - `--expect-program-hash <64-hex>` was given and differs → exit 2:
     `Error: execution {id} runs program {served}, not the --expect-program-hash {expected}; refusing to associate.`
   - the roster is too small for this client's backend (`n < S::min_parties(t)`, §C.7) →
     `OffChainCoordinatorClient::associate_client`, which reads the summary itself, refuses
     before sending the association, as
     `CoordinatorError::TopologyUnsupportedByBackend { n, t, required }`; exit 2:
     `Error: {backend} needs at least {required} nodes for threshold {t}, and the coordinator's roster has {n}; refusing to associate.`
   - a slot's outputs cannot be delivered under this backend (`8 + output_count ×
     S::serialized_share_len(t) + 16 > MAX_SEALED_OUTPUT_BYTES`, §C.1) → likewise refused
     before sending, as `CoordinatorError::SealedOutputsExceedBound { client_index, bytes,
     max }`; exit 2:
     `Error: execution {id} gives client slot {i} {k} outputs, {bytes} bytes sealed under {backend}, above the {max}-byte bound; refusing to associate.`
     Every slot is checked, not only the one this client will get: which slot that is is
     not settled until association.
   - **the slot's shape.** When the slot is known before associating — `--client-slot`
     given, or the invitation names one, as every invitation now does (§C.3) — its
     `input_count` must equal the number of `--inputs`. Under `Open` with no
     `--client-slot`, every slot must have one shape, and its `input_count` must equal the
     number of `--inputs`; otherwise exit 2:
     `Error: execution {id} has client slots of different shapes; pass --client-slot <index>.`
     Under `PreRegistered` the slot was bound at registration, association binds nothing
     new, and the count is checked right after step 3. A client that also checks input and
     output types (the SDK) checks them here against every slot the association can bind,
     not just some slot (`BindableSlots`, §E.2).
3. **Associate.** `associate_client(AssociationRequest { slot: --client-slot,
   invitation: --invitation })` → `ClientAdmission`, stored on the client. A count mismatch
   exits 2: `Error: client slot {i} takes {count} inputs, but --inputs has {m}.`
4. `wait_for_round(InputMaskReservation)`; `reserve_mask_indices(start..start + count)`.
5. **Pinned node legs.** `NodeRPCClient::start_rpc_client_for_execution(&roster, --servers,
   execution_id, cert, key)`: every leg pinned to a distinct roster member, and every leg's
   shares attributed to that member's roster position (§A).
6. `receive_assigned_masks(start, count)` — it returns once the nodes release the masks,
   which is after `InputCollection` has begun (C.7), and once every mask reconstructs by
   position; a wrong, relabelled or unverifiable share is excluded rather than believed
   (§A, §C.7) — then `wait_for_round(InputCollection)` (answered from replay) and
   `send_masked_inputs`, which submits the whole range in one call signed with the client's
   certificate key (§C.7).
7. With `OutputRights::Receive { output_count }`: `wait_for_round(OutputDistribution)`;
   `obtain_outputs()`, whose output count comes from the admission, which takes one sealed
   item per node, checks its node's signature against the roster, and reconstructs by
   position as items arrive (C.7).

A client whose admission has no `input_range` (an output-only slot) skips steps 4–6. Any
step that ends in `CoordinatorError::ExecutionAborted` exits 13 (D.3).

Step 5 **closes §7's "the client leg stays an open gap"** for coordinator-mediated clients.
That gap existed because the coordinator crate's node RPC client accepted any server
certificate; the roster pin is exactly the allowlist hook §7 said was missing. A client
that owns a `QuicNetworkManager` for some other purpose may pin nodes by calling
`add_allowed_certificate_public_key` for each roster SPKI — additive, with no local-key
precondition (`quic.rs:1452`) — but after §E.3 no shipped client owns one. The pin is only
as good as the served roster: a coordinator that serves a client a roster of its own keys
receives that client's input and can forge its outputs (§G), and `--expect-roster-digest`
is the client's defense when it knows the intended node set. Against a coordinator that
serves the true roster, steps 6 and 7 leave it nothing to alter: the submission is the
client's signature over its own inputs, and each output item is a roster node's signature
over its own ciphertext.

#### E.2 Surfaces

- **`stoffel-run --client`.** Required: `--off-chain-coord`, `--coord-cert`,
  `--execution-id`, `--cert`, `--key`, `--servers` (node RPC addresses: hints, pinned by the
  roster), `--inputs`; `--mpc-backend` and `--mpc-curve` choose the share type, as today.
  Optional: `--client-slot <u32>` (`STOFFEL_CLIENT_SLOT`), `--invitation <path>`
  (`STOFFEL_INVITATION`), `--expect-program-hash <64-hex>` (`STOFFEL_EXPECT_PROGRAM_HASH`),
  `--expect-roster-digest <64-hex>` (`STOFFEL_EXPECT_ROSTER_DIGEST`), `--expect-n-parties`
  and `--expect-threshold`. Revision 0 called the program flag `--program-hash`; it is
  `--expect-program-hash` beside
  `--expect-roster-digest`, since both only refuse. Removed, by name: `--client-index` —
  hint `The coordinator assigns each client's input range when it associates. Pass
  --client-slot <index> to ask for a specific slot.` — `--outputs` — hint `A client's
  output count comes from its admission.` — and `--roster`, `--n-parties`, `--threshold`
  and `--timestamp` as in D.3.
- **`local_runner.rs`.** `run_honeybadger_offchain_client` and `run_avss_offchain_client`
  become `run_offchain_client` (F.4), which follows E.1. `LocalClientIdentity::reserved_index_start`
  (`:883`) and `reserved_indices()` (`:892`) are deleted: the runner no longer chooses
  windows. The runner stops minting and emitting a timestamp (`:166-169`, `:196`,
  `:589-590`, `SpawnPartyContext.timestamp` at `:1378`).
- **SDK, `crates/stoffel-rust-sdk/src/client.rs` and `runtime.rs`.**
  - `OffChainClientConfig` (`client.rs:325`) loses `input_start_index`, `parties`,
    `threshold`, `output_count` and `timestamp` (`:335`, validated non-zero at `:371-375`
    for no reader), and gains `coordinator_cert_der: Vec<u8>`,
    `invitation: Option<SignedInvitation>`, `expected_program_hash: Option<[u8; 32]>` and
    `expected_roster_digest: Option<RosterDigest>`; `client_slot: u64` becomes
    `client_slot: Option<ClientIndex>` (`#[serde(default)]`, so absent means `None`).
    `validate` loses the checks that need `n` or `t` (`threshold == 0`, `parties >= 5`,
    `parties >= 4t + 1`, `:376-397`). What replaces them runs against the served roster:
    `OffChainCoordinatorClient::associate_client` refuses `n < S::min_parties(t)` before
    sending anything (E.1 step 2), and the SDK maps that `TopologyUnsupportedByBackend` to
    `Error::Unsupported`. That bound is the backend's own — `3t + 1` for HoneyBadger, the
    same one a HoneyBadger node enforces (`crates/stoffel-vm/src/net/mpc/helpers.rs:112-123`)
    — so an SDK client stops refusing `3t + 1 <= n < 4t + 1` rosters that every node
    accepts. The SDK's `4 * threshold + 1` policy stays where it describes something the SDK
    configures: `MpcConfig` (`crates/stoffel-rust-sdk/src/config.rs:220-250`) for local
    runs and servers. `validate` also loses the `output_count`/`output_types` comparison,
    which runs against the admission after association as `Error::Configuration`, and gains
    a check that `coordinator_cert_der` passes `SpkiDer::from_certificate_der`.
  - `OffChainClientConfigBuilder` (`client.rs:445`) loses the setters `input_start_index`
    (`:501`), `parties` (`:506`), `threshold` (`:511`), `timestamp` (`:491`) and
    `output_count` (`:574`), and
    `output_types` (`:587`) stops setting a count. It gains `coordinator_cert_der(Vec<u8>)`,
    `coordinator_cert_file(path)`, `invitation(SignedInvitation)`, `invitation_file(path)`
    (`serde_json`), `expected_program_hash([u8; 32])` and `expected_roster_digest(RosterDigest)`;
    `client_slot(ClientIndex)` (`:496`) sets `Some`.
  - `Runtime::offchain_client_config(client_slot: u64)` (`runtime.rs:141-165`) no longer
    derives `input_start_index` — the coordinator assigns ranges — and no longer calls
    `parties` or `threshold`. It sets `client_slot(ClientIndex(u32::try_from(client_slot)?))`,
    a slot beyond `u32` being `Error::Configuration`, plus the backend and the input and
    output types.
  - `run_offchain_with_share` (`client.rs:1193`) follows E.1.
  - `ClientBuilder::connect` (`client.rs:290`) requires `offchain_io`
    (`Error::Configuration("a client connects through the coordinator: configure offchain_io(...)")`),
    opens the pinned `CoordinatorLink` and keeps its `NodeRoster`. It no longer dials node
    QUIC listeners with a bare `QuicNetworkManager::new()` (`:294`): they refuse every
    non-node key. Removed with direct mode: `StoffelClient::connect(&[&str])` (`:702`);
    `ClientBuilder::servers`, `with_servers`, `server`, `network_config`,
    `network_deployment` and `network_config_file` (`:125-235`), since a client's node
    addresses are `OffChainClientConfig::node_rpc_addresses`; `ClientBuilder::client_id`
    (`:143`) and `StoffelClient::client_id` (`:914`), since a client's slot is a request
    (`OffChainClientConfig::client_slot`) answered by its admission;
    `StoffelClient::network_manager` (`:934`) and `transport_client_id` (`:918`); and
    `Runtime::client_for_deployment` (`runtime.rs:130`). `Runtime::client()` (`:118`)
    configures the program only. `StoffelClient` gains `node_roster()` and `admission()`,
    and `summary().server_count` becomes `node_count`, the roster's `n`.
    `NetworkConfig` and `NetworkDeployment` remain server-side deployment descriptions.
  - The configuration example `crates/stoffel-rust-sdk/examples/client_server.rs` keeps its
    server half and builds its client from an `OffChainClientConfig` instead of
    `client_for_deployment` (`:28`).
- **SDK local runs** (`execute_local_*`, `crates/stoffel-rust-sdk/src/vm.rs:244-270`)
  forward `configured_expected_clients` as `expected_output_clients` (`:260-262`) and every
  per-slot `client_output_counts` entry (`:263-265`) to `LocalCoordinatorRunner`, so they
  inherit §F.4's `build()` refusals, which the SDK surfaces as `Error::Configuration`
  (`:270`). What changes for an SDK caller: a runtime whose expected clients reach past the
  manifest's slots, over a program whose outputs are dynamic, now fails at `build()` unless
  it sets `client_output_count(slot, count)` for each such output-only slot — before, the
  run went ahead and delivered nothing to those slots — and a runtime whose slot union is
  not `0..k` fails the same way. A runtime that sets the counts, or whose program declares
  its outputs, is unaffected, which is why the review's claim that dynamic-output programs
  "would now fail" holds only without the counts.
  `runtime_accepts_explicit_expected_output_clients_for_dynamic_outputs`
  (`sdk_usage.rs:1676`) builds and validates a runtime and runs nothing, so it is unchanged;
  §H adds the SDK-level refusal.
- **SDK, `server.rs`.** `ServerBuilder::roster_certs` / `node_roster` (`:314-337`) and
  `OffChainServerConfig::expected_client_certs` (`:709`) are removed, and so is
  `OffChainServerConfig::timestamp` (`:708`, required non-zero at `:727-731`, emitted at
  `:1039-1040`) with its builder setter (`:799`).
  `OffChainServerConfig` gains `coordinator_cert_path: PathBuf`, emitted as `--coord-cert`,
  and `expected_roster_digest: Option<RosterDigest>`, emitted as `--expect-roster-digest`.
  `OffChainServerConfig::validate(expected_clients)` (`:717`) becomes `validate()`: its
  certificate-count check against `expected_clients` goes with the certificates. `start`
  requires `offchain_coordinator` where it required `node_roster()` (`:957`), and stops
  emitting `--roster` (`:1021-1029`), `--expected-clients` (`:1042`) and `--timestamp`.
  **`mpc_config.parties` and `threshold` keep a meaning:** where `start` emitted them as
  `--n-parties` / `--threshold` (`:994-997`), which `stoffel-run` now refuses, it emits
  `--expect-n-parties` / `--expect-threshold` (§D.2), so a server configured for five
  parties at `t = 1` refuses to run against a coordinator whose roster is anything else
  (exit 2, D.3) instead of silently joining it. The builder's own checks against
  `parties` — `party_id < parties` and the peer ids (`:561-580`) — are unchanged.
  **`ServerBuilder::expected_clients(n)` (`:206`) stays and
  means exactly `Program::validate_expected_clients` (`program.rs:304-312`, called at
  `server.rs:586`): the program's static client slots fit within `n`.** It names no
  identity and emits nothing, so `server_builder_rejects_sparse_client_slots_beyond_expected_clients`
  (`sdk_usage.rs:3390`) keeps its assertions unchanged. `ServerTopology::RosterMesh`
  (`:100-105`) becomes `CoordinatorRosterMesh`: still one variant, now naming the only way
  a server learns who is in its session.
- **`stoffel-cli`, `crates/stoffel-cli/src/main.rs`.** `stoffel run --network --config <toml>`:
  - `read_run_network_config` (`:2169-2193`) parses only the SDK's `OffChainClientConfig`,
    whose TOML schema is the struct above: `coordinator_host`, `coordinator_port`,
    `coordinator_cert_der`, `execution_id`, optional `client_slot`,
    `invitation`, `expected_program_hash` and `expected_roster_digest`, `backend`,
    `node_rpc_addresses`, `cert_der`, `key_der`, `input_types`, `output_types`, `timeout` —
    and no `parties`, `threshold`, `input_start_index`, `output_count` or `timestamp`.
  - A file that parses as a node `NetworkConfig` instead is refused by name:
    `network config {path} describes node transport, and clients no longer connect to the
    node mesh (direct client mode was removed); pass an off-chain client config with the
    coordinator's address and certificate, the execution id, node RPC addresses and a
    client identity`. The `RunNetworkConfig::Network` branch (`:991-1015`), which dialed
    node listeners through `ClientBuilder::network_config(..).connect()` only to bail
    afterwards, is deleted.
  - `--client-id <u64>` (`:330`) sets `config.client_slot = Some(ClientIndex(..))`,
    refusing a value above `u32::MAX`; `args.client_id.unwrap_or(config.client_slot)`
    (`:978`) and `client_id_from_u64` go.
  - `local_topology()` (`:1025-1039`) stays `LocalTopology::RosterMesh`; its comment, which
    reserves room for "a coordinator-issued roster (§5 stage 11)", now says that the one
    topology's roster is the in-process coordinator's.
  - Tests: `run_network_accepts_network_config_and_attempts_connection`
    (`crates/stoffel-cli/tests/cli.rs:2270`) is retargeted to
    `run_network_refuses_a_node_network_config_by_name`.
    `run_network_validates_config_path_before_parsing` (`:1938`) keeps its path checks and
    replaces its node-config fixture (`:1963`, asserting `missing server address`) with an
    off-chain config missing `coordinator_cert_der`, asserting that field's error.
    *Evidence corrected:* the review also cited `cli.rs:3093`, `:3120` and `:3968` as
    `parties = 5` client-config fixtures. They are `Stoffel.toml` `[mpc]` project-config
    fixtures of `project_config_rejects_invalid_mpc_values_before_running` (`:3053`),
    `project_config_numeric_type_errors_include_actionable_hints` (`:3107`) and
    `project_config_unknown_field_errors_suggest_common_config_names` (`:3955`). They
    configure the local simulator, whose in-process coordinator still takes `parties` and
    `threshold` from them (F.4), so they do not change.

Two refusals the flow adds beside E.1 step 2's, both exit 2 and both before
associating, since an association is irrevocable: a `--client-slot` (or invitation
slot) past the table is
`Error: execution {id} has {capacity} client slot(s), so it has no client slot {i}; refusing to associate.`,
and `stoffel-run --client` without `--servers` is refused before anything is dialed —
a client that associated and then reached no node would hold its slot until the
association deadline aborted the execution. An admission granting another output count
than the SDK config's `output_types` is `Error::Configuration` right after association,
before any input is sent.

The SDK checks a submission's shape and types against the program's client slot the way
step 2 settles it, and — because the summary's slot table carries only counts — it makes
the typed half of step 2 itself, before associating. The flow splits there:
`CoordinatorClientConfig::inspect` reads and checks the summary and returns a
`PendingAssociation`, whose `bindable_slots()` names every slot the association can bind;
`PendingAssociation::associate` then makes the irrevocable association. `BindableSlots` is:

- `Settled(i)` — `client_slot` or the invitation names slot `i`
  (`OffChainClientConfig::settled_slot`). It is checked before anything is sent, and an
  admission to any other slot is refused as `SlotNotGranted` (exit 13).
- `AnyOf(0..capacity)` — `Open` with no slot requested. The coordinator binds the lowest
  free slot, which the client does not choose, so **every** slot must accept the submission
  (the typed counterpart of step 2's one-shape rule), or the client refuses before
  associating with `Error::InvalidInput` naming the refusing slot and suggesting
  `client_slot`. A manifest-only client (no program) probes each slot through the
  generated manifest here.
- `Registered` — `PreRegistered` with no slot requested. Association binds nothing new,
  and the registered slot is known only from the admission, so it is checked on
  `AdmittedClient::admission` right after association, before any input is sent.
- `Nothing` — an aborted execution, or `Invitation` without an invitation: the association
  is refused with the coordinator's reason and binds nothing.

Before connecting at all, a client without a settled slot is refused a submission that no
slot of the program accepts, which no policy can bind to an accepting slot. The admitted
slot is checked once more after association under every policy; wherever the summary
settled the slot this repeats the pre-association check. Slot 0 is never assumed.
`stoffel run --network` inherits this.

#### E.3 Direct client mode and coordinator-less parties are retired

Direct mode — a client dialing the node QUIC mesh — is **retired, not kept behind a dev
flag**. `stoffel-run --client` without `--off-chain-coord` exits 2 with:

`Error: direct client mode was removed. A client associates with an execution through the coordinator: pass --off-chain-coord <host:port>, --coord-cert <path>, --execution-id <64-hex> and --servers <node RPC addresses>.`

**The refusal lands in V-b; only dead code waits for V-c.** V-b removes `--roster`, the
only way a direct client pins nodes (`Roster::install_for_client` runs only when a roster
was given, `stoffel-run.rs:1914-1923`, and the roster exists only from `--roster`,
`:4309-4313`). Left reachable until V-c, `stoffel-run --client` without
`--off-chain-coord` would keep running `run_as_client` with an empty — and therefore
fail-open (B3) — allowlist on the leg that carries input shares. So V-b puts this exit-2
refusal in front of client mode, beside §D.3's other refusals, and makes `run_as_client`
unreachable; V-c deletes the unreachable code: `run_as_client` (`:1800`), node-side
acceptance of client connections on the mesh (`--wait-for-clients`),
`sync_client_set_across_parties` (`:1344`) and `Roster::install_for_client`.

Because `--peers` now requires `--off-chain-coord` (D.3), every party branch that runs
without a coordinator is unreachable and is deleted in V-c (§9.1): the HoneyBadger
"No coordinator or non-Bls12_381 curves" `setup_hb!` branch (`:5368`), which D.7's
curve-generic coordinated party replaces; the AVSS branch after
`if let Some(coord) = coord_addr.clone()` (`:5404`), i.e. the `setup_avss!` macro (`:5442`)
and its curve match; and the direct-client phases of both setups —
`setup_hb_party_for_curve`'s "Phase 1: Wait for clients" (`:2561-2641`: `expected_client_count`,
`net.clients()`, `sync_client_set_across_parties`) and `setup_avss_party_for_curve`'s
(`:2997-3077`). `print_usage_and_exit` (`:5619`) and the README's `stoffel-run` section
(`README.md:387-484`, which documents `--roster`, `--expected-clients`, `--n-parties` and
direct `--client` runs) are rewritten to the flags of §D.2 and §E.2.

Why no dev-only flag:

1. A direct client reaches nodes through the mesh transport, so every node would have to
   allowlist its key before its manager is shared. That is an identity known in advance,
   which rule 3 forbids, and the frozen `&mut self` allowlist cannot express a client that
   arrives later in any case.
2. The allowlist is role-blind. A key allowlisted for a client can dial with the server
   ALPN and be ranked as a node (see the start of this section), so a dev flag would put a
   party-index-skewing key into the mesh one environment variable away from production.
3. A direct client has no admission record, so nodes would have no coordinator binding to
   gate its masks or outputs on: a second, weaker admission path beside §C.
4. Nothing needs it. Both backends already have coordinator-mediated clients
   (`run_hb_coordinator_client_for_field`, `run_avss_offchain_coordinator_client_for_curve`,
   `:2104`), and the one capability only direct mode has — HoneyBadger client IO off
   BLS12-381 — is restored by D.7's generalization.

### F. Deployment

#### F.0 Key material

**`ids/` is a development fixture, and it is public.** Every private key in it is
committed: `git ls-files ids` lists `ids/server_key.der`, `ids/nodes/key{0..4}.der` and
`ids/clients/key{0,1}.der` beside their certificates. §A's pin authenticates the
coordinator only while its private key is secret. With `ids/server_key.der` in the
repository, anyone holding a checkout can present the pinned key, serve a roster of keys
it also holds, or answer as any node. Today both images bake the whole directory in —
`Dockerfile:90` and `docker/coordinator.Dockerfile:77` both `COPY ids /app/ids` — the
benchmark stack bind-mounts it into every service (`docker-compose.benchmark.yml:12`,
`:83`), and the examples coordinator stack into its coordinator
(`crates/stoffel-lang/examples/docker-compose.coordinator.yml:131`). Every party container
therefore also holds every other node's key and the coordinator's, and no party is merely
one party. Revision 0 pointed `STOFFEL_COORD_CERT` at `/app/ids/server_cert.crt` without
saying any of this. Rules:

1. `ids/` never backs a deployment reachable from another host. Every compose stack in
   this repository is a development stack and may use `ids/`, so **every** compose file
   publishes every port on `127.0.0.1` only (`"127.0.0.1:31415:31415/tcp"`, not
   `"31415:31415/tcp"` as at `docker-compose.yml:121`) and none uses `network_mode: host`.
   Today no stack does either: the benchmark stack publishes its coordinator
   (`docker-compose.benchmark.yml:114`) and its node and RPC ports (`:138-139`, `:166-167`,
   `:190-191`, `:214-215`, `:238-239`) on every interface, as do `docker-compose.yml`
   (`:121`, `:164-165` and each later party), `docker-compose.mesh.yml` (`:107`, `:143-144`
   and each later party) and `docker-compose.avss.yml` (`:98-99` and each later party).
2. No image contains a private key: `Dockerfile:90` and `docker/coordinator.Dockerfile:77`
   are deleted, and no compose file mounts the `ids/` directory.
3. Each container receives exactly one private key, its own, as a compose `secrets:` entry
   mounted at `/run/secrets/<name>` and named by `STOFFEL_KEY` or `--server-key`.
   `coordinator_key` is a secret of the coordinator service only, `nodeN_key` of party N
   only, `clientN_key` of client N only. A secret's `file:` may name a key under `ids/`
   only because rule 1 holds for every stack: a fixture key behind a loopback-only port is
   a development convenience; the same key on a reachable port is a published identity.
4. Certificates are public and mounted read-only one file per mount: the coordinator gets
   the node certificates (and, under `pre-registered`, the client certificates); parties
   and clients get the coordinator's certificate and their own.
5. A real deployment mints every key on the host that owns it — `generate-ids --cert
   <cert> --key <key> --subject-alt-names <name>` run there — and distributes only
   certificates: node certificates to the coordinator's operator, the coordinator's
   certificate to every node and client, and an issuer's certificate (C.3) to the operator.

The §G rows that rest on a key being secret hold only under these rules, and say so. The
§B golden vector reads certificates only and is unaffected.
`crates/stoffel-vm-runner/tests/deployment_key_material.rs` (new) reads every Dockerfile
and compose file of the workspace — the root `Dockerfile*`, `docker/*.Dockerfile`, the root
`docker-compose*.yml` and `crates/stoffel-lang/examples/*.yml` — line by line (no YAML
parser is in the dependency graph) and fails on any of four things:

1. a Dockerfile that copies `ids`;
2. a compose file that mounts the `ids` directory;
3. a `.der` path in a compose file, outside a comment, anywhere but as the `file:` of a
   top-level `secrets:` entry;
4. a published port not bound to `127.0.0.1` — an entry of a service's `ports:` list whose
   short form does not start with `127.0.0.1:`, or whose long form has no
   `host_ip: 127.0.0.1` — or a `network_mode: host` line. A bare `"9000"` entry, which
   publishes on every interface at a random port, fails too.

Revision 1 enforced rules 2 and 3 and left rule 1 to review, so the one rule that makes a
committed key harmless was the one nothing checked. A key-minting init service that writes
fresh keys into a volume per stack is **not** adopted in its place: compose `secrets:`
come from files or the environment, not from volumes, so one volume holding every
minted key would be mounted whole into whichever service needs one of them — the very
"every container holds every key" this section removes — unless each service mounted a
volume sub-path, which older Compose releases do not support. Rule 5 is where fresh
per-host keys belong, and loopback-only stacks make the fixture keys safe to keep for
development.

#### F.1 Every compose stack runs a coordinator

**Parties** everywhere: drop `STOFFEL_NODE_ROSTER`, `STOFFEL_EXPECTED_CLIENTS`,
`STOFFEL_CLIENT_INPUT_COUNT` (`crates/stoffel-lang/examples/docker-compose.coordinator.yml:52`),
and `STOFFEL_N_PARTIES` / `STOFFEL_THRESHOLD`, which every stack sets in its party
environment (`docker-compose.yml:27-28`, `docker-compose.mesh.yml:47-48`,
`docker-compose.avss.yml:57-58` and each later party, `docker-compose.benchmark.yml:39-40`,
`docker-compose.coordinator.reserve-index.yml:29-30`,
`examples/docker-compose.coordinator.yml:23-24`) and `Dockerfile:98-99` defaults — the
entrypoint now refuses them (D.3). Set `STOFFEL_COORD_ADDR`, `STOFFEL_COORD_CERT` (the
read-only mount of the coordinator's certificate, §F.0), `STOFFEL_EXECUTION_ID`,
`STOFFEL_KEY=/run/secrets/<own key>` and `STOFFEL_RPC_ADDR` (which
`docker/entrypoint.sh:345-346` turns into `--rpc-bind`); `depends_on: coordinator:
condition: service_healthy`. **Clients:** drop `STOFFEL_N_PARTIES`, `STOFFEL_THRESHOLD`
(`docker-compose.coordinator.reserve-index.yml:68-69`,
`examples/docker-compose.coordinator.yml:63-64`),
`STOFFEL_OUTPUTS` (`examples/docker-compose.coordinator.yml:73`, `:296`) and
`STOFFEL_CLIENT_INDEX`; set `STOFFEL_COORD_CERT` and, where a specific slot is wanted,
`STOFFEL_CLIENT_SLOT`. **Coordinators:** the §F.3 flags. `--t` keeps its compose-level
default `${STOFFEL_THRESHOLD:-1}`: compose substitutes it from the invoking shell, and it
never reaches a party container.

**`docker/entrypoint.sh`.** Client mode stops emitting `--n-parties` and `--threshold`
(`:259-260`), `--outputs` (`:261-263`), `--timestamp` (`:274`), `--roster` (`:288-290`) and
`--client-index` (`:291-293`); party mode stops emitting `--n-parties` and `--threshold`
(`:321-322`), `--timestamp` (`:342`), `--expected-clients` (`:349-351`), `--roster`
(`:359-361`), `--wait-for-clients` (`:363-365`), `--client-input-count` (`:367-369`),
`--preproc-store` (`:371-373`) and the coordinator-less `--cert`/`--key` (`:389-392`).
Both roles emit `--coord-cert ${STOFFEL_COORD_CERT}` and, when set,
`--expect-roster-digest ${STOFFEL_EXPECT_ROSTER_DIGEST}`; client mode emits
`--client-slot`, `--invitation` and `--expect-program-hash` from `STOFFEL_CLIENT_SLOT`,
`STOFFEL_INVITATION` and `STOFFEL_EXPECT_PROGRAM_HASH` when they are set. Its refusals are
§D.3's.

**The program hash.** Nodes refuse a summary for another program (D.7 step 1), so every
stack's placeholder `--hash 1111…1111` (`docker-compose.yml:94-95`,
`docker-compose.mesh.yml:80-81`, `docker-compose.benchmark.yml:97`,
`docker-compose.coordinator.reserve-index.yml:110-111`,
`examples/docker-compose.coordinator.yml:107-108`) would make every party exit 13 —
§7's "Stage 11's hash check breaks every shipped stack", now resolved rather than
deferred. The coordinator takes `--program` instead (F.3). Packaged programs exist only in
the party image (`Dockerfile:76-87`; the AES circuit is compiled during the build), so a
stack that runs one adds a one-shot `programs` service built from the party image, with
`entrypoint: ["/bin/sh", "-c", "cp -R /app/programs/. /programs/"]` onto a named volume
`stoffel-programs`; the coordinator `depends_on: programs: condition:
service_completed_successfully`, mounts that volume read-only at `/app/programs`, and
passes `--program ${STOFFEL_PROGRAM:-<the stack's default program>}`. The examples stacks
bind-mount `${STOFFEL_EXAMPLES_OUT:-./dist}` into the coordinator as they already do into
their parties (`examples/docker-compose.coordinator.yml:17`).

| Stack | Coordinator today | Change |
|---|---|---|
| `docker-compose.yml` | yes | `--client-io "${STOFFEL_CLIENT_IO-}"` (empty for the default AES circuit, which has no client). The documented `client_mul` recipe (comment at `:48-67`, which names one client certificate) is rewritten: `STOFFEL_PROGRAM=/app/programs/client_mul.stflb STOFFEL_CLIENT_IO=1:0,1:0 STOFFEL_ADMISSION=pre-registered` with both client certificates, and two client containers. `client_mul` reads one share from client 0 and one from client 1 and returns their sum without sending it to either (`crates/stoffel-vm-types/examples/generate_client_mul_program.rs:19-41`), so the parties print the revealed sum and neither client collects an output (§D.7 step 12) |
| `docker-compose.mesh.yml` | yes | as `docker-compose.yml` |
| `docker-compose.benchmark.yml` | yes, inside a shell command | the same flags inside that command; its `./ids:/app/ids:ro` mounts (`:12`, `:83`) become per-service secrets and certificate mounts (§F.0) |
| `docker-compose.coordinator.reserve-index.yml` | yes | **becomes the `Open` stack:** `--client-io 1:0,1:0 --admission open --association-deadline-secs 600 --input-deadline-secs 900`; the clients' `STOFFEL_CLIENT_INDEX` / `STOFFEL_CLIENT{0,1}_INDEX` become `STOFFEL_CLIENT_SLOT` / `STOFFEL_CLIENT{0,1}_SLOT`. Input-only slots: its program `client_sub_order` returns `client[0] - client[1]` and sends neither client anything (§D.7 step 12), so revision 1's `1:1,1:1` would have left both clients waiting in `obtain_outputs` until the execution was removed, and exiting non-zero. The parties reveal and print the difference instead, and the stack's header comment (`:11-17`) says to swap `STOFFEL_CLIENT{0,1}_SLOT` to flip its sign |
| `docker-compose.coordinator.reserve-index.preproc.yml` | override of the above | drop its per-party `STOFFEL_NODE_ROSTER` restatements and `STOFFEL_PREPROC_STORE` (`:26`, `:35`, `:44`, `:53`, `:62`; §C.9 part 4). The per-party volume stays, holding `STOFFEL_EPOCH_STORE`, and its header comment (`:1-21`) says it now persists the epoch alone |
| `crates/stoffel-lang/examples/docker-compose.coordinator.yml` | yes | `--client-io "${STOFFEL_CLIENT_IO:-1:1,1:0}" --admission pre-registered --client-certs <client0 certificate>,<client1 certificate>`: its default program `mpc_share_arithmetic` takes one input from client 0 and, once V-b adds `MpcOutput.send_to_client(0, [product])` to its client branch (§D.7 step 12), sends it the product; client 1's input is unused. The coordinator's `ids` mount (`:131`) becomes certificate mounts and a secret (§F.0) |
| `docker-compose.avss.yml` | **none** | add a `coordinator` service (`docker/coordinator.Dockerfile`, `172.29.0.5:31415`, the healthcheck `docker-compose.yml` uses). Its default programs have no client IO, so `--client-io` is empty; the certificate-signing fixture's direct client becomes a coordinator-mediated AVSS client under `STOFFEL_CLIENT_IO=1:2 STOFFEL_ADMISSION=pre-registered` with client 0's certificate |
| `crates/stoffel-lang/examples/docker-compose.mpc.yml` | **none** | add a `coordinator` service at `172.29.0.5:31415`; `--client-io ${STOFFEL_CLIENT_IO-}` |

A node checks a slot's shape against the program manifest only for slots the registration
has (D.7 step 1), so a program that uses clients only when `ClientStore.get_number_clients()`
is non-zero — `mpc_share_arithmetic` in `docker-compose.mpc.yml` — still runs with an empty
slot table.

**As built** (§9.I), with three additions to this table. First, every coordinator service
takes the whole admission surface from the environment, not only `--client-io`:
`--admission "${STOFFEL_ADMISSION:-pre-registered}"`,
`--invitation-issuer-cert "${STOFFEL_INVITATION_ISSUER_CERT-}"`,
`--association-deadline-secs "${STOFFEL_ASSOCIATION_DEADLINE_SECS-}"` and
`--input-deadline-secs "${STOFFEL_INPUT_DEADLINE_SECS-}"`, which the wrapper reads as absent
when empty (§F.3). The reserve-index stack keeps `open` and its two deadlines written out,
since that is what it is. Second, the client containers of `docker-compose.yml`,
`docker-compose.mesh.yml` and `docker-compose.avss.yml` are services under Compose's
`profiles: [clients]` rather than `docker compose run` recipes in a comment, so a client
mounts its own key as a secret instead of the reader mounting it by hand, and no party
image is used to carry a client identity. Third, certificates are mounted per service and
not as one list: the `x-certificates` anchor every stack shared becomes
`x-coordinator-certificates` (the roster, plus the client certificates a pre-registered
stack names) and `x-coordinator-pin` (the coordinator's certificate alone), so a party
holds the pin and its own certificate and a client the pin and its own.
`crates/stoffel-vm-runner/tests/deployment_key_material.rs` gained a fifth check for
exactly that, and it fails on the compose files as they stood before this change.

The per-party epoch store needs no change: the same volume path now holds records keyed
by the new digest, and the old records are orphaned harmlessly (D.5).

#### F.2 Test scripts

**As built**, both docker scripts also export `STOFFEL_EXPECT_ROSTER_DIGEST`, defaulted to
the §B golden digest of `ids/nodes`, so every party and client of the run refuses a
coordinator serving any other roster; `test-coordinator-reserve-index.sh` additionally
asserts the coordinator's `Serving node roster n=5, t=1, digest=…` line and reads each
container's mounts to assert that no party or client held any identity material but the
coordinator's certificate, its own certificate and its own key.
`crates/stoffel-lang/examples/run_coordinator_compose.sh` makes the same mount assertion
for its parties. `test-coordinator-preproc-store.sh` keeps its name and becomes the restart
check below; since stage V-0 has not landed (§9.I), what makes its refutations true is that
no stack sets `STOFFEL_PREPROC_STORE` any more and the entrypoint refuses it.

- `docker/test-coordinator-reserve-index.sh` asserts the parties' revealed value, not a
  client output: every party's log must contain `Program returned: ${EXPECTED_OUTPUT}` —
  the line `print_vm_result` prints for a revealed share (`stoffel-run.rs:967-996`) —
  where it required the client line `outputs: [${EXPECTED_OUTPUT}]` (`:142`), which only the
  deleted broadcast produced. `EXPECTED_OUTPUT` keeps its default `-10` (`:8`), and
  `STOFFEL_CLIENT0_SLOT=1 STOFFEL_CLIENT1_SLOT=0 EXPECTED_OUTPUT=10` is the documented swap
  under `Open`. `assert_zero_exit_codes` stays: an input-only client exits 0 once its
  submission is accepted.
- `docker/test-coordinator-preproc-store.sh` keeps its `down`/`up` cycle, which becomes the
  restart check it now is: the digest-keyed epoch advances across restarts, and **no
  preprocessing material survives one**. As built, "the epoch advances" is asserted
  directly — every party's `Session started: instance_id=` line is read in both runs, the
  five must agree within a run, and the second run's value must differ from the first's,
  although the roster, the program and the execution id are unchanged. In V-0, its first run refutes
  `Persisted preprocessing material to store` where it required it (`:152`) and its second
  run refutes `Loaded preprocessing material from store` where it required it (`:162`) —
  the assertion that encoded §C.9's reuse — while the override loses
  `STOFFEL_PREPROC_STORE` (§F.1). In V-b, when the broadcast goes, both runs assert
  `Program returned: -10` from every party instead of the client's `outputs: [-10]`
  (`:151`, `:161`), as the script above. The script keeps its name; its header and banner
  say what it checks.
- `crates/stoffel-lang/examples/validate_examples.sh:189-212` and
  `run_coordinator_compose.sh`: `STOFFEL_CLIENT{0,1}_INDEX` become
  `STOFFEL_CLIENT{0,1}_SLOT`; `STOFFEL_COORDINATOR_N_INPUTS`, `STOFFEL_CLIENT_INPUT_COUNT`,
  `STOFFEL_OUTPUTS` and `STOFFEL_CLIENT1_OUTPUTS` become one `STOFFEL_CLIENT_IO` per
  program, the slot table its manifest declares.
- `crates/stoffel-lang/examples/run_mpc_local.sh`, called by `validate_examples.sh:217`,
  runs a coordinator-less mesh today — `--roster` with `--n-parties` and `--threshold` and
  no `--off-chain-coord` (`:100-116`) — and would exit 2. It is reimplemented on
  `stoffel run <program> --local --parties $N_PARTIES --threshold $THRESHOLD --entry $ENTRY`
  (building `-p stoffel-cli` instead of `stoffel-run`), which runs `LocalCoordinatorRunner`
  with its in-process coordinator. The repository has no stand-alone coordinator binary to
  start beside host processes — the only coordinator `main` is the wrapper, in its own
  workspace — so the local runner is the coordinator. The script stops reading
  `ids/nodes` (the runner mints identities per run, so it needs no key material at all,
  §F.0), and its `N_PARTIES >= 2` guard (`:22-25`) becomes the runner's own
  `at least 4 parties` (`local_runner.rs:328`).

#### F.3 Coordinator wrapper and `run-coord` flags

`docker/coordinator-wrapper/src/main.rs` (clap):

| Flag | Meaning |
|---|---|
| `--execution-id`, `--server-cert`, `--bind-addr`, `--port` | unchanged |
| `--server-key` | unchanged; in compose, `/run/secrets/coordinator_key` (§F.0) |
| `--program <path>` | **new**: registers `program_hash_of(bytes)` (§C.1). Exactly one of `--program` and `--hash` is required (a clap `ArgGroup`) |
| `--hash <64-hex>` | for an operator registering without the bytes; a wrong one makes every node exit 13 (D.7 step 1) |
| `--node-certs <paths>` | replaces `--initial-mpc-nodes`. Certificate DERs go to `NodeRoster::new` as bytes; the wrapper's `parse_public_keys` (`:221-237`), which produced the bare BIT STRING, is deleted |
| `--t <u64>` | unchanged; `--n` is removed, since `n` is the number of `--node-certs` |
| `--client-io <in:out>[,<in:out>…]` | replaces `--n-inputs`: one `ClientSlotSpec` per entry, in slot order; absent means no client slots |
| startup output | **as built**: beside `Listening on … (… admission)`, the wrapper prints `Serving node roster n=…, t=…, digest=…`, which is the value an operator passes as `--expect-roster-digest` / `STOFFEL_EXPECT_ROSTER_DIGEST` |
| `--admission <pre-registered\|open\|invitation>` | a clap `ValueEnum`, default `pre-registered`. It never defaults to `open`: `--client-io 1:1` without `--client-certs` fails `PreRegisteredCountMismatch` rather than admitting anyone |
| `--client-certs <paths>` | `pre-registered` only: one per slot, in slot order; replaces `--output-clients` |
| `--invitation-issuer-cert <path>` | `invitation` only; refused (exit 2) when it is one of `--node-certs` or `--server-cert` (`IssuerIsRosterNode`, `IssuerIsCoordinatorKey`) |
| `--association-deadline-secs <u64>`, `--input-deadline-secs <u64>` | **new**: seconds after startup, turned into `ExecutionDeadlines`; required under `open` and `invitation`, optional under `pre-registered`, both or neither |
| `--min-output-shares` | **not added**: the registration field is gone (§C.1) |
| `--max-connections <usize>` | **new**: `RpcServerLimits::max_connections`, default 4096; the other `RpcServerLimits` fields keep their defaults (§A) |

An empty value is the same as an absent flag — **as built**, for every flag that takes one,
including `--invitation-issuer-cert`, `--association-deadline-secs` and
`--input-deadline-secs`, whose clap value parser maps an empty or blank string to `None`
while a non-empty one still has to parse — so a compose file can pass
`--client-io "${STOFFEL_CLIENT_IO-}"` and `--client-certs "${STOFFEL_CLIENT_CERTS-}"`
unconditionally; with no client slots, the default `pre-registered` with no certificates
is the empty registration. A non-empty flag the chosen `--admission` does not read —
`--client-certs` under `open`, say — exits 2; it is not ignored. Every `RegistrationError`
exits 2 with its message.

`crates/bins/src/bin/run-coord.rs` takes the same flags, and registers its one execution at
startup in both modes: `--one-off <hash>,<execution-id>` becomes a boolean `--one-off`
(drain and exit, §C.10) beside `--execution-id` and `--program` or `--hash`. Standing mode
used to register nothing and rely on the deleted RPC. `run-coord` parses bytecode, so with
`--program` its slot table comes from the manifest, as in `0.2.0`, and `--client-io` is
refused; the wrapper does not parse bytecode and takes its slot table from `--client-io`
only. The manifest's `client_slot`s must be exactly `0..k` (otherwise exit 2:
`client IO manifest slots are not contiguous from 0`), and `--client-bindings
<slot>=<cert>` fills `PreRegistered` by slot. `--n`, `--n-inputs`, `--output-clients` and
`--initial-mpc-nodes` are removed, and so is `--backend`, whose only use was choosing the
`min_output_shares` default (`coord:bins/src/bin/run-coord.rs:346-360`).

#### F.4 `local_runner`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LocalAdmission {
    /// The runner mints one certificate per client slot and pre-registers it. Today's behaviour.
    #[default]
    PreRegistered,
    /// No client identity appears anywhere in the run's configuration. The runner registers
    /// the slot table with deadlines and starts no clients of its own.
    Open,
}

impl LocalCoordinatorRunnerBuilder {
    pub fn admission(self, admission: LocalAdmission) -> Self;
}

impl LocalCoordinatorRunner {
    /// Starts the in-process coordinator and every party, and returns while they run.
    pub async fn start(self) -> LocalCoordinatorRunnerResult<RunningLocalCoordinator>;
    /// `start`, one client per pre-registered slot with inputs, then `finish`.
    pub async fn run(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput>;
}

/// Everything `run()` held for the whole run (`local_runner.rs:109-168`), held as long as
/// the run lasts. Fields are private.
pub struct RunningLocalCoordinator {
    _local_run_guard: tokio::sync::MutexGuard<'static, ()>,   // local_run_lock(), :1593
    run_dir: TempRunDir,                // identities, program, epoch stores, coordinator.crt
    coordinator: OffChainCoordinatorServer<OffChainCoordinatorConnection>,
    parties: Vec<(String, Child)>,      // kill_on_drop
    pre_registered_clients: Vec<LocalClientIdentity>,
    endpoint: LocalClientEndpoint,
    timeout: Duration,
}

impl RunningLocalCoordinator {
    pub fn client_endpoint(&self) -> &LocalClientEndpoint;
    pub async fn finish(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClientEndpoint {
    pub coordinator: SocketAddr,
    pub coordinator_cert_der: Vec<u8>,
    pub execution_id: ExecutionId,
    pub node_rpc_addresses: Vec<SocketAddr>,
    pub backend: MpcBackendKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClientRun {
    pub admission: ClientAdmission,
    /// Reconstructed outputs, each reduced to its low 64 bits (`fr_to_u64`); empty without output rights.
    pub outputs: Vec<u64>,
}

/// E.1 for one client, against a running local coordinator.
pub async fn run_offchain_client(endpoint: &LocalClientEndpoint, cert_der: Vec<u8>, key_der: Vec<u8>,
    request: AssociationRequest, inputs: &[String], timeout: Duration)
    -> LocalCoordinatorRunnerResult<LocalClientRun>;
```

- **Lifetimes.** Today `run()` holds `local_run_lock()` (`:109`), the `TempRunDir` (`:112`)
  and the coordinator handle (`_coord`, `:160-168`) on its own stack, and its children die
  with it (`kill_on_drop`). `RunningLocalCoordinator` owns all four, so `start` can return
  while the run continues and a second run still cannot overlap it. `coordinator` is an
  `OffChainCoordinatorServer<OffChainCoordinatorConnection>` (§C.10), no longer the test
  module's `HoneyBadgerCoordinatorConnection` (`:11-13`, `:156`).
- **The run directory is private.** `TempRunDir::new` creates
  `std::env::temp_dir()/stoffel-local-<uuid>` with `create_dir_all` (`:1386-1390`), and
  `write_node_identities` and the client identities write every private key with
  `std::fs::write` (`:1441-1443`, `:1471-1472`), so the directory and the keys get the
  process umask — world-readable under a typical `022`. On a shared host with `/tmp` as the
  temp directory, any local user could read every node key of a run and answer as that node
  on its listening ports. On unix, `TempRunDir::new` creates the directory with
  `std::fs::DirBuilder::new().mode(0o700)` (`std::os::unix::fs::DirBuilderExt`), refusing
  a path that already exists, and every key file is created with
  `OpenOptions::new().write(true).create_new(true).mode(0o600)`
  (`std::os::unix::fs::OpenOptionsExt`) — `create_new` so a pre-placed file or symlink is
  an error, not a target. Certificates, the program and `coordinator.crt` are public and
  keep default modes inside the private directory. Elsewhere the default modes stay: on
  Windows the temp directory is already per user.
- **The coordinator certificate** (today in memory only, `:133`) is written to
  `<run_dir>/coordinator.crt`. `PartyRole::runner_args` (`:1286`) emits
  `--coord-cert <run_dir>/coordinator.crt` where it emitted `--roster` (`:1309`), and
  `spawn_party` (`:559`) stops emitting `--n-parties`, `--threshold` (`:571-574`),
  `--timestamp` (`:589-590`), `--expected-clients`, `--client-input-count`,
  `--client-input-total`, `--client-roster` and `--client-input-slots` (`:600-630`).
- **The slot table** replaces `coordinator_client_io_binding` (`:519-557`). Its slots are
  the union `known_client_inputs` (`:485-509`) already computes: manifest `client_slot`s,
  `client_input` slots, and `0..expected_output_clients`. `build()` (`:763`) runs its
  checks in this order, the existing ones first, so every error an existing test asserts
  is still the error it gets:
  - every check `build()` makes today, in today's order — among them the parties bounds
    (`:326-337`) and the expected-clients bound
    (`program declares ClientStore slot(s) requiring expected_clients >= {minimum}`,
    `:360-383`). `local_runner_rejects_expected_output_clients_below_static_manifest_slots`
    (`crates/stoffel-vm-runner/tests/local_coordinator_e2e.rs:395-425`) registers a
    manifest whose only slot is 2 with `expected_output_clients(2)` and asserts
    `expected_clients >= 3`; with the bound first it still gets that error, where the
    output-only rule below would otherwise have fired for slots 0 and 1;
  - the union must be exactly `0..k`, since a slot's position is its `ClientIndex` (C.1):
    `Configuration("client slots must be contiguous from 0; slot {i} has neither inputs nor outputs")`;
  - slot `i`'s `input_count` is the manifest's declared input count, or — for a program
    whose manifest declares no clients, the branch at `:528-542` — the number of values
    `client_input(i, …)` gives;
  - its `output_count` is `output_count_for_slot(i)` (`:462-483`): the manifest's count,
    else the `client_output_count` override, else 0. A slot with no inputs whose output
    count stays 0 — `expected_output_clients(n)` over a program whose outputs are dynamic,
    with no `client_output_count` — is refused here, naming the fix, rather than reaching
    the coordinator as `EmptyClientSlot`:
    `Configuration("client slot {i} is output-only, but its output count is unknown: set client_output_count({i}, <count>)")`.
- Under `Open` the deadlines are the run's `timeout` from registration, for both backends.
- **`run()` under `Open`.** `run()` starts only pre-registered clients, so under
  `LocalAdmission::Open` with a non-empty slot table nobody would bind a slot and
  `InputCollection` would be held until the deadline aborted the run. `run()` refuses it:
  `Configuration("run() starts only pre-registered clients; with LocalAdmission::Open use start() and run_offchain_client")`.
- `Invitation` is not exposed here in this change; the coordinator crate's tests cover it.
- Retargeted unit tests: `expected_clients_create_output_identities_for_dynamic_outputs`
  (`:1890`) builds with `.client_output_count(0, 1).client_output_count(1, 1)` and asserts
  the table `[0:1, 0:1]`, and asserts that without the counts `build()` fails naming
  `client_output_count`; `expected_clients_union_keeps_manifest_inputs_and_output_only_slots`
  (`:1914`) builds with `.client_output_count(1, 1)` and asserts `[1:0, 0:1]`. Both used to
  assert `coordinator_client_io_binding`'s `(n_inputs, output_clients)`, which no longer
  exists. The SDK's `runtime_accepts_explicit_expected_output_clients_for_dynamic_outputs`
  (`sdk_usage.rs:1676`) is unaffected: it builds and validates a runtime and runs nothing;
  SDK local runs inherit these refusals (§E.2).
  On the CLI, `stoffel run --local --expected-output-clients N` over a program with dynamic
  outputs now needs `--client-output-count SLOT=COUNT` for each output-only slot
  (`crates/stoffel-cli/src/main.rs:306`, `:314`), and without it fails with the builder's
  `Configuration` error before any party starts.

#### F.5 Consuming the unreleased coordinator

Until `0.3.0` is on crates.io, the root `Cargo.toml` **and**
`docker/coordinator-wrapper/Cargo.toml` (its own workspace, which `cargo build --workspace`
cannot see) carry:

```toml
# TEMPORARY — docs/design/bootnode-elimination.md §9.F.5. stoffel-mpc-coordinator 0.3.0 is
# not published yet. Delete this table, and re-lock, as soon as it is.
[patch.crates-io]
stoffel-mpc-coordinator-shared = { path = "/Users/gabriel/RustroverProjects/stoffel-mpc-coordinator-roster-admission/crates/coord-shared" }
stoffel-mpc-coordinator-off-chain = { path = "/Users/gabriel/RustroverProjects/stoffel-mpc-coordinator-roster-admission/crates/off-chain" }
```

and the pins move `=0.2.0` → `=0.3.0` in `crates/stoffel-vm-runner/Cargo.toml:20-21`,
`crates/stoffel-rust-sdk/Cargo.toml:38-39` and `docker/coordinator-wrapper/Cargo.toml:20-21`.
The bump is what makes the patch apply: a patch whose version does not satisfy the
requirement is left unused, and cargo only warns.

While the patch exists:

- **The path exists only on this machine.** GitHub CI (`.github/workflows/ci.yml`) cannot
  resolve the workspace and is red by construction until `0.3.0` is published. That is
  the honest state of an unreleased dependency, not a flake to work around.
- **`cargo publish`** of `stoffel-vm-runner` and `stoffel-rust-sdk` fails (`=0.3.0` cannot
  be satisfied from crates.io) — the correct failure.
- **Docker cannot see the path.** Every image's build context is this repository
  (`context: .`, or `${STOFFEL_VM_DIR}` for the examples stack). For the patch window each
  Dockerfile that builds a crate depending on the coordinator copies a BuildKit named
  context to the very path the patch names,

  ```dockerfile
  COPY --from=coordinator . /Users/gabriel/RustroverProjects/stoffel-mpc-coordinator-roster-admission
  ```

  **before every `cargo` invocation that resolves the workspace in that stage** — the patch
  path must exist when `cargo metadata` runs, and cargo-chef runs it in `prepare` and
  `cook`:
  - `Dockerfile`: one builder stage; before `cargo build` (`:38-40`). Its `COPY . .`
    (`:22`) copies this repository only.
  - `Dockerfile.benchmark`: in the planner, before `cargo chef prepare` (`:26`); in the
    builder, before `cargo chef cook` (`:38-45`). The builder's `COPY . .` (`:47`) comes
    after cook, and would not carry the coordinator anyway.
  - `docker/coordinator.Dockerfile`: in the planner, before `cargo chef prepare` (`:31`);
    in the builder, before `cargo chef cook` (`:43-46`) — not merely somewhere in the
    builder, since the wrapper's own `COPY` (`:48`) follows cook.

  Every compose build block declares

  ```yaml
  additional_contexts:
    coordinator: "${STOFFEL_COORDINATOR_CONTEXT:?set STOFFEL_COORDINATOR_CONTEXT to the stoffel-mpc-coordinator 0.3.0 checkout until it is published}"
  ```

  This reuses the `coordinator` named context the reserve-index and examples stacks
  already declare — today pointing at a git branch and consumed by no Dockerfile — and the
  `STOFFEL_COORDINATOR_CONTEXT` / `STOFFEL_COORDINATOR_DIR` variables both docker test
  scripts already export, and it replaces their stale default with a hard error. The
  `COPY` lines and the `:?` go when the patch goes.
- **CI `docker-build` is red for the patch window too.** Its "Build Docker image" step
  (`.github/workflows/ci.yml:215-222`) runs `docker/build-push-action` with no
  `build-contexts`, so `COPY --from=coordinator` resolves `coordinator` as an image
  reference and fails; and no `build-contexts` entry can point a GitHub runner at a path on
  this machine. Like the Rust jobs, it stays red until `0.3.0` is published.

### G. Trust table

Every row that rests on a private key being secret holds only under §F.0: each private
key exists in exactly one place, its owner's, and a fixture key is reachable only on
loopback. "The coordinator" includes its operator and the invitation issuer, which sit
inside one trust boundary (§9 preamble, §C.3).

| Actor | Can | Cannot |
|---|---|---|
| **Coordinator, honest** | Serve one immutable node roster; register executions; bind clients to slots under each execution's policy; abort an execution at its deadline; see every client identity and binding, the program hash, masked inputs, sealed output shares and all timing; stop serving (liveness). | Learn a client's input: mask shares go node→client over node RPC legs it is not on, and a masked input under a uniformly random mask carries no information. Learn an output: shares are sealed to the client's key. Choose a party index (each node sorts SPKIs itself) or an `instance_id` (local epoch plus roster digest). |
| **Coordinator, malicious** | Everything it is trusted for, which is irreducible. **Roster:** serve a roster of its own keys — to every node, to some of them, or to one client. Equivocation is detected only between nodes that appear in each other's served roster: agreement (`JoinCommit` and both digest barriers) travels over the mesh, and each node installs only the roster it was served (`join.rs:366`), so a coordinator that partitions the nodes and pads each part with keys of its own gets internally consistent meshes that never exchange a frame. A client pins its node legs to whatever roster it was served (§E.1). **Trusting the coordinator's roster is therefore trusting it with client input privacy and output integrity**: serving a client a roster of the coordinator's own keys hands it that client's inputs and lets it sign whatever outputs it likes. `--expect-roster-digest` turns that into a refusal for a node or client that knows the intended roster (§D.2), and nothing else does. **Admission:** register any execution and admit any identity, itself included, under any policy; refuse associations or round transitions, or let deadlines abort (censorship, DoS). **Relay:** withhold a client's submission or a node's sealed output (DoS). | Within one mesh: serve its nodes different rosters, summaries or admission sets without the run aborting at `JoinCommit` or `AdmissionsAgreed`, before any mask share is released, input stored or output sealed; deliver different masked inputs to different nodes without aborting at `InputsAgreed`, before any input is unmasked; unmask a client's input by naming different reservation owners to different nodes (nodes release mask shares only for reservations that match the agreed set, C.7). **Against a client served the true roster:** shift its input — nodes verify the client's signature over its submission against the agreed identity and nonce (C.7, §D.7 step 9), which revision 1 left as a `0.2.0` property; substitute or relabel its outputs — each item must carry a roster node's signature over its own position and ciphertext, and each share the id of that position (C.7); replay a submission or output from an earlier registration of the same id (the nonce is signed). Make an honest node run for a program other than the one registered (D.7 step 1). Read the outputs of a client it did not admit as itself. Make a node trust a key outside the roster it served that node, or a client a node outside the roster it served that client. Force `instance_id` reuse, or make a node reuse a mask or triple of an earlier execution (C.9 part 4). |
| **Attacker at the coordinator's address, or at a node's** | Drop, delay or refuse connections (DoS). Without any certificate, hold a listener's pending-handshake pool from `max_pending_handshakes / max_pending_handshakes_per_ip` source addresses (64 by default); with free certificates, fill the unreserved connection pool (§A). Either stops new clients from associating, and so aborts an `Open` or `Invitation` execution at its association deadline; reachability controls in front of a listener are the deployment's (§C.2). | Holds under §F.0 only. Complete a handshake as the coordinator: its key is not the pinned one, so nodes and clients stop at `ServerPinMismatch` before any RPC, and no roster, admission or relayed input comes from it. As a node RPC listener: be trusted by a client (not a roster key) or answer as a node already answering elsewhere (`DuplicateNodeIdentity`). As a mesh peer: be admitted (node allowlist). Take the connection capacity of roster nodes, which no other identity draws on, so a node connecting at startup is not crowded out; nor, with certificates alone, the bound-client pool (§A). Hold the coordinator's state mutex through a slow connection (C.6). With a committed fixture key from `ids/` on a reachable port, the first three are possible, which is why §F.0 makes every such port loopback-only and checks it. |
| **Malicious node (at most `t`)** | Whatever the MPC protocol tolerates of a corrupt party; withhold its mask and output shares; send wrong ones, which reconstruction excludes (C.7); cast its one vote of `transition_quorum()`; acknowledge retirement early (a drain starts only in a terminal round, C.10); read client identities, reservations and masked inputs through `get_client_admissions` and the node-gated subscriptions; bind a slot under `Open`, like anyone; abort a run by sending a divergent `JoinCommit`, `AdmissionsAgreed` or `InputsAgreed` frame; lose its own subscriptions by reading slowly (C.6). | Register an execution or choose its program, slot table or policy (in-process only, C.1); change membership, party indices or `t`; admit or unbind a client; learn a client's mask (it holds one share, and every honest node serves its share only to the identity the agreed admissions name, C.7); make a client use a wrong mask or output, or never reconstruct one, by relabelling its share with another node's id, changing its degree, or sending a value off the sharing — a client attributes each share to the pinned leg or signed item it came on, ignores one whose id or degree does not match that position, decodes HoneyBadger shares robustly, and accepts an AVSS share only if it verifies against the commitments it came with and `t + 1` positions presented those same commitments (A, C.7); make an oversized ciphertext block a client's other outputs (one item per node, bounded, C.1); receive another client's outputs; advance a round alone; impersonate the coordinator (pinned; §F.0); stall the coordinator for other executions or subscribers (no send under the state mutex, C.6); make honest nodes of its mesh disagree about the roster, the admissions or the masked inputs without the run aborting. |
| **Malicious client** | Fetch the node roster and an execution's summary, at a bounded rate per identity (C.6); under `Open`, bind free slots — with enough certificates, all of them — and then never reserve or never submit, which aborts that execution at its deadline (C.8); submit any value as its own input; repeat `associate_client` (idempotent); open connections and parked subscriptions up to the per-listener, per-identity and per-caller bounds (§A, C.6) — enough certificates can fill a listener's unreserved pool (row above). | Bind a pre-registered slot, or an invitation slot without an unexpired invitation for its own key issued for this registration, program, roster and **that slot** (C.3); reserve or submit outside its admitted range; submit oversized inputs that make other nodes' streams undeliverable (C.1); subscribe to reservations, masked inputs or other clients' identities (node-gated, C.6); obtain another client's mask shares (node RPC checks the caller's certificate against the reservation) or outputs (gated on admission, and sealed to the other key); learn anything from a mask a previous execution used, because no node hands one out twice (C.9 part 4); stall an execution past its deadlines; reach the node mesh transport at all (the node allowlist holds nodes only), and so pose as a server peer and skew party indices; take a roster node's connection capacity (bound clients under `Open` can fill only the bound-client pool, §A); affect any other `ExecutionId`. |
| **Invitation issuer** | Admit any identity it signs for, to an `Invitation` execution registered with its key, until the invitation's `not_after`, in the slot the invitation names. It is an admission authority inside the coordinator's trust boundary, so rule 2 requires that no node's operator runs it (§C.3). | Admit anyone to another registration of the same id, another program, another roster, another slot, or after `not_after` (C.3); use a key that is a roster node's or the coordinator's (registration refuses both, C.1 — a guard against misconfiguration: it compares keys, and cannot tell who operates a key); withdraw an issued invitation before `not_after` (there is no revocation list; keep `not_after` short). |

### H. Test plan

No test is deleted to make this pass. A test whose contract this section changes is
retargeted to the new contract, and is listed as such. When the new form of a retargeted
test can exist before its old API is deleted — a V-a roster test, say — it is written in
that earlier stage beside the old test, and the old test leaves with the old API in V-c;
its contract is then carried by the retargeted form, never dropped. A test marked
"planned" existed only in revision 1's plan — no code for it was ever written — so
replacing it removes no test.

**Coordinator repository** (`stoffel-mpc-coordinator-roster-admission`):

| Test | Location | Asserts |
|---|---|---|
| `a_pin_is_the_full_spki_of_its_certificate` | `crates/coord-shared/src/pin.rs` | `SpkiDer` equals `public_key().raw`, not the BIT STRING; trailing bytes → `TrailingBytes`; an RSA key, a P-384 key and a P-256 key with explicit curve parameters → `UnsupportedKeyAlgorithm`; Ed25519 accepted; `NonCanonicalPublicKey` for a P-256 key as a compressed (33-byte) point, as a hybrid (`0x06`/`0x07`) point and as a 65-byte `0x04` string off the curve, and for an Ed25519 key with a `NULL` parameter or of 31 or 33 bytes — the re-encodings built from the same key as an accepted certificate, so the test also shows their bytes would otherwise differ |
| `a_caller_identity_is_derived_once_and_refuses_what_the_pin_refuses` | `crates/coord-shared/src/rpc.rs` | `caller_identity` is the BIT STRING for P-256 and Ed25519 certificates, and refuses trailing bytes, unsupported algorithms and non-canonical encodings; `KeyAlgorithm::of_client_identity` names 65-byte `0x04` and 32-byte identities and nothing else |
| `the_listener_bounds_pending_handshakes_per_source_and_in_total` | same | with `max_pending_handshakes_per_ip: 2`, a third stalled TCP connection from one address is closed at once while another address still gets through; with `max_pending_handshakes: 3` a fourth from any address is closed; a stalled handshake is closed after `handshake_timeout` and frees its counts — replaces revision 1's planned, never implemented `the_listener_refuses_connections_beyond_its_limit` |
| `a_roster_node_connects_through_a_flood_of_unreserved_and_bound_connections` | same | with `max_connections: 4` filled by established connections of fresh certificates, `max_bound_client_connections: 2` filled by clients bound under `Open`, and stalled handshakes up to the per-source bound, a roster node's certificate still connects and calls `get_node_roster`; a newly bound client's next connection counts against the bound-client pool, not the unreserved one |
| `connections_per_identity_are_bounded_and_idle_unreserved_ones_are_closed` | same | with `max_connections_per_identity: 2` a third connection of one certificate is refused; an unreserved connection that makes no call for `idle_timeout` is closed, one with a live subscription or a node's is not |
| `every_listener_and_client_is_tls13_only` | `crates/coord-shared/src/self_signed_certs.rs` | a rustls client restricted to TLS 1.2 fails the handshake with the coordinator listener and the node RPC listener; `setup_client` refuses a TLS 1.2-only server |
| `a_pinned_client_reaches_the_pinned_server` | same | handshake succeeds; `server_spki` is the pinned key |
| `a_pinned_client_refuses_a_server_presenting_another_key` | same | `CoordinatorError::ServerPinMismatch`, not `ConnectError` |
| `a_roster_node_pin_reports_which_member_answered` | same | `server_spki` identifies the member |
| `node_roster_golden_vector_matches_the_shipped_node_certificates` | `crates/coord-shared/src/roster.rs`, fixtures `tests/fixtures/ids/nodes/` (certificates only) | order `cert3, cert0, cert1, cert2, cert4`; digest `da7fa2fe…e00d` (§B) |
| `node_roster_rejects_empty_zero_threshold_duplicate_and_undersized_rosters` | same | `Empty`, `ZeroThreshold`, `DuplicateKey` (same SPKI; same BIT STRING), `ThresholdTooLarge`, and `UnparseableCertificate` carrying `NonCanonicalPublicKey` for a second, compressed encoding of a member's key — **retargets** `rejects_invalid_mpc_rosters` (`crates/off-chain/tests/off_chain.rs:128`) |
| `a_served_roster_out_of_order_or_with_a_wrong_digest_is_refused_with_a_typed_error` | same, and `crates/off-chain/tests/off_chain.rs` | `NotCanonical`, `DigestMismatch`, `CountMismatch` from `TryFrom<NodeRosterWire>`; over the wire, `CoordinatorLink::connect` returns `CoordinatorError::Roster(DigestMismatch)`, not a decode string |
| `a_roster_digest_parses_and_displays_as_64_hex` | `crates/coord-shared/src/roster.rs` | `Display` is lowercase hex; `FromStr` round-trips, accepts upper case, and refuses 63 and 65 characters (`WrongLength`) and a non-hex character (`NotHex { position }`); `NodeCertificateDer::from_der(..).as_bytes()` returns the bytes |
| `share_bound_positions_parties_and_sizes_match_the_backends` | `crates/coord-shared/src/lib.rs` | `min_parties` is `3t + 1` (HoneyBadger) and `2t + 1` (AVSS); `share_id_of_position` is `p` and `p + 1`, matching the ids RanSha and AVSS share generation give party `p`; `serialized_share_len(t)` equals `CanonicalSerialize::serialized_size` of a real share — 48 bytes for `RobustShare<Fr>`, 344 for `FeldmanShamirShare<Fr, G1>` at `t = 5` (C.1) |
| `reconstruction_excludes_relabelled_resized_and_corrupted_shares` | same | HoneyBadger, `n = 4, t = 1`: a share relabelled with another position's id, or of degree 0, is ignored and the other three reconstruct; one wrong value among four still reconstructs the right secret; `Pending` with only two valid shares. AVSS, `n = 3, t = 1`: a share off its own commitments is ignored; a corrupt node presenting consistent commitments of its own design, chosen to accept an honest share, never reaches `t + 1` supporters; the honest two reconstruct |
| `program_hash_of_matches_the_shared_golden_vector` | `crates/coord-shared/src/admission.rs` | `program_hash_of(b"stoffel golden program")` is `fe9f7bf2…79ee` (§C.1) |
| `invitation_signing_bytes_have_the_documented_layout` | same | the v3 layout of C.3, with no option tag |
| `a_signed_invitation_verifies_only_for_its_registration_program_roster_window_invitee_and_issuer` | same | `WrongExecution`, `WrongRegistration`, `WrongProgram`, `WrongRoster`, `Expired`, `WrongInvitee`, `BadSignature` |
| `an_invitation_binds_only_the_slot_it_names` | `crates/off-chain/tests/off_chain.rs` | on a table of an input-only slot 0 and an output slot 1, an invitation for slot 0 binds slot 0 with `slot: None`, is `SlotMismatch` with `slot: Some(1)`, and leaves slot 1 to the invitation that names it |
| `masked_input_and_sealed_output_signatures_have_the_documented_layout_and_bind_every_field` | `crates/coord-shared/src/signing.rs` | the two layouts of C.7; `sign_with_pkcs8` then `verify_identity_signature` succeeds for a P-256 and an Ed25519 key; changing the nonce, slot, first index, any input, the position, the encapsulated key or the ciphertext fails verification; a signature from another key fails |
| `registration_refuses_an_issuer_that_is_a_roster_node_or_the_coordinator` | `crates/coord-shared/src/admission.rs` | `IssuerIsRosterNode`, `IssuerIsCoordinatorKey` |
| `registration_bounds_keep_every_response_under_the_wire_limit` | same (`serde_json` as a dev-dependency) | at the C.1 bounds, `ClientAdmissionSet`, `ExecutionSummary`, a `MaskedInputEvent` of `MAX_INPUTS_PER_SLOT` inputs of `MAX_MASKED_INPUT_BYTES`, and a `SealedOutputShares` of `MAX_SEALED_OUTPUT_BYTES` serialize — notification envelope included — within C.1's measured sizes, under 10 MiB; one past each slot bound is refused (`TooManyClientSlots`, `TooManyInputsInSlot`, `TooManyOutputsInSlot`, `TooManyInputs`) |
| `registration_refuses_missing_or_disordered_deadlines_and_non_canonical_clients` | same | `DeadlinesRequired` under `Open` and `Invitation`; `DeadlinesOutOfOrder`; `DeadlineElapsed`; `UnsupportedPreRegisteredKey` for a 33-byte identity — replaces revision 1's planned `registration_refuses_an_output_quorum_below_t_plus_one_and_missing_deadlines`, whose field is gone |
| `registration_checks_state_in_order_and_never_evicts_for_a_refused_one` | `crates/off-chain/tests/off_chain.rs` | an identical registration of a live execution past its association deadline returns its nonce; an ended id is `ExecutionIdRetired`; a different registration of a live id is `ConflictingRegistration`; at capacity with an evictable execution, a registration that fails `validate` is refused and the evictable one is still registered |
| `deleted_methods_are_not_rpc_methods` | same | raw JSON-RPC calls to `register_execution`, `request_shutdown`, `available_input_masks`, `reserve_mask_index`, `submit_masked_input`, `sub_assigned_reserved_indices` and `sub_assigned_masked_inputs` answer `METHOD_NOT_FOUND` (-32601) |
| `get_node_roster_is_served_to_a_caller_no_configuration_names` | same | a certificate minted in the test fetches the roster |
| `summary_reads_are_rate_limited_per_identity` | same | the eleventh `get_execution_summary` or `get_node_roster` call in a burst from one identity is `RateLimited` (41); another identity is unaffected; a token returns after a second |
| `pre_registered_admission_binds_only_the_registered_identities` | same | registered identity gets its slot; others `NotPreRegistered`; `PreRegisteredSlotMismatch` |
| `open_admission_binds_disjoint_ranges_first_come_first_served` | same | ranges partition `[0, n_inputs)`; `slot: Some(i)` honoured; `SlotTaken` |
| `open_admission_refuses_association_past_capacity` | same | `CapacityExhausted { capacity }` |
| `associate_client_is_idempotent_for_an_identical_request_and_refuses_a_different_one` | same | same admission returned in a later round; `AlreadyAssociated`; `ExecutionNotFound` once the execution is removed |
| `association_closes_when_input_collection_begins` | same | `AssociationClosed { current: InputCollection }` |
| `invitation_admission_accepts_a_valid_invitation_and_refuses_every_forgery` | same | `InvitationRequired`, `InvitationRejected{..}`, `UnexpectedInvitation` under `Open` |
| `an_invitation_for_an_earlier_registration_of_the_same_id_is_refused` | same | a coordinator restarted with the same `ExecutionId` and registration draws a new nonce, and the old invitation is `InvitationRejected { reason: WrongRegistration }` |
| `an_output_slot_refuses_a_key_output_shares_cannot_be_sealed_to` | same | `UnsupportedClientKey` for an Ed25519 client certificate |
| `a_reservation_must_name_exactly_the_admitted_range` | same | `NotAdmitted`, `ReservationOutsideAdmission` — **retargets** `client_may_only_call_reserve_mask_indices_once` and `reserve_mask_indices_rejects_empty_batch` onto admitted clients |
| `a_submission_must_cover_the_admitted_range_once_within_bounds_and_signed` | same | `SubmissionOutsideAdmission` (37) for a partial range, another start or an input-less slot; `MaskedInputTooLarge` (36) at 65 bytes, accepted at 64; `BadMaskedInputSignature` (38) for a signature by another key or over another nonce; `IndexNotReserved` (6) before reserving; `MaskedInputAlreadySubmitted` (5) for a second submission; the accepted submission reaches `sub_masked_inputs` byte for byte, signature included |
| `every_event_subscription_refuses_an_unadmitted_certificate` | same | `sub_round` → 31; `sub_reserved_indices`, `sub_masked_inputs` → 10; nothing is parked |
| `parked_subscriptions_are_bounded_per_caller_and_pruned_when_closed` | same | a fifth parked `sub_round` for one round from one identity drops that identity's oldest; closed sinks are dropped before parking, on the coordinator and in the node RPC listener's `assigned_sinks` |
| `no_subscriber_holds_the_state_mutex_or_another_subscriber` | same | a node subscription whose client never reads, on an execution with a replay history longer than `message_buffer_capacity`, does not delay `associate_client` on another execution or `get_node_roster` past 100 ms; a live broadcast to it fails its `try_send` and drops it while the other subscribers receive the event; a subscriber whose replay overlaps a live reservation receives every event exactly once, in order |
| `sealed_outputs_are_bounded_signed_and_delivered_one_node_per_message` | same | `SealedOutputTooLarge` (39) one byte past the bound; `BadOutputSignature` (40) for a signature over another position or by another node; accepted items reach `obtain_output_shares` one per message with the sender's position, live and on replay; one node's refused oversized item leaves the others deliverable — **retargets** `output_waiters_receive_threshold_and_later_share_snapshots` (`:1292`), whose threshold snapshots no longer exist |
| `a_client_reconstructs_despite_a_relabelled_or_corrupted_node_share` | same | through `NodeRPCClient::receive_assigned_masks`: a HoneyBadger node RPC server that relabels its mask share with another node's id, and an AVSS one that sends a wrong share, are each excluded and the mask reconstructs correctly; through `obtain_outputs` against a relaying fake coordinator: an item whose signature is another node's, whose position is out of range, or which fails to decrypt is excluded and the outputs reconstruct |
| `a_honeybadger_client_refuses_an_undersized_roster_before_associating` | same | on a roster of `n = 3, t = 1`, `associate_client` of a HoneyBadger client returns `TopologyUnsupportedByBackend { n: 3, t: 1, required: 4 }` and the coordinator records no binding; an AVSS client associates; a slot whose AVSS outputs exceed `MAX_SEALED_OUTPUT_BYTES` is `SealedOutputsExceedBound`, also without a binding |
| `input_collection_is_held_until_every_slot_is_bound` | same | proposals recorded; round applies inside the binding `associate_client` |
| `round_skips_require_an_empty_slot_table` | same | the `Preprocessing` → `MPCExecution` skip is held for an execution with inputs, and `MPCExecution` → `ProgramFinished` for one with an output slot, while the zero-input, zero-output skips still apply — **retargets** `zero_input_execution_skips_input_rounds` |
| `an_unbound_slot_at_the_association_deadline_aborts_the_execution` | same | round `Aborted`; parked `sub_round` waiters receive `ExecutionAborted { AssociationDeadline }`; later calls answer 35; the execution is evictable without acknowledgements; re-registering its id is `ExecutionIdRetired` |
| `a_one_off_coordinator_aborts_at_the_association_deadline_and_drains` | same | the same as the test above, through `start_coord_one_off`; and the one-off drain completes after the nodes acknowledge the abort |
| `a_missing_input_at_the_input_deadline_aborts_the_execution` | same | `InputDeadline { missing_inputs }` with `missing_inputs > 0`; a node's `wait_for_masked_input_submissions` ends with `ExecutionAborted` |
| `an_input_deadline_with_every_input_present_does_not_abort` | same | the last submission arrives just before the input deadline, the deadline passes before any node proposes `MPCExecution`, and the round is still `InputCollection`, not `Aborted`; the later proposals apply |
| `an_abort_reaches_sinks_a_broadcast_holds_and_subscriptions_between_accept_and_parking` | same | with the input deadline firing while a submission's broadcast holds the delivery guard, every `sub_masked_inputs` subscriber receives `ExecutionAborted` and none is re-parked; a subscription paused between `accept` and its re-lock (a test hook) receives `ExecutionAborted` rather than parking |
| `an_ended_execution_stays_refused_after_unanimous_retirement` | same | after an abort and every node's `retire_execution`, re-registering the id is `ExecutionIdRetired`, `get_execution_summary` answers 35 with the `AbortReason`, and `retire_execution` still succeeds; after a normal finish and unanimity, `get_execution_summary` is 16 and re-registering is `ExecutionIdRetired`; the 4,097th later ended execution evicts the oldest entry |
| `the_retirement_watch_wakes_on_every_path_that_changes_it` | same | `watch_for_retirement_quorum` resolves promptly — without a polling interval — after the quorum's last `retire_execution` in `ProgramFinished`, after an abort once the quorum acknowledged, and after a removal by unanimity that happened before the watcher first looked |
| `a_removal_during_output_delivery_does_not_panic` | same | an execution removed between `send_output_shares` releasing its guard and `deliver_ready_output_waiters` re-locking (a test hook) leaves the connection task running and the call answered |
| `a_listener_refuses_state_for_a_certificate_it_does_not_serve` | same | `start_coord`, `start_coord_from_cert` and `start_coord_one_off` with a state built for another key return `ServerCertificateMismatch` and bind nothing |
| `a_refused_subscription_decodes_to_a_typed_error` | same | `wait_for_indices`, `wait_for_round` and `obtain_outputs` on an aborted execution return `CoordinatorError::ExecutionAborted` with its reason, and `wait_for_indices` from a non-node returns `NotParty` — no panic |
| `client_admissions_are_node_only_and_frozen` | same | `NotParty` for a client; `AdmissionsNotFrozen` before the freeze; complete set after |
| `a_node_rpc_client_refuses_a_node_outside_the_roster_and_a_duplicated_node` | same | `ServerPinMismatch`; `DuplicateNodeIdentity` — **retargets** the VM's `a_client_pinned_to_the_roster_refuses_a_node_outside_it` (`crates/stoffel-vm/src/net/mesh/roster.rs:778`), whose API is removed |
| `open_admission_end_to_end_with_a_client_minted_at_test_time` | same | in one process: coordinator under `Open`, node RPC servers presenting roster certificates, and a client whose certificate is generated after the coordinator starts; it associates, reserves, reconstructs its mask by position, submits a signed range, and reconstructs its output from signed per-node items; its identity appears in no registration field |
| `one_off_coordinator_drains_after_the_retirement_quorum_of_a_terminal_round` | same | acknowledgements before `ProgramFinished` do not start the drain; the quorum after it does — **retargets** `one_off_shutdown_does_not_disconnect_a_slow_party_before_terminal_replay` and `one_off_shutdown_grace_bounds_a_missing_party` onto `watch_for_retirement_quorum` |
| `unanimous_retirement_keeps_outputs_for_the_retention_window` | same | an output client subscribing after every node retired still receives every node's item within `output_retention`, and `ExecutionNotFound` after it |
| `client_slots_ignore_scalar_share_types` | `crates/bins/src/bin/run-coord.rs` | **retargets** `input_assignment_ignores_scalar_share_types` |
| `run_coord_registers_its_execution_at_startup_in_both_modes` | same | the parsed flags produce one registration with or without `--one-off`; `--program` and `--hash` are exclusive; `--backend` and `--min-output-shares` are unknown flags |
| `issue_invitation_requires_a_slot_and_refuses_one_past_capacity` | `crates/bins/src/bin/issue-invitation.rs` | a missing `--client-index` is a clap error; an index not below the summary's capacity exits 2 without writing `--out` |
| `start_node_rpc`, `end_to_end` | `crates/on-chain/tests/on_chain.rs` | **retargeted**: each builds `NodeRoster::new(t, …)` from its node RPC servers' certificates and passes it to `NodeRPCClient::start_rpc_client` or `start_rpc_client_from_cert`, which lost `n` and `t` (§A "The on-chain crate") |

Every other `off_chain.rs` test (`end_to_end`, `end_to_end_fake_coord`, `trigger_pp`,
`transition_needs_a_quorum_and_ignores_which_parties_form_it`,
`mpc_execution_waits_for_every_masked_input`,
`resubscribing_for_assigned_mask_shares_supersedes_stale_request`,
`retirement_drains_healthy_stragglers_without_pinning_capacity`, …) is **retargeted** onto
`NodeRoster`, in-process slot-and-policy registrations, pinned clients, association before
reservation, one signed submission per slot and per-node signed outputs, with its
assertions unchanged. `end_to_end` (`:958`) and `end_to_end_fake_coord` (`:1180`) register
their admitted reservations with `register_admitted_reservations_for_execution` (shared
`run_node`) instead of the deleted unassigned form (§C.10).
`one_listener_isolates_and_retires_concurrent_executions` registers its two executions
through `OffChainCoordinatorServer::state()` instead of the deleted RPC. The tests built on
`n = 1, t = 0` — `coordinator_state(.., 1, 0, ..)` at `off_chain.rs:248`, `:270`, `:371`,
`:743`, `:773`, `:810`, `new(1, 0, ..)` at `:160`, and the `n = 1, t = 0` node client of
`dropping_node_server_closes_connections_and_releases_port` (`:415`) — move to `n = 3,
t = 1` with two proposing node clients, since `ZeroThreshold` refuses the old topology and
`transition_quorum()` is 2 at `n = 3`. The tests that reconstruct HoneyBadger shares
(`end_to_end`, `end_to_end_fake_coord`) keep `n >= 3t + 1`, since `min_parties` is now
checked before association. Revision 1's planned
`assigned_events_are_chunked_and_carry_admission_ordinals` and
`a_short_output_snapshot_is_waited_on_not_failed` tested streams and snapshots that no
longer exist; `deleted_methods_are_not_rpc_methods`,
`sealed_outputs_are_bounded_signed_and_delivered_one_node_per_message` and
`a_client_reconstructs_despite_a_relabelled_or_corrupted_node_share` replace them.

**This repository**, by stage (§9.1):

| Test | Location | Stage | Asserts |
|---|---|---|---|
| `a_restarted_party_never_draws_the_same_mask_or_triple_twice` | `crates/stoffel-vm/src/tests/mesh_hb_integration.rs` (`hb_itest`, as its siblings) | V-0 | five in-process HoneyBadger engines, each over its own LMDB store, preprocess, take mask shares and run a multiplication; the engines are dropped and five new ones over the same stores preprocess again and do the same; no mask share and no Beaver triple drawn in the second session is byte-equal to one drawn in the first, and no store holds a material blob after either session |
| `a_restarted_avss_party_never_draws_the_same_share_twice` | `crates/stoffel-vm/src/tests/avss_e2e_integration.rs` (`avss_itest`) | V-0 | the same for AVSS random shares and triples |
| `the_preprocessing_store_flag_fails_by_name` | `crates/stoffel-vm-runner` binary tests | V-0 | `--preproc-store` exits 2 with its D.3 hint |
| `a_coordinator_roster_matches_the_golden_digest` | `crates/stoffel-vm/src/net/mesh/roster.rs`, over `ids/nodes/*.crt` (certificates only) | V-a | the same order and digest as the coordinator's golden test |
| `a_roster_whose_served_digest_disagrees_is_refused` | same | V-a | `RosterError::DigestMismatch` |
| `a_roster_below_two_t_plus_one_or_with_a_zero_threshold_is_refused` | same | V-a | `ThresholdTooLarge` for `n = 2, t = 1` and `n = 3, t = 2`; `ZeroThreshold` — the **retarget** of `a_threshold_at_or_above_the_party_count_is_refused` (`:517`), whose accepted `n = 2, t = 1` came from the NAT stack §4 deleted; the old test leaves with `Roster::new` in V-c |
| `a_served_certificate_that_is_not_a_certificate_names_its_index` | same | V-a | `ServedCertificateUnderivable { index }` — the **retarget** of `a_file_that_is_not_a_certificate_names_itself` (`:1038`), which leaves with `from_cert_paths` in V-c |
| `the_digest_ignores_input_order_but_not_membership_or_threshold` | same | V-a | the **retarget** of `the_digest_ignores_input_order_but_not_membership_or_parameters` (`:551`, the client dimension is gone); the old test leaves in V-c |
| `an_allowlisted_non_node_key_is_ranked_as_a_server_peer` | same | V-a | pins the stoffelnet behaviour behind rule 3: an allowlisted extra key dialing with the server ALPN lands in `peer_public_keys` and in `get_sorted_public_keys` |
| the node-only `roster.rs` tests, the tournament tests (`join.rs:1533`, `:1592`), `avss_server.rs`'s `pinning_the_mesh_roster_after_start_is_an_error_rather_than_a_silent_no_op`, the harness tests of `mesh_join_harness.rs` and the `stoffel-run.rs` binary test at `:5820` | as listed in D.4 | V-a | **retargeted** onto `Roster::from_node_keys`; sizes `3..=8` and three identities where D.4 says so; assertions unchanged |
| `the_program_id_matches_the_shared_golden_vector` | `crates/stoffel-vm/src/net/program_sync.rs` | V-a | `program_id_from_bytes(b"stoffel golden program")` is `fe9f7bf2…79ee` (§C.1) |
| `the_instance_id_depends_on_the_roster_digest` | `crates/stoffel-vm/src/net/session.rs` | V-a | same program and epoch, different digests → different ids; **retargets** `derive_instance_id_is_deterministic_and_domain_separated` onto the v2 signature |
| `a_party_proposing_another_execution_is_refused_at_the_join` | `crates/stoffel-vm/src/net/mesh/join.rs` tests | V-a | `SessionDivergence { field: ExecutionId }` |
| `a_digest_barrier_names_the_first_divergent_peer` | `crates/stoffel-vm/src/net/mesh/barrier.rs` | V-a | `AdmissionDivergence` and `InputDivergence` name the peer; a peer that announced two digests is divergent |
| `a_digest_barrier_keeps_a_frame_that_arrives_before_the_local_digest` | same | V-a | `record` before `wait` still counts; a frame in another namespace is consumed and not counted |
| `digest_barrier_frames_classify_only_at_their_exact_length` | same | V-a | `prefix + 8` and `prefix + 8 + 31` bytes classify as `None` |
| `the_admission_agreement_digest_is_order_independent_and_field_sensitive` | `crates/stoffel-vm-runner/src/admissions.rs` | V-b | changing any encoded field, nonce and deadlines included, changes the digest; record order is canonical |
| `the_inputs_agreement_digest_is_field_sensitive` | same | V-b | the first index, the identity, any masked input and the signature each change the digest |
| `reservations_are_released_only_when_they_match_the_agreed_admissions` | same | V-b | a reservation naming another identity, a partial range, or an unreserved agreed range is `ReservationMismatch`, and nothing is released; `input_ordinal = index - start` |
| `submissions_the_agreed_admissions_do_not_match_are_refused` | same | V-b | `MissingSubmission`, `RangeMismatch`, `UnexpectedClient`, and `BadSignature` for a submission signed by another key, over another nonce, or re-signed after one input changed; a correctly signed set passes — replaces revision 1's planned `masked_inputs_from_an_identity_the_admissions_do_not_name_are_refused` |
| `a_summary_for_another_program_an_undersized_roster_undeliverable_outputs_or_a_mismatched_slot_is_refused` | same | V-b | each `SummaryMismatch`: `TopologyUnsupported` for HoneyBadger at `n = 3, t = 1` but not AVSS; `SealedOutputsTooLarge` for AVSS at `t = 41` with 1,024 outputs but not at `t = 40`; a manifest slot the registration lacks is accepted — replaces revision 1's planned `…_a_short_output_quorum_or_a_mismatched_slot_is_refused` |
| `removed_flags_fail_by_name_with_hints_that_name_no_removed_flag` | `crates/stoffel-vm-runner` binary tests | V-b | every D.3 removed flag, `--timestamp` included, exits 2 with its hint; no hint or refusal message of D.3 — the rewritten ones included — names a flag D.2 removes |
| `off_chain_coord_without_a_pin_is_refused` | same | V-b | the D.3 message, exit 2 |
| `an_unreadable_coord_cert_names_its_path` | same | V-b | the D.3 message, exit 2 — the **retarget** of `a_missing_certificate_file_names_itself` (`roster.rs:1025`), whose file I/O moved to `--coord-cert`; the old test leaves in V-c |
| `direct_client_mode_is_refused_by_name` | same | V-b | the E.3 message, exit 2, and no QUIC endpoint is created |
| `a_node_absent_from_the_coordinator_roster_exits_before_binding` | same | V-b | the D.3 non-member message, exit 2, no socket bound |
| `an_unexpected_roster_size_or_digest_is_refused_before_binding` | same | V-b | against an in-process coordinator, `--expect-n-parties 7`, `--expect-threshold 2` and a wrong `--expect-roster-digest` each exit 2 with their D.3 message; a malformed digest exits 2 with the `RosterDigestParseError` |
| `coordinated_run_errors_exit_4_for_execution_and_output_rights_only` | `crates/stoffel-vm-runner/src/bin/stoffel-run.rs` tests | V-b | `CoordinatedRunError::exit_code` is 4 for `Execution` and both `OutputRightsViolation`s and 13 for every other variant, on both backends' paths |
| `a_mesh_party_is_pinned_to_the_coordinator_and_names_no_roster_or_client` | `crates/stoffel-vm-runner/src/local_runner.rs` | V-b | `--coord-cert` present; `--roster`, `--expected-clients`, `--n-parties`, `--threshold`, `--timestamp` absent — **retargets** `the_mesh_topology_replaces_bootstrap_with_seeds_a_roster_and_an_epoch_store` |
| `expected_clients_create_output_identities_for_dynamic_outputs`, `expected_clients_union_keeps_manifest_inputs_and_output_only_slots` | same | V-b | **retargeted** as F.4 says |
| `sparse_client_slots_are_refused_at_build`, `run_refuses_open_admission_with_client_slots` | same | V-b | the F.4 `Configuration` errors; `local_runner_rejects_expected_output_clients_below_static_manifest_slots` (`tests/local_coordinator_e2e.rs:395`) still gets `expected_clients >= 3`, unchanged |
| `the_run_directory_and_key_files_are_private` | same, `#[cfg(unix)]` | V-b | the run directory's mode is `0700`, every `*.key.der` file's `0600`; creating a run directory over an existing path fails |
| `no_image_or_stack_distributes_a_private_key` | `crates/stoffel-vm-runner/tests/deployment_key_material.rs` (new) | V-b | §F.0's four checks over every Dockerfile and compose file, and each check fails on a fixture line that breaks it (`"9000:9000"`, a long-form port without `host_ip`, `network_mode: host`) |
| **`local_offchain_coordinator_admits_an_unconfigured_client_under_open_admission`** | `crates/stoffel-vm-runner/tests/local_coordinator_e2e.rs` | V-b | see below |
| `an_execution_without_outputs_reaches_program_finished_and_is_retired` | same (`#[ignore]`d like its siblings) | V-b | a run of a program with no client IO finishes, and afterwards `get_execution_summary` from a fresh pinned connection answers `ExecutionNotFound` (16): every node proposed `finalize`, reached `ProgramFinished` and retired (§D.7 step 12) |
| `a_local_client_refuses_a_node_rpc_listener_outside_the_served_roster` | same | V-b | `#[ignore]`d like its siblings: under `start()`, a `NodeRPCServer` presenting a freshly minted certificate is put among the endpoint's node RPC addresses, and `run_offchain_client` fails with `CoordinatorError::ServerPinMismatch` — this repository's own cover for the client-leg pin (§E.1 step 5), beside the coordinator test it moved to |
| `an_sdk_server_presents_its_identity_and_coordinator_pin` | `crates/stoffel-rust-sdk/tests/sdk_usage.rs` | V-b | **retargets** `an_sdk_server_presents_its_identity_and_roster_without_a_coordinator` |
| `an_sdk_mesh_server_without_seeds_a_coordinator_pin_or_an_epoch_store_is_refused` | same | V-b | **retargets** `an_sdk_mesh_server_without_seeds_a_roster_or_an_epoch_store_is_refused` |
| `an_sdk_coordinator_pin_without_an_identity_is_refused` | same | V-b | **retargets** `an_sdk_roster_without_an_identity_is_refused` |
| `an_sdk_coordinator_party_names_its_execution_and_drives_nothing` (`:2346`), `an_sdk_mesh_server_dials_its_peers_instead_of_a_bootnode` (`:2434`) | same | V-b | **retargeted** argv: `--coord-cert`, `--expect-n-parties` and `--expect-threshold` present, the latter two carrying `mpc_config`'s `parties` and `threshold`; `--roster`, `--n-parties`, `--threshold`, `--expected-clients`, `--timestamp` absent |
| `offchain_client_config_takes_its_topology_from_the_coordinator` | same | V-b | **retargets** `offchain_client_config_defaults_to_five_party_topology` (`:2948`): the builder has no `parties`, `threshold` or `timestamp`; a served HoneyBadger roster below `3t + 1` is `Error::Unsupported` |
| `offchain_client_config_reports_actionable_validation_errors` (`:3069`) | same | V-b | **retargeted**: its topology and timestamp cases move to the test above; a missing or unusable `coordinator_cert_der` is added |
| `offchain_client_config_round_trips_toml_and_identity_files` (`:3181`) | same | V-b | **retargeted** to the E.2 schema |
| `runtime_derives_offchain_client_config_from_typed_program_metadata` (`:3315`) | same | V-b | **retargeted**: asserts `client_slot == Some(ClientIndex(0))`, the backend and the types, not `parties` or `output_count` |
| `submit_returns_pending_handle_for_live_offchain_submission` (`:3279`) | same | V-b | **retargeted**: no `.server(..)`; the config carries a coordinator certificate |
| `client_and_server_lifecycle_validate_real_network_configuration` (`:4598`) | same | V-b | **retargeted** onto `node_rpc_addresses` validation, and `connect` without `offchain_io` → `Error::Configuration` naming `offchain_io` |
| `client_connect_opens_a_pinned_coordinator_link` | same | V-b | **retargets** `client_connect_uses_real_quic_transport` (`:4883`): against an in-process coordinator whose roster is minted in the test, `connect` succeeds and `node_roster().n()` is the roster's; a wrong `coordinator_cert_der` yields `ServerPinMismatch` |
| `sdk_local_runs_refuse_output_only_slots_without_counts` | same | V-b | `execute_local` over a program with dynamic outputs and expected clients past the manifest returns `Error::Configuration` naming `client_output_count` before any party starts, and runs once the counts are set (§E.2) |
| `run_network_refuses_a_node_network_config_by_name` | `crates/stoffel-cli/tests/cli.rs` | V-b | **retargets** `run_network_accepts_network_config_and_attempts_connection` (`:2270`) |
| `run_network_validates_config_path_before_parsing` (`:1938`) | same | V-b | **retargeted** fixture (E.2) |
| `an_installed_node_roster_refuses_every_client_certificate` | `crates/stoffel-vm/src/net/mesh/roster.rs` | V-c | a certificate that is not a node is refused at the mesh transport in both ALPN roles — **retargets** `a_roster_admits_its_clients_alongside_its_nodes`, `a_roster_pinned_node_admits_its_clients_and_refuses_an_unlisted_one`, `a_roster_pinned_node_refuses_a_client_that_brings_no_certificate`, `a_listed_client_still_exchanges_bytes_through_an_allowlisted_node` and `a_clone_taken_before_the_install_still_enforces_the_roster_for_clients` |

The docker scripts of §F.2 are their stage's end-to-end check: `test-coordinator-preproc-store.sh`
for V-0 (no material reloaded) and V-b (the epoch advances), `test-coordinator-reserve-index.sh`
and `run_coordinator_compose.sh` for V-b.

`crates/stoffel-vm-runner/Cargo.toml` gains `blake3 = "=1.8.5"` in `[dependencies]`
(`admissions.rs`) and `rcgen = "=0.14.8"` in `[dev-dependencies]` (the end-to-end tests
mint certificates); both versions are the ones `crates/stoffel-vm/Cargo.toml` already pins.

**The required end-to-end test,
`local_offchain_coordinator_admits_an_unconfigured_client_under_open_admission`.** It is
`#[ignore]`d like its siblings, and is added to the `local-topology-e2e` CI job beside
`local_offchain_coordinator_runs_networked_vm_over_a_roster_mesh`.

1. Compile, for HoneyBadger, a one-slot program that takes `ClientStore.take_share(0, 0)`,
   sends that share back with `send_to_client(0)`, and returns the opened value plus 5.
2. `LocalCoordinatorRunner::builder(…).parties(5).threshold(1).admission(LocalAdmission::Open)`,
   then `start()`: an in-process coordinator whose registration is one slot `1:1` under
   `Open` with deadlines, and five real `stoffel-run` parties.
3. **Only now** mint the client certificate with `rcgen::generate_simple_self_signed` — so
   it cannot appear in any flag, environment variable, file or registration of the run —
   and assert `get_execution_summary` reports `AdmissionPolicyKind::Open` and deadlines:
   the registration names no identity at all.
4. Connect it with `OffChainCoordinatorClient::start_rpc_client_for_execution` (pinned to the
   endpoint's coordinator certificate) and `associate_client(AssociationRequest { slot:
   None, invitation: None })`; assert slot 0, input range `[0, 1)`,
   `OutputRights::Receive { output_count: 1 }`.
5. Mint a second certificate and assert its `associate_client` fails with
   `AdmissionError::CapacityExhausted { capacity: 1 }`. This is deterministic: the first
   client has not reserved yet, so no honest node can have proposed `InputCollection`, and
   association is still open.
6. `run_offchain_client(endpoint, cert, key, <the identical request>, &["42"], timeout)`. Its
   association is the idempotent case and must return the step 4 admission; its submission
   is one signed call; its output arrives as five signed per-node items. Assert
   `LocalClientRun.outputs` is `[42]`, and that `finish()` reports every party returned `47`.

### I. Implementation status (2026-09-19)

The status of record for both repositories. §9 is otherwise written as a contract, in the
present tense; where the code deliberately differs from it, the difference is listed here
and marked **as built** in the section it belongs to.

| Stage (§9.1) | State |
|---|---|
| C-a `coord-shared` — `pin.rs`, `roster.rs`, `admission.rs`, `signing.rs`, `ShareBound`, `caller_identity`, `RpcServerLimits`, TLS 1.3-only, pinned `setup_client` | done, in `stoffel-mpc-coordinator-roster-admission` at version `0.3.0` |
| C-b `off-chain` — registration, admission RPCs and gates, signed submissions, per-node sealed outputs, delivery discipline, deadlines and sweeper, ended executions, `OffChainCoordinatorConnection` | done |
| C-c `on-chain` and `bins` — roster-taking node RPC client, `run-coord` flags, `issue-invitation`, CHANGELOG and README | done |
| V-0 no preprocessing item serves two executions | **not done.** `persist_preproc` is still called by both engines (`crates/stoffel-vm/src/net/mpc/{honeybadger,avss}/preprocessing.rs`) and `stoffel-run` still parses `--preproc-store`. What has landed is the deployment half: no compose stack sets `STOFFEL_PREPROC_STORE`, the entrypoint refuses it by name with the §D.3 hint, and `docker/test-coordinator-preproc-store.sh` refutes both persistence and load. A direct `stoffel-run --preproc-store` run can still draw a stored item into a second execution |
| V-a additive roster, session and barrier work | done |
| V-b the pin bump and everything that breaks with it | done; the `[patch.crates-io]` tables and `=0.3.0` pins are in both workspaces (§F.5) |
| V-c deletion of the now-dead branches | **partly.** The legacy `Roster` API, `run_as_client` and direct client mode went with V-a/V-b. Still present and unreachable: the uncoordinated party branches in `stoffel-run` (`setup_hb!` / `setup_avss!`, `sync_client_set_across_parties`, `ServerClientAdapter`), kept because nothing reaches them — a party without `--off-chain-coord` is refused at flag parsing |
| §F deployment — every stack runs a coordinator, the wrapper's flags, the entrypoint, the scripts, the key-material rule | done, with the three **as built** differences in §F.1 and those in §F.2 and §F.3 |

**Every stack runs a coordinator.** `docker-compose.yml`, `docker-compose.mesh.yml`,
`docker-compose.avss.yml`, `docker-compose.benchmark.yml`,
`docker-compose.coordinator.reserve-index.yml` (with its `.preproc.yml` override),
`crates/stoffel-lang/examples/docker-compose.coordinator.yml` and
`crates/stoffel-lang/examples/docker-compose.mpc.yml` each define a `coordinator` service
that registers the program the parties load, serves the node roster and decides admission;
no party carries a roster, a party count, a threshold or any client identity, and the
entrypoint refuses each of those variables by name. `docker-compose.nat.yml` is deleted
(§4).

**What is not covered by a run of the shipped stacks.** The coordinator images cannot be
built on a machine that does not hold a `stoffel-mpc-coordinator` `0.3.0` checkout (below),
so the compose stacks of this change have been validated with `docker compose config`, with
the entrypoint's emitted argv checked directly, and with the native rehearsals earlier
stages recorded — not by a full `docker compose up` of every stack. The one Docker build
step this stage did run is `docker/coordinator.Dockerfile`'s `planner` stage with the
`coordinator` named context, which is where `cargo metadata` first has to resolve the
patched path: it succeeds, and the context transfer honours the coordinator checkout's
`.dockerignore` (about 1 MB, not its `target/`).

**Building images during the patch window (§F.5).** Nothing in a Docker build context can
see the absolute path the `[patch.crates-io]` tables name, so every Dockerfile that
resolves a workspace copies a BuildKit named context, `coordinator`, to exactly that path
before the first `cargo` invocation of the stage, and every compose build block declares
that context from `STOFFEL_COORDINATOR_CONTEXT` with `:?`. The images therefore build **only**
on a machine holding the `0.3.0` checkout, and only when that variable points at it:

```bash
export STOFFEL_COORDINATOR_CONTEXT=/path/to/stoffel-mpc-coordinator   # the 0.3.0 checkout
docker compose up --build
```

Outside compose the same context is passed with
`docker build --build-context coordinator=$STOFFEL_COORDINATOR_CONTEXT …`. A plain
`docker build .` cannot build these images, CI's `docker-build` job cannot build them —
`COPY --from=coordinator` resolves `coordinator` as an image reference there — and the Rust
CI jobs cannot resolve the patch path either. All of that ends with the patch: when `0.3.0`
is published, the `[patch.crates-io]` tables, the `COPY --from=coordinator` lines and the
`additional_contexts` entries are deleted together and both lockfiles are re-locked.

**Other open items.** `crates/stoffel-lang/examples/run_mpc_local.sh` runs the wrapper
binary as a host-process coordinator instead of `stoffel run --local` (§F.2), because the
local runner requires consistent party returns and that script's default program,
`mpc_runtime_info`, returns a different value per party. Invitation admission has no
shipped stack: the wrapper, the client flag (`--invitation`, `STOFFEL_INVITATION`) and the
coordinator's `issue-invitation` binary are all in place, and a stack registers it with
`STOFFEL_ADMISSION=invitation` plus an issuer certificate mounted into its coordinator
service, but no compose file does so by default.

## 10. Post-audit hardening (2026-09-20)

Four findings from the final audit were resolved against the user's stated requirements.

**1. Preprocessing material is never served to two executions.** The audit read this as an
open hole because stage V-0 (delete `persist_preproc` and the store outright) was never
implemented. Re-examined at the storage layer, the guarantee already holds without deleting
the feature: `load` is destructive (`store.delete` after the claim), and the claim itself is a
compare-and-swap on the consumed cursor inside a single LMDB write transaction served by a
single-threaded actor (`storage/preproc.rs`, `DbRequest::Reserve`). Two claimants reading the
same blob cannot both advance the cursor from the value they read.

This is now pinned by `a_preprocessing_item_is_never_served_to_two_executions`, which races two
`LmdbPreprocStore` handles on one directory — the cross-process case — and asserts the item
ranges they receive are **disjoint**. Disjointness, not refusal, is the property the privacy
argument needs: a second execution handed a *different* slice is fine, handed the *same* slice
is a privacy break.

Honest limitation, recorded in the test's own documentation: the guarantee is structural rather
than guarded. Disabling the CAS does not make the test fail, because the `consumed > count`
bound still refuses the overclaim. The test locks in the observable contract; it is not
evidence that the CAS is load-bearing.

**Deliberate divergence from §9.I:** V-0 as specified would have deleted the preprocessing store
entirely. That is a blunter guarantee, and it would have removed preprocess-ahead-across-restart
— which the persistent-network design (`docs/design/persistent-mpc-network-plan.md`) depends on.
The requirement is that material is never used twice, not that it is never stored.

**2. The roster digest is independently checkable.** Roster substitution is an accepted risk —
the coordinator is the roster authority by design — but people must be able to verify that the
roster they were handed is the one they expect. The digest was already printed by the
coordinator at startup and by every node on fetch. What was missing was a way to compute it
from the certificate files *without* asking the coordinator. Added: the `roster-digest`
binary in the coordinator's `bins` crate.

```text
roster-digest --t 1 --node-certs ids/nodes/cert0.crt,...,ids/nodes/cert4.crt
roster-digest --t 1 --expect <digest> --node-certs ...   # exit 1 on mismatch, to gate a script
```

It talks to nothing, is order-independent (the roster sorts into canonical order before
hashing), and for the shipped certificates prints
`da7fa2fee0f97aaef9e77aa8534a2be721fbaf3ab26a52b5c2fd560f41a8e00d` — the same value the VM
pins independently as its golden vector (`net/mesh/roster.rs`) and the docker scripts default
to. Three implementations, one digest.

**3. One malicious node can no longer deny every client its connection.**
`connect_roster_legs` returned `Err` for the whole call on `ServerPinMismatch` and
`DuplicateNodeIdentity`. Since a node controls its own listener, either was a
denial-of-service switch that any single roster member could throw at every client. Both now
drop just that leg, with a warning, exactly like an unreachable or stalled one — the pin still
refuses the impostor, it simply costs that node its leg instead of the client's run.
`TooManyNodeAddresses` stays fatal: that is the caller's own argument being wrong, not a node
misbehaving. Retargeted test:
`roster_legs_drop_impostor_and_duplicate_legs_instead_of_failing_the_client`.

**4. More registered client slots than the manifest names is not a defect.** The audit flagged
this as a gap. It is intended behaviour: Stoffel supports programs with a dynamic number of
input/output clients, so the manifest is a lower bound on the client shape rather than an exact
description. `check_execution_summary` compares only the slots both sides declare, in both
directions, and the rationale is now stated at that code rather than left implicit. No code
change.
