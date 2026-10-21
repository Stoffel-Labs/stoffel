# Eliminating the Bootnode: Roster-Pinned Mesh + Coordinator

> **Later change (not part of this design).** The `stoffel-run` and
> `stoffel-coord-ctl` binaries named throughout are now `stoffel run-node` and
> `stoffel coord-ctl`, subcommands of the `stoffel` CLI with the same flags, and
> the `stoffel-vm-runner` crate's code (`crates/stoffel-vm-runner/src/...`) now
> lives in `stoffel-rust-sdk` under `src/node/` (`stoffel::node`). Its tests moved
> to `crates/stoffel-cli/tests/run_node_*`. The text below is kept as written.

Status: implemented in both repositories, except where §9.I says otherwise. §9.I is the
status of record; the rest of this document is the contract the code was built to, and the
few places where the code deliberately differs are listed there. §9.I is a **chronological
log**, not one table — its per-stage boxes run from V1 to S6 and later boxes supersede earlier
ones — and it carries its own reading instruction at its head. §14 indexes every section that
carries a correction.

Branch: `feature/no-bootnode-v2` (VM, on `dev`), `feature/no-bootnode`
(`stoffel-mpc-coordinator`). The earlier VM attempt
(`claude/bootnode-elimination-mesh-146b80`) was cut from `main` and was abandoned: `dev` had
diverged too far to merge, and had itself developed the bootnode the attempt deleted. The redo
is staged on `dev`, and §9.I carries a per-stage block for it. Where this document and `dev`'s
code disagree, the code wins and the disagreement is recorded as a correction in place.

Rule applied throughout: functionality that genuinely needs a trusted party moves to the
**coordinator**; everything else becomes **mesh** behavior in the VM nodes. Nothing is
kept under a new name.

**How to read a citation in this document.** The **symbol name is the citation**; a line number
is not. Two classes of block carry line numbers, and neither resolves against this working tree:

- the design and audit sections written for the first attempt (§1-§9, §11.5's superseded survey,
  and the bodies of §12.C, §12.D and §12.E that their own blocks mark *void* or *history*) cite
  the **main-based tree** that attempt was cut from, which this branch is not;
- findings measured during the redo cite `dev` at base **`266a416`**, and say so where they do.

`crates/stoffel-vm-runner/src/bin/stoffel-run.rs` in particular grew by several hundred lines
across stages V2-V4, so any line number into it written before the stage that grew it is off by
that much. Blocks that assert something is true of *this* tree — §9.I, §10, the correction and
as-built blocks of §11 and §12, §13, §14 and §15 — therefore name symbols only. A reader checking a
claim greps for the symbol; a stage making one writes no new line numbers into that file.

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
| Client admission | *no check today* | **mesh** | roster carries a `clients` SPKI set (see Blocker B1). *Superseded: the coordinator's per-execution admission (§9.C); client keys never enter the node allowlist. As built after stage S1: the node mesh and the client-facing `--client-bind` listener are separate transports, and only the latter accepts clients.* |
| Peer address directory | `bootnode.rs:96-123` | **mesh** | unsigned `PeerRecord` gossip (PEX); forged address fails the cert check |
| Party index assignment | `discovery.rs:877-882` | **mesh** (already) | sorted SPKIs, unchanged |
| Quorum barrier | `bootnode.rs:150-227` | **mesh** | `net.is_fully_connected(n)` |
| Session params (n, t, entry, program) | `bootnode.rs:186-192` first-registrant-wins | **mesh** | all-to-all `MeshCommit` equality: field-by-field, then a digest backstop (§12.D, as built) |
| `instance_id` freshness | `bootnode.rs:192` random nonce | **coordinator** | the minted `ExecutionId`, reduced by `derive_instance_id_for_execution`. *Corrected 2026-10-12: no epoch store was built and none is needed — see §11.3, §12.E* |
| Program byte custody | `bootnode.rs:125-139` | **deleted** | provably dead (see §3) |
| Program↔execution binding | `bootnode.rs:161-162` | **coordinator** | `ExecutionRegistration.program_hash` |
| `SessionAnnounce` / `SessionAck` / `Heartbeat` | `bootnode.rs:304-330,674-691` | **deleted** | `wait_until_mesh_connected` over authenticated peer keys, then the lock-step `MeshReady` / `PeerBook` / `MeshCommit` handshake. *Corrected 2026-10-12: the generalized `MeshBarrier` was not built, because the prefix it was to generalize does not exist on `dev` — see the V2 block in §9.I* |
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

The coordinator — the process and whoever operates it
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

**The `instance_id` entry is superseded by §12.** §12 makes the coordinator mint the
execution id and makes that id the message envelope, so "not trusted for `instance_id`"
stops holding the moment §12 lands; §12.I is the delta, for this list and for §9.G's table.
The count of things the coordinator is trusted for does not change — membership, executions,
admission — only how much "executions" covers.

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

**The trust delta, as built (stage V4, 2026-10-12).** What a reader gives up and gains against
`dev`'s bootnode, measured on `feature/no-bootnode-v2`:

- **A coordinator is now required to run a program at all.** `--peers` is what makes a process
  a party and it is refused without `--off-chain-coord` and `--coord-cert`; a party fetches the
  roster over the pinned link before it binds a socket, and it learns *which execution to run*
  from that same link. The SDK's `StoffelServer::start` refuses without an
  `OffChainServerConfig`, `local_runner` starts a coordinator in process, and every compose
  stack has a `coordinator` service. There is no configuration of this branch that runs MPC
  with no coordinator, and that is a strict increase in what one service can deny.
- **What the coordinator is trusted for grew by one item**: it mints the execution identity and
  that identity is the message envelope (§12.I), so the earlier "not trusted for `instance_id`"
  is gone. Membership, executions and admission are still the whole list.
- **What went away is a fail-open shared secret.** `STOFFEL_AUTH_TOKEN` over a `use_tls: false`
  link, accepted whenever the variable was unset, and a party id taken from the registrant's own
  assertion. Every connection on this branch is authenticated by key, and no party is
  privileged — no leader, no bootstrap, no first-started process.
- **The one defence against a substituted roster is in the binary and in no deployment.**
  `--expect-roster-digest` exists for both standing and one-shot parties and refuses a served
  roster that is not the expected one, and `roster-digest` recomputes the value from
  certificates alone. No compose stack and no docker script sets either: a reader who wants the
  refusal has to pass it. Nothing else detects a coordinator that serves one node, or one
  client, a roster of its own keys.
- **Key material is unchanged for one-shot stacks**, so §F.0's rules — the rules every §G row
  marked "holds under §F.0 only" rests on — hold only for the standing stack. See §F.0's
  not-landed block.

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

**Done** (V2, 2026-10-12; completed in the V3 repair): the feature, both flags, both
environment variables, both `ENABLE_NAT` build arguments and `docker-compose.nat.yml` are
deleted. V2 took `Dockerfile`'s but left `Dockerfile.benchmark`'s, where the argument still
selected a `--features nat,statistics` build of a feature that no longer existed in any
manifest; the V3 repair removed the argument, its three build-cache ids and the branch. The
reasoning:

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
| 8 | **Delete the bootnode** | VM | **done** (V2, 2026-10-12); see the V2 block in §9.I |
| 9 | Bump coordinator pin `=0.1.0` → `=0.2.0`; drop round-driver | VM | breaking — **done**, see below |
| 10 | Delete legacy in-VM QUIC stack (`net/p2p.rs`) | VM | **done** (V2 on `dev`; the `main` attempt had done it too). `net/mesh/form_mesh.rs` and the `PeerDialer` / `DirectDialer` / `PinnedDialer` seam were never created on `dev`, so there was nothing to close out: `join_mesh` dials through `dial_address_expecting` directly |
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
that is also a transport-security requirement. Closed in stage S1 (2026-10-13) by binding a
second, client-facing listener with no allowlist (`net/roster.rs::NodeListeners`,
`--client-bind`); see §9's rule-3 box.*

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
*Closed in both directions, and as a read-back rather than an assertion about what was passed
in: `Roster::observe_allowlist_enabled` asks the transport whether an allowlist is in force, and
is the last step of `Roster::install_into` (the node mesh, stage V-a) and of
`Roster::install_for_client` (the client's node legs, stage S2 — before which the client leg
carrying the masked inputs had no allowlist at all, which is this blocker's live instance). The
client-facing node listener of stage S1 is the one transport that deliberately has none, and it
reads that back too (`NodeListeners::bind`); what authorizes a client there is the coordinator's
per-execution admission.*

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

**B7. `MESH_CTRL_PREFIX` must be disjoint from every other in-band prefix** on the same
framed stream: `OPN1`, `XOP1`, `AXOP`, `AXG2` (`net/open_registry/wire.rs:6,12,14,16`) plus
`HB_PREPROCESSING_READY_PREFIX` (`stoffel-run.rs:198`). State and test the invariant.

> **Corrected and tightened 2026-10-12 (V2, as built).** `HB_PREPROCESSING_READY_PREFIX` does
> not exist on `dev`; `STXE` does, and it is the prefix that matters.
> `ExecutionConnectionScanner` **closes the connection** on the first frame it cannot decode as
> an execution envelope (`execution_transport.rs`'s `run_connection_receive_loop_with_owner`),
> so a mesh control frame written to a connection the scanner is reading does not fall through
> to another reader — it terminates the peer link. Two consequences, both as built:
>
> - `ReservedPrefix` enumerates seven tags, `STXE` among them, and
>   `every_reserved_prefix_is_disjoint_from_every_other` quantifies over the real constants.
>   `a_mesh_frame_is_not_an_execution_envelope` asserts the stronger property directly: a
>   framed `MeshMessage` must not decode as an `ExecutionEnvelopeV1`.
> - Mesh control frames travel **only** inside `join_mesh`'s handshake, on connections that
>   function is the sole reader of, before the scanner takes its lease. There is no post-join
>   mesh control plane: no gossip round, no heartbeat, no unsolicited peer-book answer. A peer
>   book is exchanged once, in the handshake, and the mesh is repaired afterwards by *dialing*,
>   which puts no control frame on the wire at all.

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
  `rg 'net::p2p' crates/` misses it. **Both copies are deleted.** The suite exercised the
  in-VM shadowing re-exports, so it dies with `net/p2p.rs`; the crates-internal copy
  (`crates/stoffel-vm/src/tests/p2p_integration.rs`) used the same `crate::net::{NetworkManager,
  QuicNetworkManager}` re-exports and was on dev's CI skip list (`--skip tests::p2p_integration`),
  so it was compiled but never run and no running coverage is lost. Stage 10 deleted the
  crates-internal copy and left the root file behind; the V4A repair deleted the root file and
  the now-empty root `tests/` directory. An earlier revision of this bullet claimed the cover
  "now lives in `crates/stoffel-vm/src/tests/p2p_integration.rs`, compiled and run by CI" —
  that was wrong on both counts and is corrected here.
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
  party-0 special case are all gone; `--coord-driver` is deleted outright, so it is an
  ordinary unknown argument (§13).
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
| `instance_id` freshness source? | **DECIDED (2026-10-12): the coordinator's minted `ExecutionId`, and no epoch store.** The two earlier answers on this row — an LMDB monotone epoch keyed by the roster digest, then that epoch mixed into `derive_instance_id` — are both void. §11 makes the coordinator mint every execution identity, which *is* freshness from the party that already owns admission, and §11.3 records that no epoch store, flag, environment variable or agreement round was ever built on `dev` to retire. The objection the epoch answered (shipped stacks reuse one `--execution-id` across `docker compose down`/`up`) is a property of those stacks' hardcoded default, not of the id: a reused id is a reused MPC namespace whether or not a counter is mixed in, and the fix is that the coordinator mints it. `derive_instance_id_for_execution` is the whole derivation. |
| Full `--peers` list, or partial seed + PEX gossip? | **Ship PEX, but keep it independently revertible.** Every compose file *could* supply a full list, so PEX is not strictly required. The coordinator serves keys, never addresses (§9.B), so address discovery stays a mesh concern. *Corrected 2026-10-12: the claim that there is **no reconnection logic anywhere in the VM** was true of `main` and false of `dev`, which has `spawn_standing_mesh_reconnect_loop` — a tournament-filtered repair sweep with `cleanup_dead_connections` and an `assign_party_ids` after each reconnect. V2 did not add a second one: `ReconnectSupervisor` absorbed that loop's behaviour, including both calls and its 500ms/3s schedule, and the standing node now runs the supervisor. What PEX adds is the book the supervisor's targets and discovery's aimed probes come out of.* |
| SDK: hard break or deprecation shim? | **Hard break — no shim.** (Superseded 2026-10-12 by the project rule that removal means deletion: no deprecation markers, no fail-by-name guards, and breaking changes are acceptable. The original reasoning, kept for the record:) ~~**Shim.**~~ `stoffel-rust-sdk/tests/sdk_usage.rs` is the only bootnode-shaped contract CI actually enforces (not in the skip list). A shim lets those assertions be relaxed rather than rewritten. ~10 lines. **Superseded by §9.E.2 and §9.F:** the coordinator `0.3.0` train is a hard break for the SDK — a pinned coordinator, no `node_roster`, no `expected_client_certs`, input ranges assigned by the coordinator — and a shim cannot default any of them. *Measured
2026-10-12: the break list is right about the pin and the input ranges and wrong about one item
— `OffChainServerConfig::expected_client_certs` and its two builder methods are still there, and
still become `stoffel-run --expected-clients`, which is live (§D.2's measured block). What the
SDK server did lose is `bootstrap`/`configured_bootstrap`/`bootstrap_addr`, `execution_id`, and
the ability to start without an `OffChainServerConfig` carrying a `coordinator_cert_path`.* |
| Flip `hb_server.rs:101 use_tls: false` in scope? | **Out of scope, file as follow-up.** It is a genuine gap — with TLS off there is no peer authentication on that path — but `stoffel-run` never constructs `HoneyBadgerQuicServer`, and bundling it would turn Stage 3 from a pure env addition into a semantics change. |

## 9. Coordinator roster and client admission — contract

Status: **binding contract** for both repositories, **revision 2**. Implementers in
`stoffel-mpc-coordinator` (worktree `stoffel-mpc-coordinator-roster-admission`, branch
`feature/no-bootnode`, at version `0.3.0`; the branch and base named here before stage V1 were
`claude/coordinator-roster-admission` on tag `v0.2.0`) and in this repository
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
trust boundary and nowhere else.

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
| S4 | Invitations replay across registrations, programs and rosters | moot: the `Invitation` policy was removed in review and never shipped (§C.3) |
| S5 | `Open` squatting stalls an execution forever | association and input deadlines, terminal `Round::Aborted` (§C.8); what `Open` is for (§C.2) |
| S6 | Masked inputs are not agreed across nodes | `InputsAgreed` digest barrier (§D.6, §D.7 step 9) |
| S7 | Roster equivocation claimed detectable | §G rewritten; optional `--expect-roster-digest` (§D.2, §E.1) |
| S8 | The invitation issuer key may be a node's or the coordinator's | moot: the `Invitation` policy was removed in review and never shipped (§C.3) |
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
| S12 | Mask shares and triples come back in a later execution through the preprocessing store | §C.9 part 4 (new rule: no preprocessing item serves two executions), §D.7 steps 2 and Abort, §9.1 V-0, §H. *Differs:* the write path is made a **division** rather than cursor-exact — an engine commits only material it keeps none of, so a stored item was never served, and the draw (`take_bundle_from_reservoir`) removes it physically. A cursor-exact store is still ruled out, because triples are drawn inside `stoffelcrypto` where no commit can precede the draw; commit-before-use is achieved one step earlier, at generation. **Status: fixed and witnessed.** Reproduced live first — 5 parties, 2 sequential one-shot executions over retained `--preproc-store` volumes, every client input mask of run 2 byte-identical to one run 1 had already published — and reproduced at item-content level in both engines independently (HoneyBadger `RobustShare`, AVSS `FeldmanShamirShare` including commitments). Exposure was **latent**: at the time, no shipped stack reached the one-shot commit path, since both compose uses of `--preproc-store` sat inside `--standing-node` commands and `docker/entrypoint.sh:250-252` had no shipped caller; it was reachable through `STOFFEL_PREPROC_STORE`, the raw CLI and `cffi.rs`. *That is no longer the tree:* `docker-compose.coordinator.reserve-index.oneshot-preproc.yml` and `docker/test-oneshot-preproc-store.sh` (2026-10-15) drive that configuration deliberately, so the path now has live coverage — of the commit and the draw, not of item identity, which no container log can show without printing the share bytes the property exists to withhold. Witnessed now by `material_one_execution_used_is_never_handed_to_a_later_execution` (HB) and `client_masks_one_execution_used_are_never_handed_to_a_later_execution` (AVSS), which assert item identity through the real commit, store and draws, failed on the unfixed tree, pass now, are no longer `#[ignore]`d and are run by CI; the concurrent variant by `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`. Replacing the division with the copy it used to be fails nine tests across both engines. *Corrected 2026-10-14: this row said the write path is deleted; see §9.1 V-0.* *Measured 2026-10-15: a second place this store is written — `ReservationRegistry::persist`, which put a `masked_inputs` map in the same LMDB environment as the mask shares — was examined as the same harm class as this finding and is **not**. Two independent facts, each sufficient: that map had no production writer, so it was always empty (`submit_masked_input`'s only callers were tests; a client's `x + r` goes to the coordinator and the node subtracts its mask share in memory, `stoffel-run.rs:2792-2794`); and `persist` was unreachable, because the registry is initialized only inside `if engine.is_standing()` (`stoffel-run.rs:2579`) while `persist_reservation_state_if_configured` early-returns for a standing engine. The harm claim was wrong independently of reachability: `write_robust_share` serializes `share.share[0]` only, so the volume holds party i's share `[r]_i`, not the scalar `r`, and `[r]_i` with `x + r` yields `[x]_i` — that party's own input share, which it computes legitimately anyway; recovering `x` needs 2t+1 of them. **Status: no defect; the unreachable surface is deleted and the surviving property is pinned** — see §9.1 V-0 closeout item 6.* |
| S13 | Share ids are not tied to roster positions; reconstruction stops at the first `min_shares` answers | `ShareBound::reconstruct` over position-bound shares, Feldman verification, per-node output items (§9.0, §A, §C.7), §G. *Refined:* reconstruction returns as soon as it is conclusive, which is already correct with at most `t` corrupt positions, and otherwise waits for every leg; the position inside the sealed plaintext is not added — the share-id check and the node's signature already bind it (§C.7) |
| S14 | One connection pool, no per-source or per-identity bound, no idle timeout, no capacity for nodes; summaries cloned under the state mutex; no reconnection | `RpcServerLimits` (§A "Server side"), rate limit and summary snapshot (§C.6, §C.7), a lost link exits the node (§D.1 step 10), residual stated (§G) |
| S15 | §F.0 rule 1 is not enforced and `ids/` keys may back compose secrets | every compose stack in this repository is loopback-only, enforced by a fourth check (§F.0). *Declined:* a key-minting init service (§F.0) |
| S16 | `Invitation.client_index: None` lets an invitee take any role, including a slot another invitation names | moot: the `Invitation` policy was removed in review and never shipped (§C.3) |
| S17, C23 | One P-256 key has several SPKI encodings, so byte comparisons are not key comparisons | canonical SPKI layouts, `PinError::NonCanonicalPublicKey` (§A) |
| S18 | HoneyBadger reconstructs only at `n >= 3t + 1`, but only `n >= 2t + 1` is checked | `ShareBound::min_parties`; nodes (§D.7 step 1), `associate_client` (§C.7), every client surface (§E.1 step 1, §E.2) |
| S19 | A malicious coordinator can shift a client's input and substitute its outputs | clients sign masked inputs, nodes sign sealed outputs (§C.7), nodes verify at §D.7 step 9, clients at §E.1 step 7; §G |
| S20 | The local runner writes node keys under the shared temp directory with default modes | run directory `0700`, key files `0600` (§F.4) |
| S21 | §3 still claims the coordinator cannot make a node dial an impostor | §3 rewritten |
| S22 | The issuer checks compare keys, not operators | moot: the `Invitation` policy was removed in review and never shipped (§C.3) |
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
| V28 | SDK `parties` and `threshold` silently stop meaning anything | the node's own `--n-parties` / `--threshold` refuse a served roster of another shape (§D.2); on the client they are deleted rather than left meaningless (§E.2) |
| V29 | `--timestamp` is emitted but never parsed | removed everywhere, leaving nothing behind: an ordinary unknown argument, no by-name refusal (§13, §D.2, §D.3, §E.2, §F.1, §F.4) |
| V30 | The runner and SDK import coordinator `tests::fake_coord` | `OffChainCoordinatorConnection` promoted; both `fake_coord` modules stay public (§C.10) |
| V31 | Module docs that D.5 makes wrong; the `n == 1` join branch | listed under V-a; the branches are deleted in V-c (§D.5, §9.1) |

> **Corrected 2026-10-13 (stage S6). Three rows of the table above prescribe something §13
> forbids or claim something that is not true of this tree.** The rows are kept as the record of
> what the critic found; the resolutions they name are superseded here.
>
> - **V22** — "the refusal lands in V-b". There is no refusal. §13 makes deletion the resolution,
>   and stage S2 deleted direct client mode outright: `run_as_client` and its curve-generic
>   protocol runners are gone, client mode requires `--off-chain-coord`, `--coord-cert`, `--cert`
>   and `--key`, and `stoffel-run --client` without them is an ordinary missing-parameter
>   refusal that names no removed mode (§E.3's S2 box, §15's decision, §9.I's stage S2 box).
> - **V24** — "every site listed with a new hint". Replacement hint text is exactly what §13
>   forbids; §D.3's table keeps its rows only as the record of what used to be prescribed, and
>   says so at its head. A removed flag is an ordinary unknown argument.
> - **V29** — "`--timestamp` … removed everywhere, leaving nothing behind". Not true of this
>   tree, and it was never made true. What is gone is only `stoffel-run`'s parser arm. The flag
>   is still minted and emitted by `docker/entrypoint.sh` in both roles, by the SDK's
>   `OffChainServerConfig` launcher and by `local_runner`, it is still a **required**,
>   must-be-nonzero field on both `OffChainServerConfig` and `OffChainClientConfig` with
>   builders, validation and SDK tests behind it, and `stoffel-run`'s own
>   `cli_option_takes_value` still lists `"--timestamp"` so that the value the entrypoint passes
>   is skipped rather than read as a positional argument. **Removal is open work**, and under §13
>   it is a deletion across both SDK configs, both builders, `local_runner`'s mint and emit, the
>   entrypoint's two emissions and that parser-table entry — a breaking SDK change, which §13
>   accepts. §D.3's row is corrected to the same effect.

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

> **As built on `dev` after stage V1 (2026-10-12).** The *roster* half holds: the node
> allowlist is now installed from the coordinator's served roster and nothing else enters
> it before that call (`Roster::install_into`,
> `crates/stoffel-vm/src/net/roster.rs`), and
> `an_installed_node_roster_refuses_every_client_certificate` pins that a client
> certificate is refused at the mesh transport in both ALPN roles.
> `an_allowlisted_non_node_key_is_ranked_as_a_server_peer` pins the hazard this section
> describes, so the reason the rule exists is executable rather than prose.
>
> The *client* half is **not yet satisfied on `dev`**, and this is the one open item of
> stage V1. `run_standing_node` still extends the same process-wide allowlist with the
> `--client-cert-dir` catalog's keys after the mesh forms
> (`crates/stoffel-vm-runner/src/bin/stoffel-run.rs`, `network.add_allowed_certificate_public_key`),
> because on `dev` an MPC client reaches a node *through the mesh listener*: it dials the
> party's QUIC address with the client ALPN and is demultiplexed by
> `ExecutionTransportMux` (`EXECUTION_CLIENT_ROUTE_HELLO_V1`,
> `authorize_client_route_if_registered`), and the SDK client does the same
> (`QuicNetworkManager::connect_as_client`, `crates/stoffel-rust-sdk/src/client.rs`).
> stoffelnet checks the allowlist before it knows the connection's role, so removing those
> keys refuses every client at the handshake — known or unknown — rather than moving the
> decision to the per-execution admission.
>
> Closing it is therefore not a deletion but a transport change: the standing node needs a
> second, client-facing `QuicNetworkManager` with its own listener and no allowlist, a
> second `ExecutionConnectionScanner` feeding the same mux (the per-execution client roster
> is then the only client authorization), plus the compose port, the SDK's dial target and
> the acceptance harness's client containers. That fan-out is the stage that retargets the
> harness, not this one. Until it lands, a standing deployment still pre-lists its client
> certificates, and the §9 rule 3 guarantee is the per-execution mux check rather than the
> transport's.
>
> **Re-checked in the V1 repair pass (2026-10-12), still open and unchanged.**
> `crates/stoffel-vm/src/net/roster.rs`'s own module documentation used to assert the
> satisfied form of this rule — "client certificates never enter the mesh transport's
> allowlist" — which was the one place a reader would go to learn what the allowlist holds.
> It now states what actually holds, names the standing node as the thing that extends the
> allowlist afterwards, and points at
> `an_allowlisted_non_node_key_is_ranked_as_a_server_peer`. The gap was not closed in the
> repair, because closing it is a change to the deployed network topology — a second
> listener port, the SDK's dial target and the harness's client containers — and the only
> coverage for standing client I/O is the `docker/standing-concurrency` campaign, which is
> red for an unrelated reason until the downward execution stream lands (§I).

> **Closed 2026-10-13 (stage S1). Everything above this box about the client half is
> history; the two paragraphs it describes as open are done, in the shape they prescribe.**
> A standing node binds **two** transports, and `net/roster.rs::NodeListeners` is the only
> place either one's allowlist is decided:
>
> * `NodeListeners::mesh` is given the coordinator's roster by `Roster::install_into`
>   before it binds, and nothing else ever writes it. The
>   `network.add_allowed_certificate_public_key` loop in `run_standing_node` is **deleted**;
>   `--client-cert-dir` remains what §12.B says it is, the catalog a node resolves a
>   published client identity against, and is not a transport allowlist.
> * `NodeListeners::clients` binds `--client-bind` and carries **no** allowlist — read back
>   from the transport after `listen`, so it is observed and not assumed, the same way
>   `install_into` reads its own back for blocker B3. The coordinator's per-execution
>   admission, enforced by `ExecutionTransportMux::register_with_client_identities` against
>   the published client roster, is therefore the whole of client authorization, which is
>   what §9 rule 3 asks for.
>
> The two managers are constructed side by side rather than cloned from one another, because
> `allowed_peer_public_keys` is an `Arc<DashSet>` shared across `clone()` — the mechanism
> `a_member_exchanges_bytes_through_a_clone_taken_before_the_install` depends on, and the
> reason a clone of the mesh manager would refuse every client.
>
> One mux sits behind both, and each scanner is told what it may read with the new
> `ExecutionScannerScope` (`Parties` for the mesh, `Clients` for the client-facing listener,
> `PartiesAndClients` for a one-shot party's single socket). Without the scope, a dial that
> negotiated the *server* ALPN on the unauthorized listener would be attributed to a party
> and routed to a party inbox; with it, that cannot happen even if stoffelnet's own
> unknown-peer refusal were bypassed.
>
> Pinned by four tests in `net/roster.rs`:
> `a_client_the_mesh_refuses_reaches_the_client_facing_listener` (the mesh refuses a client
> certificate in both ALPN roles while the same node's client-facing listener admits it, and
> the mesh still admits its own roster afterwards — this is the test that fails if a non-node
> key ever reaches the mesh allowlist, since stoffelnet offers no way to enumerate an
> installed one), `a_client_route_is_authorized_by_the_per_execution_roster_alone` (an
> admitted client reaches the listener, announces its execution and is bound to that
> execution's client inbox; a certificate the admission does not name gets a handshake and
> reaches no inbox), `the_client_facing_listener_refuses_a_peer_role_dial` and
> `the_two_listeners_may_not_share_one_address`. Both of the first two were verified to fail
> against the defect they describe before being kept.
>
> Deployment fan-out, as prescribed: `docker-compose.standing-concurrency.yml` gives every
> party a `CLIENT_BIND_ADDR` (`172.33.0.1x:910x`, beside the mesh `:900x`) and passes
> `--client-bind`; `docker/standing-concurrency/acceptance.py`'s
> `NODE_CLIENT_TRANSPORT_SERVERS` — which `all_examples.py` imports — points at those ports,
> `roster_guards` passes `--client-bind`, and `malformed_datagrams` now probes both sockets,
> since the client-facing one is reachable by anyone.
>
> `assert_unauthorized_client` is **unchanged in strength**, and an earlier version of this
> box claimed otherwise. Its rogue client declares inputs, and
> `--client-transport-servers` is read only inside the output-only branch of coordinator
> client mode (`stoffel-run.rs` — `input_values.is_empty() && output_len > 0`), so a client
> with inputs never dials a party's client socket at all; `associate_coordinator_client`
> runs before that branch, which is also why making the rogue output-only would not reach
> the listener either — the coordinator refuses the association first. That probe tests the
> coordinator's association refusal, which is a different boundary and still worth having.
>
> The node-side boundary — the per-execution client roster being the whole of client
> authorization on a listener that authorizes no certificate — is pinned in-process by
> `roster.rs::a_client_route_is_authorized_by_the_per_execution_roster_alone` and
> `roster.rs::a_client_admitted_to_one_execution_is_refused_the_route_of_another`, and from
> outside the node by `acceptance.py::assert_unadmitted_client_route_refused` (repair
> stage, 2026-10-13): the `client_listener_probe` example dials every party's
> `--client-bind` address directly, sends `EXECUTION_CLIENT_ROUTE_HELLO_V1` for a live
> execution the probe's certificate is not admitted to, and the campaign asserts every
> party *reports* the refusal and that no party container or process changed. The node did
> not report it before that stage — the refusal was swallowed by a bare
> `Err(_) => continue` — so the deployment-level boundary was unobservable as well as
> untested.
>
> Since the socket itself now admits only coordinator-named certificates (the box below),
> that probe is wrapped in `Harness.probe_certificate_admitted`, which submits a sibling
> execution whose published client *is* the probe's certificate and aborts it afterwards.
> The adversary it tests is therefore strictly harder than before — a client the
> coordinator admitted, reaching for an execution it has no part in — and it is the only
> adversary that reaches the per-execution roster on a standing node at all. The same
> wrapper is what lets `assert_client_connection_flood_refused` keep testing the
> per-certificate occupancy cap unchanged, rather than being refused one layer earlier.
>
> `--client-bind` is required in standing mode, with no default and no port arithmetic: an
> operator who omits it gets a missing-parameter refusal rather than a silently unreachable
> node or a socket nobody meant to open.
>
> Still outside this box: the SDK client's own dial target, which reaches parties through
> `--servers`/the coordinator rather than through a `--client-bind` constant.
> `stoffel-run --client` without a coordinator was the other item here (§E.3's open item,
> finding 18); stage S2 deleted it, and §E.3's S2 box records what went.

> **Who may hold a connection, 2026-10-13 (repair stage).** Carrying no allowlist is the
> right boundary for the *transport* — stoffelnet authorizes a certificate before it knows
> the connection's role, so a key in an allowlist is a key with node-level standing, and no
> client certificate may acquire that — and it is no boundary at all for the socket. Before
> the split, an unlisted certificate died at the TLS handshake, so a standing node's
> connection table was bounded by the operator's `--client-cert-dir` catalog; afterwards,
> stoffelnet admits any certificate it can read on a listener with no allowlist
> (`verify_peer_public_key_allowed` returns `Ok(())` for an empty set), appends every
> accepted connection to its client table without dedup, and has no client-connection
> limit of its own.
>
> So the decision moves one layer up, to where the coordinator's admissions already are.
> `net/client_ingress.rs::ClientIngressGate`, applied in
> `spawn_client_connection_accept_loop`, keeps a connection only for a certificate some
> registered execution's published client roster names, and caps what those admissions may
> occupy. **Every client connection a node holds is one the coordinator admitted**, and the
> caps are bounds on the deployment's own clients rather than on an attacker's supply of
> free certificates. It refuses four things:
>
> * **A certificate the handshake exposed no public key for.** stoffelnet can admit one
>   here precisely because there is no allowlist to fail, and that key is fixed when the
>   connection is accepted — it never becomes readable later — so
>   `ExecutionTransportMux` would answer `ClientCertificateIdentityUnavailable` for this
>   connection forever. `run_connection_scanner` used to `continue` past it, which left it
>   with no reader and therefore no `CLIENT_EXECUTION_HELLO_TIMEOUT` deadline to reap it:
>   retained for the life of the process. Both layers now close it.
> * **A certificate no execution registered here names.** Asked of every connection whose
>   certificate the handshake did expose, before any occupancy is counted, and the question
>   that makes the two caps below meaningful. Certificates are free and this
>   listener has no allowlist, so a bound stated per certificate bounds nothing a peer
>   cannot defeat by churning them: a peer could hold the whole listener — re-dialled past
>   the hello reaper, with free certificates in batches of 256 — and turn the total cap
>   into a deterministic refusal for every client the coordinator admitted, reachable by
>   the attacker and never by the deployment. So the gate asks the mux the weaker question
>   it can answer about a connection with no frame on it yet — does *any* registered
>   execution's client roster name this certificate
>   (`ExecutionTransportMux::names_client_certificate`) — and refuses every certificate it
>   answers `false` for, before counting any occupancy. A certificate the coordinator
>   admitted nowhere here holds no slot and costs the node nothing but the handshake
>   stoffelnet had already completed.
>
>   This does not move the per-execution decision, which stays per frame in
>   `authorize_client_route_if_registered`: an admission to one execution authorizes no
>   route into another, which is now the only adversary that reaches that boundary at all
>   (`roster.rs::a_client_admitted_to_one_execution_is_refused_the_route_of_another`, and
>   from outside the node the campaign's route probe, which is given an admission of its
>   own before it dials).
>
>   What it costs: a client that dials a party before the party has registered the
>   execution naming it is refused and has to dial again. The refusal is a closed
>   connection rather than a handshake failure — the gate runs after the handshake, so
>   `connect_as_client` still returns `Ok` — so a client must treat a dropped connection as
>   retryable, which `establish_coordinator_output_client_routes` now does for
>   `CLIENT_ROUTE_ESTABLISH_BUDGET` (30s), closing the slots each attempt took before
>   dialling again so a patient client does not spend its own per-certificate allowance on
>   its retries.
>
>   *Corrected 2026-10-13 (final audit): this paragraph used to add "and the first frame is
>   what fails", and `CLIENT_ROUTE_ESTABLISH_BUDGET`'s own doc comment said the same. It is
>   false, and it was measured rather than argued — a loopback probe against a gated accept
>   loop that names nobody showed the send immediately after the dial returning `Ok`, with
>   writes beginning to fail only once the transport had processed the party's
>   `CONNECTION_CLOSE`, about 7ms later (three runs: 6.98ms, 6.71ms, 6.69ms). The retry was
>   built on that false mechanism: it checked only the hello it sent straight after the
>   dial — the one send that cannot see a refusal — and discarded the errors of the two
>   re-sends 100ms and 200ms behind it, so a refused route was reported as established and
>   the client kept a dead route to that party. `establish_coordinator_output_client_routes`
>   now sends the hello through `send_execution_hello_to_every_party` and checks **every**
>   pass, `CLIENT_ROUTE_HELLO_RESEND_INTERVAL` apart, falling through to the existing
>   close-then-re-dial branch on any of them. Pinned by
>   `roster.rs::a_refused_client_route_fails_a_later_frame_not_the_dial`, which asserts the
>   dial succeeds, the gate refuses, and a later frame fails — and which deliberately does
>   not assert that the first frame succeeds, since that is the transport's timing and not a
>   contract. Falsified against two mutations: a gate that asks the coordinator nothing, and
>   an accept loop that keeps what the gate refused.* The admission is re-read on every accept, so the retry is admitted the
>   moment the registration lands, and in the ordinary flow there is nothing to retry: the
>   coordinator publishes an execution to its nodes before the client it admitted
>   associates with that execution, and the campaign starts no client before every party
>   has reported the execution ready.
>
> * **The total cap** (`ClientIngressLimits::standing_node`: 1024), which is what every
>   client connection together may occupy.
> * **The per-certificate cap** (256, a quarter of the listener). One certificate
>   legitimately holds more than one connection, but not the whole listener. This is the
>   number that is easy to set too low: the campaign's examples take their client
>   certificate from the program manifest's client slot, so nearly every single-client
>   example runs as `cert0`, and `all_examples` submits waves of 16 (raisable) at once —
>   a cap of 16 would sit exactly at the campaign's own concurrency. A cap a healthy
>   deployment can reach is an outage, not a bound, and
>   `the_standing_caps_leave_room_for_real_load` fails if the margin is narrowed silently.
> Pruning is lazy: a cap that is already reached triggers a walk of the occupancy table
> and is then re-evaluated, so the healthy path pays nothing and only the accepts at a
> bound pay for liveness checks.
>
> Log volume is a resource too, so neither accepts nor refusals cost a line each: the
> accept loop summarises at most once a second, with refusals and healthy accepts on
> independent windows so a burst arriving alongside real clients is not discarded by them.
> The refusal summary counts a certificate the coordinator admitted nowhere here
> (`refused_unadmitted_certificate`) apart from the occupancy caps
> (`refused_over_capacity`), because on a socket anyone can reach the first is ordinary
> and the second is a deployment that has outgrown its bounds, and an operator has to be
> able to tell which one they are looking at.
>
> **Residual, and what these caps do not bound.** They bound concurrent occupancy of this
> listener, which is not the whole cost of an unauthenticated handshake. stoffelnet inserts
> every accepted client's public key into its own `client_public_keys` map inside
> `accept()`, and `cleanup_dead_connections` prunes `client_connections` and `client_ids`
> but never that map — there is no `remove`, `retain` or `clear` on it anywhere in
> stoffelnet 0.1.1. A peer cycling free self-signed certificates therefore leaves roughly
> one SPKI behind per handshake, for the life of the process, on exactly this listener.
> Because the insert is inside `accept()`, `ClientIngressGate::admit` runs strictly
> afterwards and no policy here can prevent it: bounding it needs stoffelnet to prune that
> map alongside `client_ids`, which both scanners already drive every tick. It is memory
> only, not misrouting: the attacker-influenced `get_sorted_client_keys` ordering feeds
> `resolve_client_transport_id` and the HoneyBadger identity-digest fallback, but standing
> mode returns from the installed per-execution client roster before that fallback
> (`net/mpc/honeybadger.rs::client_identity`) and replies through the per-execution mux.
> `roster.rs::the_transports_client_key_table_outlives_its_connections` pins the upstream
> behaviour this residual rests on — it closes two client connections, waits for the
> transport to release them, and asserts their keys are still there — so when stoffelnet
> starts pruning, that test fails and this paragraph goes with it.
>
> Pinned by `client_ingress.rs`'s eight unit tests (over a `PeerConnection` double and a
> directory double, so the admission rule and the caps are exercised without a network),
> `execution_transport.rs`'s two tests that the directory follows registration exactly,
> `roster.rs::the_client_facing_listener_refuses_connections_past_its_cap` (over real
> loopback QUIC: the surplus past the cap is refused and closed while the admitted client
> keeps routing),
> `roster.rs::a_flood_of_unnamed_certificates_cannot_lock_out_an_admitted_client_over_quic`
> (also over loopback QUIC: every dial carrying a certificate no execution names is
> refused and holds no slot, on a listener wide enough that no cap could have been what
> refused it, and the client the execution names then connects *and* routes),
> `roster.rs::a_client_admitted_to_one_execution_is_refused_the_route_of_another` (the
> socket admission does not become a route authorization) and, from outside the node,
> `acceptance.py::assert_unadmitted_client_certificate_refused` and
> `assert_client_connection_flood_refused`.
>
> Each of these was verified to fail against the defect it describes: dropping the
> admission refusal from `ClientIngressGate::admit` fails the two
> `a_flood_of_unnamed_certificates_cannot_lock_out_an_admitted_client` tests and
> `naming_a_certificate_is_what_admits_it`; making
> `ExecutionTransportMux::names_client_certificate` answer `true` unconditionally fails
> both `execution_transport.rs` directory tests and the loopback flood; and letting
> `authorize_client_route_if_registered` fall back to the transport client id instead of
> refusing an unnamed certificate fails
> `a_client_admitted_to_one_execution_is_refused_the_route_of_another` — and *only* that
> one, because `a_client_route_is_authorized_by_the_per_execution_roster_alone` has a
> single execution, where a route conflict masks the missing check.

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
| `ClientIdentity` (moved from `coord:off-chain/src/lib.rs:51`, re-exported there), `ClientIndex`, `ClientSlotSpec`, `ClientSlotTable`, `InputRange`, `OutputRights`, `UnixSeconds`, `ExecutionDeadlines`, `RegistrationNonce`, `AdmissionPolicy`, `AdmissionPolicyKind`, `AssociationRequest`, `ClientAdmission`, `ClientAdmissionRecord`, `ClientAdmissionSet`, `AbortReason`, `ExecutionOutcome`, `AdmissionError`, `SubmissionError`, `RegistrationError`, `program_hash_of`, the `MAX_*` bounds | shared, `src/admission.rs` (new) | C |
| `Round::Aborted`; new `CoordinatorError` variants; `RpcRefusal` | shared, `src/lib.rs:145`, `:257` | A, C |
| reshaped `ExecutionRegistration`, `ExecutionSummary`, `CoordinatorLink`, `MaskedInputSubmission`, `SealedOutput`, `SealedOutputShares`, `Event::ExecutionAborted`, `EndedExecutions`, new and deleted RPC methods, new `CoordinatorRPCBaseError` codes, `OffChainCoordinatorServer::state`, `OffChainCoordinatorConnection`, deadline sweeper | `stoffel-mpc-coordinator-off-chain`, `src/lib.rs` | B, C |
| `run-coord` flags | `stoffel-mpc-coordinator-bins`, `src/bin/` | F.3 |
| on-chain `NodeRPCClient::start_rpc_client` and `start_rpc_client_from_cert` taking a `&NodeRoster` (both lose `n` and `t`, `coord:on-chain/src/lib.rs:113-160`); `Round::Aborted` handling | `stoffel-mpc-coordinator-on-chain`, `src/lib.rs` | A |
| `serde_json = "1.0"` in `[workspace.dependencies]`; `serde_json` in `crates/coord-shared` `[dev-dependencies]` (the wire-bound test); `blake3 = "1.8"` in `[workspace.dependencies]` and `coord-shared` | coordinator `Cargo.toml`, `crates/coord-shared/Cargo.toml` | B, C.1, H |
| the preprocessing store is never written with material an execution may still draw: a commit divides the pool instead of copying it, so only what this engine keeps none of is written (`commit_generated_material` + `GeneratedMaterialCommit`). *Corrected 2026-10-14: `persist_preproc` is NOT deleted — see §9.1 V-0* | `crates/stoffel-vm/src/net/mpc/{honeybadger,avss}/preprocessing.rs` | C.9 |
| `Roster` (nodes only), `Roster::from_node_keys`, `Roster::from_coordinator`, `Roster::install_into` | `crates/stoffel-vm/src/net/roster.rs` | D.4 |
| ~~`SessionExecutionId`, `derive_instance_id` (v2)~~ — **void**, see §D.5's correction box: `net/session.rs` carries its own `ExecutionId` and `derive_instance_id_for_execution` | `crates/stoffel-vm/src/net/session.rs` | D.5 |
| ~~`JoinRequest.execution_id`, `JoinProposal.execution_id`, `session_digest` (v2)~~ — **void**, see §D.5's correction box and §12.D as built: `JoinRequest.session: Option<SessionCommitment>`, `MeshCommit`, `SessionField` (seven variants, `ExecutionId` among them) | `crates/stoffel-vm/src/net/mesh/{mod,join,wire}.rs` | D.5, 12.D |
| ~~`DigestBarrier`, `DigestBarrierTag`, `ADMISSIONS_AGREED_PREFIX`, `INPUTS_AGREED_PREFIX`, `MeshError::{AdmissionDivergence, InputDivergence, DigestBarrierUnannounceable, DigestBarrierIncomplete}`~~ — **void**, see §D.6's correction box: there is no `net/mesh/barrier.rs` on `dev`; the admissions half is `AdmittedExecution::config_digest` compared in the reservoir exchange, and the masked-input half is unbuilt | `crates/stoffel-vm/src/net/mesh/{barrier,wire,mod}.rs` | D.6 |
| ~~`check_execution_summary`, `admission_agreement_digest`, `inputs_agreement_digest`, `reservations_matching_admissions`, `submissions_matching_admissions`, `SummaryMismatch`, `ReservationMismatch`, `MaskedInputMismatch`~~ — **void**, see §D.6's correction box: `crates/stoffel-vm-runner/src/admissions.rs` does not exist on `dev` | `crates/stoffel-vm-runner/src/admissions.rs` (new) | D.6, D.7 |
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

- **V-0 — no preprocessing item serves two executions (§C.9 part 4).**

  > **Rewritten 2026-10-14. The previous text is obsolete and must not be executed.** It
  > prescribed deleting `persist_preproc` in both engines, deleting `--preproc-store` and its
  > plumbing, and stopping `docker/entrypoint.sh` reading `STOFFEL_PREPROC_STORE` — i.e.
  > removing persisted preprocessing material **entirely**. That was written against the
  > `main`-based tree, where the only consumer of persistence was one compose stack.
  >
  > On `dev` it would delete a shipped capability. Standing nodes are built around persisted
  > material: `--preproc-store` with named volumes, `--reservoir-burst-capacity`,
  > `STOFFEL_STANDING_POOL_ID`, and the Rebuild / Reuse / TopUp agreement. That *is* the
  > persistent-network premise — preprocess ahead, top up between runs, pay only the online
  > cost. Three arms of a passing campaign depend on it: "retained preprocessing volumes",
  > "elastic refill" and "asymmetric-store recovery" in
  > `docker/test-standing-concurrency.sh`, and the whole of
  > `docker/test-coordinator-preproc-store.sh`, whose second phase is "load preprocessing from
  > LMDB". A reader who executed the old text would delete the reservoir's reason to exist.

  **The property, which is what S12 actually requires:** no preprocessing item serves two
  executions. Deletion was only the mechanism the old text chose; the stated reason was that
  "triples are drawn inside `stoffelcrypto` where no commit can precede the draw", which is an
  argument about *drawing*, not about *storing*.

  **What enforces it in the storage layer.** Not the consumed-cursor compare-and-swap, which an
  earlier version of this section credited. That attribution was wrong twice over: there was no
  `DbRequest::Reserve` (the LMDB actor takes boxed `DbJob` closures), and `reserve_at` — the
  compare-and-swap's only entry point — had **no reachable production caller**. Its two
  non-test callers sat in `net/mpc/honeybadger/reservation.rs` inside `!is_standing()` branches
  that `init_reservations_for_run` never reached, and `consumed` was measured at 0 on every key
  in every live run. *2026-10-15: that primitive is now **deleted** — `PreprocStore::reserve_at`,
  `LmdbPreprocStore::reserve_cursor`, `PreprocStoreError::CursorMismatch`, the `!is_standing()`
  branches that called them, and `deserialize_one_robust_share` are gone from the tree. It
  implemented marking-without-removal, the discipline this section rejects, and after the commit
  became a division of the generated pool it was also semantically wrong: it indexes the stored
  blob by logical mask index, and the store no longer mirrors the pool.*

  What actually enforces it is physical removal. A stored item reaches a running execution only
  through `PreprocStore::take_bundle_from_reservoir`, which slices the bundle and deletes or
  compacts the source **inside the same LMDB write transaction** that yields it, on a
  single-threaded actor. Two takes are therefore disjoint or one is refused. That is pinned by
  `reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources`,
  `two_executions_never_receive_the_same_reservoir_item_content` (item *content*, decoded, not
  cursor ranges) and, at engine level, by
  `a_standing_reservoir_never_hands_two_executions_the_same_item`.

  *Corrected 2026-10-15: this used to add "breaking either the delete-on-empty or the compaction
  write-back fails them", which is measurably not the coupling. The take has two mechanisms and
  each has its own witnesses, so a reader re-verifying the property needs the right probe for the
  claim being checked. Measured on this tree, both probes applied to the write-back of
  `take_bundle_from_reservoir` and each restored byte-exact:*

  - *Removing the physical removal — the `remaining == 0` delete and the compaction write-back —
    while the cursor still advances fails **four** tests:
    `reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources`,
    `reservoir_bundle_zero_counts_return_none_and_compact_unrequested_sources` (renamed on
    2026-10-16, see item 10), and
    `preprocess_reserves_persistent_random_shares_when_loaded` /
    `preprocess_reserves_persistent_avss_random_shares_when_loaded` at engine level. The two
    identity witnesses named above **survive** it, because a retained byte that is never served
    again is not a reuse.*

    *Re-measured 2026-10-16, after §9.1 item 10: this probe no longer has its premise, and that
    changes the answer. Advancing the cursor now writes a record the next read refuses
    (`ConsumedCursorInVolume`), so "keep the bytes, advance the cursor" is not a store anyone can
    read afterwards. Run on the current tree it fails **eight**:
    `reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources`,
    `two_executions_never_receive_the_same_reservoir_item_content`,
    `preprocess_reserves_persistent_random_shares_when_loaded`,
    `preprocess_reserves_persistent_avss_random_shares_when_loaded`,
    `a_standing_reservoir_never_hands_two_executions_the_same_item`,
    `standing_mask_reservation_reads_owned_preprocessing_bundle` and
    `a_load_that_does_not_cover_the_targets_is_not_full_provisioning` on both engines — so the
    two identity witnesses no longer survive it, for the new reason rather than the old one.
    `reservoir_bundle_zero_counts_return_none_and_leave_sources_untouched` (renamed, same item)
    drops out of the list, because a kind nobody requested has no cursor to advance. The second
    probe below is still the one those witnesses key on, though its own count was re-measured a
    second time the same day — see the note under it. Both acceptance reproductions survive this
    probe, as before.*
  - *Also holding the cursor — serve off the front, delete nothing, write nothing back, so the
    same item is served twice — fails **eight**, including
    `two_executions_never_receive_the_same_reservoir_item_content`,
    `a_standing_reservoir_never_hands_two_executions_the_same_item` and
    `standing_mask_reservation_reads_owned_preprocessing_bundle`. That is the probe the identity
    witnesses key on.*

    *Re-measured 2026-10-16 (final report): this bullet said **nine** and it is **eight**, and
    the eight are the same eight the probe above fails — the two probes have converged, because
    once a nonzero cursor is refused the only difference between them is which error the next
    read returns. The three tests named here are correct and all three are in that set; only the
    count was stale. Said plainly, because the convergence is the interesting part: with
    `decode_material_meta` in place there is no longer any way to leave a drawn item readable,
    so there is no longer a probe that separates "retained but never served again" from "served
    twice". That is why §9.1 item 10 can simplify the draw at all. Both acceptance reproductions
    pass under **both** probes — they are commit-side, guarded by the `split_off` division, and
    the probe that fails them is reverting that split to a clone, which is measured separately
    in §9.1's V-0 bullet and is deliberately not re-applied here.*

  *Every test named here is non-vacuous; the retracted sentence simply collapsed two mechanisms
  onto one probe. Physical removal is what makes the retained-byte case unreachable in the first
  place, which is why it is still the mechanism this section credits.*

  The two cursor tests that used to sit here —
  `a_preprocessing_item_is_never_served_to_two_executions` and
  `a_preprocessing_item_is_never_served_to_two_concurrent_claimants` — were deleted on
  2026-10-15 together with the `reserve_at` primitive they drove. They were sound and
  non-vacuous (removing the swap as a *mechanism*, so that the new cursor came from the caller's
  `expected`, failed both with "overlapping preprocessing items: 0..4 and 0..4"), but their
  subject was a contract no shipped path invoked, so deleting the primitive took them with it
  and cost no production-reachable coverage. The property's witnesses are the three tests named
  in the paragraph above, plus `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`
  for the concurrent case.

  **Item 1, answered adversely and fixed: a finished execution may persist only what it did not
  keep.** The question was answered by execution, at item-content level, in both engines — and
  the question itself was **wrong at its hinge**, which matters more than the answer. It asked
  whether `persist_preproc` "only ever drains the *unused* pool", as though a yes would settle
  it. The measured answer to that literal question is **yes**: at the moment it ran, nothing had
  been drawn, so everything it drained was unused. The property still failed, because *draining
  is not taking*. `persist_preproc` wrote a byte-identical `consumed: 0` copy of the pool to
  LMDB and then handed the identical items straight back to the live pool
  (`prep.add(restore_bt, …)` / `prep.add(None, Some(items))`), so execution 1 went on to use
  exactly the material execution 2 would later draw, index for index. The discriminator is
  **store-before-use with no later removal**, not used-versus-unused; a dichotomy framed on the
  latter cannot see this defect at all, which is why the question sat open while the code was
  broken. That is also why the fix is stated as a division of the generated round rather than as
  a rule about which items are "unused". A restart was not needed either: `PreprocKeyScope` carries no
  execution component, so two *concurrent* one-shot executions of one program on one node shared
  the keys — and the write primitive they shared, `PreprocStore::store`, read no existing
  metadata, accumulated nothing and reset `consumed`, so they also clobbered each other.

  The fix makes a commit a **division instead of a copy**:

  - `PreprocStore::store` is deleted. The sole write primitive is now `append_items`, which
    read-modify-writes inside one transaction, enforces `item_size`, accumulates `count` and
    preserves `consumed`. Concurrent commits therefore both survive instead of one clobbering
    the other, and no future caller can reach the unconditional put. (The raw put survives as a
    `#[cfg(test)]` helper for the one fixture that must build a *corrupt* source for
    `reservoir_bundle_rejects_corrupt_sources_before_mutation` to reject.)
  - Both engines commit through one function, `commit_generated_material`, parameterised by
    `GeneratedMaterialCommit`. `AgreedChunk(chunk)` is the standing top-up: commit exactly the
    agreed chunk, discard the protocol's over-production, keep nothing. `SurplusAbove(targets)`
    is the one-shot commit: keep the declared targets for this execution, commit only what is
    above them. The guard that keeps generated material from existing in two places now exists
    once rather than twice with opposite signs, and — because the commit needs no network — it
    is unit-testable for the first time.
  - Both engines pair a store handle with a scope in exactly one place (`preproc_home`), so the
    "standing execution preprocessing is owned in memory, not persisted" refusal guards the
    commit path too. `persist_preproc` used to build its own `PreprocKeyScope` inline and bypass
    it, which one edit to `preprocess()`'s early return would have turned into a live defect.
  - AVSS's standing top-up now drains exactly the agreed amount rather than whatever the round
    left, so reservoir content is a deterministic function of the program on both engines.
    Divergent per-party inventories would otherwise force a `Rebuild` on every execution.

  `--preproc-store`, `STOFFEL_PREPROC_STORE`, `docker/entrypoint.sh`'s forwarding, the standing
  reservoir, the volumes and the Rebuild / Reuse / TopUp agreement are all **kept**, as item 2
  requires. What narrowed is only the privacy-violating part: a one-shot run no longer banks the
  portion of its pool it goes on to use, just the surplus above its declared targets. Because
  `plan_preprocessing` bands targets up, that surplus is often small — a one-shot store will
  usually carry little, and deliberate over-generation would be a feature request, not part of
  this fix.

  **A third error, in the deployment half, corrected: nothing sets `STOFFEL_PREPROC_STORE`.**
  Five passages of this document asserted that the preprocessing override "sets
  `STOFFEL_PREPROC_STORE` on all five party services" (§F.1's table row and its correction
  point 5, §F.2's S6 box and its script prescription, §9.I's §F.1 row and §14's `[8]`-class
  sweep row). Measured: `docker-compose.coordinator.reserve-index.preproc.yml` sets no such
  variable, and **no compose file in this repository does** — its only occurrences anywhere in
  the tree are `docker/entrypoint.sh:69` (banner) and `:250-252` (forwarding). The override
  passes `--preproc-store /var/lib/stoffel-preproc` once, at `:48`, inside the
  `x-standing-node-command` anchor (`:28`) that all five parties take through
  `command: [*standing-node-command]`. The conclusion those passages drew — the flag is live,
  the deletion is obsolete — was right; the mechanism was not, and the difference is the whole
  reason this defect was latent rather than active. `:48` sits inside a `--standing-node`
  command (`:30`), so those five parties are *standing* and never reach `persist_preproc`,
  while `entrypoint.sh:250-252`, the one route that would give an **ordinary** party a store,
  has no shipped caller. All six passages now say so.

  **Narrowing the write forced a matching change to the draw.** `preprocess()` treated any
  non-empty load as full provisioning: it marked the engine ready and returned without running
  the preprocessing protocol. That was consistent while a commit copied the whole pool, because
  a load then always covered the targets. Against a store that holds only surplus it is not: the
  execution was left provisioned with the banding slack alone — measured live at `triples=0,
  randoms=2` per party — and then declared itself ready, admitted clients, and failed at its
  first multiplication with `NotEnoughPreprocessing` (HB, reproduced here) or blocked in
  `regenerate_random_shares` waiting on a network, while on AVSS, which has no regeneration path
  at all, it could not serve even its own client input masks. Both engines now compare the loaded
  pool against the declared targets (`pool_availability()` against `preproc_targets()`) and fall
  through to generation when it does not cover them. A load is a head start, not a substitute for
  the protocol, and falling through costs only the shortfall: `run_preprocessing` in both
  dependencies generates the pool's deficit against those same targets rather than the whole of
  them (`honeybadger/mod.rs` `total_triples_to_generate`, `avss_mpc/mod.rs`
  `random_pool_shortfall`). `is_ready` is set by the execution's own provisioning again rather
  than by activating any bundle: `activate_preallocated_standing`, which refuses a bundle that
  does not equal the targets, still marks the engine ready, because for a standing execution that
  activation *is* its whole preprocessing.

  **Evidence.** `material_one_execution_used_is_never_handed_to_a_later_execution` (HB) and
  `client_masks_one_execution_used_are_never_handed_to_a_later_execution` (AVSS) assert the
  property through the real commit, the real store and the real draws; both failed on the
  unfixed tree and both pass now, no longer `#[ignore]`d, so CI runs them. Their sizing had to
  be corrected — with a 6-item pool they demanded two disjoint 4-item sets, which is
  arithmetically impossible under any sound fix, because the old constants encoded the broken
  behaviour in which both executions received all six items. Every assertion in them is
  unchanged. The concurrent variant has its own test,
  `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`, and the
  `StandingPreprocAction::Reuse` arm — previously driven end to end by nothing — has
  `a_reuse_plan_neither_generates_nor_rewrites_the_reservoir`.

  The draw-side gate has `a_load_that_does_not_cover_the_targets_is_not_full_provisioning` in
  both engines: a donor commits its slack, the next execution of the same program loads it, and
  that execution must not report success — restoring the pre-fix short-circuit fails both, with
  the engine's own numbers in the message. The two tests that pin the covering branch,
  `preprocess_reserves_persistent_random_shares_when_loaded` and its AVSS twin, had to declare
  targets their fixture covers, because an uncovered target now reaches a protocol round that
  needs a network; that is a change of premise only, and every assertion in them is unchanged.

  Three guards that carry this now have coverage they did not have, each confirmed by breaking
  it and watching a named test fail: the commit's emptying of the live pool
  (`a_standing_commit_keeps_nothing_and_banks_no_overproduction` in both engines; deleting it
  previously left all 705 tests green), `append_items`' accumulation
  (`two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`), and — added
  2026-10-15 — the top-up's emptying of the pool it inherited, before it generates anything
  (`a_standing_top_up_destroys_the_pool_it_inherited_before_generating` and
  `a_standing_top_up_banks_the_round_it_ran_and_never_what_it_inherited`, in both engines). A third,
  `reserve_cursor`'s `consumed > count` bound, was covered by
  `a_claimant_is_never_served_past_the_end_of_the_pool`; both were deleted with the primitive on
  2026-10-15, and what remains in its place is `take_bundle_from_reservoir`'s own availability
  bound (`count > meta.available()` → `Insufficient`), which every production draw passes
  through. *Corrected 2026-10-16 (final report): this sentence also credited that draw with a
  `consumed > count` validity check, and item 10 deleted it — the draw now refuses a nonzero
  cursor outright in `decode_material_meta`, which subsumes `consumed > count` and is strictly
  stronger, leaving the draw only one piece of metadata to disbelieve, a nonempty pool whose
  items have no size. `grep -n 'consumed >' crates/stoffel-vm/src/storage/preproc.rs` now matches
  one line, a test's doc comment describing the old bound in the past tense.* Replacing the
  division with the copy it used to be — `items.clone()` in place of
  `items.split_off(retained)` — fails nine tests across both engines, including both
  reproductions with the exact messages recorded against the unfixed tree. One line that looks
  like a guard is *not* one, and is recorded as such rather than given a test:
  `apply_standing_preproc_plan`'s `if plan.action != Reuse` around
  `store_standing_preproc_generation` writes identical bytes when taken, because
  `agree_standing_preproc_plan` gives a `Reuse` plan the generation id already in the store, so
  nothing observable depends on it.

  **What the docker suites do and do not show.** `docker/test-coordinator-preproc-store.sh`
  is not V-0 coverage and is no longer presented as such (§H's corrected sentence, and the
  script's own header). Its overlay makes all five parties `--standing-node`, so
  `persist_preproc` is unreachable inside it, and its phases 1 and 2 pass in full even with
  `take_bundle_from_reservoir`'s compaction write-back removed. It is a liveness check —
  generate, reuse after `down`/`up`, recover from a lost volume — and it now also asserts the
  premise that makes it *not* V-0 coverage, that no party commits material from inside a live
  execution.

  **A second suite now covers the path that one cannot reach**, which until 2026-10-15 nothing
  in `docker/` or CI exercised at all: `docker/test-oneshot-preproc-store.sh`, with
  `docker-compose.coordinator.reserve-index.oneshot-preproc.yml`. Five **one-shot** parties over
  retained per-party `--preproc-store` volumes, two sequential coordinator-minted executions,
  `client_mul.stflb` because it is the only shipped program whose targets include a Beaver
  triple. It asserts: run 1 commits into a volume it found empty (commit marker on every party,
  load marker nowhere); run 2 draws what run 1 banked; run 2 finds that draw **insufficient**
  and generates the shortfall; both runs complete with no `NotEnoughPreprocessing` and every
  container at exit 0; and neither run leaves a reservation record in the volume (closeout item
  6's property, measured rather than argued). The third of those is the one assertion that is
  more than liveness: under the copy semantics this section replaced, run 1 banked its whole
  pool, run 2's load covered its targets, and that line could not be emitted. Proven
  non-vacuous by three full campaigns — clean (pass), the `split_off` division replaced by
  `items.clone()` (**fail**, `got 0`, while every other assertion still passed), restored
  byte-exact (pass).

  Neither suite can witness V-0 itself. Item identity, which is what single use means, is
  observable only inside the process: witnessing it from outside would mean printing share bytes
  to container logs, which is the disclosure the property exists to prevent. So the unit tests
  above carry V-0, and the CI step that runs them is `cargo test --workspace --all-features`
  (verified: all ten execute there, none matched by its ten `--skip` patterns), alongside a
  `cargo test -p stoffel-vm --lib --all-features -- --ignored` step so that a future
  `#[ignore]`d reproduction cannot be silently invisible — which is how this defect stayed
  green. That step carried `--all-features` from 2026-10-15; before then it ran under
  `default = []`, which compiles neither feature-gated test module, so it listed exactly 1 test
  where the same command with `--all-features` lists 3 and its comment was false as written.

  **The assertions no longer turn on free-text log strings.** `assert_no_party_committed_from_a_live_execution`
  used to grep a hard-coded `"Committed surplus"` with nothing in the Rust sources tying them
  together, so rewording either engine's commit message would have made an *absence* assertion
  pass forever while witnessing nothing. The phrase now lives in one place —
  `PREPROC_COMMIT_LOG_MARKER`, `PREPROC_LOAD_LOG_MARKER` and
  `PREPROC_PARTIAL_LOAD_LOG_MARKER` in `storage/preproc.rs`, which both engines interpolate —
  and the tie has two halves because neither alone suffices:
  `docker/preproc-log-markers.sh` reads the value out of the source and **fails closed** if a
  constant is renamed or deleted, and the unit test
  `both_engines_interpolate_the_preprocessing_store_log_markers` fails if an engine stops
  interpolating one or spells a marker out literally. An absence assertion cannot demonstrate
  its own sensitivity, so its positive control is the one-shot suite, which asserts the
  *presence* of the same marker on the same image; campaign 2 above also reworded HoneyBadger's
  commit message to "Banked leftover …" and the commit assertion still matched, which is the
  property the hard-coded grep did not have. AVSS's commit, load and shortfall lines now emit
  `eprintln!` as well as `info!`, like HoneyBadger's, so no assertion depends on an operator's
  `RUST_LOG` — the one true half of the concern that AVSS's commit was unobservable (the rest
  was not: the runner installs a stderr subscriber defaulting to `info`, and the recorded
  five-party logs show both copies of the same line side by side).

  **Item 3 is unchanged: `PreprocKeyScope` stays execution-independent** — `(program_hash,
  field_kind, n, t, node_identity)`. That is deliberate: a standing pool is shared across the
  executions of one program on one node, which is the point of preprocessing ahead. Single-use is
  enforced by the destructive take, not by partitioning the keyspace. Note that the scope being
  shared is no longer *sufficient* for reuse either, since nothing an execution holds is in the
  store — which is why the concurrent variant closes without giving the scope an execution
  component.

  **Status:** done. The property holds on both engines and both variants (cross-restart and
  concurrent-same-program-no-restart), and is witnessed by tests that fail when the guards they
  rest on are broken. §9.I's "V-0 not done" row refers to the obsolete deletion, and is
  corrected to this.

  **Closed out 2026-10-15.** Seven items are now done: six that the fix left standing, and a
  seventh for the coverage those six could not supply themselves. The sixth
  turned out not to be a defect at all; it is recorded here because the question it raised
  deserved an answer, and because the answer is now structural rather than argued.

  1. **The marking-without-removal code is deleted.** `reserve_at` / `reserve_cursor` and the
     non-standing cursor-marking branches of `get_mask_share` / `get_mask_shares` /
     `consume_masked_inputs` were production-dead code implementing the discipline this section
     rejects, and after the commit became a division they were semantically wrong as well: they
     index the stored blob by logical mask index, and the store no longer mirrors the pool. Gone,
     with `PreprocStoreError::CursorMismatch`, `deserialize_one_robust_share`,
     `PreprocBlob::unconsumed_data`, the orphaned `StoreForbiddenInStandingMode`, and the 10
     tests whose only subject they were. Four tests that kept their subject were re-premised on
     `take_bundle_from_reservoir` and the test-only `put_blob_unchecked` rather than on the
     cursor, each confirmed non-vacuous against a fresh probe. `get_mask_share` and
     `get_mask_shares` now read the shares `reserve_masks` drew out of the live pool and consult
     no store at all, in either deployment mode.
  2. **The standing top-up's safety is local.** `GeneratedMaterialCommit::AgreedChunk` commits
     everything it drains, and nothing inside `top_up_exact` prevented it draining material the
     engine was still holding — three facts outside it did. `top_up_exact` now takes its node
     through `lease_node_with_emptied_pool_for_top_up`, which empties the live pool before the
     first round, in both engines. One clear covers every chunk, because the in-commit clear at
     the end of chunk *k* re-establishes the precondition for chunk *k+1*. Destroying material is
     a liveness cost and never a privacy one, which is why this is the safe direction. The hazard
     is reproducible rather than theoretical: with the clear deleted, `top_up_exact` returns
     `Ok(())` immediately — `run_preprocessing` finds the pool already holding the counts it was
     asked for and does nothing — and the commit banks the inherited items verbatim.
  3. **Pre-division store volumes are refused, and so is a volume contaminated after it was
     claimed.** There was no schema marker and no migration, so a directory written by a
     pre-division binary still held a full `consumed: 0` copy, including items that run had used,
     and the first post-fix run would have drawn it. Every `LmdbPreprocStore` constructor now
     passes `admit_preproc_volume` inside the write transaction that opens the database: a volume
     with a current `PreprocVolumeHeader` proceeds, an empty directory is claimed, and anything
     else — content without a header, a header this binary cannot decode — is **refused**.
     The *unmarked* check is deliberately volume-scoped rather than prefix-scoped — any content
     at all condemns a header-less volume, reservation blobs included, because everything in it
     was written under the copy discipline. No migration, by design: the material in an unmarked
     volume may already have served an execution, and adopting it is the defect. (*Amended
     2026-10-16:* this read "because `rsv:` blobs predating the marker were written under the
     same discipline and are never deleted". The first half is the reason and stands; the
     second half was a statement about a namespace that no longer exists — see item 6 — and
     `rsv:` is now a condemned *prefix* as well, below.)

     A marker alone certifies a volume's **creation** discipline, not its **contents**, and that
     gap was real rather than theoretical. A volume created and claimed by a post-fix binary,
     written into by a pre-division binary, and reopened post-fix carried a valid header beside
     foreign material, and was admitted and drawn from — reproduced, with the draw returning the
     foreign items. Image rollback onto a retained `--preproc-store` volume followed by a roll
     forward is the route. A marker cannot close it on its own, because a pre-division binary
     ignores markers by construction; what closes it is that such a binary cannot write a key
     prefix it does not know. The material prefix is therefore `PREPROC_MATERIAL_NAMESPACE`
     (`b"ppd:"`), and every prefix only an older binary writes is a variant of a closed
     `CondemnedNamespace` enum — `PreDivisionMaterial` (`b"pp:"`) and, since 2026-10-16,
     `RetiredReservation` (`b"rsv:"`); `find_condemned_records` refuses any volume holding a
     record under either, naming which one it found, on **every** open, not only the first,
     since the foreign write lands between two opens. Two independent barriers result: such a
     record is never a key this binary looks up, and its presence condemns the volume. A prefix
     may join that set only once nothing current writes it, or a node would refuse the volume it
     had just written; `the_condemned_prefixes_are_ones_this_binary_never_writes` asserts that
     over every key the binary can produce *and* over the volume a real write leaves behind, and
     measured, pointing a live `BlobNamespace` variant at `b"rsv:"` fails it.

     Of the two residuals recorded here on 2026-10-15, one is **closed** and one is **accepted**.

     *Closed (2026-10-16).* A volume a pre-division binary wrote only `rsv:` into used to be
     admitted, because such a blob was byte-indistinguishable from a current one. It no longer
     is: nothing current writes that namespace (item 6), so `b"rsv:"` is a condemned prefix and
     such a volume is refused like any other contaminated one. The precondition was the
     deletion, not the scan — condemning a live namespace would refuse a node's own volume —
     which is why these two items had to be resolved together rather than independently.
     Witnessed by `a_claimed_volume_holding_a_retired_reservation_record_is_refused`; measured,
     dropping `RetiredReservation` from `CondemnedNamespace::ALL` fails it.

     *Accepted residual: a volume header certifies a volume's creation, not its contents.* A
     writer that knows the **current** material prefix is indistinguishable from this binary, so
     everything above catches the binaries that predate the division — the stated threat — and
     not an arbitrary forger. This is recorded as a decision, not left as a hole.

     **Threat model.** The only writer who can put `ppd:` records into a claimed volume is a
     process with write access to the node's `--preproc-store` directory. That directory is
     inside the node's trust boundary: the same place holds its certificate key and its
     `--admitted-store`, and a process that can write there can equally serve the node forged
     material at any other layer. The adversary the volume rules are for is not that process —
     it is an *operator accident*: a rollback, a bind mount shared between two pools, a volume
     kept across an upgrade.

     **What is closed, and by what.** Pre-division writers, by the prefix rename plus
     `find_condemned_records` on every open. Cross-pool and cross-node reuse, by the owner
     record (item 5). Non-destructive production reads, by the typed blob API plus
     `#[cfg(test)]` on `PreprocStore::load` (item 4). A metadata cursor claiming items are
     already spent, by `decode_material_meta` (item 10). Inside this crate, the routes a *buggy*
     writer could take are closed too: `BlobNamespace` has no material variant, `load`,
     `PreprocBlob` and `put_blob_unchecked` are test-only, and `append_items` is the sole
     production material write.

     **Why no affordable mechanism closes the rest.** A content digest maintained by every
     material write and verified on read would detect a foreign `ppd:` write — but an *unkeyed*
     digest is recomputable by precisely the writer the threat statement names, who knows the
     format, so it cannot close that threat at any price. Closing it needs a *keyed* MAC whose
     key does not live in the volume, which means plumbing a secret into `LmdbPreprocStore` — a
     type that today takes a pool id and a public `DurableIdentityDigest` and nothing else — and
     a place to keep that secret with its own set of rollback questions. The cost is not the
     digest; it is the key.

     *(The earlier record rejected a seal for three reasons, and they are replaced rather than
     repeated, because judged on the merits they were artifacts of the one design considered — a
     volume-wide accumulator verified at open. It said the seal "touches all four material write
     paths": there are three production ones (`append_items`,
     `take_bundle_from_reservoir`, `delete`), the fourth being test-only. It said `delete` would
     need an extra read of a large blob to XOR the digest out: true of an accumulator, but a
     per-key digest is deleted with its key, and `append_items` already re-concatenates the
     whole blob while the draw already copies the tail, so that asymptotic cost is paid. And it
     said a missed update refuses the volume only on reopen: true of verification at open, but
     verification at the draw fails in process, on the very next `take_bundle_from_reservoir`.
     So the cheaper design does exist; the keyed-versus-unkeyed argument above is why it still
     should not be built. If the project ever wants **buggy-writer** detection specifically — a
     different goal from forgery detection — that is the design to build: a per-key digest
     written in the same transaction and verified at the draw.)*

     Volumes written by this branch's own earlier commits — after the division fix but before the
     rename — hold material under the old prefix and are refused; that is the same "refuse, never
     migrate" rule applied once more, and every shipped suite starts from `down -v`.
  4. **The inconsistent-blob constructors are gone from production.** `PreprocBlob::new` and
     `try_new` take the agreement between `count`, `item_size` and `data.len()` on trust, and had
     no production caller left. Both are `#[cfg(test)]` and the fields are `pub(crate)`. Gating
     the constructors alone proved insufficient — a struct literal builds the same inconsistent
     value, measured — so `PreprocStore::load`, the one non-destructive read and itself without a
     production caller, and `PreprocBlob` with it, are now test-only too. Gating those proved
     insufficient in turn, and for the same reason twice over: the blob API — `store_blob`,
     `load_blob`, `delete_blob`, `atomic_increment` — sits on the same `pub trait` and the same
     LMDB database, took its namespace as `&[u8]`, and `PreprocKey::encode` is public with the
     material prefix as its leading bytes. So `load_blob(b"pp:", &key.encode()?[3..])` was a
     production-visible non-destructive read of exactly the material data blob, and `store_blob`
     the unconditional non-accumulating put of one — the capability deleting `PreprocStore::store`
     removed. Measured, not argued: the read returned the item bytes with availability unchanged
     at 2, and the write desynchronised data from meta, which is the physically inconsistent state
     gating `try_new` exists to prevent, reachable without naming `PreprocBlob` at all. That
     namespace is now a closed `BlobNamespace` enum with no material variant, so the material
     namespace cannot be named through the blob API; with that, production reads this store
     through two inventory reads and one destructive take, and there is no production path that
     reads a stored item and leaves it where a second execution could be handed it.
  5. **One volume, one standing pool, enforced.** It was prose in `stoffel-run.rs` — neither
     tested nor prevented — and the likelier operator mistake, two parties sharing one bind
     mount, silently half-worked because keys are namespaced by node identity. The header records
     the claiming pool and node on a volume's first open, and
     `LmdbPreprocStore::open_for_standing_pool` is the only constructor that claims one; every
     other opener of a claimed volume is refused, including a one-shot `--preproc-store` run.
     Honest limit, and its consequence spelled out (*2026-10-16*): two deployments sharing a
     pool id *and* a node identity are byte-identical to this check, so it does not separate
     them. That is a statement about where the boundary lies rather than a gap inside it. The
     material key namespace is derived from the pool id *and* the node identity
     (`PreprocKey::encode`), so in the protocol's own terms such deployments **are** one node in
     one pool, and what has gone wrong is a pool-id collision — a different defect, upstream of
     any volume. Nothing in the volume could separate them either: a per-deployment nonce
     written at claim time would refuse the same deployment's own restart, which is the entire
     purpose of a standing volume, unless it were persisted outside the volume, which is a
     second store to keep in step and a new half-restored failure mode. What defends the
     collision is therefore upstream: `--pool-id` is required, the all-zero value is refused, it
     is an operator requirement that it be globally unique among live deployments, and party
     certificates differ per node so two parties cannot present one node identity. Separately,
     a *one-shot* `--preproc-store` volume is claimed with no pool at all, so it admits a second
     one-shot opener and refuses every standing pool; two concurrent one-shot openers are safe
     because the draw is atomic and destructive, not because they are kept apart (measured:
     disjoint draws). The README said "refuses every other opener", which was loose on exactly
     that point, and now says so.

     *Added 2026-10-16:* the owner check had been exercised with two threads in one process. The
     deployment's case is two OS **processes** bind-mounting one volume, where what separates
     them is LMDB's own writer lock — `admit_preproc_volume` does its check and its claim inside
     one write transaction — an argument that had been read but never run.
     `crates/stoffel-vm/tests/preproc_volume_two_processes.rs` runs it: a `harness = false`
     target that re-execs itself, four deterministic cases (second pool, same pool on another
     node, and a one-shot opener all refused; the owning pool readmitted) plus eight rounds in
     which two processes open the same fresh volume at one instant and exactly one is admitted.
     The tightest observed two-process window was 0 ms, so the rounds are genuinely contended;
     that is reported rather than asserted, because a late child is simply refused and the
     property holds either way. Measured: deleting the `header.owner != owner` comparison fails
     the deterministic cases and, on its own, the race rounds too (both processes admitted).
     Runtime about 2 s, picked up by CI's `cargo test --workspace --all-features`.

  6. **The node-side masked-input registry is deleted; it was never a defect.**
     `ReservationRegistry::persist` bincode-serialized the whole `RegistryState`, including a
     `masked_inputs: BTreeMap<u64, Vec<u8>>`, into the same LMDB environment as the
     preprocessing material — one `data.mdb`, one named database `"store"`, the `b"rsv:"` versus
     material key prefix the only separation, and `rsv:` keys are never deleted. That co-location
     is real. The reading of it as "`r` and `x + r` in one place yields `x`", a second S12, is
     not, and fails on three counts measured against the source.

     First, the volume never held `r`. `write_robust_share` serializes `share.share[0]` with
     `id` and `degree` and nothing else, so what is on disk is party i's share `[r]_i`.
     `[r]_i` together with δ = `x + r` yields `[x]_i`, that party's own input share — exactly
     what the node computes legitimately, and `x` needs 2t+1 of them. δ is broadcast to every
     node through the coordinator in any case, so an adversary holding 2t+1 nodes has it by
     other means; the amplification would be retrospective convenience behind a threshold
     breach that already breaks the security assumption, not new capability. S12 by contrast
     needed no compromise at all.

     Second, the map had no production writer, so it was always empty. Its only writer was
     `ReservationRegistry::submit_masked_input`, whose only callers were tests. The real input
     path never touches the registry: client → coordinator → `coord.wait_for_inputs(total,
     mask_shares)` (`stoffel-run.rs:2792-2794`), unmasking in process memory with the mask
     shares passed in as an argument.

     Third, `persist` was unreachable. `self.reservation` starts `None` and is set only inside
     `init_reservations_for_run`, whose one production caller sits inside
     `if engine.is_standing()` (`stoffel-run.rs:2579`) — while
     `persist_reservation_state_if_configured` early-returns for a standing engine. So a
     standing run never persisted and a one-shot run never initialized; a one-shot run takes
     its masks straight from the live pool (`stoffel-run.rs:2598-2611`) and does not go near the
     registry.

     A reachability argument decays, so the surface is gone rather than documented:
     `RegistryState.masked_inputs` with its validation, `submit_masked_input` and
     `get_masked_input` on the registry, the orphaned `ReservationError::NotReservedByClient`,
     the engine's `submit_masked_input` and `consume_masked_inputs` (whole — item 1 removed its
     cursor-marking branch, and the remaining one had no production caller either, since the
     runner calls `retire_masks`), and `persist_reservations`, which was the one entry point
     that never checked `is_standing()` and had no caller anywhere. Their declarations leave
     `MpcEngineReservation`, which is a breaking change this branch allows: there is one
     implementor and no user outside this crate.

     **Finished 2026-10-16: the persistence itself is deleted.** The 2026-10-15 pass kept
     `persist`, `load`, `load_for_run` and `init_reservations_for_run`'s `!is_standing()`
     restore branch as the index cursor's crash recovery, while recording in the same breath
     that they were unreachable. Half-wired is not a state to merge: under "delete means
     delete", and with no consumer found anywhere in the tree, they are gone — with
     `ReservationPersistenceKey`, the orphaned `ReservationError::Storage`, the `PreprocStore`
     imports, `persist_reservation_state_if_configured` and its three call sites, and
     `BlobNamespace::Reservation`. Two independent guards had made the call unreachable, not
     one: the hook early-returned for a standing engine, *and* a one-shot engine never
     initialized `self.reservation`, because `init_reservations_for_run`'s only production
     caller sits inside `if engine.is_standing()`. That had been true since `dc857b5`
     (2026-07-22) and, at `dc857b5^`, the call site was already standing-gated — so a one-shot
     run has never persisted a cursor, and nothing regressed here. The claim is now stronger
     and needs no call graph to state: **this registry has no way to reach disk at all**, and
     `rsv:` is a prefix whose presence condemns a volume (item 3).

     The live surface of `MpcEngineReservation` is `init_reservations` /
     `init_reservations_for_run`, `reserve_masks`, `get_mask_share` / `get_mask_shares`,
     `retire_masks` and `available_masks` — offered by standing engines only (item 8).
     `init_reservations_for_run` now always builds a fresh registry and passes the caller's
     `preproc_offset` through instead of discarding it, since there is no second branch for it
     to disagree with.

     The deletion was larger than the three names, because those three were holding up a
     skeleton. `ReservationRegistry::try_from_state` existed to validate a state read back from
     disk, `RegistryState::validate` existed for `try_from_state`, `snapshot` existed for
     `persist`, and `run_id` and `preproc_offset` existed for the restore path's identity check;
     all five had **zero** callers of any kind once the persistence went, and are deleted.
     `is_fully_consumed` is deleted too: its one production caller was the restore branch
     deciding whether a persisted run was finished, and its documentation said so in as many
     words ("a partially allocated crash must remain recoverable"), so keeping it would have
     left a method whose stated purpose is a feature that no longer exists. The assertion it
     carried in `consume_marks_reserved_slots_and_refuses_a_second_pass` is replaced by one
     about what `consume` does to the cursor, which is that test's surviving subject and is
     measured non-vacuous: making `consume` reset `next_index` fails it. Three accessors with
     test callers but no production caller — `ReservationRegistry::new`, `from_state` and
     `all_reserved_slots_consumed` — are `#[cfg(test)]` instead, on item 9's reasoning.
     `ReservationError::InvalidState` survives because `reserve` still produces it on a
     corrupted cursor, which `reserve_rejects_invalid_cursor_without_underflow` pins.

     The witness moves with the subject. `the_persisted_reservation_record_carries_index_state_and_nothing_else`
     and `a_standing_engine_writes_no_reservation_record_beside_its_preprocessing` were retired
     with the code they were about — the first asserted the bytes of a record that is no longer
     written, the second that a standing engine did not write it — together with
     `persist_and_restore`, `persistence_isolated_by_run_id`, `load_nonexistent`,
     `load_rejects_invalid_persisted_state` and
     `reserve_masks_persists_registry_cursor_for_restart`, seven in all. In their place,
     `a_standing_engine_writes_nothing_into_the_volume_holding_its_preprocessing` seeds real
     preprocessing material into a volume, drives a standing engine through
     `init_reservations` / `reserve_masks` / `retire_masks` while it holds a real mask share,
     and then asserts over the volume's **keys** — not over an API return, because the typed API
     has no variant that could name the prefix under test, which is the property — that the
     volume holds this node's material and no record under any condemned prefix. Measured:
     re-adding a reservation write to `retire_masks` (with the namespace variant restored to
     express it) fails it, naming the prefix.

     On format, the measurement that stands and what it now justifies: `bincode::deserialize` as
     this crate calls it **tolerates trailing bytes**. Measured again at field granularity for
     item 10 — a 12-byte `PreprocMeta` decodes into a two-field struct as
     `{count, item_size: <old consumed>}` — which is why dropping a field from a persisted
     struct is a *silent misread* of the next field rather than a refusal, and why
     `PreprocMeta::consumed` is kept rather than removed.

  7. **The coverage gaps are closed, and the assertions no longer rest on free text.** Four
     items, detailed in "What the docker suites do and do not show" above: the one-shot
     `--preproc-store` deployment — the only one that reaches this section's commit path — now
     has a shipped suite, `docker/test-oneshot-preproc-store.sh`, proven non-vacuous by three
     campaigns; AVSS's commit, load and shortfall lines gained the dual emission HoneyBadger
     already had, so no assertion depends on `RUST_LOG`; the docker assertions read their
     grep phrases out of `storage/preproc.rs` through `docker/preproc-log-markers.sh`, which
     fails closed, with `both_engines_interpolate_the_preprocessing_store_log_markers` carrying
     the half a shell script cannot; and CI's ignored-test step passes `--all-features`, without
     which it compiled neither feature-gated module and listed 1 test where the same command
     lists 3.

     AVSS live coverage is the one place to be precise about what exists and what does not.
     It was **not** absent — `docker/test-standing-concurrency.sh` and
     `docker/test-standing-adversarial.sh` run AVSS executions on five standing nodes that each
     hold a `--preproc-store` volume, against AVSS-backend fixtures the Dockerfile compiles, and
     a standing node takes a program's backend from its artifact manifest, so
     `apply_standing_preproc_plan`'s `Rebuild` arm puts AVSS `top_up_exact` and its `AgreedChunk`
     commit on that route. What was missing is that nothing *asserted* it: the matrix's
     `"backend": "avss"` is a claim about a fixture, and pointing the AVSS catalog entry at a
     HoneyBadger artifact would have left every other assertion passing while no AVSS reservoir
     was ever built. `assert_reservoir_backends` now requires each party's own reservoir-ready
     lines to report exactly `{honeybadger, avss}`.

     *Corrected 2026-10-16 (residual stage).* This paragraph ended "the gap that genuinely
     remains: AVSS reaches `top_up_exact` only through `Rebuild`, a full generation … so an AVSS
     *partial* refill has still never run anywhere". That is false, and it was refuted by
     observation rather than by argument: `docker/test-standing-concurrency.sh` was run
     **unmodified**, with a poller reading the five live containers before teardown (rc 0,
     502 s), and every party logged `AVSS standing preprocessing agreement: action=TopUp
     generation=760337d2` at the SIGKILL restart, between the first-start and
     asymmetric-recovery `Rebuild`s. The restart brings the AVSS reservoir back *partially*
     full — the fresh wave's `avss-multi-io` drew from the scope and a draw removes — so the
     re-warm to `per_execution × (burst_capacity + 1)` finds one allocation's worth missing and
     agrees `TopUp`. The arm has been running once per campaign in every passing run. What was
     genuinely missing is narrower, and is item 11.

  **Residual items closed out 2026-10-16.** The seven above left a tail: things kept while
  unreachable, a trait whose documentation told implementors to do the one thing this whole
  effort removed, and two residuals recorded without a decision. Items 3, 5, 6 and 7 are
  amended in place above; what follows is new.

  8. **The reservation capability is standing-only in the type, and the trait no longer
     advises marking without removal.** This was the single item worth fixing before merge, and
     it was a *doc* defect with teeth: `MpcEngineReservation::get_mask_shares` carried a
     provided default whose documentation said "engines with persistent preprocessing should
     override this to amortize store reads and cursor updates" — advice item 1 had falsified,
     and which an implementor who followed it would have used to reintroduce exactly the
     marking-without-removal discipline that was deleted. Worse, the documented lifecycle
     `reserve_masks` → `get_mask_share` was unusable in one-shot mode at all, because item 1
     removed the only one-shot way to serve a mask; it failed closed one call late, with "mask
     index N was not reserved before retrieval".

     Fixed in the type rather than in a caveat. All four production call sites of this
     capability sit inside `if engine.is_standing()`, so the capability was already
     standing-only in fact: `HoneyBadgerMpcEngine::as_reservation` and `capabilities` now
     withhold it unless the engine is standing — both, because disagreeing would make the error
     read "advertises reservation but does not implement `MpcEngineReservation`" instead of
     "does not support preprocessing reservation" — and `reserve_masks`' internal mode gate goes
     with them, since there is no non-standing caller left to take the other arm. (That gate had
     been kept in item 1 only because a one-shot test drove it; item 6 retired that test with
     its subject, which is why these two had to land in that order.) `get_mask_shares` loses its
     default and becomes required: there is one implementor, it already overrides it, and a
     default whose documentation is false is worse than no default. Its documentation now says
     what the batch form is actually for — one lock over the process-local shares — and the
     trait's own says, in as many words, that an implementor must not serve a mask out of
     persistent storage, and why.

     `MpcBackendKind::capabilities` is untouched: it is documented pre-construction *family*
     metadata, consulted before any engine exists, and `test_honeybadger_capabilities` keeps
     asserting `RESERVATION` there. One consequence is visible to programs: `Mpc.capabilities`
     reports one fewer flag on a one-shot HoneyBadger node, which is accurate.

     Witnessed by `a_one_shot_engine_offers_no_reservation_capability`, which also asserts a
     standing engine still offers it, so the test cannot pass by withholding it from everyone.
     Measured: restoring `as_reservation` to `Some(self)` fails it, and un-narrowing
     `capabilities` too fails it one assertion earlier.

  9. **Two `PreprocStore` methods with only test callers, decided per method.**
     `PreprocStore::available` is gated `#[cfg(test)]` on the trait and the impl — the precedent
     is in-house, since item 4 did exactly this to `load` — because deleting it would cost
     eleven assertions in tests whose subject survives, while gating it makes item 4's claim
     exact: production reads this store through `meta`, `scope_availability` and
     `take_bundle_from_reservoir`, and this per-key convenience was a fourth read nothing used.
     `PreprocStore::atomic_increment` is **deleted**, with `lmdb_atomic_increment_is_unique`,
     whose only subject it was: zero callers anywhere in `crates/`, `docker/`, `.github/` or the
     scripts, and its deadness predates the division fix. That also removes one blob-API write
     path, shrinking the surface `BlobNamespace` has to defend. Note for the next reader:
     `rustc` does not warn on an uncalled trait method that has an impl, so no build gate can
     witness this — the call-site survey is the evidence.

  10. **A consumed cursor is refused on every read.** `PreprocMeta::consumed` is zero on
      everything this binary writes — `append_items` starts it at zero and otherwise leaves it
      as it found it, and `take_bundle_from_reservoir` writes zero back — because material is
      *removed* when it is drawn rather than marked. But it was still **read**, as the draw's
      slice start. The hazard that leaves, measured during verification: a foreign
      `consumed > count` was already refused as incoherent, while `0 < consumed < count` was
      honoured, and what it does is shift **which** items the next draw serves — past items that
      are still on disk and may already have served an execution. A rolled-back image or a
      foreign writer is the only way to produce one.

      Every read of material metadata now goes through one private funnel,
      `decode_material_meta`, which refuses a nonzero cursor with
      `PreprocStoreError::ConsumedCursorInVolume`: `meta`, `append_items`,
      `take_bundle_from_reservoir`, `scope_availability` and the test-only `load`. It fails
      closed on the draw and on the next append alike — a commit that accumulated onto such a
      record would hand its own fresh material a cursor it never wrote. With that, the draw
      simplifies: the bundle always comes off the front, so the start offset, the end-index
      addition and its overflow guard are gone, and the physical-consistency check narrows to
      the one thing left to disbelieve, a non-empty pool whose items have no size.

      Deliberately **not** extended to `agree_standing_preproc_plan`, where `PreprocMeta` rides
      the party-exchanged `StandingPreprocSnapshot`: a peer's inventory cannot shift which items
      are served locally — only the local draw can, and that is where the refusal sits — and
      snapshot disagreement already forces `Rebuild`. The field itself stays, for a better
      reason than the wire: measured, removing it would make a 12-byte record decode as
      `{count, item_size: <old consumed>}`, a silent misread rather than a refusal.

      Witnessed by `material_metadata_carrying_a_consumed_cursor_is_refused_on_every_read`,
      which checks all six read paths and that the refused record is still there for the
      operator the message addresses. Measured: deleting the `consumed != 0` check fails it.
      Three tests that item 1 had re-premised *onto* a nonzero cursor are re-premised again, onto
      what production can now actually produce:
      `lmdb_append_preserves_cursor_and_reports_scope_availability` becomes
      `lmdb_append_accumulates_and_reports_scope_availability` and asserts the second append
      lands behind the first (measured: making `append_items` overwrite fails it);
      `reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources` keeps its
      compaction subject intact (measured: writing back `count: meta.count` fails it and three
      other tests); and `reservoir_bundle_zero_counts_return_none_and_compact_unrequested_sources`
      becomes `..._and_leave_sources_untouched`, because with no cursor there is nothing in front
      of a pool to compact — but its second subject survives in a better form, the no-op-write
      guard, which is load-bearing rather than an optimization (measured: removing it makes the
      write panic on its own `expect`, because an unrequested kind has no compacted bytes to
      write).

  11. **The AVSS `TopUp` arm is asserted and drawn from, and the suites run in CI.** Two
      coverage items, closed together because the first is part of what the second now runs.

      *What the AVSS gap actually was.* Item 7's claim — that an AVSS partial refill had never
      run anywhere — is corrected there: the arm already ran once per campaign. Three narrower
      things were true, and each is now closed in `docker/test-standing-concurrency.sh`.
      (a) **Nothing asserted it.** `start_nodes(expected_rebuild=False)` counts rebuilds across
      all backends together and cannot tell `TopUp` from `Reuse`, so an AVSS scope that came
      back full enough would have agreed `Reuse` and retired this coverage with every other
      assertion still passing. `Harness.assert_agreement_actions` pins the per-backend action
      counts as a delta against a pre-restart baseline — the containers keep their predecessor's
      log across a restart — and the campaign requires exactly `{"TopUp": 1}` for AVSS, one
      because the catalog holds exactly one AVSS program.
      (b) **Nothing drew from it.** The retained, post-refill and asymmetric waves were all
      HoneyBadger, so no execution had ever allocated out of a topped-up AVSS reservoir: the
      destructive-allocation digest had no second AVSS digest to differ from, and
      `assert_inventory_decreases_between_refills` — which needs two allocations between
      resets — was vacuous for AVSS, because the restart's `standing reservoir ready:` line is a
      reset and the fresh wave's single AVSS allocation sat before it. Nine `retained-avss`
      executions now run after the restart, the first two deliberately with the fresh wave's own
      inputs, so the cleartext is identical and the allocation digests still have to differ.
      (c) **The elastic refill had never run on AVSS.** Nine allocations is what crosses
      `availability_reached_refill_threshold` and drives `spawn_synchronized_reservoir_refill`,
      a top-up running concurrently with a live deployment, which the HoneyBadger side has
      always exercised. The campaign now waits for
      `RESERVOIR_REFILL_COMPLETED program=<multi-avss>` on every party and runs two more
      executions out of what that refill produced.

      This was the one place in this effort where a first execution of a never-run path could be
      mistaken for a regression, so the order was fixed in advance: baseline the shipped campaign
      unmodified, add (a) and (b) and re-run, and only then turn on (c). Measured in that order:
      rc 0 / 502 s, rc 0 / 481 s, rc 0 / 549 s. (c) passed on its first execution and costs 68 s
      against a 481 s campaign, which is why it ships unconditional rather than behind a flag — a
      flag defaulting off would reproduce the "runs nowhere" problem this item exists to close —
      and the shipped path was then re-run rather than inferred (rc 0, 541 s).

      *The suites run in CI*, in three tiers by cost, and none of them gates merge; they report
      and `build-and-test` gates. **Every pull request** gets `harness-wiring`
      (`.github/workflows/ci.yml`) running a new `docker/check-harness-wiring.sh`: ~1-2 min, no
      image, no campaign, and measured to need no Docker *daemon* at all. It guards the seven
      ways a campaign goes vacuous instead of red — every `docker/*.sh` parses, both Python
      drivers compile, all three log-marker constants and every `CondemnedNamespace` prefix read
      back out of `storage/preproc.rs` and no *live* `BlobNamespace` prefix is read as condemned,
      the canonical example count matches the catalog, every compose project resolves and each
      override does **not** resolve alone, and every preprocessing-bearing project gives each
      party its own distinct volume at the path that party was told to use. It deliberately
      carries no `needs:`, so it still reports while the cargo jobs are red for §9.F.5's reason.
      **Nightly at 07:00 UTC, on `workflow_dispatch`, and — for the cheaper pair — on a pull
      request carrying the `docker-e2e` label**, a new `.github/workflows/docker-e2e.yml` runs
      the campaigns: `preproc-store` runs `test-oneshot-preproc-store.sh` then
      `test-coordinator-preproc-store.sh` (~10 min of campaign, in that order because they are
      each other's presence/absence control for the commit marker, so the side that cannot pass
      vacuously runs first), and **nightly or on demand only** `standing` runs
      `test-standing-concurrency.sh` and `test-standing-adversarial.sh` (~13 min), the only live
      AVSS coverage. **Not wired, said plainly:** `test-coordinator-reserve-index.sh` (largest
      overlap with the one-shot suite, weakest unique signal) and
      `test-standing-all-examples.sh` (estimated 1-3 h; the part of it that breaks for everyone,
      its canonical-example-count precondition, is in the per-pull-request tier instead). Six
      campaigns on the pull-request path was rejected on measurement: the four warm campaigns
      alone are 23 minutes, on top of an image build nothing can cache today, because `COPY . .`
      invalidates it on any repository edit and no compose file in this repository declares
      `cache_from`. That last is recorded in `docker-e2e.yml`'s header as the one change that
      would make a cache shared with `docker-build` possible; aligning that job's build-contexts
      with the local clones is necessary for it and not sufficient.

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
  `stoffel-run` (party and client, including the §E.3 **deletion** of direct client mode —
  *corrected 2026-10-13 (stage S6)*: this read "the §E.3 refusal of direct client mode", which
  §13 forbids and which stage S2 did not build; the mode is deleted and what remains is an
  ordinary missing-parameter refusal),
  `local_runner.rs`, the runner's `lib.rs` re-exports, `admissions.rs`, the SDK,
  `stoffel-cli`, the wrapper, `docker/entrypoint.sh`, every compose file, every
  Dockerfile, the scripts of §F.2, `crates/stoffel-lang/examples/mpc_share_arithmetic/main.stfl`
  and `README.md`. Six call graphs break at once when the pin moves (`stoffel-run.rs`,
  `local_runner.rs`, SDK `client.rs`/`server.rs`/`coordinator/mod.rs`, `stoffel-cli`
  through the SDK, and the wrapper's separate workspace), so this is not splittable.
  **Done when**, from the repository root:
  `cargo build --workspace && cargo test --workspace --no-run` passes;
  `cargo build --manifest-path docker/coordinator-wrapper/Cargo.toml` passes — the
  wrapper is its own workspace, so `cargo build --workspace` does not reach it, which is
  why CI builds it in a step of its own (`.github/workflows/ci.yml`, "Build the coordinator
  wrapper" — *corrected 2026-10-13 (stage S6 repair)*: this read "neither `--workspace` nor
  CI sees it", citing two line numbers that now fall inside the `actions/cache` block. Stage
  S5 added that dedicated step, as its §9.I box records, so the claim contradicted this
  document one section away; the numbers are dropped because this document's citation rule
  is to name symbols rather than lines); and both
  `Cargo.lock` and `docker/coordinator-wrapper/Cargo.lock` are re-locked
  (`cargo update -p stoffel-mpc-coordinator-shared -p stoffel-mpc-coordinator-off-chain`,
  once with and once without `--manifest-path docker/coordinator-wrapper/Cargo.toml`) and
  name `0.3.0` from the patch.
- **V-c — deletion.** The now-dead `Roster::new(nodes, clients, t)`, `from_cert_paths`,
  `install_for_client`, `clients()`, `admits_client`, the legacy `RosterError` variants
  (`AllowlistDisabled` loses its `clients` field); both `n == 1` branches of the join
  (`join.rs:559-561`, `:1098-1112`), unreachable once every roster has `n >= 2t + 1` with
  `t >= 1`; the body of direct client mode and the uncoordinated party branches (§E.3);
  and the retargets of the legacy tests (§H).

  > **Note 2026-10-13 (stage S2).** `install_for_client` is back under that name, meaning
  > something else: not "install the `--roster` file's client keys", which is what V-c lists
  > for deletion, but "make the coordinator's served node roster a *client's* peer allowlist".
  > The v1 method took its keys from an operator's file and is gone with `--roster`; the new
  > one takes them from `CoordinatorLink::node_roster` and can take them from nowhere else.
  > See §E.3's S2 box.

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
certificate this system handles goes through it: server pins, roster certificates (§B)
and callers (below). `key_algorithm` and `client_identity`
are infallible because the constructor already refused everything else.

**Canonical layouts.** An admitted algorithm is necessary but not sufficient. One P-256
key has an uncompressed (`0x04`), a compressed (33-byte) and a hybrid (`0x06`/`0x07`)
point encoding, and an Ed25519 SPKI may carry a stray `NULL` parameter; each is a
different `SpkiDer` and a different `ClientIdentity` for the same key. Every identity comparison in this section —
`DuplicateKey`, `by_identity`, reservation ownership, the node RPC delivery gate — is a byte comparison,
so each of them could be evaded by re-encoding a key. `from_certificate_der` therefore
requires `public_key().raw` to be byte for byte one of:

```text
EcdsaP256   3059301306072a8648ce3d020106082a8648ce3d030107034200 || point     91 bytes
            point: 65 bytes, uncompressed, on the curve -- decided by re-encoding
            and not by inspection: p256::PublicKey::from_public_key_der(raw) must
            round-trip through to_public_key_der() back to raw, byte for byte
Ed25519     302a300506032b6570032100 || key                                   44 bytes
            key: 32 bytes, parameters absent, BIT STRING with zero unused bits
```

and refuses anything else with the algorithm's `NonCanonicalPublicKey`. The prefixes are
the DER of the two `AlgorithmIdentifier`s and the BIT STRING header with zero unused
bits; `openssl pkey -pubin -outform DER` produces exactly them, and every certificate
under `ids/` has the 91-byte form (§B's golden vector). Deciding the P-256 case by
round-trip rather than by inspecting the point is a simplification, not a strengthening:
it admits exactly the byte strings the prefix comparison and three point tests it
replaced admitted. Every DER length byte and the unused-bits byte sit inside the 26-byte
`P256_SPKI_PREFIX`, which was compared for equality, so a non-minimal length or a
declared unused bit was already refused there; the re-encoding pins those same bytes
instead, and keeps the layout above the one thing the code states. `p256` is already a
`coord-shared` dependency whose default features supply both the `arithmetic` the curve
check needs and, through `pem`, the `pkcs8` the encoder needs, so no dependency is added.
The algorithm test stays separate from the round-trip: a bare round-trip would collapse
`UnsupportedKeyAlgorithm` into `NonCanonicalPublicKey`, and both cross the wire. Nothing
that works today is refused: ring verifies ECDSA only over uncompressed points
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
    /// Established connections of one identity, whatever its class (default 64 **as built**;
    /// this section was written with 8). The cap is sized in *concurrent executions*, not in
    /// callers: a client opens two connections per execution and a node holds one per
    /// execution beside its execution stream, so 8 refused honest concurrency — and refused it
    /// as a bare `Connection reset by peer`. See §9.I's V4-repair row.
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
  /// `server_spki` is the key of the certificate the operator serves this state with.
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
  `cert_der` separately from the state (`coord:off-chain/src/lib.rs:2552-2568`). So a
  registration check against the coordinator's own key could be made against a key the
  listener does not serve.
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
    /// Required under `Open`, optional under `PreRegistered` (C.8).
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
  execution's program hash, slot table and policy — `Open`, say —
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
| `PreRegistered`: every named slot is in the table | `PreRegisteredSlotOutOfRange { client_slot, slots }` |
| `PreRegistered`: named slots unique — with the count already equal, no gap can hide behind a duplicate | `DuplicatePreRegisteredSlot { client_slot }` |
| `PreRegistered`: every identity is a canonical key (`KeyAlgorithm::of_client_identity` is `Some`, §A) — a P-256 one for a slot with `output_count > 0`, judged by the slot the client *names* | `UnsupportedPreRegisteredKey { client_slot }` |
| `PreRegistered`: identities unique | `DuplicatePreRegisteredClient { client_slot }` |
| `Open` carries `deadlines` | `DeadlinesRequired` |
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
association request (under 1 KiB) — about 100 MiB and 16 MiB — and the
coordinator holds up to `DEFAULT_MAX_CONCURRENT_EXECUTIONS` (1,024) of them. Registration
is operator-only, so that product is the operator's to size; nothing remote can create an
execution.

#### C.2 Admission policies

```rust
// coord-shared/src/admission.rs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// One client bound at registration, and the slot it owns.
///
/// Two index spaces, both meaningful. `client_slot` is the program's slot: it fixes the
/// input range and output rights this client holds, and it is the only index the
/// coordinator reasons about. The entry's position in the vector is the execution-local
/// client ordinal the MPC backend numbers its clients by. They coincide in the common case
/// and need not — see the correction in §12.A.
///
/// `identity` is the certificate's `subject_public_key`, not an SPKI DER and not the
/// certificate-exact `CertificateIdentity` the execution transport authorizes routes
/// against. It is a key to look a local certificate up by; §12.B states how a node
/// resolves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreRegisteredClient {
    pub identity: ClientIdentity,
    pub client_slot: ClientIndex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicy {
    /// `clients[i]` is bound at registration to the slot it names, with `i` as its
    /// execution-local client ordinal. Every slot of the table is named exactly once.
    PreRegistered { clients: Vec<PreRegisteredClient> },
    /// Any certificate holder may bind a free slot, first come, first served.
    Open,
}

/// What a non-node may learn about the policy: never the pre-registered identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicyKind { PreRegistered, Open }
```

| Policy | A slot is bound | By whom | Capacity | Deadlines |
|---|---|---|---|---|
| `PreRegistered` | at registration: every `AdmittedClient` exists before the first RPC | nobody else; `associate_client` returns the existing admission | `client_slots.len()`, all bound from the start | optional |
| `Open` | at `associate_client` | any caller | `client_slots.len()` | required |

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
`Open` on a private network, behind an authenticating front end, or in tests. Admitting
arbitrary clients on a reachable network needs an admission policy this change does not
ship; §C.3 records what was removed in review and what would replace it.

#### C.3 Signed invitations — *removed in review*

Revisions 0-3 of this document specified a third admission policy, `Invitation`, under
which a coordinator-registered issuer key signed a `SignedInvitation` naming an invitee
and a slot. It was **removed in review and never shipped**: it was a hand-rolled
certificate authority — its own signing-bytes layout, its own expiry, its own revocation
story (none) — and it added a principal that holds extra trust to a change whose whole
thesis is that no principal does. No deployment used it; every shipped stack defaulted to
`pre-registered`.

The need it answered is real: admitting clients that are not known in advance, on a
network where `Open` would let anyone squat every slot. The replacement is **future work**
and is not implemented: an `AdmissionPolicy::TrustedIssuer` over rustls'
`WebPkiClientVerifier`, so the issuer is an ordinary X.509 CA, verified by an audited
implementation, with the revocation and expiry semantics that come with it. Until then the
shipped policies are `PreRegistered` and `Open` (§C.2), and §C.2's advice stands: run
`Open` on a private network, behind an authenticating front end, or in tests.

The flags and variables the policy took are gone outright, with no refusal-by-name guard
left behind: `--invitation`, `--invitation-issuer-cert` and `STOFFEL_INVITATION` are simply
not arguments any more, and a stack still passing one gets the ordinary unknown-argument
error. The removed-flag guards elsewhere in §D.3 exist for flags that shipped in a release
and whose users need redirecting; `Invitation` only ever existed on this branch, so a
guard naming it would advertise a mechanism nobody could have used.

The section letters after this one are unchanged. C.4-C.10 are cross-referenced from code
comments in both repositories, so the gap is kept deliberately rather than renumbering.

#### C.4 `associate_client`

```rust
// coord-shared/src/admission.rs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationRequest {
    /// `None` binds the lowest-numbered free slot under `Open`.
    pub slot: Option<ClientIndex>,
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

2. *(Step 2 was the invitation check; it went with §C.3. The step numbers are kept so the
   later steps, which code comments in both repositories cite, do not shift.)*
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
     pre-registered check — `slot: Some(i)` for
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
   - `Open`: the slot asked for is `request.slot`, which step 8 binds.
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
    UnsupportedClientKey { client_index: ClientIndex },
    AlreadyAssociated { execution_id: ExecutionId, admission: ClientAdmission },
    NotAdmitted { execution_id: ExecutionId },
    ReservationOutsideAdmission { admitted: Option<InputRange> },
    AdmissionsNotFrozen { execution_id: ExecutionId, current: Round },
    NoOutputRights { execution_id: ExecutionId },
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
| 26, 27, 28 | **retired** (`InvitationRequired`, `InvitationRejected`, `UnexpectedInvitation`) | — | never reused; the `Invitation` policy was removed in review (§C.3). The ledger is in `coord:off-chain/src/lib.rs`, beside 1, 3, 4, 7, 11, 13, 15, 17, 18 and 19 |
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

**The two read methods are rate limited, on a bucket each** (**as built**; this section was
written with one bucket of 10 shared by both, and §9.I's V4-repair row records why that was
replaced). `get_node_roster` and `get_execution_summary` are the only calls an unbound identity
can make repeatedly, and a summary is up to 688,129 bytes (C.1) for a request of a few dozen.
The coordinator keeps two token buckets per caller identity and answers an empty one with
`RateLimited` (41):

| Method | Constants | Why that size |
|---|---|---|
| `get_execution_summary` | `SUMMARY_READS_PER_MINUTE = 60`, `SUMMARY_READ_BURST = 64` | the burst is sized for the executions one identity may be *starting at once* — a client reads the summary once per connection it opens, so a client in several concurrent executions legitimately reads it a dozen times in a second or two — and the refill is what throttles polling |
| `get_node_roster` | `ROSTER_READS_PER_MINUTE = 240`, `ROSTER_READ_BURST = 64` | reading the roster is not a request a caller chooses to make: every link opened to this coordinator fetches and verifies it once as the only way to learn the party set it must pin, a client opens two links per execution, and a node reopens its link whenever the connection under its subscription ends. What is served is also one cached, constant wire struct — the same bytes for every caller, cloned under the lock — so answering costs a clone rather than a walk of per-execution state |

Spending one bucket does not spend the other
(`summary_reads_are_rate_limited_per_identity`, `roster_reads_are_rate_limited_per_caller_identity`).
Buckets live in a least-recently-used map bounded at `SUMMARY_READ_BUCKETS = 65_536`
identities, so reconnecting does not refill one. Identities cost nothing, so a bucket bounds
one identity's reads, not a flood's; what bounds a flood's is the unreserved connection pool
and the idle timeout (§A).

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
  commitments, at the id its roster position fixes, is ignored (`reconstruct` calls
  `stoffelcrypto`'s public `verify_feldman`,
  `stoffelcrypto-0.1.1/src/common/share/avss.rs:103`, passing
  `share_id_of_position(position)` as the expected id; upstream bounds the commitment
  count by `share.feldmanshare.degree + 1`, which the degree filter above has already
  pinned to `t + 1`); the first group with `t + 1` verified shares is interpolated
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
one-off coordinator would never abort an `Open` execution — S5's permanent
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
memory: a new registration draws a new nonce, which orphans every
signed submission and sealed output of the old one (C.7), and no node ever provisions
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
   the node's preprocessing store handed the same material to consecutive executions.

   **The defect as found** — past tense throughout: this is what the code did before stage
   V-0's fix, confirmed by execution at item-content level in both engines, not a description
   of the tree as it stands. Line numbers are the pre-fix ones.

   - After fresh preprocessing, `HoneyBadgerMpcEngine::preprocess` called `persist_preproc`,
     which took every item out of the pool, wrote a copy to the LMDB store with its consumed
     cursor at 0, and put *the same items* back (`prep.add(restore_*)`). The execution then
     drew its masks from memory (`take_random_shares`) and its triples inside `stoffelcrypto`
     (`take_beaver_triples`, `stoffelcrypto-0.1.1/src/honeybadger/mod.rs:612-616`), and
     nothing ever rewrote the store. On the next start `try_load_preproc` loaded that blob,
     keyed only by program hash, field, `n`, `t` and node identity (`PreprocKeyScope`) —
     nothing that changes between executions — so the overlap was index for index. The AVSS
     engine did the same. A restart was not even required: `PreprocKeyScope` carries no
     execution component, and the write primitive the two shared, `PreprocStore::store`, read
     no existing metadata, accumulated nothing and reset `consumed`, so two *concurrent*
     one-shot executions of one program on one node shared the keys and clobbered each other.
   - Reachability, measured rather than assumed, and this is where an earlier version of this
     bullet was wrong: it said
     `docker-compose.coordinator.reserve-index.preproc.yml:26` turns the store on for the
     `Open` stack. That file sets no `STOFFEL_PREPROC_STORE` — **no compose file in the tree
     does** — and passes `--preproc-store` once, at `:48`, inside a `--standing-node` command
     anchor (`:30`), so its five parties are *standing* and never reached `persist_preproc` at
     all. The route that would give an ordinary one-shot party a store is
     `docker/entrypoint.sh:250-252`, which had no shipped caller. So the defect was **latent in
     a supported configuration** — that environment variable, the raw CLI, or `cffi.rs` — not
     active in any shipped stack, and `docker/test-coordinator-preproc-store.sh` was never
     exercising it (§9.1 V-0's docker paragraph, §F.1's corrected point 5).
     *Updated 2026-10-15:* `docker/entrypoint.sh`'s `STOFFEL_PREPROC_STORE` hook now has
     exactly one shipped caller, `docker-compose.coordinator.reserve-index.oneshot-preproc.yml`,
     whose purpose is to let `docker/test-oneshot-preproc-store.sh` drive the configuration this
     bullet describes. A configuration nothing exercised is a configuration whose defects stay
     green, which is how this one did.
   - The attack it enabled: under `Open`, an attacker binds slot 0 in run 1 and reconstructs its mask
     `r₀`. After `down`/`up`, an honest client in slot 0 of run 2 is given the same `r₀`,
     and any single node reads `x + r₀` from `sub_masked_inputs` and learns `x`; so does the
     coordinator, with no node at all. Reused triples leak the same way through the opened
     values of a multiplication.

   **The rule:** a node's preprocessing store never holds an item any execution has been
   served. Stated that way round it is an invariant about *stored* items, which is what can
   be enforced: material an execution regenerates in memory mid-run
   (`regenerate_random_shares`, and the deficits `node.mul` absorbs) never reaches the store
   at all, so "all material is single-homed" would be a stronger claim than the code makes.
   Concretely, in both engines:

   - **A draw removes.** `take_bundle_from_reservoir` slices the bundle and deletes or
     compacts the source inside the same LMDB write transaction that yields it, on a
     single-threaded actor, so two draws are disjoint or one is refused. It is the only route
     by which a stored item reaches a running execution, on both the one-shot and the
     standing path. Because a commit writes only surplus, what the store can serve is usually
     smaller than an execution's targets, so the drawing engine treats a load as a head start and
     generates the shortfall rather than as full provisioning (§9.1 V-0). *Corrected 2026-10-14: an earlier version of this bullet credited
     `try_load_preproc`'s `reserve_at` cursor. `reserve_at` had no reachable production
     caller and `consumed` is 0 on every production key; the physical removal is what
     enforces this. Deleted 2026-10-15: `reserve_at` and `reserve_cursor` no longer exist, so
     physical removal is now the only way material leaves the store, and
     `PreprocStore::load` — the one non-destructive read — is test-only, so no production path
     reads a stored item without removing it. That took two changes, not one: gating `load` left
     the untyped blob API (`load_blob`/`store_blob`, whose namespace was a `&[u8]`) able to
     address a material key by its `pp:` prefix, which was measured to read the item bytes
     without removing them and to forge a record `append_items` would have refused. The namespace
     is now a closed `BlobNamespace` enum with no material variant, so the material keys are not
     nameable through it, and the prefix itself moved — see the volume bullet below.*
   - **A volume is admitted before it is read.** Every `LmdbPreprocStore` constructor checks a
     `PreprocVolumeHeader` inside the write transaction that opens the database, and refuses a
     volume that holds content without one: such a volume was written when a commit copied the
     pool instead of dividing it, so its material may already have served an execution, and there
     is no migration that could make it safe. The header also records the one standing pool and
     node that claimed the volume, so a volume cloned into a second pool, or shared between two
     parties, is refused rather than serving the same correlated material twice. A header speaks
     only to a volume's creation, so a volume claimed here and written into by a pre-division
     binary was admitted until the material prefix changed; a record under any prefix only an
     older binary writes — the pre-division material prefix, or the reservation-index namespace
     such binaries persisted beside the material — is now refused on every open
     (`find_condemned_records`), and is not a key this binary would look up in any case.
     Metadata claiming the first N items of a pool are already spent is refused on the same
     grounds (`decode_material_meta`). *Added 2026-10-15, extended the same day and again
     2026-10-16.*
   - **A commit divides; it never copies.** Both engines commit through one function
     (`commit_generated_material`), and an item is appended only if the engine that generated
     it keeps none of it. A standing top-up commits exactly the party-agreed chunk and
     discards the protocol's over-production (`GeneratedMaterialCommit::AgreedChunk`); a
     one-shot execution keeps its declared targets and commits only the surplus above them
     (`SurplusAbove`). The single write primitive is `append_items`, which accumulates inside
     one transaction, so concurrent commits cannot clobber one another.
     *Corrected 2026-10-14: this bullet said "generation never writes" and that
     `persist_preproc` was deleted in both engines. Neither is the plan — see §9.1's rewritten
     V-0. What was deleted is the copy: `persist_preproc` used to write the whole pool at
     `consumed: 0` and hand the identical items back, which is the defect S12 names and which
     was reproduced at item-content level in both engines.*
   - **An abort needs no record.** The mask shares an aborted execution provisioned, and
     any triples it drew, were never in the store: they die with the process and with the
     node RPC listener's retired execution (§D.7 "Abort").
   - *Corrected 2026-10-14: `--preproc-store` is NOT deleted — see §9.1's rewritten V-0. The
     paragraph below describes the obsolete plan.* ~~`stoffel-run --preproc-store` is deleted (§D.3), leaving nothing behind. With the write
     path gone nothing in this repository writes the store, so the flag could only ever load
     nothing.

   **Why a committed cursor is not the mechanism.** The review proposed rewriting the store
   after every take. One fact still rules that out: a take cannot be committed before its use,
   because triples are drawn inside `stoffelcrypto`'s multiplication
   (`honeybadger/mod.rs:612-616`, `:1122-1126`), where the VM has no hook — a cursor-exact
   store needs a change to that crate. The conclusion drawn from it was too strong, though.
   Commit-before-use is achievable one step earlier, at *generation* rather than at the draw:
   the engine divides a finished round's pool, writes only the part it does not keep, and
   thereafter the store is the owner of record for those items. Marking is then unnecessary,
   because the draw removes.

   What that costs is bounded by what a one-shot run can honestly bank: `plan_preprocessing`
   bands targets up by an eighth of an octave per count, an extra octave for a dynamic program,
   and two random shares (`stoffel-run.rs:100-127`, `:148-183`), so the surplus above the
   declared targets is often small. Everything the store used to save beyond that slack was
   material the previous execution had already used. Note also what this does not fix: whether
   to generate is still decided locally and greedily on the one-shot path, and HoneyBadger
   preprocessing is interactive, so parties whose stores diverge can still hang. The standing
   path's authenticated `agree_standing_preproc_plan` is the shape that fixes it; the one-shot
   path does not have it, which is pre-existing and out of scope here. Ahead-of-time material —
   a pool of whole executions' worth, the persistent-network design's — meets the rule the same
   way: generation commits before use, and the draw is the only thing that hands material to an
   execution.

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
- **Error codes:** 35 through 41 added; 1, 3, 4, 7, 11, 13, 15, 17, 18, 19, 26, 27 and 28
  retired (C.5).
- **Binaries:** `run-coord` and the wrapper flags change (§F.3).

### D. VM node behavior

#### D.1 Startup order

> **Corrected 2026-10-13 (stage S6): the list below is the `main`-based attempt's startup order,
> not this tree's, and five of its ten steps are false of `feature/no-bootnode-v2`.** The shape
> is right and is built — identity, pinned coordinator, roster once, membership, VM roster,
> transport, peer book, join — which is why the party path in `stoffel-run.rs` still cites
> "§9.D.1 steps 2-5", "step 6" and "step 9" at the places that implement them. What is not true:
>
> 1. **There is no epoch store, so step 8 does not exist.** `EpochStore`, `epoch_store_path` and
>    `--epoch-store` have zero occurrences anywhere under `crates/` or `docker/`; §11.3 and
>    §12.E record that none of it was ever built on `dev`. Step 7's peer book is followed
>    directly by the join.
> 2. **`MeshJoin::new` takes two arguments, not three** (`roster`, `seeds`), and there is no
>    `epochs` parameter on it or on `join_mesh`, no `epochs.propose(&roster.digest())` and no
>    epoch in the committed digest. The only "epoch" in `net/mesh/join.rs` is a comment
>    explaining that there is no stored one.
> 3. **The allowlist install is `Roster::install_into`, reached from `join_mesh`** — not the
>    `MeshJoin::new` constructor the step cites. A standing node installs it earlier and from
>    another place, `net/roster.rs::NodeListeners::bind`, which is what gives the mesh listener
>    the roster *before* it binds and gives the client listener no allowlist at all (§9's rule-3
>    box, stage S1).
> 4. **`JoinRequest` carries no `execution_id`, and party mode forbids `--execution-id`.** What
>    the join commits to is `Option<SessionCommitment> { execution_id, program_id, entry }`
>    inside `MeshCommit` (§12.D as built), and the identity in it is the one the coordinator
>    minted and published — `take_published_execution` — which the party takes **after** the
>    roster and before the transport is bound. §D.5, which this step cites, is itself marked void
>    as a contract.
> 5. **A one-shot party does reach the roster fetch.** An earlier §9.I box said
>    `fetch_node_roster` and `Roster::install_into` were "reached from `run_standing_node` and
>    nowhere else"; since stage V3 the party path reaches both — the fetch directly, the install
>    through `join_mesh` — so steps 2-5 apply to both modes, and the §H row that repeated the
>    claim is corrected.
>
> The one further addition, not a correction: between the roster and the transport the party
> takes its execution identity off the coordinator's `sub_executions` stream, because the
> coordinator mints it (§12.A, §12.G). A **standing** node's order is different again and is
> §12.F's, not this list's.

Party mode (`stoffel-run <program> --peers …`), in this order and no other:

1. **Own identity.** Read `--cert` and `--key` (already read for the storage identity,
   `required_storage_identity`). Read `--coord-cert` and derive its `SpkiDer`; a missing
   file, a non-certificate, a refused key algorithm or a non-canonical key exits 2 before
   any network I/O. Parse `--expect-roster-digest` (`RosterDigest::from_str`, §B) if
   given.
2. **Pinned coordinator.** `CoordinatorLink::connect(host, port, &coordinator,
   expected_roster_digest, cert_der, key_der)`. A transport failure exits 13, as
   coordinator connection failures do today; compose stacks gate parties on the
   coordinator's healthcheck. `ServerPinMismatch` exits 13 with its own message (D.3).
3. **Roster, once.** Inside `connect`: one `get_node_roster`, verified by
   `NodeRoster::try_from(wire)` (§B) — a failure exits 13 — and compared with
   `--expect-roster-digest` when given — a mismatch exits 2. Then, outside it, `n` and `t`
   are compared with this node's own `--n-parties`/`--threshold` — a mismatch exits 2.
   Nothing re-fetches the roster for the life of the process.
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
| `--expect-roster-digest <64-hex>` | **new**, optional, party and client mode; no environment variable |
| `--execution-id <64-hex>` / `STOFFEL_EXECUTION_ID` | required (unchanged, §7) |
| `--cert`, `--key` / `STOFFEL_CERT`, `STOFFEL_KEY` | required (unchanged); in compose, the key is a per-service secret (§F.0) |
| `--peers`, `--bind`, `--advertise`, `--epoch-store`, `--rpc-bind`, `--party-id` (a label), `--mpc-backend`, `--mpc-curve`, `--local-store` | unchanged |
| `--roster` / `STOFFEL_NODE_ROSTER` | **removed**; under §13 it leaves nothing behind — an ordinary unknown argument, and the variable is simply not read |
| `--expected-clients` / `STOFFEL_EXPECTED_CLIENTS` | **removed**; same, nothing left behind |
| `--wait-for-clients` / `STOFFEL_WAIT_FOR_CLIENTS` | **removed** with direct clients (§E.3) |
| `--client-roster`, `--client-input-slots`, `--client-input-count` (`STOFFEL_CLIENT_INPUT_COUNT`), `--client-input-total` | **removed**; the layout is `get_execution_summary`'s |
| `--n-parties`, `--threshold` / `STOFFEL_N_PARTIES`, `STOFFEL_THRESHOLD` | **removed** in party and client mode — `--peers` now always comes with `--off-chain-coord` — so `n` and `t` have exactly one source |
| `--preproc-store` / `STOFFEL_PREPROC_STORE` | **kept.** *Corrected 2026-10-14:* V-0's deletion is obsolete — standing nodes persist preprocessing by design (§9.1 V-0). The flag and the variable are live on this tree. |
| `--timestamp` / `STOFFEL_TIMESTAMP` | **not removed — open work, corrected 2026-10-13 (stage S6).** `stoffel-run` has no parser arm for it, which is what this row was written from, and no coordinator version takes a timestamp. But it is live everywhere else on this tree: `docker/entrypoint.sh` emits `--timestamp ${STOFFEL_TIMESTAMP:-0}` in **both** the client and the party branch, the SDK emits it when it launches a coordinator (`OffChainServerConfig::timestamp`, read in `crates/stoffel-rust-sdk/src/server.rs`), `local_runner` mints one and passes it, both SDK coordinator configs make it a **required** non-zero field (`OffChainServerConfig` and `OffChainClientConfig`, with builders, `validate()` and SDK tests), and `stoffel-run`'s `cli_option_takes_value` still lists `"--timestamp"` so the entrypoint's value is skipped instead of being read as a positional argument — which is why that one entry cannot go before the emitters do. Removing it under §13 means deleting all of that, a breaking SDK change §13 accepts; §7's correction box under the Revision 2 table says the same |

`--expect-roster-digest` is defense in depth, not a second roster authority: it carries no
certificate and can only refuse what the coordinator served, never supply membership, so
rule 1 holds. It is what lets an operator who knows the intended node set detect a
coordinator that serves this node a different one (§G); the coordinator wrapper prints the
value to pin on startup (§F.3).

> **Corrected 2026-10-12 (the `dev` redo).** Revision 1 also specified
> `--expect-n-parties` and `--expect-threshold`, and the main-based attempt shipped them.
> They are **deleted**. A node already states the session shape it was deployed for, with
> `--n-parties` and `--threshold`, and the one path that fetches a roster — the standing
> node — checked the served `(n, t)` against *those*, so the extra pair never decided
> anything: in standing mode their values were overwritten and in every other mode
> discarded. A flag whose help text promises a refusal it cannot perform is worse than no
> flag, and a second pair that has to agree with the first is one more thing to get wrong
> rather than one more check. The size refusal itself stays, sourced from the node's own
> configuration, and so does `--expect-roster-digest`, which has no second source. Under
> §13 the two flags leave nothing behind: they are ordinary unknown arguments. The SDK's
> `parties` and `threshold` therefore stop reaching any RPC — see the correction in §E.2.

> **Measured 2026-10-12 against this tree (stage V4): most of this table's "removed" rows
> never landed, and two more are stale.** Of the rows marked **removed**, only `--roster` /
> `STOFFEL_NODE_ROSTER` (and, from the block above, `--expect-n-parties` and
> `--expect-threshold`) are gone on `feature/no-bootnode-v2`. `--expected-clients`,
> `--wait-for-clients`, `--client-roster`, `--client-input-slots`, `--client-input-count`,
> `--client-input-total`, `--n-parties`, `--threshold` and `--preproc-store` all still parse.
> Reachability differs per flag, and the difference matters: `--expected-clients`,
> `--wait-for-clients`, `--client-input-count`, `--n-parties`, `--threshold` and
> `--preproc-store` have a parse arm, a `--help` line *and* an emission from
> `docker/entrypoint.sh`; `--client-input-total` has the parse arm and the entrypoint emission
> but no `--help` line; and `--client-roster` and `--client-input-slots` have a parse arm and no
> `--help` line, and `docker/entrypoint.sh` names neither them nor any variable for them, so no
> *containerised* deployment reaches either one — their only caller is `local_runner`, which
> builds a party's argument vector directly and passes both from the program manifest's client
> slots. The two client-bearing stacks
> still set `STOFFEL_EXPECTED_CLIENTS` to a client-certificate list
> (`docker-compose.coordinator.reserve-index.yml`,
> `crates/stoffel-lang/examples/docker-compose.coordinator.yml`) and
> `docker-compose.coordinator.reserve-index.preproc.yml` still configures a preprocessing store
> for all five parties.
>
> *Corrected 2026-10-14: it does so by passing `--preproc-store /var/lib/stoffel-preproc` in each
> standing party's command (`:48`), not by setting `STOFFEL_PREPROC_STORE`, which no compose file
> in the tree sets any more — only `docker/entrypoint.sh` still reads it (`:69`, `:250-252`), and
> it is kept. Every claim in this document that the preprocessing override sets that variable is
> stale in the same way; the variable's own row at §D.3 is correct.*
>
> This is not residue of a half-finished removal. Those flags are `dev`'s live client-shape and
> preprocessing configuration, and deleting `--preproc-store` is no longer V-0 work at all
> (§9.1's rewritten V-0 keeps it); deleting the client-shape flags is V-c work, which §9.I
> records as **partly** done. `--n-parties` and `--threshold` have a reason to
> stay that this row missed, and §D.3's own parenthetical already states it: they are the
> node's statement of the shape it was deployed for, and `fetch_node_roster` refuses a served
> roster that disagrees with them — two independent sources meeting in a check, not a second
> membership authority. `--timestamp` looked like the one row that is true, and is not:
> *corrected 2026-10-13 (stage S6)*. There is no parse arm, which is as far as the row's
> evidence went, but the flag is still emitted by `docker/entrypoint.sh` in both roles, by the
> SDK's coordinator launcher and by `local_runner`, it is still a required non-zero field on
> both SDK coordinator configs, and `cli_option_takes_value` still names it so the emitted
> value is skipped rather than read as a positional argument. So nothing lands among the
> positionals either, and "removed" is false in every half but the parse arm. The row itself now
> says so.
>
> Two rows are stale rather than wrong. `--execution-id` is **forbidden** in party mode and
> required only in client mode (§12.G's correction), not "required (unchanged, §7)". And
> `--epoch-store`, listed as unchanged, has never existed on `dev` at all (§11.3).
>
> If any of these flags is removed later it is removed under §13 — deleted outright, no
> by-name refusal, no hint — whether or not it shipped in a release.

#### D.3 Exact messages

> **Corrected 2026-10-12 (§13).** Removed flags get no by-name refusal and no hint. There is
> no `fail_removed_flag` on `dev` — the helper this section named does not exist — and none is
> added: a removed flag is an ordinary unknown argument, which clap already reports. The table
> below is kept only as the record of which flags were removed and why; the hint column is the
> prose of that record, not text any binary prints.
>
> **And most of them are not removed on this tree** (§D.2's measured block): `--expected-clients`,
> `--wait-for-clients`, the four client-layout flags, `--n-parties`, `--threshold` and
> `--preproc-store` are all live. For those rows the hint column is not even the record of a
> removal — it is the record of a removal this effort did not make.

| Flag | Hint |
|---|---|
| `--roster` | `Membership is the coordinator's node roster, fetched once at startup. Pass --off-chain-coord, --coord-cert and --execution-id instead.` |
| `--expected-clients` | `Client certificates no longer enter a node's transport allowlist. Clients associate with an execution through the coordinator, and nodes read the admissions from it.` |
| `--wait-for-clients` | `Clients no longer connect to the node mesh. They associate through the coordinator and fetch their masks from the nodes' --rpc-bind listeners.` |
| `--client-roster`, `--client-input-slots`, `--client-input-count`, `--client-input-total` | `The client slot layout is the coordinator's execution registration.` |
| `--n-parties`, `--threshold` | `n and t come from the coordinator's node roster.` (On `dev` these flags are not removed: they are the node's own statement of the session shape it was deployed for, and the served roster is refused if it differs.) |
| ~~`--preproc-store`~~ | **void, and the hint is now false.** The flag is kept (§D.2's measured block, the `--preproc-store` row of §9.1 V-0) and material IS stored between executions — only never material an execution was served. *Corrected 2026-10-14.* |
| `--timestamp` | `No coordinator takes a timestamp; an execution's deadlines are part of its registration. Remove the flag.` |

> **Corrected 2026-10-12 (§13).** This table used to prescribe replacement hint text for
> each of these refusals. Under §13 none of them survives: a removed flag is deleted
> outright, so there is no site left to carry a hint and nothing names the flag. The rows
> are kept as the record of which existing refusals went with the flags they named.

| Site | Refusal that existed | Fate |
|---|---|---|
| `--client-id` (`stoffel-run.rs:3960-3964`) | `Client IDs are now transport-derived. Remove --client-id.` | deleted with the flag |
| `--expected-client-count` (`:3965-3969`) | `Use --expected-clients <cert-paths-or-addrs> instead.` | deleted with the flag |
| `--bootnode` (`:3985-3991`, flag at `:3987`) | `… give every node --roster <cert-paths>, --peers <addrs> and --epoch-store <dir> …` | deleted with the bootnode |
| `--bootstrap` (`:3992-3997`, flag at `:3994`) | `… Pass --peers <addrs> (seed hints) and --roster <cert-paths> (membership) instead.` | deleted with the bootnode |
| `--coord-driver` (`:4005-4011`) | names `0.2.0` | deleted with the flag |
| `build_session_join` without a roster (`:282-286`) | `--peers forms a mesh, so membership must come from --roster …` | deleted; the function takes the `Roster` built at §D.1 step 5, not an `Option`, so there is no roster-less case to refuse |
| `--roster` in coordinator client mode (`:4434-4443`) | `… use direct client mode … where the roster is installed and enforced.` | deleted with the flag |
| usage text (`print_usage_and_exit`, `:5619`; `--n-parties` "required … without --roster" at `:5650-5651`, `--party-id` naming `--preproc-store` at `:5643-5644`, `--roster` at `:5699-5704`, "Multi-Party Execution" at `:5707-5727`) | describes `--roster` membership | rewritten to the flags of §D.2 and §E.2; no removed flag appears |

The rest exit with these exact messages:

| Condition | Exit | Message |
|---|---|---|
| `--off-chain-coord` without `--coord-cert` | 2 | `Error: --off-chain-coord requires --coord-cert <path>. The coordinator is the roster authority, and a connection that does not pin its certificate accepts any server.` |
| `--peers` without `--off-chain-coord` | 2 | `Error: --peers forms a mesh whose membership only the coordinator defines. Pass --off-chain-coord <host:port>, --coord-cert <path> and --execution-id <64-hex>.` |
| `--coord-cert` unreadable | 2 | `Error: cannot read --coord-cert {path}: {reason}` |
| `--coord-cert` not a certificate, a refused key algorithm or a non-canonical key | 2 | `Error: --coord-cert {path} is not a usable DER X.509 certificate: {reason}` |
| `--expect-roster-digest` does not parse | 2 | `Error: --expect-roster-digest: {error}` — `{error}` is the `RosterDigestParseError` (§B) |
| `ServerPinMismatch` | 13 | `Error: the coordinator at {host}:{port} presented a key that --coord-cert {path} does not pin. Refusing to fetch a roster from it.` |
| served roster fails the receiver check | 13 | `Error: the coordinator at {host}:{port} served a node roster that fails verification: {error}` |
| `UnexpectedRosterDigest` | 2 | `Error: the coordinator serves roster digest {served}, not the --expect-roster-digest {expected}; refusing to install it.` |
| served `n` or `t` differs from this node's `--n-parties` / `--threshold` | 2 | `Error: the coordinator serves a roster of {n} nodes, and this node is deployed for {expected}` / `Error: the coordinator serves threshold {t}, and this node is deployed for {expected}` |
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

> **Corrected 2026-10-12 (§13).** This paragraph used to say that `docker/entrypoint.sh`
> refuses each removed variable by name. It does not, and must not: a removed variable is
> simply ignored, exactly as a removed flag is an ordinary unknown argument. The list below
> is the record of which variables stop being read — `STOFFEL_NODE_ROSTER`,
> `STOFFEL_EXPECTED_CLIENTS`, `STOFFEL_WAIT_FOR_CLIENTS`, `STOFFEL_CLIENT_INDEX`,
> `STOFFEL_CLIENT_INPUT_COUNT`, `STOFFEL_OUTPUTS`, `STOFFEL_N_PARTIES`,
> `STOFFEL_THRESHOLD`, `STOFFEL_PREPROC_STORE`, `STOFFEL_TIMESTAMP`, `STOFFEL_INVITATION` —
> not a specification for refusal text. Every site of the entrypoint that names them has
> the reference removed in the same edit:

| `docker/entrypoint.sh` | Today | `0.3.0` |
|---|---|---|
| `:6-9` header | "membership is STOFFEL_NODE_ROSTER, enforced per connection by mTLS" | membership is the coordinator's node roster, pinned by `STOFFEL_COORD_CERT` |
| `:16-19` | `STOFFEL_AUTH_TOKEN` refusal says "set STOFFEL_NODE_ROSTER (plus STOFFEL_CERT/STOFFEL_KEY) instead" | "set STOFFEL_COORD_ADDR, STOFFEL_COORD_CERT and STOFFEL_EXECUTION_ID (plus STOFFEL_CERT/STOFFEL_KEY) instead" |
| `:51-58` | `STOFFEL_NODE_ROSTER requires STOFFEL_CERT and STOFFEL_KEY` | becomes `STOFFEL_COORD_ADDR requires STOFFEL_CERT and STOFFEL_KEY` |
| `:60-72` | `STOFFEL_WAIT_FOR_CLIENTS requires STOFFEL_EXPECTED_CLIENTS …` | deleted; both variables stop being read and neither is mentioned (§13) |
| `:78-83` | `STOFFEL_COORD_ADDR` without `STOFFEL_EXECUTION_ID` refused | unchanged, and `STOFFEL_COORD_ADDR` without `STOFFEL_COORD_CERT` refused beside it |
| `:85-94` | "`STOFFEL_PEERS` requires `STOFFEL_NODE_ROSTER`" | "`STOFFEL_PEERS` requires `STOFFEL_COORD_ADDR` and `STOFFEL_COORD_CERT`" |
| `:112` banner | `Client Index` | `Client Slot` |
| `:118-123`, `:128` banner (`N Parties` at `:122`) | `N Parties`, `Threshold`, `Expected Clients`, `Node Roster`, `Preproc Store` | no longer printed; `Coordinator Cert` is |
| `:389-392` | emits `--cert`/`--key` when there is no coordinator | deleted: a party without `STOFFEL_COORD_ADDR` is refused before this point, and the coordinator branch (`:333-343`) already emits both |

#### D.4 `Roster` becomes nodes only

`crates/stoffel-vm/src/net/roster.rs`, as it stands after V-c (during V-a and V-b the
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

> **Void as a contract (stage V5 repair, 2026-10-13). Nothing in this subsection was built,
> and §12.D is what landed instead.** It is kept for the reasoning, not as a prescription: a
> reader who follows it would add `SessionExecutionId` beside `net/session.rs`'s own
> `ExecutionId`, re-key the mesh commitment digest, and re-introduce an epoch counter §8 has
> already declared void. As built:
>
> | §D.5 prescribes | On this tree |
> |---|---|
> | `SessionExecutionId`, with `UNUSED` | does not exist, and neither does `UNUSED`. `stoffel-vm` has its own 32-byte `ExecutionId` (`net/session.rs`), which is the execution field of `ExecutionEnvelopeV1` and the key `NodeSupervisor` holds an execution under; `stoffel-vm-runner` converts the coordinator's with `ExecutionId::from_bytes(*id.as_bytes())` |
> | `derive_instance_id(roster_digest, program_id, epoch)`, context `stoffel-session-instance-v2` | **void**, as §8 records. `derive_instance_id_for_execution(&ExecutionId)` takes the minted identity and nothing else — `blake3(b"stoffel-execution-instance-v1" ‖ execution_id)`, first 8 bytes little-endian — because freshness comes from the 256-bit identity the coordinator minted rather than from a counter kept per roster digest. There is no epoch store and no `net/mesh/epoch.rs` on `dev`, so the roster-digest namespacing has nothing to namespace. `derive_execution_id_for_instance` is the inverse direction, for a one-shot caller that already holds a `u64`. Pinned by `execution_instance_id_is_deterministic_and_execution_scoped` |
> | `JoinRequest.execution_id`, `JoinProposal.execution_id`, `SessionField::ExecutionId` as a divergence of its own, `SESSION_DIGEST_CONTEXT` bumped to `stoffel-mesh-session-v2` | the execution is agreed, but inside the commitment: `JoinRequest.session: Option<SessionCommitment>` (`{ execution_id, program_id, entry }`), `None` on a standing node because many executions ride one mesh. `SESSION_DIGEST_CONTEXT` is `stoffel-mesh-commit-v1`. `SessionField` survives with seven variants, `ExecutionId` and `SessionScope` among them, and a divergence is `MeshError::CommitDivergence`, not `SessionDivergence`. See §12.D as built, which is the section this one was superseded by |
> | "Every party now carries `--execution-id`" | the reverse. Party mode **refuses** `--execution-id`: the coordinator mints it and a one-shot party learns it from the execution stream (`take_published_execution`), which is the whole subject of §11 and §12 |
> | the `n == 1` join branches, and the `epoch.rs` / `session.rs` documentation to rewrite | nothing to do. Those files and branches are `main`-only |

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

> **Void as a contract (stage V5 repair, 2026-10-13).** `crates/stoffel-vm/src/net/mesh/barrier.rs`
> does not exist on `dev` and neither does `crates/stoffel-vm-runner/src/admissions.rs`:
> `MeshBarrier`, `BarrierTag`, `DigestBarrier`, `DigestBarrierTag`, `ADMISSIONS_AGREED_PREFIX`,
> `INPUTS_AGREED_PREFIX`, the four `MeshError` variants, `admission_agreement_digest`,
> `inputs_agreement_digest`, `reservations_matching_admissions`, `submissions_matching_admissions`
> and `check_execution_summary` were all `main`-only, as §12.D's "Not followed 2" block records
> for the barrier half. The reasoning about why a barrier frame with an adversary-chosen body
> needs its own type, and the two digest layouts, are kept for a stage that builds the
> agreement; they are not a description of this tree. A reader who follows them would also
> duplicate `net/mesh/join.rs`'s `MeshCommit` / `SessionCommitment` and
> `net/execution_transport.rs`, which is the mistake §12.0's correction box exists to prevent.
>
> **What carries the admissions half as built.** Every party independently recomputes
> `AdmittedExecution::config_digest` over the published registration plus its own frozen
> catalogs (`resolve_published_execution`, `crates/stoffel-vm-runner/src/execution_stream.rs`),
> and the parties compare it before any correlated preprocessing moves: the digest travels in
> `ReservoirAllocationSnapshot::admission_config_digest` and
> `validate_reservoir_allocation_admission` refuses the allocation naming the first divergent
> party, pinned by `reservoir_admission_mismatch_is_separate_from_inventory_repair` and by
> `the_config_digest_moves_whenever_any_committed_field_does`. So a coordinator that equivocated
> between parties fails closed, which is this subsection's property — reached through the
> reservoir exchange the standing pool already runs rather than through a mesh barrier of its
> own.
>
> **The masked-input half is not built, and nothing stands in for it.** No as-built path
> compares delivered masked-input submissions between the parties of a mesh before they are
> unmasked. A coordinator that served different submissions to different nodes of one roster is
> caught only where a later protocol step happens to disagree. That is an open gap, recorded in
> §9.I rather than papered over here.

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
  update( policy tag as u8 )     0 PreRegistered, 1 Open
      (tag 2 was Invitation, removed in review; the two surviving tags keep
       their values, so the digest of every Open and PreRegistered execution
       is byte for byte what it was)
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
   `--expect-roster-digest`; the served `NodeRoster` gives `n` and `t`, which a client has
   no second source for and therefore does not cross-check. Failures exit as in §D.3. The
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
     given — its
     `input_count` must equal the number of `--inputs`. Under `Open` with no
     `--client-slot`, every slot must have one shape, and its `input_count` must equal the
     number of `--inputs`; otherwise exit 2:
     `Error: execution {id} has client slots of different shapes; pass --client-slot <index>.`
     Under `PreRegistered` the slot was bound at registration, association binds nothing
     new, and the count is checked right after step 3. A client that also checks input and
     output types (the SDK) checks them here against every slot the association can bind,
     not just some slot (`BindableSlots`, §E.2).
3. **Associate.** `associate_client(AssociationRequest { slot: --client-slot })`
   → `ClientAdmission`, stored on the client. A count mismatch
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
precondition (`quic.rs:1452`) — and *as built after stage S2 (corrected 2026-10-13, stage S6,
where this read "after §E.3 no shipped client owns one")* the one shipped client that does own
one, the coordinator-mediated output client, pins it through `Roster::install_for_client` over
the roster the coordinator served, not key by key: that call *sets* the allowlist and refuses a
transport that already has one, so the roster is the first writer or no writer at all. The pin is only
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
  Optional: `--client-slot <u32>` (`STOFFEL_CLIENT_SLOT`),
  `--expect-program-hash <64-hex>` (`STOFFEL_EXPECT_PROGRAM_HASH`),
  and `--expect-roster-digest <64-hex>`. Revision 0 called the program flag `--program-hash`; it is
  `--expect-program-hash` beside
  `--expect-roster-digest`, since both only refuse. Removed outright, leaving nothing behind
  (§13): `--client-index`, because the coordinator fixes each client's input range when it
  associates and `--client-slot` is what a client asks for; `--outputs`, because a client's
  output count comes from its admission; and `--roster`, `--n-parties`, `--threshold` and
  `--timestamp` as in D.3. *As built (2026-10-12): `--client-index` is deleted and
  `--client-slot` carries the request; `--outputs` is still parsed, see §I.*
- **`local_runner.rs`.** `run_honeybadger_offchain_client` and `run_avss_offchain_client`
  become `run_offchain_client` (F.4), which follows E.1. `LocalClientIdentity::reserved_index_start`
  (`:883`) and `reserved_indices()` (`:892`) are deleted: the runner no longer chooses
  windows. The runner stops minting and emitting a timestamp (`:166-169`, `:196`,
  `:589-590`, `SpawnPartyContext.timestamp` at `:1378`).
- **SDK, `crates/stoffel-rust-sdk/src/client.rs` and `runtime.rs`.**

  > **As built on `dev` after the V1 repair pass (2026-10-12).** Of the removals below,
  > `input_start_index`, `parties` and `threshold` are **done** — fields, builder fields,
  > setters, `Default`, `build`, the two topology checks in `validate`, and the manifest
  > prefix sum in `Runtime::offchain_client_config` — and `coordinator_cert_der` is **done**
  > and required. Still carried, and still planned for removal: `output_count`, `timestamp`,
  > `client_slot: u64` (not yet `Option<ClientIndex>`), and the client config has no
  > `expected_program_hash` or `expected_roster_digest` yet.

  - `OffChainClientConfig` (`client.rs:325`) loses `input_start_index`, `parties`,
    `threshold`, `output_count` and `timestamp` (`:335`, validated non-zero at `:371-375`
    for no reader), and gains `coordinator_cert_der: Vec<u8>`,
    `expected_program_hash: Option<[u8; 32]>` and
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
    `coordinator_cert_file(path)`, `expected_program_hash([u8; 32])` and
    `expected_roster_digest(RosterDigest)`;
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
  **`mpc_config.parties` and `threshold` keep a meaning**, but it is the node's own
  `--n-parties` / `--threshold`, not a separate expectation. The SDK server keeps emitting
  those two flags, and the node refuses a served roster that does not match them (§D.2), so
  a server configured for five parties at `t = 1` still refuses to run against a
  coordinator whose roster is anything else instead of silently joining it. The builder's
  own checks against `parties` — `party_id < parties` and the peer ids (`:561-580`) — are
  unchanged.
  **Corrected 2026-10-12 (the `dev` redo):** on the *client* side they keep no meaning at
  all and are deleted. `OffChainClientConfig` no longer carries `parties`, `threshold` or
  `input_start_index`: `n` and `t` come from the node roster the pinned coordinator serves,
  and the block of mask indices a client may reserve comes from the admission the
  coordinator grants when it associates. `StoffelRuntime::offchain_client_config` stops
  computing a manifest prefix sum for the start index, and the builder loses all three
  setters.
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
    `expected_program_hash` and `expected_roster_digest`, `backend`,
    `node_rpc_addresses`, `cert_der`, `key_der`, `input_types`, `output_types`, `timeout` —
    and no `parties`, `threshold`, `input_start_index`, `output_count` or `timestamp`.
  - A file that parses as a node `NetworkConfig` instead is refused as a config this mode
    does not accept, naming the shape it does accept — an off-chain client config with the
    coordinator's address and certificate, the execution id, node RPC addresses and a client
    identity. Under §13 the refusal does not name the removed mode or point at it as a prior
    way of doing this. The `RunNetworkConfig::Network` branch (`:991-1015`), which dialed
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
associating, since an association is irrevocable: a `--client-slot` past the table is
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

- `Settled(i)` — `client_slot` names slot `i`
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
- `Nothing` — an aborted execution: the association is refused with the coordinator's
  reason and binds nothing.

Before connecting at all, a client without a settled slot is refused a submission that no
slot of the program accepts, which no policy can bind to an accepting slot. The admitted
slot is checked once more after association under every policy; wherever the summary
settled the slot this repeats the pre-association check. Slot 0 is never assumed.
`stoffel run --network` inherits this.

#### E.3 Direct client mode and coordinator-less parties are retired

> **Corrected 2026-10-13 (stage V5 repair): half of this happened, and the half that did not
> is the client.** The *party* half holds: `--peers` requires `--off-chain-coord`, so no party
> runs without a coordinator (§D.2, §12.G). The *client* half does not. On this branch
> `stoffel-run --client` without `--off-chain-coord` is accepted — client mode requires a
> program, `--n-parties`, `--servers` and `--execution-id`, and nothing more — and falls through
> to `run_as_client`, the branch commented "Direct client mode (no coordinator)". Direct client
> mode is **live**, so this subsection's title, and §8's decision row that points at it
> ("§9.E (client flow; direct client mode retired)"), describe the v1 plan rather than this
> tree.
>
> Two consequences, and neither is a shim:
>
> - the exit-2 message quoted below is **void** under §13. Nothing removed on this branch gets a
>   refusal that names it, so when direct client mode is deleted, `--client` without
>   `--off-chain-coord` becomes an ordinary missing-parameter refusal of the flags client mode
>   does require — not a message about a mode that used to exist. The §9.H row
>   `direct_client_mode_is_refused_by_name` is void for the same reason.
> - deleting it means deleting it: `run_as_client` and its curve-generic protocol runners, the
>   node-side acceptance of client connections on the mesh, and the flags that exist only for
>   it. No stage of the redo has done that, so it is **open work**, recorded in §9.I rather than
>   claimed here. Until then the fail-open allowlist this subsection identified (B3) is reachable
>   by anyone who passes the direct client flags.

> **Stage S2 (2026-10-13): the client half is now true, and this is what it cost.** The box
> above is V5's; this supersedes its "open work" line. The title of this subsection now holds
> for clients as well as parties, and nothing refuses direct client mode by name — it is gone,
> so `--client` without `--off-chain-coord` is an ordinary missing-parameter refusal of the
> flags client mode requires.
>
> Deleted from `stoffel-run.rs`: `run_as_client`; `run_hb_client_for_curve`,
> `run_avss_client_for_curve`, `run_hb_client_protocol_for_curve` and
> `run_avss_client_protocol_for_curve` with `ClientProtocolConfig`; the direct client's
> transport adapter and id-skew mapping (`ScopedClientNetworkAdapter`,
> `client_transport_recipient`, `send_execution_client_hellos`, `DirectClientInboundMessage`,
> `direct_client_inbound_message`); the completion-quorum helpers that only it called
> (`client_input_completion_quorum`, `hb_input_only_completion_proven`); and the direct AVSS
> output formatting (`field_outputs_to_hex`, `fixed_width_be_bytes`). Each of those helpers'
> unit tests went with the code they tested; the one surviving test that merely *used* the
> deleted mapping, `direct_client_downstream_queue_retains_ingress_capacity_lease`, keeps all
> three of its mux ingress-lease assertions and now asserts the mux's own
> `ExecutionTransportSource::Party` attribution in place of the skew it no longer performs.
> (It was renamed again in the S2 repair below, which moved it onto the production mux — on
> the direct-client mux it was asserting a construction nothing shipped.)
>
> Client mode requires `--off-chain-coord` (hence `--coord-cert`, which
> `resolve_coordinator_pin` already demands with it), `--cert` and `--key`, so the
> "coordinator client mode"/"direct client mode" branching in argument validation is one
> required-parameter list. The dispatch resolves the endpoint once and
> `run_hb_coordinator_client` takes a `CoordinatorEndpoint` rather than an `Option` of one;
> its unreachable on-chain arm (`contract_addr`, `eth_node_addr`, `wallet_sk_str`, already
> dead behind main's exit-2 for `--on-chain-coord`) went with the `Option`.
>
> **The pin the deleted path never had is now on the path that survives.**
> `Roster::install_for_client` makes the coordinator's served roster a *client's*
> peer-certificate allowlist — `set_allowed_certificate_public_keys`, not
> `install_expected_server_public_keys`, which requires the local key to be one of the keys
> it installs and so can never serve a client — with the same B3 read-back
> `install_into` does, now shared as `Roster::observe_allowlist_enabled`.
> `establish_coordinator_output_client_routes` installs it before its first dial, from
> `client_transport_roster(coord.node_roster())`, so an address that answers with a
> certificate the roster does not name is refused at the handshake instead of being trusted
> for having answered. `fetch_node_roster`'s certificate-to-`Roster` conversion is now
> `roster_from_served`, shared by the node and client paths so neither can pin a key the
> coordinator did not serve. Two loopback tests:
> `a_client_pinned_to_the_roster_reaches_only_its_nodes` (admits a roster node, refuses an
> impostor listening on another address with
> `peer certificate public key is not in allowlist`) and
> `a_client_pin_authorizes_every_roster_node` (every node the roster names answers the pinned
> client, not only the one the first test dials).
>
> Dependents, inventoried before the deletion:
>
> | Dependent | State |
> |---|---|
> | `crates/stoffel-vm-runner/tests`, `crates/stoffel-cli/tests` | **no dependency.** Nothing in either directory drives `stoffel-run --client`; `cli.rs`'s `--client-*` matches are `stoffel run`'s local `ClientStore` flags |
> | `local_runner` | **already migrated.** It spawns parties only, and its in-process clients (`run_honeybadger_offchain_client`, `run_avss_offchain_client`) already pin their node RPC legs to `NodeRoster` |
> | compose stacks | **already migrated.** Every service with `STOFFEL_ROLE: client` already sets `STOFFEL_COORD_ADDR`: `docker-compose.coordinator.reserve-index.yml`, `crates/stoffel-lang/examples/docker-compose.coordinator.yml`, and `docker-compose.standing-concurrency.yml`, whose clients are driven by `acceptance.py`/`all_examples.py` with explicit `--off-chain-coord` and `--coord-cert` |
> | `docker/entrypoint.sh` | **migrated.** `STOFFEL_COORD_ADDR` is now required for the client role (`validate_env`), and the coordinator arguments it used to emit only `if [ -n "${STOFFEL_COORD_ADDR:-}" ]` are unconditional |
> | the SDK's client builder | **migrated, in the shape this subsection's own plan prescribes.** `ClientBuilder::connect` no longer dials node QUIC listeners with a bare `QuicNetworkManager::new()` and no local certificate; it requires `offchain_io`, opens the pinned `CoordinatorLink`, and keeps the roster it served. `StoffelClient::connect(&[&str])` — the coordinator-less convenience — is deleted, with `network_manager()` and `transport_client_id()`; `node_roster()` and `pinned_node_count()` replace them, and `ClientSummary::transport_client_id` becomes `pinned_node_count`. `verify_ordering()` keeps the ordering a caller attached and no longer reads one off a transport the client no longer owns. `client_connect_uses_real_quic_transport` is replaced by `client_connect_dials_its_coordinator_and_no_node`, which hands the client a live node listener as both a `--servers` address and a node RPC address and asserts it is never dialled. **Not done here**, and still this subsection's plan rather than the tree: removing `ClientBuilder::servers`/`client_id`/`network_config`/`network_deployment`, `Runtime::client_for_deployment`, and renaming `summary().server_count` to `node_count`. Those are API shape, not an unpinned leg |
>
> Two items the V-c paragraph below pairs with this deletion did **not** need deleting, and the
> reason is stage S1 rather than this one. "Node-side acceptance of client connections on the
> mesh" is already gone: `NodeListeners` gives the mesh listener the roster allowlist and
> nothing else, and a client reaches the separate `--client-bind` listener through
> `ClientIngressGate`. `--wait-for-clients` survives with it, because what it counts is the
> coordinator-admitted clients of an execution arriving on that listener — `expected_client_count`
> reaches `admit_execution_clients`, which reads the execution's inbox on the mux — not a direct
> client dialling the mesh. §9.D.3's row calling it "removed with direct clients" is the v1 plan's,
> not this tree's.
>
> One residual, stated rather than claimed closed: the SDK's `OffChainClientConfig` is still
> `Option` on `ClientBuilder`, so a client can be *built* without one. It cannot reach a node
> that way — `connect`, `run` and `submit` all refuse without it — and making the field
> required is the same API-shape change the table's last row defers.

> **Stage S2 repair (2026-10-13): the transport residue, and the guard the client pin was
> missing.** Three things the box above claimed or left behind.
>
> *The deletion was one layer short.* Direct client mode's transport plumbing outlived it as
> live `pub` API with no production caller, still carrying the removed mode's name:
> `ExecutionTransportMux::new_client` and `new_client_with_limits`, the `direct_client` flag
> they set, the `(true, ...)` arms of `inbox_route`,
> `ExecutionTransportError::ClientSourceOnClientEndpoint` (whose text read "an authenticated
> client cannot send to direct client endpoint"), and `ExecutionScopedNetwork::for_client`
> with the `tolerate_party_omission = false` only it produced — all re-exported from
> `stoffel_vm::net`. Their only production callers had been the four sites inside the two
> curve-generic client protocol runners S2 deleted. All of it is now gone (§13: breaking the
> public API is allowed). A node is the only endpoint that holds a mux, so `inbox_route` is
> three total arms and is infallible; `ExecutionScopedNetwork::for_party` is the only
> constructor, and omission tolerance is decided by the adapter's message kind alone.
>
> *A test of a construction nothing ships is not a test.*
> `client_downstream_queue_retains_ingress_capacity_lease` built the mux with
> `new_client_with_limits` and asserted a `Party(5)` frame arrives on `inbox.client` — which
> only the deleted `direct_client = true` routing does; on the mux a node ships that frame
> goes to `inbox.party`. It was the last caller keeping that constructor alive. It is now
> `downstream_queue_retains_ingress_capacity_lease`, built with `new_with_limits` and read
> through `inbox.party`, keeping all three capacity assertions and the `Party(5)` attribution.
> The two `execution_transport.rs` tests of the deleted mode were retargeted onto what
> survives rather than dropped: `party_send_tolerates_omission_but_client_send_does_not`
> becomes `mpc_send_tolerates_omission_but_control_send_does_not` (the axis that remains), and
> `authenticated_context_selects_the_only_valid_inbox` now pins all three of the production
> mux's routes, including that an admitted client's frame lands on the client inbox *even
> carrying the MPC kind a party's round would* and never reaches the party inbox.
>
> *`install_for_client` was an unguarded write to the allowlist.* It reached stoffelnet's
> `set_allowed_certificate_public_keys`, which clears the set and replaces it with no freeze —
> unlike `install_expected_server_public_keys`, which refuses when the allowlist is already
> non-empty and different. Both functions are `pub` on a `pub` type and both write the same
> `allowed_peer_public_keys` of any `QuicNetworkManager`, mesh managers included, so this
> contradicted the module's own invariant ("`install_into` is the only thing that sets the
> allowlist ... nothing may precede it"). `install_for_client` now refuses a transport that
> already has an allowlist (`RosterError::ClientAllowlistAlreadyInstalled`) — the roster is
> the first writer of a transport's allowlist or it is no writer at all — and `roster.rs`'s
> header now says so: `install_into` is the mesh's only writer, `install_for_client` is the
> client's, and neither may overwrite an installed set. The one production call site
> (`stoffel-run.rs:3428`) creates the manager immediately before, so the guard never fires
> there. `a_client_pin_refuses_a_transport_that_is_already_pinned` pins it on real loopback
> QUIC: both a different roster and the *same* roster are refused on a pinned transport, and
> the first pin is then shown still in force — the second roster's node still refused with
> `peer certificate public key is not in allowlist`, the first roster's node still admitted.

> **Stage S2 repair, attempt 2 (2026-10-13): the vacuous assertion, and the connect nothing
> proved succeeds.** Two defects the repair above left standing.
>
> *A loop over the roster is not a test of the transport.*
> `a_client_pin_observes_the_allowlist_on_the_transport` asserted
> `roster.index_of(&identity.public_key).is_some()` for each identity the roster was built
> from, under the message "every roster node is one of the keys the client now authorizes".
> `index_of` is a binary search of `self.nodes` for a key that is in `self.nodes` by
> construction, so it held before `install_for_client` was called, with the call deleted, and
> with no transport created at all — the same defect class the repair above enforced against
> `client_downstream_queue_retains_ingress_capacity_lease`, one function earlier in the same
> file, and the previous attempt declined to fix it as "pre-existing" on a provenance claim
> that does not survive `git show :crates/stoffel-vm/src/net/roster.rs` (831 lines, no
> `install_for_client`): the test is this work's own. The claim is now asserted against the
> transport, which is the only thing that can answer it — `QuicNetworkManager` exposes no
> reader for the installed key set, only its enabled-ness. The test is
> `a_client_pin_authorizes_every_roster_node`: a `#[tokio::test]` that stands up a listener
> for each of the three roster identities and dials every one of them with the pinned client
> over loopback QUIC. It is live — pinning `self.nodes[..1]` instead of the whole roster fails
> it on node 1 with `peer certificate public key is not in allowlist`, which the deleted loop
> would not have noticed. The two real assertions it carried are kept or already covered: the
> pin needs no local certificate (kept, via an anonymous manager), and an empty roster never
> reaches a transport (`an_empty_roster_is_refused_before_the_transport_is_touched`, which
> covers both constructors rather than one).
>
> *Every `connect` in the SDK suite ended in `unwrap_err`.*
> `client_connect_dials_its_coordinator_and_no_node` replaced
> `client_connect_uses_real_quic_transport` and dropped its six success assertions
> (`Connected`, `is_connected`, `network_manager`, `transport_client_id`, `server_count`,
> `connected`) for two negatives against a coordinator port nothing serves. Nothing proved
> `connect` ever succeeds, that `client_node_roster` accepts a roster a real coordinator
> serves, that the recomputed §9.B digest check passes on a well-formed one, or that
> `pinned_node_count`/`node_roster` — which `is_connected` now depends on — hold anything.
> That is load-bearing: `stoffel run --network` has exactly one path and it goes through this
> call. The negative test stays, and the prescribed
> `client_connect_opens_a_pinned_coordinator_link` now sits beside it: a coordinator is stood
> up in-process over a `NodeRoster` minted in the test
> (`HoneyBadgerCoordinatorRPCServerSharedBase::new` plus `start_coord` under a
> `self_signed_certs::server_cert()` pin, as `local_runner` does it), and `connect` is asserted
> to reach `Connected`, to report `is_connected()`, and to hold a roster whose `n`, `t` and
> recomputed digest are the served ones. `client_connect_refuses_a_coordinator_that_is_not_the_pinned_one`
> is the wrong-`coordinator_cert_der` case: a well-formed certificate for a key the coordinator
> does not hold is refused as `Error::Coordinator`, not accepted and not reported as a
> configuration error. The positive test is live — taking two of the three served certificates
> in `client_node_roster` fails it.

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
   certificates: node certificates to the coordinator's operator and the coordinator's
   certificate to every node and client.

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

> **Not landed on this tree, measured 2026-10-12 (stage V4).** This subsection is written in
> the present tense and names a test that does not exist. What is true of
> `feature/no-bootnode-v2`:
>
> | §F.0 | State |
> |---|---|
> | rule 1 — every published port on `127.0.0.1` | **no.** `docker-compose.yml` publishes `31415:31415/tcp` and each party's `9000`/`16180` pair on every interface, and `docker-compose.avss.yml`, `docker-compose.benchmark.yml` and `docker-compose.coordinator.reserve-index.yml` do the same. `docker-compose.standing-concurrency.yml` and both examples stacks publish nothing, so they satisfy it by having no `ports:` at all |
> | rule 2 — no image contains a private key | **partly.** `Dockerfile` has a `standing-runtime` target that copies only `*.crt` plus the operator certificate, and that is the image the standing stack builds; its `runtime` target still ends in `COPY ids /app/ids`, and `docker/coordinator.Dockerfile` still does too, so every one-shot stack's image carries every key |
> | rule 3 — one key per container, as a Compose secret | **standing stack's node and operator services only.** `docker-compose.standing-concurrency.yml` is the one file with a top-level `secrets:` block; every other stack names a `.der` path in `STOFFEL_KEY` or `--server-key` out of the baked `ids/`. Even there the *coordinator* service builds `docker/coordinator.Dockerfile`, which bakes the whole directory, so that one container still holds every key |
> | rule 4 — certificates mounted one file per mount | **standing stack only**, and with the same exception |
> | `crates/stoffel-vm-runner/tests/deployment_key_material.rs` | **does not exist.** No test reads the Dockerfiles or the compose files for any of this |
>
> The requirement stands as a requirement; nothing here is retracted. It is recorded as
> unlanded because it is orthogonal to bootnode elimination — the standing path, which this
> effort rebuilt, is the part that mostly satisfies it, and the one-shot stacks kept `dev`'s
> key handling untouched. Every §G row that says "holds under §F.0 only" therefore does not
> hold for a one-shot stack on this branch.

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
Both roles emit `--coord-cert ${STOFFEL_COORD_CERT}` (**as built on `dev`**, defaulting to
`/app/ids/server_cert.crt`); client mode emits
`--client-slot` and `--expect-program-hash` from `STOFFEL_CLIENT_SLOT`
and `STOFFEL_EXPECT_PROGRAM_HASH` when they are set. Its refusals are
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
| `docker-compose.coordinator.reserve-index.preproc.yml` | override of the above | drop its per-party `STOFFEL_NODE_ROSTER` restatements. ~~and `STOFFEL_PREPROC_STORE` (`:26`, `:35`, `:44`, `:53`, `:62`)~~ — **void on two counts, measured 2026-10-14.** (a) This override sets no `STOFFEL_PREPROC_STORE` and never did on `dev`: it passes `--preproc-store /var/lib/stoffel-preproc` once, at `:48`, inside the `x-standing-node-command` anchor (`:28`) that all five parties reference through `command: [*standing-node-command]`. `grep -c PREPROC` over the file is 1, and that one hit is a comment at `:11`. No compose file in the repository sets the variable; its only occurrences in the tree are `docker/entrypoint.sh:69` (banner) and `:250-252` (forwarding). The lines cited (`:26` … `:62`) carry `PARTY_ID` and bind addresses. (b) The prescription itself belonged to V-0's obsolete deletion; the flag is **kept** (§9.1 V-0). The per-party volume stays and holds preprocessing material — there is no epoch store |
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

~~The per-party epoch store needs no change: the same volume path now holds records keyed
by the new digest, and the old records are orphaned harmlessly (D.5).~~ There is no epoch
store, on `dev` or anywhere else (§11.3, §12.E).

> **Corrected 2026-10-12 against this tree (stage V4).** This subsection is the plan the
> `main`-based attempt was built from, and five of its statements are not true of
> `feature/no-bootnode-v2`:
>
> 1. **`docker-compose.mesh.yml` has never existed in this repository.** It is named in the
>    prose above and in §12.F's mode table. §9.I carries the measurement; the stacks are the
>    eight in §9.I's V2 row.
> 2. **The entrypoint does not refuse the dropped variables "by name (D.3)".** It cannot, under
>    §13, and it does not: `docker/entrypoint.sh` simply stops reading what is gone. §D.3's own
>    correction says the same.
> 3. **Parties still carry `STOFFEL_N_PARTIES` and `STOFFEL_THRESHOLD`, deliberately**, and the
>    two client-bearing stacks still carry `STOFFEL_EXPECTED_CLIENTS` — see §D.2's measured
>    block for why each stayed. "Drop them" did not happen and is not pending.
> 4. **No party is given `STOFFEL_EXECUTION_ID`.** The sentence above that tells a stack to set
>    it on its parties is exactly the flow stage V3 reversed. The variable survives in two
>    stacks' `client-env` anchors only, because a client is not on the node roster and has to be
>    handed the identity the coordinator minted (§12.G).
> 5. **The preprocessing override configures a store, and its per-party volume holds
>    preprocessing material, not an epoch (there is none).** The row telling it to drop the
>    variable is void: the flag is kept (§9.1 V-0, now done).
>
>    *Corrected 2026-10-14 (stage V-0's fix).* This point used to read "**The preprocessing
>    override still sets `STOFFEL_PREPROC_STORE`** on all five parties". The conclusion was
>    right — a store is configured, the flag is live — but the mechanism was not, and the same
>    wrong mechanism was repeated in §F.2's S6 box, in §9.I's §F.1 row and in §14's
>    `[8]`-class sweep row. Measured: the override sets no environment variable. It passes
>    `--preproc-store /var/lib/stoffel-preproc` once, at `:48`, inside the
>    `x-standing-node-command` anchor at `:28`, which all five parties take through
>    `command: [*standing-node-command]`; the only `PREPROC` string in the file is a comment at
>    `:11`. **No compose file in this repository sets `STOFFEL_PREPROC_STORE`** — the variable
>    occurs only in `docker/entrypoint.sh:69` and `:250-252`. That distinction is not cosmetic:
>    `:48` is inside a `--standing-node` command (`:30`), so these five parties are *standing*
>    and never reach the one-shot commit path where the S12 reuse defect lived, whereas
>    `entrypoint.sh:250-252` — the route that would give an **ordinary** party a store — has no
>    shipped caller at all. That is why the defect was latent rather than active, and why this
>    stack is a liveness check and not V-0 coverage (§9.1 V-0's docker paragraph, §H).
>
> What *is* true of every stack, and is what this stage checked: a `coordinator` service, a
> pinned coordinator certificate (`--coord-cert`, defaulted by the entrypoint to
> `/app/ids/server_cert.crt`), a `--node-roster` of the five node certificates, an
> `--operator-certs` set, and no `STOFFEL_AUTH_TOKEN`, `LEADER_ARGS`, `BOOTSTRAP_ARGS`,
> bootstrap address or mounted control directory anywhere. All eight parse under
> `docker compose config`.

#### F.2 Test scripts

**As built in the `main`-based attempt** — and *not* on `dev`, where no
`STOFFEL_EXPECT_ROSTER_DIGEST` variable exists and no script exports one — both docker
scripts also export `STOFFEL_EXPECT_ROSTER_DIGEST`, defaulted to
the §B golden digest of `ids/nodes`, so every party and client of the run refuses a
coordinator serving any other roster; `test-coordinator-reserve-index.sh` additionally
asserts the coordinator's `Serving node roster n=5, t=1, digest=…` line and reads each
container's mounts to assert that no party or client held any identity material but the
coordinator's certificate, its own certificate and its own key.
`crates/stoffel-lang/examples/run_coordinator_compose.sh` makes the same mount assertion
for its parties. `test-coordinator-preproc-store.sh` keeps its name and becomes the restart
check below.

> **Corrected 2026-10-13 (stage S6), and corrected again 2026-10-14 (stage V-0's fix).** The
> sentence that used to close the paragraph above — "since stage V-0 has not landed (§9.I), what
> makes its refutations true is that no stack sets `STOFFEL_PREPROC_STORE` any more and the
> entrypoint refuses it" — is false in both halves on this tree. S6's replacement text got the
> conclusion right and the mechanism wrong, and is itself corrected here: it said
> `docker-compose.coordinator.reserve-index.preproc.yml` sets
> `STOFFEL_PREPROC_STORE: /var/lib/stoffel-preproc` on **all five** party services. It does not,
> and no compose file in the tree does. The override passes `--preproc-store` once, at `:48`,
> inside the `--standing-node` command anchor the five parties share (see §F.1's corrected
> point 5). What is true, and is what S6 was reaching for, is that
> `docker/entrypoint.sh` refuses nothing: it prints the value in its banner and forwards it as
> `--preproc-store`, which `stoffel-run` parses. Nor would a refusal be legitimate — §13 makes
> the resolution a deletion, not a guard. So V-0 is still open exactly as §9.I records, and what
> the script's refutations rest on is the script itself: it drives the stack with the store
> configured and asserts what the store does and does not carry across the restart. The
> deployment half of V-0 has **not** landed either, and the §9.I row claiming it had is
> corrected there. Concretely the script runs the base stack plus that override three times and
> asserts: all five parties agree `action=Rebuild` on a fresh volume, no party rebuilds on the
> retained volume, and all five rebuild again once one party's volume is deleted — which is a
> statement about the store's contents, made with the store switched on.

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
  although the roster, the program and the execution id are unchanged.

  > **Void, 2026-10-14 (stage V-0's fix).** The V-0 half of this bullet said the first run
  > refutes `Persisted preprocessing material to store` where it required it (`:152`), the
  > second refutes `Loaded preprocessing material from store` where it required it (`:162`),
  > and "the override loses `STOFFEL_PREPROC_STORE`". All three are void. V-0 as rewritten
  > *keeps* persistence and keeps the flag, so both log lines stay required — the script still
  > asserts them, and its second phase is still "load preprocessing from LMDB". The override
  > never set that variable to lose (§F.1's corrected point 5). What the script gained instead
  > is `assert_no_party_committed_from_a_live_execution`, pinning its own premise — that its
  > five standing parties never take the one-shot commit path — and a header saying what it
  > does and does not witness. It is a liveness check, not V-0 coverage (§9.1 V-0).

  In V-b, when the broadcast goes, both runs assert
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

> **Corrected 2026-10-12 (the `dev` redo).** This section used to show one flag table,
> headed with the wrapper's path but listing `run-coord`'s surface, and marked parts of it
> **as built**. They are two binaries in two repositories with two different surfaces. The
> `run-coord` table below is the coordinator worktree's, which the redo does not touch; the
> wrapper table is what `docker/coordinator-wrapper/src/main.rs` actually parses. Flags the
> old table attributed to the wrapper and the wrapper does not have: `--execution-id`,
> `--program`, `--node-certs`, `--client-io`, `--client-certs`, `--admission`,
> `--association-deadline-secs`, `--input-deadline-secs`, `--max-connections`, and the
> empty-value-equals-absent rule. The one thing the old table promised that was worth
> keeping — the roster-digest startup line — has been **implemented** rather than
> redescribed, because §D.2 names it as where an operator gets the value to pin.

`docker/coordinator-wrapper/src/main.rs` (clap), **as built**:

| Flag | Meaning |
|---|---|
| `--server-cert <path>`, `--server-key <path>` | the coordinator's certificate and PKCS#8 key; clients and nodes pin the certificate's key. In compose, the key is a per-service secret (§F.0) |
| `--bind-addr <addr>` (default `0.0.0.0`), `--port <u16>` (default `31415`) | listen address |
| `--node-roster <paths>` | **required**: the node roster, one certificate DER per MPC node, comma-separated. Membership is fixed for the process's whole life, and `NodeRoster::new` derives every identity and every pinned key from the certificate itself, so nothing extracts a public key by hand. `n` is the number of entries, so there is no `--n` |
| `--t <u64>` | the roster's corruption threshold |
| `--hash <64-hex>` | optional: register one execution at startup, for this program hash. The coordinator mints its identity; `requires = "client_slots"`, so a startup registration always states its slot table |
| `--entry <name>` (default `main`) | the entry function nodes call in that program |
| `--client-slots <in:out>[,<in:out>…]` | one `ClientSlotSpec` per entry, in slot order |
| `--association-timeout-secs <u64>` (default 3600), `--input-timeout-secs <u64>` (default 7200) | seconds from startup, turned into the registration's `ExecutionDeadlines` |

Admission is `AdmissionPolicy::Open` and is not a flag: clients bind their slot at run
time, so a client the deployment never listed can take part, which is the point of §C.
`RpcServerLimits::default()` is used as-is. Startup prints, in order,
`Serving node roster n=…, t=…, digest=…` — before anything can connect, so the value a
deployment pins with `--expect-roster-digest` is the value this process actually serves —
then `Minted execution {id} (registration nonce {nonce})` if `--hash` was given, then
`Listening on {addr}:{port}`.

`crates/bins/src/bin/run-coord.rs`, in the coordinator workspace, is the richer surface and
is unchanged by the redo:

| Flag | Meaning |
|---|---|
| `--program <path>` \| `--hash <64-hex>` | a required clap `ArgGroup`: `--program` registers `program_hash_of(bytes)` and takes its slot table from the manifest; `--hash` registers without the bytes, and a wrong one makes every node exit 13 (D.7 step 1) |
| `--entry <name>` (default `main`) | the entry function |
| `--node-certs <paths>` | the roster, as certificate DERs; the bare-BIT-STRING `parse_public_keys` is gone |
| `--t <u64>` | threshold; there is no `--n` |
| `--client-io <in:out>[,…]` | one slot per entry; refused with `--program`, whose manifest supplies them. Empty is the same as absent |
| `--admission <pre-registered\|open>` | a `ValueEnum`, default `pre-registered`. It never defaults to `open`: `--client-io 1:1` without `--client-certs` fails `PreRegisteredCountMismatch` rather than admitting anyone |
| `--client-certs <paths>`, `--client-bindings <slot>=<cert>[,…]` | `pre-registered` only: by slot order, or by explicit slot |
| `--association-deadline-secs <u64>`, `--input-deadline-secs <u64>` | seconds after startup, turned into `ExecutionDeadlines` |
| `--one-off`, `--one-off-shutdown-grace-secs <u64>` | drain and exit once the retirement quorum has acknowledged the execution (§C.10); omit for a standing coordinator |
| `--max-connections <usize>` | `RpcServerLimits::max_connections`; the other limits keep their defaults (§A) |
| `--server-cert`, `--server-key`, `--addr` (default `127.0.0.1`), `--port` (default `31415`) | identity and listen address |

`run-coord` registers its one execution at startup in both modes; standing mode used to
register nothing and rely on the deleted RPC. The manifest's `client_slot`s must be exactly
`0..k` (otherwise exit 2: `client IO manifest slots are not contiguous from 0`). `--n`,
`--n-inputs`, `--output-clients`, `--initial-mpc-nodes` and `--backend` — whose only use
was choosing the `min_output_shares` default — are gone, and `--min-output-shares` is not
added, because the registration field is gone (§C.1).

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

> **Corrected 2026-10-13 against this tree (stage S5).** This subsection described a
> `[patch.crates-io]` table of **git** entries pinned to the coordinator's pushed branch. The
> tree has never carried that shape on `feature/no-bootnode-v2`: stage V1 repointed both tables
> at a **path** (§12.H), and five of the statements below were consequences of the git form and
> are false of a path form — including the stated reason the Rust CI jobs are red. They are
> rewritten here with what was measured. What survives unchanged is why the table exists at all
> — coordinator `0.3.0` is not on crates.io — and the `cargo publish` consequence.

Until `0.3.0` is on crates.io, the root `Cargo.toml` **and**
`docker/coordinator-wrapper/Cargo.toml` (its own workspace, which `cargo build --workspace`
cannot see) carry:

```toml
# TEMPORARY, until stoffel-mpc-coordinator 0.3.0 is published
# (docs/design/bootnode-elimination.md §9.F.5, §12.H).
[patch.crates-io]
stoffel-mpc-coordinator-off-chain = { version = "0.3.0", path = "../stoffel-mpc-coordinator-roster-admission/crates/off-chain" }
stoffel-mpc-coordinator-shared = { version = "0.3.0", path = "../stoffel-mpc-coordinator-roster-admission/crates/coord-shared" }
```

The path is **relative to the manifest that carries it** and names a sibling checkout of
`stoffel-mpc-coordinator` on branch `feature/no-bootnode`, so the wrapper's copy of the table
reads `../../../stoffel-mpc-coordinator-roster-admission/...` instead. It was an absolute path
under one developer's home directory until stage S5, which made every host-side `cargo`
invocation of either workspace fail on any other machine: a `[patch]` whose path is absent is
not a silent drop but a hard error — `failed to load source for dependency`, exit 101, measured
on a relocated copy of the wrapper, which resolves cleanly in the same location once the entry
is relative. Nothing in the tree outside this document names an absolute host path. *One
exception, measured 2026-10-16 and worth knowing because `ci.yml`'s first cargo step is the one
it covers:* `cargo fmt` is not among those invocations. It enumerates targets through `cargo
metadata --no-deps`, which does not load a dependency source, so on a probe crate with a real
dependent of a patch pointed at a missing path `cargo fmt --all -- --check` is rc 0 while
`cargo metadata` (without `--no-deps`), `cargo check` and `cargo clippy` are all rc 101.

and the pins move `=0.2.0` → `=0.3.0` in `crates/stoffel-vm-runner/Cargo.toml`,
`crates/stoffel-rust-sdk/Cargo.toml` and `docker/coordinator-wrapper/Cargo.toml`.
The bump is what makes the patch apply: a patch whose version does not satisfy the
requirement is left unused, and cargo only warns. All of those requirements read `=0.3.0`, the
coordinator worktree's `[workspace.package]` version is `0.3.0`, and `cargo tree -p
stoffel-mpc-coordinator-off-chain` resolves to the sibling path from both workspaces, so the
patch binds and no "was not used in the crate graph" warning is emitted.

While the patch exists:

- **A build sees the coordinator working tree, not a commit.** A path patch resolves to what
  is on disk, uncommitted changes included — which is what the sequence needs (§12.H), and also
  why "the VM builds" does not say which coordinator source it was built against. **Why the
  Rust CI jobs are red** is now one thing only: the coordinator half this repository is written
  against **does not exist as a commit**. Measured at stage S5 against
  `origin/feature/no-bootnode` (`012f5e3`, version `0.3.0`), `cargo check -p stoffel-vm-runner`
  fails with two `E0432`s — `ExecutionNotice`, `PublishedExecution`, `CoordinatorIncarnation`,
  `Subscription` and `ExecutionRequest` are not in that commit's
  `stoffel-mpc-coordinator-off-chain`.

  *Sharpened 2026-10-16, because the earlier wording — "the coordinator commits this repository
  is written against are not pushed" — prescribes the wrong action and invites the wrong
  conclusion.* The branch **is** pushed: in the coordinator worktree `git rev-parse HEAD` and
  `git rev-parse origin/feature/no-bootnode` are both `012f5e3` and `git log
  origin/feature/no-bootnode..HEAD` is empty, so `git push` there reports everything up to date
  and a reader who runs it concludes the blocker is cleared. What is missing is missing because
  it was never **committed**: `git diff --stat HEAD` is 8 files, 2063 insertions, 282 deletions,
  staged and uncommitted, in one working tree on one machine — `crates/off-chain/src/lib.rs`
  (+752/−51) and its tests (+961/−114) among them. Half the contract is on origin and half is
  not: `get_node_roster` and `AdmissionPolicy` are in the pushed commit, while `ExecutionNotice`
  appears on 34 lines of that working tree's Rust — 16 in `crates/off-chain/src/lib.rs`, 18 in
  `crates/off-chain/tests/off_chain.rs`, 37 lines counting `CHANGELOG.md` and `README.md` — and
  on no line of **any** file of the pushed tree (`git grep -c ExecutionNotice HEAD` matches
  nothing, and the same count over `git archive origin/feature/no-bootnode` extracted to a
  scratch directory is 0). `CoordinatorIncarnation` and `PublishedExecution` likewise, and
  `Subscription` is a `pub use jsonrpsee::core::client::Subscription` added by the same
  uncommitted work. This repository consumes exactly the missing half: for those three types
  alone, 38 lines across `crates/stoffel-vm-runner/src/execution_stream.rs` (35) and
  `src/bin/stoffel-run.rs` (3), and `ExecutionRequest` reaches `src/bin/stoffel-coord-ctl.rs`,
  `src/local_runner.rs` and `docker/coordinator-wrapper/src/main.rs` besides. So the action this
  blocker needs is *commit, review and push*, not push; and until it is taken, a red run on this
  branch is this, not the change under review.

  *Measured again 2026-10-16, in a second pass, because the first version of this paragraph said
  "every cargo step and both Docker jobs fail to compile, at the two `E0432`s above, before a
  test runs" — and three parts of that are wrong. The shape of a red run is worth stating
  exactly, since a reader who watches `cargo fmt` pass may conclude the clone cleared the
  blocker.* The pushed tip was extracted with `git archive` and the patch tables repointed at it
  through `cargo --config`, so no file of this tree was changed to measure any of this.

  - `cargo fmt --all -- --check` — `ci.yml`'s **first** cargo step — **passes**. rustfmt parses
    and resolves no name: a probe crate whose only defect is
    `use std::collections::ThisDoesNotExist;` gives `cargo fmt --all -- --check` rc 0 and
    `cargo check` rc 101.
  - `cargo clippy --workspace --all-targets -- -D warnings` is where both `build-and-test`
    matrix jobs (`ubuntu-latest`, `macos-latest`) go red: rc 101, `stoffel-vm-runner` failing
    with 9 errors in the lib and 19 in its lib test. The nine are the two `E0432`s above plus
    seven consequences of them — an `E0599` for `CoordinatorLink::subscribe_executions`,
    five `E0609`s in `execution_stream.rs` and an `E0308` in `local_runner.rs`. `cargo check`
    reports only the two: the same `--workspace --all-targets` run under `cargo check` gives 2
    in the lib and the same 19 in the lib test, and S5's narrower
    `cargo check -p stoffel-vm-runner` gives the two alone. So those seven are what clippy's
    analysis of the lib surfaces and `cargo check`'s does not, and "two `E0432`s" is the floor
    rather than the whole.
  - **the gap is wider than those five names**, which is what a would-be committer needs to
    know. Behind `--all-targets` the lib test adds ten errors to the lib's nine: two `E0432`s,
    one of them for `stoffel_mpc_coordinator_shared::admission::PreRegisteredClient` (`no
    PreRegisteredClient in admission`); an `E0560` for an `ExecutionRegistration.request` field
    the pushed struct does not have — its fields there are `execution_id`, `program_hash`,
    `client_slots`, `admission`, `deadlines`; and seven `E0599`s for
    `AbortReason::OperatorRequest`. Counted over the extracted tip's Rust as whole words
    (`grep -ro '\bX\b' --include='*.rs'`), `PreRegisteredClient`, `OperatorRequest` and
    `subscribe_executions` are 0 occurrences each, against 14, 3 and 18 in the working tree.
    Count `PreRegisteredClient` as a bare substring instead and the tip gives 3, all of them
    inside `RegistrationError::DuplicatePreRegisteredClient`, which is a different name and is
    committed. So the missing half spans **both** coordinator crates and includes a struct
    field, an enum variant and two methods, not only the five absent type names. The second
    method is `CoordinatorRPCServerSharedBase::with_operators`, which this inventory missed until
    the fourth pass because it is reached from the *wrapper's* own workspace rather than from the
    runner, so neither the clippy run nor `cargo check -p stoffel-vm-runner` surfaces it — see
    the wrapper bullet below. A committer who lands the five names and the first three extras is
    still red on it.
  - the cargo steps after clippy never run: no step in that job carries `continue-on-error` or
    `if: always()`.
  - `cargo build --manifest-path docker/coordinator-wrapper/Cargo.toml` would fail on its **own**
    two errors, in its own workspace, not on the runner's two — which is why that step exists at
    all. *Measured 2026-10-16 (fourth pass), rather than inferred:* rc 101 with an `E0432` for
    `ExecutionRequest` (`docker/coordinator-wrapper/src/main.rs:9`) **and** an `E0599` for
    `CoordinatorRPCServerSharedBase::with_operators`
    (`docker/coordinator-wrapper/src/main.rs:210`), "due to 2 previous errors". Non-vacuous: the
    same command against the coordinator *working* tree is rc 0 with zero errors, so both are
    tip-specific rather than pre-existing. `with_operators` is a **sixth** item the five absent
    type names do not cover — whole words over the extracted tip's Rust it is 0 occurrences
    against 6 in the working tree, where it is defined at the uncommitted
    `crates/off-chain/src/lib.rs:2481` — and it is the operator set that
    `--operator-certs` fills, i.e. the authorization boundary that replaced the mount (§12).
  - **no Docker job fails on a pull request.** `ci.yml`'s `docker-build` declares
    `needs: [build-and-test]`, so it is *skipped*; `docker-e2e.yml`'s two jobs do not run on a
    plain pull request at all (`preproc-store` wants the `docker-e2e` label, `standing` is
    schedule or dispatch only). Nightly they do run, and they clone the same pushed branch and
    build the same `stoffel-vm-runner` lib inside the image, so they fail there — deduced from
    the compile above, not separately run in Docker.
  - so `harness-wiring` is the only job that reports at all; the paragraph below says why it
    carries no `needs:`.

  *Measured a third time 2026-10-16, in the repair pass that reproduced this blocker again, to
  say what a committer actually has to land. The numbers above are confirmed unchanged on that
  re-run: `cargo fmt --all -- --check` rc 0, clippy rc 101, 9 errors in the lib and 19 in its
  lib test.*

  - **the clearing commit is a breaking change, not an addition.** The second pass called the
    five `E0609`s "consequences" without naming the cause, and the cause is one type: at the
    pushed tip `AdmissionPolicy::PreRegistered` carries `clients: Vec<ClientIdentity>` over
    `pub type ClientIdentity = Vec<u8>` (`crates/coord-shared/src/lib.rs:75`), where the staged
    work carries `clients: Vec<PreRegisteredClient>`, a struct of `identity` and `client_slot`
    — so `execution_stream.rs:1231-1255` reads those two fields off a `Vec<u8>`. The `E0308`
    is the same kind: `new_for_execution`, on the off-chain crate's
    `tests::fake_coord::HoneyBadgerCoordinatorRPCServerSharedBase`, returns one value at the tip
    and the `(coord_state, registered)` pair the tree destructures in the staged work
    (`local_runner.rs:227`). The payload type of a shipped enum variant changes, so this cannot
    land additively, and landing the five absent type names alone would not clear it — which is
    also why 961 of the 2063 inserted lines are the coordinator's own tests
    (`crates/off-chain/tests/off_chain.rs`, `git diff --cached --numstat`).
  - **the commit is sufficient, not only necessary, for the cargo jobs.** CI's exact
    `cargo clippy --workspace --all-targets -- -D warnings`, same machine, same pinned
    `nightly-2026-08-21`, within the same hour: rc **101** with the `[patch]` tables pointed at
    the extracted pushed tip, rc **0** with them pointed at the coordinator working tree, whose
    only difference from that tip is those 8 staged files. Nothing else in either repository
    stands between a red cargo job on this branch and a green one.
  - **and the change under review is green against that very tip.** With the tables pointed at
    the extracted pushed tip, `cargo test -p stoffel-vm --lib` is rc **0** with the same
    737 passed / 0 failed / 1 ignored, both acceptance reproductions among them by name.
    `crates/stoffel-vm/Cargo.toml` names no `stoffel-mpc-coordinator-*` dependency at all — only
    `crates/stoffel-vm-runner`, `crates/stoffel-rust-sdk` and `docker/coordinator-wrapper` do —
    so the preprocessing mechanism cannot reach the missing API, and the red run belongs to the
    runner's §12 execution-stream contract. That is the sharpest answer available to a reviewer
    who reads the red run as a defect in the preprocessing change.

  `cargo publish` of any VM crate is impossible for the separate reason below.

  The jobs clone that branch into the sibling path the tables name (`.github/workflows/ci.yml`,
  "Check out the unpublished coordinator beside this repository"), so they go green when that
  work lands, with no edit of this repository. `harness-wiring`, added 2026-10-16, carries no
  `needs:` for exactly this reason and reports in the meantime (§9.1's residual item 11).
  Vendoring the coordinator source in-tree instead — the shape `dev` used for the browser fork — was
  considered and rejected at S5: it would copy uncommitted work of a repository this port is
  still editing into this one, and the host build would then stop exercising the checkout the
  Docker stacks build from.

  *Third pass, 2026-10-16: the obvious-looking in-repo fix — point the clone at a ref that does
  carry the API — is ruled out by measurement rather than by argument, because `ci.yml` is where
  a reader meets that temptation.* **No pushed ref of that repository carries it.**
  `git ls-remote --heads --tags origin` lists 21 heads and 2 tags. Grepped at each pushed SHA
  itself rather than at a tracking ref that may be stale, the 20 heads whose tip object the
  worktree already holds give **0 files** for each of `ExecutionNotice`,
  `CoordinatorIncarnation`, `PublishedExecution`, `subscribe_executions` and
  `PreRegisteredClient`, while the control `AdmissionPolicy` is 5 files on `feature/no-bootnode`
  and 0 on every other head — so the clone already names the only branch that carries even the
  committed half. The one head the worktree had never fetched (`add-browser`, `06a72b6`) was
  shallow-cloned into a scratch directory and gives 0 for all five; both tags (`v0.2.0` →
  `dffffd6e`, `stoffel-mpc-coordinator-libs-v0.1.0` → `c558a8d`) give 0; and
  `git log --all -S'\b<name>\b' --pickaxe-regex -- '*.rs'` matches **0 commits** for each name,
  so they are in no commit reachable from any ref, not merely absent from the tips. *Corrected
  2026-10-16 (fourth pass): the whole-word form is load-bearing here and this paragraph
  originally gave the plain `-S` form.* `-S` is a literal substring search, so
  `git log --all -SPreRegisteredClient` matches **1** commit (`272e493`) on the three lines
  holding `RegistrationError::DuplicatePreRegisteredClient` — the same substring trap this
  section's second pass records two bullets above, walked into by the pass that was warning
  about it. The conclusion is unchanged, and the four other names are 0 either way; only the
  stated measurement needed the `\b` anchors. `git ls-remote` puts
  `refs/heads/feature/no-bootnode` at `012f5e3`, identical to that worktree's `HEAD`, so none of
  this is a stale fetch. Repointing the clone, vendoring (above) and deleting the execution
  stream are the only in-repo alternatives to that commit, and all three are dead: the first has
  no target, the second copies uncommitted work of a repository this port is still editing, and
  the third deletes shipped behaviour to make a compile error go away.
- **`.githooks/pre-commit` refuses the git shape and passes this one.** Its first scan rejects
  a `git`/`branch`/`rev`/`tag` reference to a Stoffel crate; its second rejects a `path` entry
  for one but exempts any line that also carries a `version =`, which both entries above do.
  `bash .githooks/pre-commit --manifest-scan-only` passes on this tree, so the table needs no
  `--no-verify`. The refusal of the git shape is right — it exists to keep an unpublished
  dependency out of a release — and it stops mattering when the table goes.
- **`cargo publish`** of `stoffel-vm-runner` and `stoffel-rust-sdk` fails (`=0.3.0` cannot
  be satisfied from crates.io) — the correct failure.
- **Docker reads neither table.** An image that runs `cargo` on this workspace writes its own
  `[patch.crates-io]` into `.cargo/config.toml`, and a `.cargo/config.toml` `[patch.crates-io]`
  entry **replaces** the manifest's entry of the same name — silently, with no warning of any
  kind, and without the manifest's path ever being read. That holds only while every such table
  **covers** both coordinator entries: for those images it is why they build on a host with no
  sibling coordinator checkout, and why the absolute path never broke them. An image whose table
  omits the entries does read the manifest's path, and dies on it — which is exactly what the
  absolute path did to the two images recorded below, for the whole V1-S4 window.

  The rule this imposes, stated as a rule rather than as a list of files, because the list is
  what went stale: **since the root table names a path no image contains, an image that runs
  `cargo` on this workspace is broken unless its injected table covers both coordinator
  entries** — whatever else that image builds, and whether or not the crate it builds depends
  on the coordinator, because the failure is workspace resolution and not dependency selection.
  Four files run `cargo` here, and all four now cover them: `Dockerfile`,
  `Dockerfile.benchmark`, `docker/coordinator.Dockerfile` and
  `docker/vm-ebpf-profile.Dockerfile`. A fifth added later is a fifth instance of this defect
  until its table says otherwise.

  The override is keyed on the patched **source**, not on the crate name. A config table headed
  `[patch."https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git"]` therefore overrides
  nothing here: it patches a git source no manifest in this tree depends on any more, the
  manifest's relative sibling path survives into the image, and the build dies resolving it.
  `Dockerfile.benchmark` carried that git-keyed header at both of its `.cargo/config.toml`
  writes, inherited unchanged from `dev` — where it was harmless, because `dev`'s root table
  pointed at the **in-tree** `vendor/stoffel-mpc-coordinator-browser`, which `COPY . .` brought
  into the image. Stage V1 deleted that vendor directory and repointed the table out of tree,
  which turned the inherited header into a hard break of the benchmark stack — a stack that is
  meant to work, since `docker-compose.benchmark.yml` builds this file twice and V3 made the
  stack self-driving with a `stoffel-coord-ctl` built by it. No stage caught it because no
  stage's verification exercises that stack. Both headers now read `[patch.crates-io]`,
  matching `Dockerfile`; the entries underneath already named
  `/opt/stoffel-coordinator/crates/{off-chain,coord-shared}`, which is where the `coordinator`
  named context is copied. Measured inside the image itself, by building `--target planner`
  both ways and resolving in each: with the git-keyed header, `cargo metadata` at `/build`
  exits **101** — `patch location /stoffel-mpc-coordinator-roster-admission/crates/off-chain
  does not contain packages matching stoffel-mpc-coordinator-off-chain`, blamed on
  `/build/Cargo.toml`, and `ls /` confirms no such directory — while with `[patch.crates-io]`
  it exits **0** and both crates resolve to
  `/opt/stoffel-coordinator/crates/{off-chain,coord-shared}` at `0.3.0`. Note where that
  failure lands: the `planner` stage passes either way, because `cargo chef prepare` only
  skeletonises manifests and never resolves, so the break surfaces one stage later in
  `cargo chef cook` / `cargo build` — which is the other reason a cheap smoke check would not
  have found it. With the fix, `docker build -f Dockerfile.benchmark --build-context
  coordinator=<coordinator worktree> .` now runs to completion for the first time in this
  branch's history: `cargo chef cook --release`, then `cargo build --release -p
  stoffel-vm-runner --features statistics --bin stoffel-run --bin stoffel-coord-ctl`, then the
  two `stoffellang` compiles, and the runtime image carries `/app/stoffel-run`,
  `/app/stoffel-coord-ctl` and both `.stflb` programs.

  `docker/vm-ebpf-profile.Dockerfile` was the **fourth** instance, and it is the reason the rule
  above is now stated as a rule. It is unchanged from `dev`, so the git-URL sweep that found the
  two `Dockerfile.benchmark` headers structurally could not find it: its table was already
  `[patch.crates-io]`-keyed and simply **incomplete**, naming only
  `stoffelnet = { path = "/build/stoffelnet" }` while `COPY . .` brought in the root manifest
  whose coordinator entries point at a sibling checkout the image does not contain. `cargo build
  --release -p stoffel-vm --bin vm_ebpf_profile` therefore died in resolution with the same error
  as next door, and the profiled binary is real
  (`crates/stoffel-vm/src/bin/vm_ebpf_profile.rs`), so this is V1's regression and not dead
  weight predating the port — which is why it was repaired rather than deleted under §13, even
  though nothing in any compose file, script, CI job or document references the image. Measured
  by replicating the file's `COPY`/config prelude in an image and resolving at `/build`: before,
  exit **101** — `patch location /stoffel-mpc-coordinator-roster-admission/crates/off-chain does
  not contain packages matching stoffel-mpc-coordinator-off-chain`, blamed on
  `/build/Cargo.toml`; after, exit **0**, with both crates resolving to
  `/opt/stoffel-coordinator/crates/{off-chain,coord-shared}` at `0.3.0`. The file now takes a
  `coordinator` named context beside the `networking` one it already demanded, copies both
  external workspaces to `/opt` rather than under `/build` (the reason `Dockerfile` gives:
  Cargo would otherwise attach their workspace-inherited manifests to this workspace), and
  documents both contexts in its header. One pre-existing condition is untouched and is not this
  branch's: the `stoffelnet` entry does not bind, because the operator's sibling checkout is
  `0.1.0` while all three manifests require `=0.1.1`, so resolution falls through to the registry
  `0.1.1` and cargo warns `patch stoffelnet v0.1.0 was not used in the crate graph`. That was
  equally true of the `/build/stoffelnet` form it replaced.

  *Both repairs in this subsection are code changes made under stage S6, whose §9.I box says it
  changed none; see the "Repair of stage S6" box in §9.I, which records them and corrects that
  claim.*
- **The `coordinator` named context is what feeds those builds.** The copy is the dependency
  source, not residue of the path form:

  ```dockerfile
  COPY --from=coordinator . /opt/stoffel-coordinator
  ```

  (`/build/coordinator` in `docker/coordinator.Dockerfile`), and it is exactly the path the
  injected table points at, so every compose build block demanding it is load-bearing:

  ```yaml
  additional_contexts:
    coordinator: "${STOFFEL_COORDINATOR_CONTEXT:?Set an absolute coordinator checkout}"
  ```

  A stack that started without the variable would build the registry `0.2.0`, so
  `STOFFEL_COORDINATOR_CONTEXT` must name a `0.3.0` checkout. The injected tables use a bare
  `path =` with no version requirement, so the manifest bump is what makes them bind and they
  need no edit of their own. They go when the table goes, together with the
  `STOFFEL_COORDINATOR_CONTEXT` / `STOFFEL_COORDINATOR_DIR` plumbing in the two
  `crates/stoffel-lang/examples/` scripts and in `docker/test-coordinator-reserve-index.sh`.
- **CI `docker-build` named a `0.2.0` coordinator.** Both its build steps did pass
  `build-contexts`, but `coordinator=` named commit `dffffd6e`, whose `[workspace.package]`
  version is `0.2.0` — which cannot satisfy this tree's `=0.3.0`, leaving the injected patch
  unused and sending the build to a `0.3.0` crates.io does not have. Stage S5 repointed both
  steps at `#feature/no-bootnode`, whose tip is `0.3.0`.

### G. Trust table

Every row that rests on a private key being secret holds only under §F.0: each private
key exists in exactly one place, its owner's, and a fixture key is reachable only on
loopback. "The coordinator" includes its operator, which sits
inside one trust boundary (§9 preamble, §C.3).

**§12.I amends two cells of this table.** Once §12 lands, the honest coordinator can no
longer be said to be unable to "choose … an `instance_id`" — it mints it and it is the
envelope — and the malicious node row loses the epoch proposal, so one roster member can no
longer brick honest nodes' persistent counters. §12.I states both, and what each side gains
and loses.

> **The trust posture as it finally stands, after stages S1 and S2 (2026-10-13, recorded in
> stage S6).** Two cells of this table were written as contract and were not true of the code
> until those stages; both are now true, and nothing else in the table moved.
>
> - **Malicious client, "Cannot … reach the node mesh transport at all (the node allowlist holds
>   nodes only), and so pose as a server peer and skew party indices".** Until stage S1 a
>   standing node extended its *mesh* transport's certificate allowlist with every
>   `--client-cert-dir` key once the mesh had formed, so a client certificate held node-level
>   network standing on the mesh listener and was admitted in either ALPN role — §6 blocker B1,
>   with `net/roster.rs::an_allowlisted_non_node_key_is_ranked_as_a_server_peer` pinning the
>   cost. S1 deleted that loop and split the sockets: `NodeListeners` is the only writer of
>   either allowlist, the mesh listener gets the coordinator's roster before it binds, and the
>   client-facing `--client-bind` listener carries no allowlist at all, read back from the
>   transport. The cell is now a property of the code. Index skew was never reachable through
>   the roster rank check — mesh consensus completed before the loop ran — so what the split
>   removed is the network standing itself.
> - **The client's own side of rule 1.** The table's malicious-coordinator cell says a client
>   "pins its node legs to whatever roster it was served", which assumes the client pins at all.
>   Until stage S2 the surviving coordinator-mediated client dialled every node address with no
>   peer allowlist, and `stoffel-run --client` without `--off-chain-coord` fell through to a
>   `run_as_client` that could not pin anything (§6 blocker B3: stoffelnet's empty allowlist
>   returns `Ok`). S2 deleted direct client mode outright (§13, §15's decision) and pinned the
>   surviving leg with `Roster::install_for_client` over the roster the coordinator served,
>   including the SDK's builder and `stoffel-cli`. So every client leg on this tree is pinned to
>   a coordinator-served roster, which is what makes the cell's "whatever roster it was served"
>   the exact boundary — and the attacker who holds the coordinator's trust is still the one who
>   holds client input privacy, unchanged from §3.
>
> Two things these stages did **not** change, recorded so the posture is not read as stronger
> than it is: stoffelnet's own client public-key table is never pruned, so a determined peer
> still grows it per handshake (the §9 occupancy box names the upstream change that would close
> it, and `the_transports_client_key_table_outlives_its_connections` fails when upstream starts
> pruning); and `--expect-roster-digest` remains the only thing that turns a coordinator serving
> a different roster into a refusal.

| Actor | Can | Cannot |
|---|---|---|
| **Coordinator, honest** | Serve one immutable node roster; register executions; bind clients to slots under each execution's policy; abort an execution at its deadline; see every client identity and binding, the program hash, masked inputs, sealed output shares and all timing; stop serving (liveness). | Learn a client's input: mask shares go node→client over node RPC legs it is not on, and a masked input under a uniformly random mask carries no information. Learn an output: shares are sealed to the client's key. Choose a party index (each node sorts SPKIs itself) or an `instance_id` (local epoch plus roster digest). |
| **Coordinator, malicious** | Everything it is trusted for, which is irreducible. **Roster:** serve a roster of its own keys — to every node, to some of them, or to one client. Equivocation is detected only between nodes that appear in each other's served roster: agreement (`JoinCommit` and both digest barriers) travels over the mesh, and each node installs only the roster it was served (`Roster::install_into`, reached from `join_mesh` and, on a standing node, from `NodeListeners::bind`), so a coordinator that partitions the nodes and pads each part with keys of its own gets internally consistent meshes that never exchange a frame. A client pins its node legs to whatever roster it was served (§E.1). **Trusting the coordinator's roster is therefore trusting it with client input privacy and output integrity**: serving a client a roster of the coordinator's own keys hands it that client's inputs and lets it sign whatever outputs it likes. `--expect-roster-digest` turns that into a refusal for a node or client that knows the intended roster (§D.2), and nothing else does. **Admission:** register any execution and admit any identity, itself included, under any policy; refuse associations or round transitions, or let deadlines abort (censorship, DoS). **Relay:** withhold a client's submission or a node's sealed output (DoS). | Within one mesh: serve its nodes different rosters, summaries or admission sets without the run aborting at `JoinCommit` or `AdmissionsAgreed`, before any mask share is released, input stored or output sealed; deliver different masked inputs to different nodes without aborting at `InputsAgreed`, before any input is unmasked; unmask a client's input by naming different reservation owners to different nodes (nodes release mask shares only for reservations that match the agreed set, C.7). **Against a client served the true roster:** shift its input — nodes verify the client's signature over its submission against the agreed identity and nonce (C.7, §D.7 step 9), which revision 1 left as a `0.2.0` property; substitute or relabel its outputs — each item must carry a roster node's signature over its own position and ciphertext, and each share the id of that position (C.7); replay a submission or output from an earlier registration of the same id (the nonce is signed). Make an honest node run for a program other than the one registered (D.7 step 1). Read the outputs of a client it did not admit as itself. Make a node trust a key outside the roster it served that node, or a client a node outside the roster it served that client. Force `instance_id` reuse, or make a node reuse a mask or triple of an earlier execution (C.9 part 4). |
| **Attacker at the coordinator's address, or at a node's** | Drop, delay or refuse connections (DoS). Without any certificate, hold a listener's pending-handshake pool from `max_pending_handshakes / max_pending_handshakes_per_ip` source addresses (64 by default); with free certificates, fill the unreserved connection pool (§A). Either stops new clients from associating, and so aborts an `Open` execution at its association deadline; reachability controls in front of a listener are the deployment's (§C.2). | Holds under §F.0 only. Complete a handshake as the coordinator: its key is not the pinned one, so nodes and clients stop at `ServerPinMismatch` before any RPC, and no roster, admission or relayed input comes from it. As a node RPC listener: be trusted by a client (not a roster key) or answer as a node already answering elsewhere (`DuplicateNodeIdentity`). As a mesh peer: be admitted (node allowlist). Take the connection capacity of roster nodes, which no other identity draws on, so a node connecting at startup is not crowded out; nor, with certificates alone, the bound-client pool (§A). Hold the coordinator's state mutex through a slow connection (C.6). With a committed fixture key from `ids/` on a reachable port, the first three are possible, which is why §F.0 makes every such port loopback-only and checks it. |
| **Malicious node (at most `t`)** | Whatever the MPC protocol tolerates of a corrupt party; withhold its mask and output shares; send wrong ones, which reconstruction excludes (C.7); cast its one vote of `transition_quorum()`; acknowledge retirement early (a drain starts only in a terminal round, C.10); read client identities, reservations and masked inputs through `get_client_admissions` and the node-gated subscriptions; bind a slot under `Open`, like anyone; abort a run by sending a divergent `JoinCommit`, `AdmissionsAgreed` or `InputsAgreed` frame; lose its own subscriptions by reading slowly (C.6). | Register an execution or choose its program, slot table or policy (in-process only, C.1); change membership, party indices or `t`; admit or unbind a client; learn a client's mask (it holds one share, and every honest node serves its share only to the identity the agreed admissions name, C.7); make a client use a wrong mask or output, or never reconstruct one, by relabelling its share with another node's id, changing its degree, or sending a value off the sharing — a client attributes each share to the pinned leg or signed item it came on, ignores one whose id or degree does not match that position, decodes HoneyBadger shares robustly, and accepts an AVSS share only if it verifies against the commitments it came with and `t + 1` positions presented those same commitments (A, C.7); make an oversized ciphertext block a client's other outputs (one item per node, bounded, C.1); receive another client's outputs; advance a round alone; impersonate the coordinator (pinned; §F.0); stall the coordinator for other executions or subscribers (no send under the state mutex, C.6); make honest nodes of its mesh disagree about the roster, the admissions or the masked inputs without the run aborting. |
| **Malicious client** | Fetch the node roster and an execution's summary, at a bounded rate per identity (C.6); under `Open`, bind free slots — with enough certificates, all of them — and then never reserve or never submit, which aborts that execution at its deadline (C.8); submit any value as its own input; repeat `associate_client` (idempotent); open connections and parked subscriptions up to the per-listener, per-identity and per-caller bounds (§A, C.6) — enough certificates can fill a listener's unreserved pool (row above). | Bind a pre-registered slot; reserve or submit outside its admitted range; submit oversized inputs that make other nodes' streams undeliverable (C.1); subscribe to reservations, masked inputs or other clients' identities (node-gated, C.6); obtain another client's mask shares (node RPC checks the caller's certificate against the reservation) or outputs (gated on admission, and sealed to the other key); learn anything from a mask a previous execution used, because no node hands one out twice (C.9 part 4); stall an execution past its deadlines; reach the node mesh transport at all (the node allowlist holds nodes only), and so pose as a server peer and skew party indices; take a roster node's connection capacity (bound clients under `Open` can fill only the bound-client pool, §A); affect any other `ExecutionId`. |

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
| `reconstruction_excludes_relabelled_resized_and_corrupted_shares` | same | HoneyBadger, `n = 4, t = 1`: a share relabelled with another position's id, or of degree 0, is ignored and the other three reconstruct; one wrong value among four still reconstructs the right secret; `Pending` with only two valid shares. AVSS, `n = 3, t = 1`: a share relabelled with another position's id is ignored, and `verify_feldman` rejects it against the `share_id_of_position` id; a share off its own commitments is ignored; a corrupt node presenting consistent commitments of its own design, chosen to accept an honest share, never reaches `t + 1` supporters; the honest two reconstruct |
| `program_hash_of_matches_the_shared_golden_vector` | `crates/coord-shared/src/admission.rs` | `program_hash_of(b"stoffel golden program")` is `fe9f7bf2…79ee` (§C.1) |
| `masked_input_and_sealed_output_signatures_have_the_documented_layout_and_bind_every_field` | `crates/coord-shared/src/signing.rs` | the two layouts of C.7; `sign_with_pkcs8` then `verify_identity_signature` succeeds for a P-256 and an Ed25519 key; changing the nonce, slot, first index, any input, the position, the encapsulated key or the ciphertext fails verification; a signature from another key fails |
| `registration_bounds_keep_every_response_under_the_wire_limit` | same (`serde_json` as a dev-dependency) | at the C.1 bounds, `ClientAdmissionSet`, `ExecutionSummary`, a `MaskedInputEvent` of `MAX_INPUTS_PER_SLOT` inputs of `MAX_MASKED_INPUT_BYTES`, and a `SealedOutputShares` of `MAX_SEALED_OUTPUT_BYTES` serialize — notification envelope included — within C.1's measured sizes, under 10 MiB; one past each slot bound is refused (`TooManyClientSlots`, `TooManyInputsInSlot`, `TooManyOutputsInSlot`, `TooManyInputs`) |
| `registration_refuses_missing_or_disordered_deadlines_and_non_canonical_clients` | same | `DeadlinesRequired` under `Open`; `DeadlinesOutOfOrder`; `DeadlineElapsed`; `UnsupportedPreRegisteredKey` for a 33-byte identity; and, added in C1, that the slot a client **names** decides which keys it may use while its position does not, plus `PreRegisteredSlotOutOfRange` and `DuplicatePreRegisteredSlot` — replaces revision 1's planned `registration_refuses_an_output_quorum_below_t_plus_one_and_missing_deadlines`, whose field is gone |
| `registration_checks_state_in_order_and_never_evicts_for_a_refused_one` | `crates/off-chain/tests/off_chain.rs` | an identical registration of a live execution past its association deadline returns its nonce; an ended id is `ExecutionIdRetired`; a different registration of a live id is `ConflictingRegistration`; at capacity with an evictable execution, a registration that fails `validate` is refused and the evictable one is still registered |
| `deleted_methods_are_not_rpc_methods` | same | raw JSON-RPC calls to `register_execution`, `request_shutdown`, `available_input_masks`, `reserve_mask_index`, `submit_masked_input`, `sub_assigned_reserved_indices` and `sub_assigned_masked_inputs` answer `METHOD_NOT_FOUND` (-32601) |
| `get_node_roster_is_served_to_a_caller_no_configuration_names` | same | a certificate minted in the test fetches the roster |
| `summary_reads_are_rate_limited_per_identity` | same | the eleventh `get_execution_summary` or `get_node_roster` call in a burst from one identity is `RateLimited` (41); another identity is unaffected; a token returns after a second |
| `pre_registered_admission_binds_only_the_registered_identities` | same | registered identity gets its slot; others `NotPreRegistered`; `PreRegisteredSlotMismatch` |
| `open_admission_binds_disjoint_ranges_first_come_first_served` | same | ranges partition `[0, n_inputs)`; `slot: Some(i)` honoured; `SlotTaken` |
| `open_admission_refuses_association_past_capacity` | same | `CapacityExhausted { capacity }` |
| `associate_client_is_idempotent_for_an_identical_request_and_refuses_a_different_one` | same | same admission returned in a later round; `AlreadyAssociated`; `ExecutionNotFound` once the execution is removed |
| `association_closes_when_input_collection_begins` | same | `AssociationClosed { current: InputCollection }` |
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
| `a_node_rpc_client_refuses_a_node_outside_the_roster_and_a_duplicated_node` | same | `ServerPinMismatch`; `DuplicateNodeIdentity` — **retargets** the VM's `a_client_pinned_to_the_roster_refuses_a_node_outside_it` (`crates/stoffel-vm/src/net/roster.rs:778`), whose API is removed |
| `open_admission_end_to_end_with_a_client_minted_at_test_time` | same | in one process: coordinator under `Open`, node RPC servers presenting roster certificates, and a client whose certificate is generated after the coordinator starts; it associates, reserves, reconstructs its mask by position, submits a signed range, and reconstructs its output from signed per-node items; its identity appears in no registration field |
| `one_off_coordinator_drains_after_the_retirement_quorum_of_a_terminal_round` | same | acknowledgements before `ProgramFinished` do not start the drain; the quorum after it does — **retargets** `one_off_shutdown_does_not_disconnect_a_slow_party_before_terminal_replay` and `one_off_shutdown_grace_bounds_a_missing_party` onto `watch_for_retirement_quorum` |
| `unanimous_retirement_keeps_outputs_for_the_retention_window` | same | an output client subscribing after every node retired still receives every node's item within `output_retention`, and `ExecutionNotFound` after it |
| `client_slots_ignore_scalar_share_types` | `crates/bins/src/bin/run-coord.rs` | **retargets** `input_assignment_ignores_scalar_share_types` |
| `run_coord_registers_its_execution_at_startup_in_both_modes` | same | the parsed flags produce one registration with or without `--one-off`; `--program` and `--hash` are exclusive; `--backend` and `--min-output-shares` are unknown flags |
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

> **Measured 2026-10-13 (stage V5 repair): what of this test plan exists.** Every test name in
> this section was grepped for in both repositories. The **coordinator** table above is true of
> the coordinator worktree — every test it names exists — with one exception: its
> `a_node_rpc_client_refuses_a_node_outside_the_roster_and_a_duplicated_node` row names no test
> in either repository, and `a_pinned_client_refuses_a_server_presenting_another_key` and
> `a_roster_node_pin_reports_which_member_answered` are what cover a client's pin of a node RPC
> listener. Two of the rows it does name changed shape and are corrected here:
>
> - `summary_reads_are_rate_limited_per_identity` no longer asserts "the eleventh
>   `get_execution_summary` **or** `get_node_roster` call is `RateLimited`". The two methods have
>   a bucket each (§9.B as built), and the test now asserts the stronger, opposite property: an
>   empty summary bucket must *not* refuse a roster read. The roster side is its own test,
>   `roster_reads_are_rate_limited_per_caller_identity`, which spends `ROSTER_READ_BURST`.
> - `connections_per_identity_are_bounded_and_idle_unreserved_ones_are_closed` still holds, over
>   the §9.A default of 64 rather than 8.
>
> The **VM** table below was written for the v1 (`main`-based) tree, and most of its rows name a
> test that was never written on this branch. It is kept as the plan it was; this is the mapping
> to what carries each contract here. Line numbers in it are `main`-based and resolve against
> nothing in this tree (see the citation rule in the header).
>
> | Row of the table below | Status on this branch |
> |---|---|
> | `a_restarted_party_never_draws_the_same_mask_or_triple_twice` | **void.** `crates/stoffel-vm/src/tests/mesh_hb_integration.rs` does not exist on `dev`. *Updated 2026-10-14:* the property belongs to V-0, which is now **done** — but it is witnessed by unit tests in `net/mpc/{honeybadger,avss}/preprocessing.rs` rather than by a `hb_itest` of this name, because item identity is only observable in-process (§9.1 V-0's Evidence paragraph) |
> | `a_restarted_avss_party_never_draws_the_same_share_twice` | **void.** `avss_e2e_integration.rs` exists but holds no test of this name; same V-0 dependency, same resolution — `client_masks_one_execution_used_are_never_handed_to_a_later_execution` in `net/mpc/avss/preprocessing.rs` carries it |
> | `the_preprocessing_store_flag_fails_by_name` | already marked **void** in place, twice over (§13, and `--preproc-store` is live) |
> | `a_roster_below_two_t_plus_one_or_with_a_zero_threshold_is_refused` | **retargeted** to `a_served_roster_is_held_to_the_coordinators_bounds` and `an_empty_roster_is_refused_before_the_transport_is_touched` (`net/roster.rs`): the VM no longer builds a roster of its own, so what it refuses is a *served* one |
> | `a_served_certificate_that_is_not_a_certificate_names_its_index` | **retargeted** to `a_served_certificate_the_transport_cannot_read_is_refused` (same file) |
> | `the_digest_ignores_input_order_but_not_membership_or_threshold` | **void.** There is no input-order dimension left in the VM: the roster arrives in canonical order from the coordinator and `NodeRoster::try_from` refuses `NotCanonical`. `a_coordinator_roster_matches_the_golden_digest`, `a_roster_whose_served_digest_disagrees_is_refused` and `a_repeated_node_certificate_is_refused` carry what remains |
> | `pinning_the_mesh_roster_after_start_is_an_error_rather_than_a_silent_no_op` | **void.** `net/avss_server.rs` holds no such test on `dev`. `adding_a_client_before_the_nodes_freezes_the_node_install_out` and `a_node_outside_its_own_roster_cannot_install_it` (`net/roster.rs`) are the install-time refusals that exist |
> | `the_program_id_matches_the_shared_golden_vector` | **now written** (stage V5), in `net/program_id.rs`, over the same input and the same 32 bytes the coordinator's `program_hash_of_matches_the_shared_golden_vector` asserts. Until this stage nothing on the VM side pinned the two implementations to each other |
> | `the_instance_id_depends_on_the_roster_digest` | **void** (§D.5's correction box, §8): there is no roster-digest derivation. `execution_instance_id_is_deterministic_and_execution_scoped` (`net/session.rs`) carries the contract that exists |
> | `a_party_proposing_another_execution_is_refused_at_the_join` | **retargeted** to `a_commitment_names_the_first_field_that_diverged` (`net/mesh/join.rs`), which names `SessionField::ExecutionId` through `MeshError::CommitDivergence`, and to `a_standing_commitment_and_a_one_shot_commitment_diverge_by_scope` for the scope case §12.D added |
> | the three `a_digest_barrier_*` / `digest_barrier_*` rows | **void** (§D.6's correction box): there is no `net/mesh/barrier.rs` |
> | the five `crates/stoffel-vm-runner/src/admissions.rs` rows (`the_admission_agreement_digest_…`, `the_inputs_agreement_digest_…`, `reservations_are_released_only_when_they_match_the_agreed_admissions`, `submissions_the_agreed_admissions_do_not_match_are_refused`, `a_summary_for_another_program_…`) | **void** (§D.6's correction box): that file does not exist. The admissions half is covered by `the_config_digest_moves_whenever_any_committed_field_does` (`execution_stream.rs`) and `reservoir_admission_mismatch_is_separate_from_inventory_repair` (`stoffel-run.rs`); the masked-input half is an open gap |
> | `removed_flags_fail_by_name_with_hints_that_name_no_removed_flag` | **void** under §13: nothing removed gets a by-name refusal, so there is no behaviour to assert. A removed flag is an ordinary unknown argument |
> | `direct_client_mode_is_refused_by_name` | **void**, and now for one reason rather than two. §13 removes the by-name refusal, and since stage S2 direct client mode is **deleted**, so there is no mode left to refuse: `stoffel-run --client` without `--off-chain-coord` is an ordinary missing-parameter refusal naming the parameters client mode requires. Corrected 2026-10-13 (stage S6); the row's earlier wording, that the mode was still live, was true until S2 |
> | `off_chain_coord_without_a_pin_is_refused`, `an_unreadable_coord_cert_names_its_path` | **not written.** The behaviour is in `resolve_coordinator_pin` (`stoffel-run.rs`), which refuses `--off-chain-coord` without `--coord-cert` and surfaces `CoordinatorPin::load`'s error, and the SDK half is pinned by `offchain_client_config_requires_a_coordinator_pin`. No binary test covers the `stoffel-run` side: a gap, recorded in §9.I |
> | `a_node_absent_from_the_coordinator_roster_exits_before_binding`, `an_unexpected_roster_size_or_digest_is_refused_before_binding` | **not written.** Both refusals are in `fetch_node_roster` (`check_size`, the membership check, the digest rebuild), and only the campaigns and `local_coordinator_e2e` exercise them end to end. A gap, recorded in §9.I. *Corrected 2026-10-13 (stage S6): the row said `fetch_node_roster` is "reached only from `run_standing_node`". Since stage V3 the one-shot party path reaches it too — §D.1's correction box has the as-built startup order — so the refusals cover both modes and the missing coverage is the unit tests, not the call site* |
> | `coordinated_run_errors_exit_4_for_execution_and_output_rights_only` | **void.** There is no `CoordinatedRunError` on this branch |
> | `a_mesh_party_is_pinned_to_the_coordinator_and_names_no_roster_or_client` | **void** as written; `local_runner`'s argv is asserted by its own suite and by `local_coordinator_e2e.rs` end to end |
> | `expected_clients_create_output_identities_for_dynamic_outputs` | **retargeted** to `expected_clients_become_output_slots_once_their_output_count_is_known` and `expected_output_clients_without_an_output_count_is_refused_with_the_flag_to_set` (`local_runner.rs`); its sibling `expected_clients_union_keeps_manifest_inputs_and_output_only_slots` exists under its own name |
> | `sparse_client_slots_are_refused_at_build`, `run_refuses_open_admission_with_client_slots` | **retargeted** to `local_runner_rejects_duplicate_client_input_slots` (`local_coordinator_e2e.rs`) and, on the SDK surface, `network_config_expected_clients_rejects_sparse_client_slots` and `server_builder_rejects_sparse_client_slots_beyond_expected_clients` |
> | `the_run_directory_and_key_files_are_private`, `no_image_or_stack_distributes_a_private_key` | **not written**, and `crates/stoffel-vm-runner/tests/deployment_key_material.rs` does not exist. This is §F.0, which §9.I records as unimplemented for every one-shot stack |
> | `local_offchain_coordinator_admits_an_unconfigured_client_under_open_admission`, `an_execution_without_outputs_reaches_program_finished_and_is_retired`, `a_local_client_refuses_a_node_rpc_listener_outside_the_served_roster` | **not written.** `local_coordinator_e2e.rs` covers open admission and finalize-without-client-inputs through `local_offchain_coordinator_runs_networked_vm_without_docker_compose`, `local_output_only_runs_finalize_without_client_inputs` and the `assert_all_parties_acknowledged_completion` helper; the client-leg pin of a node RPC listener has no VM-side test |
> | the five `an_sdk_*` rows | **void** as named; the SDK's surface is asserted by `server_builder_captures_operational_configuration`, `topology_aware_server_builder_requires_all_peer_addresses`, `offchain_client_config_requires_a_coordinator_pin` and `client_and_server_builders_can_load_network_config_files` |
> | `offchain_client_config_takes_its_topology_from_the_coordinator` | **retargeted** to `offchain_client_config_defaults_to_the_honeybadger_backend`, which is the retarget that was actually made of `offchain_client_config_defaults_to_five_party_topology` |
> | `client_connect_opens_a_pinned_coordinator_link` | **written**, in the S2 repair below. `client_connect_uses_real_quic_transport` was replaced by the negative `client_connect_dials_its_coordinator_and_no_node`, which left the success path uncovered; the prescribed test now exists beside it, with `client_connect_refuses_a_coordinator_that_is_not_the_pinned_one` for the wrong-pin case |
> | `sdk_local_runs_refuse_output_only_slots_without_counts` | **retargeted** to `runtime_rejects_expected_output_clients_below_static_manifest_slots` and `runtime_allows_static_output_only_clients_without_inputs` |
> | `run_network_refuses_a_node_network_config_by_name` | **void** under §13 and in fact: `run_network_accepts_network_config_and_attempts_connection` was not retargeted and is what `crates/stoffel-cli/tests/cli.rs` asserts |
>
> Every other row of the table below names a test that exists.

**This repository**, by stage (§9.1):

| Test | Location | Stage | Asserts |
|---|---|---|---|
| `a_restarted_party_never_draws_the_same_mask_or_triple_twice` | `crates/stoffel-vm/src/tests/mesh_hb_integration.rs` (`hb_itest`, as its siblings) | V-0 | five in-process HoneyBadger engines, each over its own LMDB store, preprocess, take mask shares and run a multiplication; the engines are dropped and five new ones over the same stores preprocess again and do the same; no mask share and no Beaver triple drawn in the second session is byte-equal to one drawn in the first, and no store holds a material blob after either session |
| `a_restarted_avss_party_never_draws_the_same_share_twice` | `crates/stoffel-vm/src/tests/avss_e2e_integration.rs` (`avss_itest`) | V-0 | the same for AVSS random shares and triples |
| ~~`the_preprocessing_store_flag_fails_by_name`~~ | — | V-0 | **void, twice over.** `--preproc-store` is a live flag on this tree (§D.2's measured block), so there is nothing to refuse; and under §13 a removed flag never gets a by-name refusal, so there would be nothing for such a test to assert even after V-0. No test of this name exists |
| `a_coordinator_roster_matches_the_golden_digest` | `crates/stoffel-vm/src/net/roster.rs`, over `ids/nodes/*.crt` (certificates only) | V-a | the same order and digest as the coordinator's golden test |
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
| `an_unexpected_roster_size_or_digest_is_refused_before_binding` | same | V-b | against an in-process coordinator, a `--n-parties`/`--threshold` the served roster does not match, and a wrong `--expect-roster-digest`, each exit 2 with their D.3 message; a malformed digest exits 2 with the `RosterDigestParseError` |
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
| `an_sdk_coordinator_party_names_its_execution_and_drives_nothing` (`:2346`), `an_sdk_mesh_server_dials_its_peers_instead_of_a_bootnode` (`:2434`) | same | V-b | **retargeted** argv: `--coord-cert` present, and `--n-parties`/`--threshold` carrying `mpc_config`'s values, which the node checks the served roster against; `--roster`, `--expected-clients`, `--timestamp` absent |
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
| `an_installed_node_roster_refuses_every_client_certificate` | `crates/stoffel-vm/src/net/roster.rs` | V-c | a certificate that is not a node is refused at the mesh transport in both ALPN roles — **retargets** `a_roster_admits_its_clients_alongside_its_nodes`, `a_roster_pinned_node_admits_its_clients_and_refuses_an_unlisted_one`, `a_roster_pinned_node_refuses_a_client_that_brings_no_certificate`, `a_listed_client_still_exchanges_bytes_through_an_allowlisted_node` and `a_clone_taken_before_the_install_still_enforces_the_roster_for_clients` |

The docker scripts of §F.2 are their stage's end-to-end check: `test-coordinator-reserve-index.sh`
and `run_coordinator_compose.sh` for V-b, and `test-coordinator-preproc-store.sh` for V-b (the
epoch advances).

> **Corrected 2026-10-14.** This sentence also credited
> `test-coordinator-preproc-store.sh` for V-0, as "no material reloaded". Both halves were
> wrong. V-0 as rewritten (§9.1) *keeps* cross-execution reuse of never-served material, so "no
> material reloaded" is not the property; and the script cannot witness the property it names,
> for two measured reasons. Its overlay makes all five parties `--standing-node`, and
> `preprocess()` routes a standing engine to `preprocess_standing()` before it can reach
> `persist_preproc`, so the one-shot commit path where the reuse defect lived is unreachable
> inside it. And it is insensitive to the guard that does carry the property: with
> `take_bundle_from_reservoir`'s compaction write-back removed, its phases 1 and 2 still pass in
> full.
>
> No integration script can close that gap. Single use is a claim about item *identity*, and
> identity is observable only inside the process — comparing one run's items with the next from
> outside would mean printing share bytes to the container logs, which is the disclosure the
> property exists to prevent. V-0's witnesses are therefore the unit tests §9.1 names, all of
> which run in CI. The script keeps its name and its three phases as a **liveness** check for
> persisted standing preprocessing (generate, reuse after `down`/`up`, recover from a lost
> volume), and it now says so in its own header. It also asserts the premise that makes it *not*
> V-0 coverage — that no party commits material from inside a live execution
> (`assert_no_party_committed_from_a_live_execution`) — so the stack cannot drift into
> privacy-relevant persistence unobserved.

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
   None })`; assert slot 0, input range `[0, 1)`,
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

**How to read this section (added 2026-10-13, stage S6).** It is not one table but a
**chronological log**, and the tables are layered: the first table below is the abandoned
`main`-based attempt's and the box under it says so, after which each per-stage box states the
rows above it that it supersedes ("the rows above are V2's; these are V3's", and so on through
the V-stages, their repair passes, the V5 campaign, and stages S1-S6 and the S1 repairs).
**Later boxes win.** A row is the status of record only until a later box revisits it, so a
reader looking for the state of one item reads forward to the last box that names it rather
than stopping at the first. Where a box here and a §9/§12 subsection disagree, the subsection
carries its own correction box pointing back at the box that corrected it; §14's list of
corrected sections is the index.

| Stage (§9.1) | State |
|---|---|
| C-a `coord-shared` — `pin.rs`, `roster.rs`, `admission.rs`, `signing.rs`, `ShareBound`, `caller_identity`, `RpcServerLimits`, TLS 1.3-only, pinned `setup_client` | done, in `stoffel-mpc-coordinator-roster-admission` at version `0.3.0` |
| C-b `off-chain` — registration, admission RPCs and gates, signed submissions, per-node sealed outputs, delivery discipline, deadlines and sweeper, ended executions, `OffChainCoordinatorConnection` | done |
| C-c `on-chain` and `bins` — roster-taking node RPC client, `run-coord` flags, CHANGELOG and README | done |
| V-0 no preprocessing item serves two executions | **done; the deletion is obsolete.** *Rewritten 2026-10-14 — see §9.1's V-0 bullet.* The open question — whether a finished execution may persist leftovers at all — was answered adversely by execution and then fixed: `persist_preproc` copied the whole pool at `consumed: 0` and handed the identical items back, in both engines, so execution 1 used exactly what execution 2 would draw, and two concurrent one-shot runs also clobbered each other through the non-accumulating `PreprocStore::store`. A commit is now a division (`commit_generated_material` + `GeneratedMaterialCommit`): only material the committing engine keeps none of is written, `append_items` is the sole write primitive, and `take_bundle_from_reservoir`'s physical removal — not the consumed-cursor CAS, which had no reachable production caller and was **deleted on 2026-10-15** along with the two tests that drove it — is what keeps a stored item single-use. Witnessed by `material_one_execution_used_is_never_handed_to_a_later_execution` (HB), `client_masks_one_execution_used_are_never_handed_to_a_later_execution` (AVSS) and `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`, all passing and all run by CI. `--preproc-store`, the reservoir, the volumes and the agreement are kept. *Closed out 2026-10-15:* seven items are done — the marking-without-removal primitive deleted; the standing top-up's pool emptied before it generates (`lease_node_with_emptied_pool_for_top_up`, both engines); pre-division volumes refused by a `PreprocVolumeHeader` with no migration, **and** a volume contaminated after it was claimed refused too, since a marker certifies a volume's creation and not its contents — the material prefix moved to `PREPROC_MATERIAL_NAMESPACE` (`b"ppd:"`) and `count_legacy_material_records` (renamed `find_condemned_records` on 2026-10-16) refuses a record under the pre-division prefix on every open; `PreprocBlob`, its constructors and the one non-destructive read (`PreprocStore::load`) made test-only, **and** the untyped blob API that could still address a material key by prefix narrowed to a closed `BlobNamespace` enum with no material variant; one-volume-one-standing-pool enforced by an owner record rather than documented; the node-side masked-input registry deleted as unreachable (examined as a second S12 and measured **not** to be one — the volume held party *i*'s share `[r]_i`, not the scalar `r`, the map had no production writer, and `persist` was unreachable in both modes); and the coverage: `docker/test-oneshot-preproc-store.sh` for the one-shot commit path that nothing exercised, the docker assertions tied to `storage/preproc.rs`'s marker constants rather than to free text, AVSS's commit/load/shortfall lines made `RUST_LOG`-independent, CI's ignored-test step given `--all-features`, and the standing campaigns' AVSS reach pinned by `assert_reservoir_backends`. Volume rules witnessed by tests in `storage/preproc.rs` and the top-up clear by four `a_standing_top_up_*` tests across both engines. *Closed out 2026-10-16 (residual tail):* the reservation persistence itself is deleted rather than kept-while-unreachable, so the registry has no way to reach disk at all and `rsv:` joins the pre-division material prefix as a condemned prefix (`find_condemned_records`); the registry property is now witnessed by `a_standing_engine_writes_nothing_into_the_volume_holding_its_preprocessing`, which asserts over the volume's keys — the two tests this row previously named were retired with the code they were about; the reservation capability is standing-only in the type and `MpcEngineReservation::get_mask_shares` no longer carries a default whose documentation advised reintroducing marking-without-removal (`a_one_shot_engine_offers_no_reservation_capability`); a nonzero `consumed` cursor is refused on every material-metadata read (`material_metadata_carrying_a_consumed_cursor_is_refused_on_every_read`); `PreprocStore::available` is `#[cfg(test)]` and `atomic_increment` deleted; the owner check is exercised across two OS processes (`tests/preproc_volume_two_processes.rs`); and the content-integrity residual is recorded as an **accepted residual** with its threat model rather than left as an open hole. *Closed out 2026-10-16 (coverage tail):* AVSS's `TopUp` arm — a *partial* refill of a live reservoir — was measured already running in every passing standing campaign (all five parties log `action=TopUp` at the restart, in the **unmodified** suite), and is now asserted (`assert_agreement_actions`), drawn from (nine `retained-avss` executions after the restart) and followed by an elastic concurrent refill the AVSS side had never run; and the suites themselves now run in CI — a static wiring check on every pull request, the campaigns nightly — with two suites deliberately unwired. See §9.1 V-0's "Closed out" list and its residual item 11. **Still open, and external to this repository:** until the coordinator half this repository compiles against is committed and pushed, both `build-and-test` matrix jobs go red at the clippy step and every job that would build an image either fails there too or is skipped; `harness-wiring`, which compiles nothing, is the one job that can report — §9.F.5, re-measured 2026-10-16, the shape of that red run corrected there in a second pass the same day, and a third pass the same day ruling out the one in-repo alternative — repointing the clone — over every pushed ref of that repository, naming the breaking `AdmissionPolicy::PreRegistered` payload change behind the five `E0609`s, and measuring the clearing commit sufficient as well as necessary (that same clippy command is rc 101 against the pushed tip and rc 0 against the working tree). |
| V-a additive roster, session and barrier work | done |
| V-b the pin bump and everything that breaks with it | done; the `[patch.crates-io]` tables and `=0.3.0` pins are in both workspaces (§F.5) |
| V-c deletion of the now-dead branches | **partly.** The legacy `Roster` API, `run_as_client` and direct client mode went with V-a/V-b. Still present and unreachable: the uncoordinated party branches in `stoffel-run` (`setup_hb!` / `setup_avss!`, `sync_client_set_across_parties`, `ServerClientAdapter`), kept because nothing reaches them — a party without `--off-chain-coord` is refused at flag parsing |
| §F deployment — every stack runs a coordinator, the wrapper's flags, the entrypoint, the scripts, the key-material rule | done, with the three **as built** differences in §F.1 and those in §F.2 and §F.3 |

> **Superseded for the `dev`-based redo (stage V1, 2026-10-12).** The table above is the
> status of the abandoned `main`-based attempt (`StoffelVM-no-bootnode`). On
> `StoffelVM-nb2` the VM rows read as follows, and the coordinator rows (C-a, C-b, C-c)
> still hold because the coordinator worktree is unchanged by the redo.
>
> | Item | State on `StoffelVM-nb2` |
> |---|---|
> | the `[patch.crates-io]` tables and the `=0.3.0` pins | **done, and left repointed.** `Cargo.toml`'s table and a new one in `docker/coordinator-wrapper/Cargo.toml` (its own workspace, which had none) both point at the coordinator worktree as a sibling checkout — an absolute path under one developer's home directory until stage S5 made it relative (§9.F.5) — and `crates/stoffel-vm-runner/Cargo.toml`, `crates/stoffel-rust-sdk/Cargo.toml` and the wrapper all require `=0.3.0`. Without the version bump the repoint is silently discarded — cargo drops the patch and resolves the registry `0.2.0` instead |
> | `vendor/stoffel-mpc-coordinator-browser` and the browser coordinator path | **deleted.** The vendored fork existed only to supply `start_coord_with_browser`, reached by the wrapper's `--browser-bind-addr`; both are gone, along with the workspace `exclude` entry. This also fixes the one pre-existing build failure on `dev`: the wrapper did not compile, because it is its own workspace with no patch table and pinned the registry `0.2.0`, which has no such function |
> | `Roster` (nodes only), served by the coordinator | **done**, at `crates/stoffel-vm/src/net/roster.rs` — not `net/mesh/roster.rs`, which the redo does not create. Thirteen tests, including the §9.B golden vector, which the coordinator's `node_roster_golden_vector_matches_the_shipped_node_certificates` asserts over byte-identical certificates |
> | every coordinator RPC client pinned | **done.** `CoordinatorEndpoint` cannot be built without a `CoordinatorPin`, so a call site cannot forget one; `--coord-cert` is required exactly where `--off-chain-coord` is given, in one-shot and standing mode, in `docker/entrypoint.sh` and in every compose stack. The SDK's `OffChainClientConfig` gained a required `coordinator_cert_der` and refuses to build without it |
> | nodes fetch the roster once and verify their own membership | **done** for the standing node: `fetch_node_roster` opens the pinned `CoordinatorLink` before any socket is bound, checks the served `(n, t)` against this node's own, refuses a roster this node's `--cert` is not in, rebuilds the §9.B digest from the served certificates, and installs the result as the transport allowlist. Every later per-execution connection carries the digest that link served, so a coordinator that starts serving a different roster mid-life is refused |
> | `--party-cert-dir` | **kept, demoted.** It is now only the map from a logical `--party-id` to one of the roster's certificates, and the served roster and the directory must name the same key set or the node refuses. It is not a second roster authority. Renumbering parties into roster order (SPKI order, which for the shipped `ids/nodes` certificates is `3,0,1,2,4`) would change preprocessing identities and every compose stack, so it belongs to the stage that replaces the bootnode's mesh formation |
> | client admission at run time | **done** where the coordinator decides it: `AdmissionPolicy::Open` plus `associate_client`, in `local_runner` and in the SDK client, so the coordinator's answer — not the configuration — fixes the input range a client reserves and submits. **Not done** at the node's transport allowlist; see the block at the end of §9's "Rule 3 is a transport-security requirement" |
> | V-0 no preprocessing item serves two executions | **not done**, unchanged. `dev` has instead the per-node shared reservoir §11.6 asked for |
> | V-c deletion of dead branches, bootnode, control directory | **not started.** Stage V1 deliberately leaves the bootnode and the mounted control directory working |
> | the roster as a *party set* | **standing mode only.** `fetch_node_roster` and `Roster::install_into` are reached from `run_standing_node` and nowhere else. A one-shot party still registers with `expected_party_public_keys: None` and installs no certificate allowlist, because the roster's canonical party order is the lexicographic order of the node SPKIs while one-shot numbering is `--party-id`. So the integration-tested paths — `local_coordinator_e2e`, `stoffel-cli`, the SDK's `--ignored` suite — exercise the pin and the admission, not the roster install; the roster's own 13 tests are unit-level. One-shot gains the roster in the stage that replaces the bootnode's mesh formation. *Superseded: it did — since stage V3 the one-shot party fetches the roster itself and installs the allowlist through `join_mesh`. §9.D.1's S6 box has the as-built order* |
> | `crates/stoffel-wasm-client` | **deleted.** Its only counterpart was the browser RPC listener that went with `vendor/stoffel-mpc-coordinator-browser`; both halves shared the domain separator `b"stoffel-browser-rpc-auth-v1"`, and `0.3.0` has no browser RPC at all. Leaving it would have been a workspace member whose unit tests pass over a protocol no server can speak |
> | `--expect-n-parties`, `--expect-threshold` | **deleted** (§D.2's correction). They were parsed and advertised but never enforced: standing mode rebuilt the size expectation from the node's own `--n-parties`/`--threshold`, and no other mode fetches a roster. The size check itself stays, and is the node's own configuration |
> | `stoffel-run --client` association | **done.** Both CLI coordinator clients (`run_hb_coordinator_client_for_field`, `run_avss_offchain_coordinator_client_for_curve`) call `associate_client` on every connection they open, and take the indices they reserve and submit from `admission.input_range`. Until this landed the CLI client was the one client implementation that never associated, so `reserve_mask_indices` was refused `NotAdmitted` and `send_masked_inputs` / `obtain_outputs` returned `NotAssociated` — each `.unwrap()`ed into a panic — in every deployed stack including the standing campaigns' own clients |
> | `--client-index` / `STOFFEL_CLIENT_INDEX` | **deleted**, leaving nothing behind. A client-supplied reserved index is exactly the mechanism §E.2 removed from the SDK: the coordinator's slot table fixes each slot's block. `--client-slot` is what a client asks for, the compose stacks and `validate_examples.sh` pass `STOFFEL_CLIENT{,0,1}_SLOT`, and the manifest's prefix-sum slot inference (`client_slot_for_reserved_index`, `client_schema_for_reserved_index`) went with it |
> | the node-side output-rights filter | **re-sourced from the admission set, resolved by identity.** A short-lived guard in this stage skipped a sealed output submission when the coordinator's `ClientSlotTable` gave the slot no output rights, but it indexed that table with an `enumerate()` position over the party's own output ids — a different index space from `ClientIndex` (`coord-shared/src/admission.rs:277-285`, and `--client-roster` permutes them). `retain_output_entitled_submissions` replaces it: it looks each client up in the coordinator's frozen `ClientAdmissionSet` by identity (`record_of`), keeps only `OutputRights::Receive`, and treats a client the coordinator never admitted as an error rather than a skip. `get_client_admissions` is called once per execution and caches the agreed set that `send_output_shares` needs anyway, so it costs no extra round trip. **A filter is needed, not just a correct one.** Review proposed dropping it and letting `send_output_shares` refuse, on the grounds that the only effect was a silent `continue`; measured, that kills two previously passing tests (`execute_local_adapts_prd_secret_int_quickstart`, `execute_local_adapts_loaded_secret_int_bytecode`, SDK `--ignored`), because a party offers the program's returned-value share to every client in `output_ids` and a client admitted with `output_count == 0` is then refused `NoOutputRights`, which the party turns into exit 13. On `dev` that submission silently succeeded, because the `0.2.0` coordinator had no output-rights concept |
> | `--expected-output-clients` with no declared output count | **refused at configuration time**, not inside slot-table construction. The `0.3.0` coordinator admits a client for the inputs it submits and the outputs it receives, so a slot with neither is not registrable (`RegistrationError::EmptyClientSlot`). This is a real functional loss against `dev`, where `--expected-output-clients N` produced identities for slots whose output count was only known while the program ran: that count must now be declared, with `stoffel run --client-output-count SLOT=N`, `[mpc.client_output_counts]` or `LocalCoordinatorRunnerBuilder::client_output_count`. `LocalCoordinatorRunner::validate_expected_clients` says so and names the flag |
> | the standing campaigns' expected-red state | **marked in the drivers.** `docker/test-standing-{concurrency,adversarial,all-examples}.sh` and the module docstrings of `docker/standing-concurrency/{acceptance,all_examples}.py` each carry a header note saying they are expected red on this branch until the node consumes `sub_executions`, pointing here, so nobody reads their failure as a regression |
> | `docker-compose.nat.yml` | **not deleted**, deferred to the bootnode-removal stage. §4 decided it goes; stage V1 still maintains it (its `STOFFEL_COORDINATOR_CONTEXT` default was made loud with every other stack's), and it has no coordinator service, so deleting it here would be a deletion with no replacement and no bootnode removal to justify it. See the corrected §F paragraph for the full per-stack inventory |
>
> Three mechanisms the `0.3.0` coordinator does not have were deleted from the VM rather
> than adapted, under §13: `request_shutdown` (a party no longer asks the coordinator to
> exit; retirement ends an execution), `InputAssignment`/`InputClientRange` (replaced by
> `ClientSlotTable`, whose `input_range` is what a client reserves), and the node's upward
> `coord.register_execution(...)` push — the inverted flow this whole section exists to
> reverse. A standing node now tells only its own RPC listener which execution it serves.
>
> **The coordinator leg of the deployed stacks is broken between stage V1 and the stage
> that adds the downward stream, and that is not confined to the one-shot stacks.** With the
> upward `register_execution` push gone and the downward `sub_executions` consumer not yet
> built, nothing registers an execution with the coordinator in any deployed stack, and no
> coordinator RPC for an unminted id can succeed.
>
> - **One-shot stacks.** They used to pre-agree an id by giving the same `--execution-id` to
>   the coordinator and to every node, and the coordinator now mints every identity itself.
>   `docker-compose.yml`, `docker-compose.coordinator.reserve-index.yml`,
>   `docker-compose.benchmark.yml` and
>   `crates/stoffel-lang/examples/docker-compose.coordinator.yml` have had the removed flags
>   taken out so they are consistent with the wrapper, but they cannot complete a run.
> - **The standing stack.** Its ids come from `Prepare` commands in the mounted control
>   directory, which the controller mints. A node then drives the coordinator's rounds for
>   that id — `start_preprocessing`, `wait_for_round`, `get_execution_summary` in
>   `StandingRunnerExecutionHandler` — and the coordinator refuses each of them for an id it
>   never minted (`live_execution` → the gone refusal). `docker-compose.standing-concurrency.yml`
>   starts the wrapper with no `--hash`, so nothing is pre-registered either. The
>   `docker/standing-concurrency` concurrency, adversarial and all-examples campaigns are
>   therefore **red for this reason** — not because they are control-directory-driven. The
>   control directory and the bootnode both still exist on this branch, so those campaigns
>   still *run*; they fail at the first coordinator RPC of the first admitted execution.
>   They go green again when the node learns its executions from the coordinator's
>   `sub_executions` stream, which is the same change that retires the control directory.
>
> The host `local_coordinator_e2e` suite is unaffected and is the real end-to-end net for
> this stage: it builds the coordinator in process, takes the minted id from
> `new_for_execution`, and passes it down to the five parties it spawns.

> **Stage V2 (2026-10-12): the mesh landed and the bootnode is deleted.** The rows above are
> V1's; these are V2's, on the same worktree.
>
> | Item | State on `StoffelVM-nb2` |
> |---|---|
> | `net/mesh/` | **built**, four modules: `wire.rs` (the `MSH1` frame, `MESH_READY_PREFIX`, the seven-entry `ReservedPrefix` registry), `pex.rs` (`PeerRecord`, `PeerBook`, `PeerDirectory`, `SeedHints`, the `RecordSource` ranking, `MAX_PEX_SEQ_JUMP`), `dial.rs` (the one dial schedule, `dial_address_expecting`, `ReconnectSupervisor`) and `join.rs` (`join_mesh`, the `dials_towards` tournament, `missing_ranks`, the lock-step handshake, `session_digest`). No `roster.rs` (it is `net/roster.rs`, V1's), no `epoch.rs` (§12.E), no `program.rs` (§2), no `barrier.rs` and no `router.rs` (§12.D as built). 44 unit tests |
> | the bootnode | **deleted**: `net/discovery.rs`, `net/discovery/bootnode.rs`, `tests/leader_bootnode_integration.rs`, `--bootnode`, `--leader`, `--bootstrap`, `STOFFEL_AUTH_TOKEN`, `STOFFEL_BOOTSTRAP_ADDR`, `LEADER_ARGS`/`BOOTSTRAP_ARGS`, the `STOFFEL_ROLE=leader` and `=bootnode` entrypoint branches, and every `bind + 1000` convention (the leader's second listener, the published `10000` ports, `reserve_udp_port_pair`, party0's `:10000` advertise). Nothing is guarded by name: a removed flag is an ordinary unknown argument and a removed variable is simply unread (§13) |
> | the legacy in-VM QUIC stack | **deleted**: `net/p2p.rs` (1164 lines) and the `net/mod.rs` re-exports of its `QuicNetworkManager` / `NetworkManager` / `PeerConnection`, which shadowed stoffelnet's. Its only remaining consumers were `net/session.rs`'s `send_ctrl` / `recv_ctrl` — the `CONTROL_STREAM_ID` pair §1 showed could not talk to the bootnode at all — and `tests/p2p_integration.rs` |
> | `net/program_sync.rs` | **replaced** by `net/program_id.rs`. The transfer protocol, the chunked send/receive, the `~/.stoffel/programs` cache and `STOFFEL_CACHE` are gone with the `ProgramFetch` path §2 proved dead; `program_id_from_bytes` is all that had a caller |
> | `net/session.rs` | **trimmed** to identity: `ExecutionId`, `derive_instance_id_for_execution`, `derive_execution_id_for_instance`. `SessionInfo`, `SessionMessage`, `MeshInfo` (defined, never used), `CONTROL_STREAM_ID`, `send_ctrl`, `recv_ctrl`, `random_instance_id`, `derive_instance_id` and `SessionError`/`SessionResult` all went with their only callers |
> | the `nat` feature | **deleted**: `crates/stoffel-vm/Cargo.toml`'s `nat = []`, the `#[cfg(feature = "nat")]` ICE paths, `--nat`, `--stun-servers`, `STOFFEL_ENABLE_NAT`, `STOFFEL_STUN_SERVERS`, the `ENABLE_NAT` build arg and its branch in **both** `Dockerfile` and `Dockerfile.benchmark`, and `docker-compose.nat.yml` (§4). V2 missed `Dockerfile.benchmark`; the V3 repair took it. |
> | one-shot party mode | **the roster is now its party set.** `--peers` is what selects party mode; it requires `--off-chain-coord`, `--coord-cert`, `--rpc-bind`, `--cert` and `--key`. A party fetches the roster over the pinned link before binding, installs it as the transport allowlist, dials its half of the tournament, and commits to the roster *and* this execution. `--party-id` is demoted to a label for on-disk state, and a party whose label differs from its roster rank says so once and runs on the rank |
> | the standing node's mesh | **formed by `join_mesh`**, with `session: None`. It keeps V1's pre-`listen` `Roster::install_into` (the join's own install is the identical set, which `install_expected_server_public_keys` accepts), and its repair loop is now `ReconnectSupervisor` with that loop's own behaviour and schedule. Its reconnect targets come from the agreed mesh and the roster, filtered by `dials_towards`, instead of from `--party-cert-dir` keyed by `--party-id` |
> | `--party-cert-dir` | **unchanged, still demoted.** The renumbering §9.I expected this stage to force did not happen: `register_and_wait_for_session` already ended in `assign_party_ids()`, so a standing node was already addressed by SPKI rank, and `join_mesh`'s `RankMismatch` check passes without moving any preprocessing identity |
> | the deployed stacks | **every one is a coordinator stack.** `docker-compose.avss.yml` and `crates/stoffel-lang/examples/docker-compose.mpc.yml` gained a `coordinator` service, node certificates and RPC binds; `docker-compose.nat.yml` is deleted. All eight remaining stacks pass `docker compose config -q`, and the entrypoint's emitted argv was checked directly |
> | `run_mpc_local.sh` | **rewritten** on the coordinator wrapper as a host process plus one `--peers` party per node, per §F.2. Marked expected-red in its own header for the same reason as the standing campaigns: nothing registers an execution with the coordinator until the downward stream lands |
> | the SDK server | **a mesh party.** `ServerBuilder::bootstrap`, `configured_bootstrap` and `StoffelServer::bootstrap_addr` are deleted; the builder's existing peer list — which `build()` already requires in full — is what becomes `--peers`. A server start now requires an `OffChainServerConfig`, which gained the `coordinator_cert_path` and `execution_id` a party cannot start without |
> | `local_runner` | **symmetric.** Five identical parties, each with `--party-id`, `--bind` and the other four addresses; no party is started first and no readiness gate waits for one. `DEFAULT_AUTH_TOKEN`, `LocalCoordinatorRunnerBuilder::auth_token`, `PartyRole`, the `bootnode-ready` marker and the `+1000` port-pair reservation are gone |
> | what V2 expects to remove later | nothing of the epoch store (§12.E: there was never one to retire). Two things do belong to V3: `--execution-id` on a party, once a node learns its executions from the coordinator's downward stream rather than being told one; and `JoinRequest::session`, if a standing node's per-execution agreement (§12.D as built) makes the one-shot special case redundant |
>
> **Was any of `dev`'s bootnode work load-bearing for something other than bootstrap?** One
> thing was, and it survives. `dev` developed the bootnode after the V1 branch was cut
> (`dc857b5`, `871d66e`, `7f3c891`, `d490890`, `00b40aa`), and that work was mostly a *shrink* —
> `dc857b5` alone removed 1066 lines and added 644, deleting the program transfer. What it added
> beyond bootstrap:
>
> 1. **Full-tuple registration agreement.** `register_session` refuses a registration whose
>    `(execution_id, program_id, entry, n_parties, threshold)` differs from the pending one, and
>    refuses a party already registered under a different identity or address. This is the check
>    §12.D flagged as having no successor, and it is genuinely an agreement rather than a
>    bootstrap step. **It survives as `MeshCommit`**, and is strictly stronger: every party
>    checks it against every peer instead of one process checking it centrally, it covers the
>    roster digest as well, and the digest backstop catches a field the comparison forgot.
> 2. **One TLS identity cannot represent two logical parties.** **Survives, and earlier**:
>    `Roster::from_node_keys` refuses `DuplicateNode` on a compact-id collision when the roster
>    is built, before a socket exists, and `install_expected_server_public_keys` refuses two
>    distinct certificates that collide at one compact id.
> 3. **The all-zero execution id is refused.** **Survives** at flag parsing
>    (`--execution-id must be nonzero`), in the coordinator, and in the execution transport's
>    `ZeroExecutionId`. Review correction: the flag-parsing refusal was first written inline in
>    `main`'s argument loop, where no unit test could reach it, while `ExecutionId::from_str`
>    accepts 64 zeros because it validates only the hex encoding. It is now
>    `parse_execution_id_flag`, which both `--execution-id` and `--pool-id` go through and
>    which three tests cover, so this refusal has a successor test and not only a successor
>    line.
> 4. **Idempotent exact retries**, and **session replay to a party that connected late**
>    (`send_ready_session_if_waiting` and the `watch` channel). Both are bootstrap concerns with
>    no successor needed: there is no registration to retry, and a late party is *dialed again*
>    by a discovery loop that re-reads its missing set every round, rather than needing an
>    announcement replayed to it. The accept loop spanning discovery and the handshake is what
>    makes a late arrival safe.
> 5. **`authenticated_sender_matches`** guarded the ICE relay's sender id against the
>    connection's. It went with the relay (§4).
>
> **No party is privileged, including at retirement.** Collapsing the leader role left one
> place where a party could still have been singled out: `--one-off`, which acknowledges the
> execution's retirement with the coordinator. V2 first emitted it for `STOFFEL_PARTY_ID = 0`
> alone, on the premise that retirement is a single-process action. That premise is false
> against the coordinator this branch pins: `retire_execution` counts acknowledgements **per
> roster party** — it refuses an identity that is not on the roster precisely so that one
> party's acknowledgements cannot stand in for several — and `retirement_quorum() = n - t`
> gates both evictability and the one-off drain, with `n` required for removal or output
> retention. One acknowledgement of five therefore never reaches a quorum of four and the
> drain never starts. Every party now emits it, and the AVSS path tolerates an execution
> already forgotten the way the HB path and `cleanup_execution_resources` already did
> (a duplicate acknowledgement is `Ok(())` at the coordinator by design).

> **A deleted mechanism can survive in a doc comment, and `cargo check` will not say so.**
> Two rustdoc intra-doc links outlived their targets. `ExecutionId`'s own doc still said the
> full 256 bits were "carried through discovery and retained in [`SessionInfo`]" — a module
> and a type this change deletes — and `dial_duties` carried an intra-doc link to
> `discover_peers`, which is private. Neither `cargo check --all-targets` nor clippy reports either; `cargo doc -p
> stoffel-vm --no-deps` reports both, and it is **now part of this change's gate list** for
> that reason. A residue sweep by removed *name* could not have found the first one: the words
> left behind were "discovery" and a type name that was never on the removal list. Both docs
> now state their invariant positively — the 256 bits are the execution field of
> `ExecutionEnvelopeV1` and the key `NodeSupervisor` holds a running execution under, with
> `derive_instance_id_for_execution` the `u64` reduction protocols ask for and nothing routing
> on it — as does the `Network::parties()` rationale in `net/mesh/join.rs`, which cited "the
> deleted discovery path" for a trap that stands on its own. `stoffel-vm`'s doc warnings go
> from 8 to 6; the six that remain (`cffi.rs`, `net/mpc/avss/shares.rs`,
> `net/open_registry/instance.rs`) are `dev`'s, in files this change does not touch, as is the
> one in `stoffel-run.rs`.

**Every stack ends with a coordinator — and as of V2 every stack has one.**

> **Settled 2026-10-12 by stage V2.** The inventory below is V1's, kept because it is the
> measurement the work was planned from. What V2 changed: `docker-compose.avss.yml` and
> `crates/stoffel-lang/examples/docker-compose.mpc.yml` gained a `coordinator` service,
> `docker-compose.nat.yml` is deleted, and the standing stack and every one-shot stack form
> their mesh from the coordinator's roster out of `STOFFEL_PEERS` seed hints. No stack has a
> bootstrap address or a shared secret left. Read the V2 block earlier in this section for the
> per-surface state.

> **Corrected 2026-10-12 against `dev` (V1's measurement).** The paragraph this replaces listed
> `docker-compose.mesh.yml`, which has never existed in this repository, and claimed a
> `coordinator` service in two stacks that define none. Measured on branch
> `feature/no-bootnode-v2` (`ls docker-compose*.yml` plus a grep for `^  coordinator:`):
>
> | Stack | `coordinator:` service | Mesh formation today |
> |---|---|---|
> | `docker-compose.yml` | yes | coordinator |
> | `docker-compose.benchmark.yml` | yes | coordinator |
> | `docker-compose.coordinator.reserve-index.yml` (+ `.preproc.yml` override) | yes | coordinator |
> | `docker-compose.standing-concurrency.yml` | yes | **bootnode** — `LEADER_ARGS: --leader` on party0, `--bootstrap` on parties 1-4 |
> | `crates/stoffel-lang/examples/docker-compose.coordinator.yml` | yes | coordinator |
> | `docker-compose.avss.yml` | **no** | bootnode (`STOFFEL_ROLE=leader` + `STOFFEL_BOOTSTRAP_ADDR`) |
> | `crates/stoffel-lang/examples/docker-compose.mpc.yml` | **no** | bootnode (same shape) |
> | `docker-compose.nat.yml` | **no** | bootnode; the file is **not** deleted — see below |
>
> So three stacks are still bootnode stacks with no coordinator at all, and the standing
> stack has a coordinator and still forms its mesh through the bootnode. They become
> coordinator stacks in the stage that replaces mesh formation (§9's V2), not in V1, and
> §4's deletion of `docker-compose.nat.yml` is deferred to that same stage: V1 still
> maintains the file (its `STOFFEL_COORDINATOR_CONTEXT` defaults were updated with every
> other stack's), so deleting it here would leave the NAT path broken without a
> replacement and with no bootnode removal to justify it.

Where a stack does define a `coordinator` service, that service registers the program the
parties load, serves the node roster and decides admission; no party in those stacks carries
a roster, a party count, a threshold or any client identity. Under §13 the entrypoint does
not refuse the removed variables by name: it simply stops reading them.

**What is not covered by a run of the shipped stacks.** No image can be built until the
`coordinator` named context is satisfied (below), so the compose stacks of this change have
been validated with `docker compose config`, with the entrypoint's emitted argv checked
directly, and with the native rehearsals earlier stages recorded — not by a full
`docker compose up` of every stack. The one Docker build step this stage did run is
`docker/coordinator.Dockerfile`'s `planner` stage with the `coordinator` named context,
with the patch table in its path form, so `cargo metadata` had to resolve it: it succeeds,
and the context transfer honours the coordinator checkout's `.dockerignore` (about 1 MB,
not its `target/`).

**Building images during the patch window (§F.5).** The `[patch.crates-io]` tables name a
path, and no image reads either of them: every Dockerfile that runs `cargo` writes its own
patch table into `.cargo/config.toml`, pointing at the checkout the `COPY --from=coordinator`
lines land — `/opt/stoffel-coordinator`, or `/build/coordinator` in
`docker/coordinator.Dockerfile`. That holds only while every such table **covers** both
coordinator entries; an image whose table omits them does read the manifest's path, and dies on
it. §F.5 states the rule, and §9.I's "Repair of stage S6" box records the two files that broke
it. The `coordinator` named context the compose
`additional_contexts` entries demand is therefore the dependency source rather than residue,
so the variable has to name a `0.3.0` checkout and not merely some directory:

```bash
export STOFFEL_COORDINATOR_CONTEXT=/path/to/stoffel-mpc-coordinator   # a 0.3.0 checkout
docker compose up --build
```

Outside compose the same context is passed with
`docker build --build-context coordinator=$STOFFEL_COORDINATOR_CONTEXT …`. A plain
`docker build .` cannot build these images, because `COPY --from=coordinator` then resolves
`coordinator` as an image reference. CI's `docker-build` job does pass the context: it named a
`0.2.0` coordinator commit until stage S5 repointed it at the coordinator's
`feature/no-bootnode` branch (§F.5). The `[patch.crates-io]` tables, the `COPY` lines, the
`additional_contexts` entries and the re-lock of both lockfiles all wait for `0.3.0`.

**Other open items.** `crates/stoffel-lang/examples/run_mpc_local.sh` runs the wrapper
binary as a host-process coordinator instead of `stoffel run --local` (§F.2), because the
local runner requires consistent party returns and that script's default program,
`mpc_runtime_info`, returns a different value per party.

**Removed in review: the `Invitation` admission policy.** It was specified in §C.3 and
implemented across both repositories — the `InvitationIssuer`, `Invitation`,
`SignedInvitation` types, the `issue-invitation` binary, the `--invitation-issuer-cert`
and `--invitation` flags, error codes 26-28 — and never shipped in any stack. Review
judged it a hand-rolled certificate authority that added a trusted principal to a change
whose thesis is that no principal holds extra trust, so all of it was deleted: types,
errors, wire fields, CLI flags, environment variables, compose entries and tests.

No deprecation hint survives. A first pass left refusal-by-name guards for `--invitation`
and `STOFFEL_INVITATION`, a `--admission invitation` invalid-value assertion, and the
retired error codes named after the mechanism. Those were removed too. The reasoning recorded
here was that a guard exists to redirect someone whose working configuration a release broke,
and that `Invitation` never reached one; §13 supersedes that test, and the conclusion holds for
the simpler reason it gives: the guard is the one trace left of the thing we deleted, and it
advertises a mechanism nobody should use, released or not. The flags are now ordinary unknown arguments. Error codes 26, 27 and 28 stay
unallocated and unnamed. The digest tags for `PreRegistered` (0) and
`Open` (1) in §D.6 are unchanged, so no shipped execution's admission-agreement digest
moved. The replacement — `AdmissionPolicy::TrustedIssuer` over rustls'
`WebPkiClientVerifier`, with a real X.509 CA — is **future work and is not implemented**;
§C.3 records it. The shipped policies are `PreRegistered` and `Open`.

> **Stage V3 (2026-10-12): the coordinator replaced the mounted control plane.** The rows above
> are V2's; these are V3's, on the same worktree.
>
> | Item | State on `StoffelVM-nb2` |
> |---|---|
> | `crates/stoffel-vm-runner/src/standing_control.rs` | **deleted**, 984 lines. With it: `StandingControlCommandV1`, `StandingControlOutcomeV1`, `StandingExecutionAdmissionV1`, `StandingClientAdmissionV1`, `StandingNodeControl`, the `commands/` and `events/<party>/` directories, the contiguous command cursor, the durable acknowledgement and async-lifecycle event files, the `retired_execution_ids` marker directory, the 1 MiB bounded control-file reader and the 25 ms poll loop. `--control-dir` is gone from `stoffel-run`, from its `--help`, from `docker-compose.standing-concurrency.yml` and from the five per-party mount lines. Nothing in the tree names any of it. |
> | `crates/stoffel-vm-runner/src/execution_stream.rs` | **new**, the replacement. `CoordinatorExecutionStream::run` subscribes once with `CoordinatorLink::subscribe_executions` and serves `ExecutionNotice::{Prepare, Cancel, SnapshotComplete}` into `dev`'s existing `NodeSupervisor`. A stream that ends is routine, not fatal: it re-subscribes with 250 ms→30 s backoff and takes a fresh snapshot, keeping every running instance, because the mesh is a separate transport the coordinator is not on. `StandingProgramCatalog`, `StandingProgram` and `StandingExecutionHandler` moved over unchanged. Reaching `SnapshotComplete` stops every instance *that run of the coordinator admitted* and the snapshot did not name, which is what recovers a `Cancel` a saturated connection queue dropped (the incarnation scope landed in stage V5; see §12.B). |
> | `resolve_published_execution` | **the retargeted `resolve_admission`.** Same refusals — nonzero identity, program in the startup catalog, entry present in the compiled program, `validate_client_io_admission` against the manifest, duplicate client identity — against the coordinator's typed `PublishedExecution` instead of a JSON file. Two refusals are new: an `AdmissionPolicy::Open` execution (a standing node runs only pre-registered admissions, because under `Open` any certificate holder that can reach the coordinator may bind a slot of a program the node holds) and a published client identity the node holds no certificate for. |
> | `StandingClientCatalog` | **re-keyed** from certificate filename to the `subject_public_key` the coordinator publishes, which is the `ClientIdentity` it reasons about. The certificate-exact `CertificateIdentity` that authorizes a transport route still comes from the local file; nothing on the wire is trusted as certificate material. Two files holding one key is now a refusal of the catalog, because an ambiguous published identity must not resolve to whichever file sorted first. |
> | `config_digest` | **re-derived**, domain `stoffel-coordinator-admission-v1`, over the execution identity, the program address, the registration nonce, the entry name, the ordinal list of program slots, and the resolved client keys and certificate identities. The nonce is in the preimage so two registrations of one identity differ; the ordinal list is in it so a permuted client list is a different admission. Every party still recomputes it independently and the parties still compare it in `ReservoirAllocationSnapshot` before any correlated material moves, so a coordinator that equivocates between parties still fails closed. |
> | Durable non-reuse | **re-homed into LMDB**, `crates/stoffel-vm/src/storage/retired_executions.rs`. `RetiredExecutionIndex::claim` inserts an identity if absent inside one write transaction and reports whether this call recorded it; the claim is taken at admission, before the instance starts, exactly as the marker-file directory did, so a node that crashed mid-execution cannot re-admit an identity whose correlated material its peers already consumed. This is the index `net/execution_transport.rs` delegates non-reuse to. `stoffel-run --admitted-store <path>` names it and the standing compose gives each party a retained volume beside its preprocessing one. |
> | Operator submission | **new, and it is what replaces the mount's authority.** `CoordinatorRPCBase::submit_execution` and `abort_execution`, gated on `shared.operators.contains(&self.id)`, with `CoordinatorRPCBaseError::NotOperator = 42` and `RegistrationRefused = 43` carrying the typed `RegistrationError`. The operator set is `CoordinatorRPCServerSharedBase::with_operators`, fixed at startup and **empty by default**, so a coordinator started without one accepts no submission. `docker/coordinator-wrapper --operator-certs` supplies it and `crates/stoffel-vm-runner/src/bin/stoffel-coord-ctl.rs` is the operator's client. `AbortReason::OperatorRequest` is the one abort reason an identity rather than the clock produces. |
> | One-shot parties | **stop being configured with an identity.** `take_published_execution` subscribes on the link the party already opened for the roster, takes the first published execution naming the program it holds, refuses one whose entry differs from the one it was told to call, and uses that identity for the mesh commitment and everything after it. Party mode forbids `--execution-id`; §12.G records why client mode keeps it. `local_runner.rs` and the Rust SDK's server builder stopped passing one, and `local_coordinator_e2e`'s eight real five-party runs pass unchanged, which is the end-to-end proof. |
> | Acceptance drivers | **retargeted, not deleted.** `docker/standing-concurrency/acceptance.py` submits every execution with `stoffel-coord-ctl` through a new tools-profile `operator` service and learns each identity from what the coordinator minted; `matrix.json` no longer names one. Node lifecycle is read from the nodes' own logs instead of acknowledgement files, which is why the completion line now carries `instruction_budget_yields=` and `online_effect_yields=`: those counters are the only evidence an execution shared its process, and the campaign asserts on them. `all_examples.py` follows. Two arms changed subject: the malformed-control-file cases became a refused submission (not an operator; a zero program hash) plus an execution naming a program no node holds, and the retired-identity replay became an assertion that the admitted index survived the SIGKILL — an operator cannot name an identity, so the replay itself is no longer constructible from docker and the refusal is pinned by `storage::retired_executions::tests::a_claim_survives_the_process_that_made_it` and `::a_reopened_index_reports_every_identity_it_retained`. The replacement observes the restarted process, not the dead one: a standing node prints `admitted_identities=` on its startup line, read from the index it has just reopened and before it has taken anything off the coordinator's stream, and `assert_admission_index_survived_restart` requires that number to have grown past the party's first startup and to cover every identity the campaign watched all five parties admit. The arm first written here read the container's whole log, which keeps the dead process's lines across `kill` + `up`, and so was satisfied by pre-kill output; it was corrected in stage S4. |
> | Not run | The three docker campaigns. They are retargeted and `py_compile`-clean and every compose stack validates, but no campaign was executed in this stage; V5 runs them. |
>
> **Stage V3 repair (2026-10-12).** Four things the stage left broken or unstated, fixed on the
> same worktree.
>
> | Item | State on `StoffelVM-nb2` |
> |---|---|
> | The adversarial "a non-operator cannot submit" arm | **fixed.** `acceptance.py` passed `ids/clients/cert0.crt` with the *operator's* private key, which rustls refuses locally as a key mismatch: the process died before opening a connection, so the arm asserted nothing about authorization and the campaign would have failed on the missing `NotOperator`. It now presents `client0`'s certificate *with `client0`'s key*, mounted into the `operator` service as the `stoffel_nonoperator.{crt,key}` secrets, so the handshake succeeds and the coordinator is the party that refuses. (An earlier revision of this row said the key came from the mounted client-certificate directory; that directory holds only `*.crt` by default, which is deliberate, so the secrets are where the key had to come from.) This is the arm that replaces the mount's authorization boundary in docker, so it is the one that had to work. |
> | One-shot stacks that can drive themselves | **three more now can.** `docker-compose.yml` got a `registrar` service in V3; `docker-compose.avss.yml`, `docker-compose.benchmark.yml` and `crates/stoffel-lang/examples/docker-compose.mpc.yml` have **no client services** and so had no reason to be left manual — each now has the same registrar and `docker compose up` completes unaided. `Dockerfile.benchmark` builds `stoffel-coord-ctl` for its own registrar. The V3 report grouped these with the client-bearing stacks, which was wrong about all three. |
> | One-shot stacks that genuinely need an operator | **only the two with clients**: `docker-compose.coordinator.reserve-index.yml` and `crates/stoffel-lang/examples/docker-compose.coordinator.yml`. A client is not on the node roster, so the coordinator publishes it nothing and the minted identity has to reach it as `STOFFEL_EXECUTION_ID`. Both are now driven for themselves: `docker/test-coordinator-reserve-index.sh` and `docker/test-coordinator-preproc-store.sh` had a `mint_execution` step in V3, and `crates/stoffel-lang/examples/run_coordinator_compose.sh` — which V3 left asserting `outputs: [315]` against a stack nothing ever submitted to, and which `validate_examples.sh` drives — now has the same step. |
> | `validate_examples.sh`'s docker-MPC loop | **retargeted.** It bounded each run with `--abort-on-container-exit --exit-code-from party0`, which a registrar's normal exit would trip. It now starts detached, streams the logs and takes `party0`'s own exit code from `docker compose wait`. |
> | `CoordinatorExecutionStream`'s notice handling | **now covered.** V3 tested the catalogs, `resolve_published_execution`, the digest and the cursor, but nothing exercised `apply`/`admit`/`stop`/`reconcile_snapshot` — including the stage's headline claim about `SnapshotComplete`. Five tests over a real `NodeSupervisor` and a real `RetiredExecutionIndex` now pin: a `Prepare` admits once, a republication while live is `AlreadyRunning`, a replay after it finished is `AlreadyAdmitted` (the durable single-use claim), a refused program starts nothing, a `Cancel` tears down a live instance while an unknown one is ordinary, `SnapshotComplete` stops exactly the instances the snapshot omitted and leaves the named ones running, and a `Prepare` after the snapshot survives. |
> | A second `SnapshotComplete` | **hardened.** `SnapshotCursor::complete` returned an empty set once the snapshot had closed, and `apply` reconciled against it — so a duplicate `SnapshotComplete` on one subscription would have stopped **every** running instance, including those the live stream started. It now returns `None` on the second call and `apply` reconciles nothing, which is what the cursor's own test comment already claimed. |

> **Stage V4A repair (2026-10-12).** Three review findings, fixed on the same worktrees.
>
> | Item | State |
> |---|---|
> | `README.md`'s two "Docker Flows" commands | **fixed.** Both still opened with `STOFFEL_EXECUTION_ID="$(openssl rand -hex 32)"` — the operator-invents-the-identity pattern this work exists to delete, three lines below the bullet saying a party is published its execution and its clients are given the identity the coordinator minted. For the reserve-index stack the line was live, not merely stale: `docker-compose.coordinator.reserve-index.yml` forwards the variable into `client0`/`client1`, that stack has no `registrar` service, and so a reader following the README submitted nothing, the parties were published nothing, and the clients presented an identity no coordinator minted. The block is now the coordinator-first sequence its own stack header and `docker/test-coordinator-reserve-index.sh` use, and points at that script. The AVSS block drops the variable entirely, because that stack's `registrar` submits for itself and no service reads it. |
> | `crates/coord-shared/src/rpc.rs`'s idle-connection accounting | **fixed.** It called `Atomic*::fetch_update`, which is deprecated on `nightly-2026-08-21` — the toolchain `rust-toolchain.toml` pins — so `cargo clippy --workspace --all-targets -- -D warnings` under that toolchain failed to compile `stoffel-mpc-coordinator-shared`. The method is now `try_update`, which is stable on `1.95.0` as well, so both the pinned-nightly and default-stable builds are clean. The gate blind spot that hid this is worth naming: the coordinator worktree has no `rust-toolchain.toml` and resolves stable, where the method is not deprecated, and the VM's own gate cannot see it either because cargo applies `--cap-lints allow` to a non-workspace-member path dependency. **The coordinator's clippy gate must therefore be run as `rustup run nightly-2026-08-21 cargo clippy --workspace --all-targets -- -D warnings`, not bare `cargo clippy`.** No toolchain file was added to the coordinator worktree: it is a separately published crate and builds on both toolchains, so pinning its consumers would be the wrong fix. |
> | Root `tests/p2p_integration.rs` | **deleted**, along with the now-empty root `tests/` directory. §7's bullet is corrected: see that section. |

> **Stage V4 (2026-10-12): deployment surfaces verified, and the document made true of this
> tree.** No mechanism changed in this stage. Every deployment surface was measured and, where
> the document disagreed with it, the document was corrected in place.
>
> | Surface | Measured state |
> |---|---|
> | the eight compose stacks | **in line.** Each of the seven standalone stacks plus the preprocessing override has a `coordinator` service, a pinned `--coord-cert`, a `--node-roster` of the five node certificates and an `--operator-certs` set; `docker-compose.yml`, `docker-compose.avss.yml`, `docker-compose.benchmark.yml` and `crates/stoffel-lang/examples/docker-compose.mpc.yml` carry a `registrar`, the standing stack carries an `operator` under `profiles: [tools]`, and the two client-bearing stacks are driven by their own scripts. `STOFFEL_EXECUTION_ID` survives only in two `client-env` anchors. No `STOFFEL_AUTH_TOKEN`, `LEADER_ARGS`, `BOOTSTRAP_ARGS`, bootstrap address, control directory or `.der` key outside a secret or a baked `ids/`. All eight pass `docker compose config -q` |
> | `docker/entrypoint.sh`, the Dockerfiles, `docker/*.sh`, the examples scripts | **in line.** Two roles, `party` and `client`; the client role is the only one that names an execution identity; no removed variable is refused by name, each is simply unread (§13). Every modified script passes `bash -n`, and both acceptance drivers `py_compile` |
> | `local_runner`, the Rust SDK, `stoffel-cli` | **in line**, as V2 and V3 left them. The SDK's `README.md` names no removed mechanism; `crates/stoffel-cli` names none either |
> | `README.md` | **in line** after the V4A repair: the coordinator mints, an operator submits with `stoffel-coord-ctl`, a party is published its execution and names none, a client is handed the identity that was printed |
> | §F.0 key material | **corrected: not landed.** `deployment_key_material.rs` does not exist, the `runtime` image target and `docker/coordinator.Dockerfile` still `COPY ids`, and four stacks publish ports on every interface. Only the standing stack's node and operator services satisfy rules 2-4, and its coordinator image does not. §F.0 now says so, and so does every §G row that depends on it |
> | §D.2 / §D.3 removed-flag tables | **corrected: nine of the "removed" rows are live flags** — all nine parse, but with different reach: six (`--expected-clients`, `--wait-for-clients`, `--client-input-count`, `--n-parties`, `--threshold`, `--preproc-store`) have a parse arm, a `--help` line and an entrypoint emission; `--client-input-total` has the arm and the emission but no `--help` line; `--client-roster` and `--client-input-slots` have the arm and no `--help` line, and are emitted only by `local_runner`, never by `docker/entrypoint.sh`. They are `dev`'s client-shape and preprocessing configuration. *Corrected 2026-10-14:* their removal was filed as "V-0/V-c work that is not done"; for `--preproc-store` that is now void in both halves — V-0 is done and it **keeps** the flag (§9.1 V-0), so there is no pending removal of it. The eight client-shape flags remain V-c work. `--execution-id`'s row and the `--epoch-store` row were stale |
> | §F.1 | **corrected** on five counts: `docker-compose.mesh.yml` never existed, the entrypoint refuses nothing by name, parties keep `STOFFEL_N_PARTIES`/`STOFFEL_THRESHOLD` and two stacks keep `STOFFEL_EXPECTED_CLIENTS`, no party is given an execution identity, and the preprocessing override configures a store over a volume that holds preprocessing material and not an epoch. *Corrected 2026-10-14:* this row, like §F.1's point 5 it summarises, said the override "sets `STOFFEL_PREPROC_STORE`"; it sets no variable — it passes `--preproc-store` once inside the standing-node command anchor the five parties share, and no compose file in the tree sets that variable |
> | §12.G | **corrected.** Its closing paragraph said the entrypoint loses the `STOFFEL_COORD_ADDR` ⇒ `STOFFEL_EXECUTION_ID` requirement; the requirement is kept and narrowed to the client role, which is what the same section's own correction block describes |
> | §H's `the_preprocessing_store_flag_fails_by_name` | **struck.** No such test exists, the flag it names is live, and §13 forbids the by-name refusal it would have asserted |
> | §8's SDK row, §10's guard rationale | **both carry their supersession.** §13 is the rule for everything removed in this effort, released or not; §8's parenthetical now also records that `expected_client_certs` survived its break list |
> | `stoffel-run.rs`'s `register_coordinator_execution` doc comment | **disambiguated.** It read "the coordinator is not told anything here: it is the party that minted the identity and published it" — correct, since "it" is the coordinator, but "party" means *node* everywhere else in that file, so a V5 reviewer read it as the inverse of this effort's invariant. It now names the coordinator twice and says why. The code was always right: a standing node registers the execution with its own RPC listener and with nothing else |
> | the three docker campaigns | **not run in this stage**, and that was the stage's own unproven leg: they were retargeted, `py_compile`-clean and their stack validated, but nothing had executed them. The V4 repair below ran `docker/test-standing-concurrency.sh` against a freshly built image, which found two defects no static check could have — see §12.B |

> **Stage V4 repair (2026-10-12).** Four review findings against the V4 stage, three of them
> about this document and one about a file that would not have reached the branch.
>
> | Finding | Fix |
> |---|---|
> | `ids/operator/cert.crt` and `ids/operator/key.der` were present in the working tree but **untracked**, while `Dockerfile` copies the certificate into the image, the standing stack declares the key as the `standing-operator-key` secret, and five scripts and stacks name one or the other. A clean checkout of the branch would not have built | both files are now **tracked**, exactly as the sibling fixtures `ids/nodes/*` and `ids/clients/*` are. There is no generator for any of them — these are development fixtures, and the pair is self-consistent (the certificate's public key equals the key's) |
> | the same omission, found while fixing it, covered **every new file this effort wrote**: `stoffel-coord-ctl.rs`, `execution_stream.rs`, the whole `net/mesh/` module (`mod.rs`, `join.rs`, `dial.rs`, `pex.rs`, `wire.rs`), `net/program_id.rs`, `net/roster.rs`, `storage/retired_executions.rs` and **this document** were all untracked, and the worktree's deletions were only half staged. The branch as recorded would not have compiled | the whole change set is now staged: 88 paths, no untracked file left, no build output among them (`target/` is ignored). The cause is structural rather than anyone's slip — every stage of this effort runs under a no-commit rule, so nothing could enter the index until a review asked for it |
> | §D.2's own measured block and the matching §9.I row claimed all nine live flags have "a parse arm, a `--help` line and an entrypoint emission". The entrypoint emits **seven**: `--client-roster` and `--client-input-slots` appear nowhere in `docker/entrypoint.sh` and in no `--help` line either, and `--client-input-total` has no `--help` line | both places now state the reach **per flag**: six flags have all three, `--client-input-total` lacks the `--help` line, and the last two are reachable only from `local_runner`, which builds a party's argument vector itself and passes both from the manifest's client slots — no containerised deployment reaches them. That is the same class of defect those blocks exist to remove, so it is corrected rather than softened |
> | every `stoffel-run.rs` line number in the blocks that claim to be true of *this* tree was stale by 200-300 lines, because stages V2-V4 grew that file by that much after the blocks were written. A reader checking `run_standing_node`, `setup_hb_party_for_curve`, `PreprocessingExchangePhase`, `standing_preproc_pool_program_id`, `warm_reservoirs` or `set_preproc_store` landed on unrelated code | **symbol-only citations** in every such block, and a *How to read a citation* rule at the head of this document: the symbol is the citation; line numbers survive only in the historical sections, which cite the main-based tree, and in findings that name base `266a416` explicitly. Two citations were also re-pointed in substance: §11.1's and §11.5's upward `register_execution` is `register_coordinator_execution` **as `dev` had it at `266a416`** (on this branch that function talks only to the node's own RPC listener), and §12.H's `__standing_node_pool_v1` is likewise a base measurement |
> | the three docker campaigns had never been executed | `docker/test-standing-concurrency.sh` was **run against freshly built images**, eight times, and it earned its place: it found seven defects that every static check in this effort had passed over, and after them its headline phase passes — see the as-run block below this table. (1) **No execution could reach a standing node at all** — see §12.B: the node's coordinator link idled through preprocessing, the coordinator reclaimed it, and the node then retried a dead client forever. Fixed, and verified in the live stack: `cannot subscribe … Connection was closed` → `reopened the link to the coordinator` → `subscribed to the coordinator's execution stream` → `execution snapshot complete`. (2) The acceptance driver could not read the identity the coordinator minted: `stoffel-coord-ctl submit` prints it as the last line, `docker compose run` narrates the one-off container onto the same captured stream, and `Harness.submit` split the whole output and demanded exactly two tokens. Fixed by parsing the last line, with the same strictness on it. (3) The campaign's own program delivery, in the block below: nodes froze catalogs of one or two of the five installed artifacts and warmed only those reservoirs |
>
> **A third defect, in how the campaign delivers programs.** In three of four runs the five
> standing nodes froze a *short* program catalog — one or two artifacts of the five the campaign
> had installed — warmed those reservoirs, declared themselves ready, and then idled while
> `start_nodes` waited for reservoirs that would never be warmed. The artifacts were not late:
> the host had written all five seven seconds before the node containers started, and a
> container reading the same mount in that window listed all five. The catalog loader is
> fail-closed about everything it *does* see — a mis-addressed or uninspectable artifact refuses
> the whole load — and a standing node has no independent statement of what the directory should
> hold, which is the point of freezing it, so it cannot detect a short read on its own.
>
> What differed is who wrote the files. `acceptance.py` copied each artifact out of the node
> image with a one-off container that bind-mounted the shared programs directory, and a write
> made that way is not reliably visible to a *different* container mounting the same host path
> moments later; `all_examples.py` compiles its catalog on the host and has never shown the
> symptom. `install_artifact` now extracts the artifact to the host — the host process is the
> only writer — and renames it into place atomically, so a node can never read a half-written
> artifact either. `Harness.assert_programs_are_visible` additionally reads the mount from the
> node image until every installed artifact appears, before any node starts: a wait where there
> was a hang, and a named failure if they never all appear.
>
> **What the campaign proves now, and where it still stops.** The matrix phase passes: the
> coordinator mints six executions on one submission each, publishes them down to five standing
> nodes over their subscriptions, and all nine client containers of the wave produce correct
> output — HoneyBadger and AVSS, single- and multi-client, two concurrent executions of one
> program, two of different programs, and an input-only client. That is the property this whole
> effort exists to deliver, exercised under concurrency against a rebuilt image rather than
> argued. The run then fails in the next sub-phase, the CPU-fairness pair: `cpu-long` is
> cancelled on `party1` while the harness waits for it, which is a question about instruction-
> budget fairness between two concurrent executions of one program and has nothing to do with
> where an execution identity comes from. It is recorded as the next thing to chase, not as part
> of this effort.
>
> Reaching that point needed four more defects fixed beyond the two above, three of them
> policy sizings in the coordinator that are only reachable under concurrency:
>
> | Defect | Fix |
> |---|---|
> | a node's log, not the node, lost the evidence: the MPC libraries log one line per protocol message, which at the campaign's preprocessing sizes pushed each node's startup out of the retained log within a minute. Every readiness check and most assertions here read container logs, so `start_nodes` waited for markers that had been printed and rolled away — which is what looked for several runs like nodes freezing a short program catalog | the libraries' per-message chatter drops to `warn` for this stack while the node's own lines stay at `info`, and the node services keep 5 × 200 MB of logs. `StandingProgramCatalog::load` also no longer drops a directory entry it cannot read — a fail-open in an otherwise fail-closed loader — and a node now says how many artifacts it froze, so a short catalog is one line rather than a deduction |
> | `get_node_roster` shared one token bucket with `get_execution_summary`, 10 deep. Every link open fetches the roster, a client opens two links per execution, and a node reopens its link whenever the connection under its subscription ends, so on one identity in six concurrent executions the bucket emptied before the executions could start | the roster has its own bucket, `ROSTER_READ_BURST` = 64 at `ROSTER_READS_PER_MINUTE` = 240, because reading it is not a request a caller chooses to make and what is served is one cached constant. `SUMMARY_READ_BURST` becomes 64 at the unchanged 60/minute, sized for the executions one identity may be starting at once rather than for one. Both are pinned by tests, including that spending one bucket does not spend the other |
> | `max_connections_per_identity` was 8, and the campaign's client identity legitimately holds two connections per concurrent execution. The refusal arrived as a bare `Connection reset by peer`, with the reason only in a `tracing` warning that nothing was subscribed to | the cap is 64, sized in concurrent executions rather than in callers, and `docker/coordinator-wrapper` installs a `tracing` subscriber so every sub-RPC refusal the coordinator makes — a certificate it will not admit, a failed handshake, a full pool, a subscriber that fell behind — is visible instead of silent |
>
> Two of §12.G's prescriptions were found **void** while re-resolving its citations:
> `UNUSED_EXECUTION_ID` and `resolve_coord_execution_id` have never existed on `dev` — not at
> base `266a416` and not here — so there was nothing to delete. The property they were to carry
> is enforced from the other end instead: party mode refuses `--execution-id`, and a run without
> a coordinator is refused at argument validation.

> **Stage V5 repair (2026-10-13).** One defect and four documentation divergences, all found by
> review of stage V4's output.
>
> | Item | State |
> |---|---|
> | a coordinator restart aborted every in-flight execution on the roster | **fixed**, in both repositories. `ExecutionNotice::SnapshotComplete` carries a `CoordinatorIncarnation` and the node scopes reconciliation to the run of the coordinator that admitted each instance (`CoordinatorExecutionStream::incarnations`, `reconcile_snapshot`, `NoticeOutcome::SnapshotReconciled { stopped, kept }`; stage S3 below moved that map into the shared `InstanceLedger` and added a third list). Three tests: `a_restarted_coordinator_stops_nothing_it_never_admitted`, `a_cancel_from_a_restarted_coordinator_still_stops_an_older_instance`, `every_snapshot_names_the_run_of_the_coordinator_that_took_it`. The §12.B V5 box has the analysis and says what is still open: a restarted coordinator cannot *adopt* executions in flight, and nothing here makes it able to |
> | §9.D.5 and §9.D.6 stood as live contract text for a mesh/session design this tree deliberately replaced | **corrected.** Both have a correction box naming the as-built symbols, and the four §9.0 inventory rows that listed `SessionExecutionId`, the `JoinRequest.execution_id` shape, `net/mesh/barrier.rs` and `stoffel-vm-runner/src/admissions.rs` are struck through |
> | §9.B's rate-limit policy and §9.A's `max_connections_per_identity` still stated the numbers the V4 repair replaced | **corrected**, with **as built** markers in place and the two-bucket table in §9.B |
> | §9.H named tests that do not exist | **measured and mapped.** Every test name in §9.H was grepped for in both repositories; the result is the block at the head of the VM table. The coordinator half is true but for one row; most of the VM half was the v1 plan. One row stopped being void by being written: `the_program_id_matches_the_shared_golden_vector` now exists in `net/program_id.rs`, so the VM's program id and the coordinator's `program_hash_of` are pinned to each other by a test rather than by a comment |
> | §E.3's "direct client mode is retired" | **corrected.** It is live: client mode does not require `--off-chain-coord` and falls through to `run_as_client`. Deleting it is open work. *Superseded by the stage S2 box below, which deleted it* |
>
> Gaps this stage measured and did not close, all now stated where they belong:
>
> - no VM-side test covers `resolve_coordinator_pin`'s two refusals, `fetch_node_roster`'s
>   membership and size refusals, or the client leg's pin of a node RPC listener. Each
>   behaviour exists; only the campaign exercises the `fetch_node_roster` ones.
> - no as-built path compares delivered masked-input submissions between the parties of a mesh
>   (§D.6's `InputsAgreed` half). The admissions half is covered.
> - direct client mode is still reachable, and with it the fail-open client allowlist §E.3
>   identified. *Closed by the stage S2 box below.*
> - §F.0's key-material rule still has no enforcing test and
>   `crates/stoffel-vm-runner/tests/deployment_key_material.rs` does not exist.
> - the standing campaign's CPU-fairness sub-phase, where stage V4's run stopped, was not
>   re-run: this stage changed the execution-stream reconciliation and the coordinator's
>   notice vocabulary, both covered by unit tests, and not the instruction-budget scheduling
>   that phase asserts.

> **Stage V5 campaign (2026-10-13).** The sub-phase the box above left unrun was run, and so
> was the rest of `docker/test-standing-concurrency.sh`. It passes end to end for the first
> time on this branch — twice, the second time on the tree as this stage leaves it, after the
> two acknowledgement fixes below changed what a node publishes: the concurrent HoneyBadger/AVSS matrix, the CPU-fairness pair, the
> SIGKILL restart with its retained admitted-execution index, the nine-execution elastic
> refill with its post-refill pair, and the asymmetric party2 recovery. Twenty-one client runs
> across those waves each produced exactly their expected outputs, and `assert_completed`
> checked a distinct destructive allocation digest per execution on every party, so six
> concurrent executions — three of them the same program, two of those with identical inputs —
> neither shared material nor mixed results.
>
> Getting there needed four fixes. The first two are defects only reachable under
> concurrency; the second two are transitions the port stopped publishing, which only a
> campaign that waits for them could notice.
>
> | Defect | State |
> |---|---|
> | a node reported a **successful** execution as cancelled | **fixed** in `NodeSupervisor::finish_terminal`. `Cancel` is not only the abort notice: `remove_execution` publishes one, with outcome `Finished`, for an execution that has left the coordinator's table, because the roster is told whatever the reason. A node acknowledges its retirement inside `cleanup`, after `execute` returned its metrics and before the terminal event is emitted — so the acknowledgement that *completes* an execution, the last party's, races the notice it causes against that party's own completion, and `finish_terminal` rewrote any event as `Cancelled` once the token was cancelled. This is what stopped stage V4's run (`execution cpu-long failed on party1: {'event': 'cancelled'}`) after the execution had completed 1525 instruction-budget yields on every party. A cancellation arriving after the online phase produced its metrics was made to have nothing left to stop, so the completion stood; an interrupted `execute` or `prepare` still reported `Cancelled`. Confirmed live at the time: one party logs `cancelled execution 04c5…` and then `execution 04c5… completed: instruction_budget_yields=7`. **Superseded 2026-10-13** — that leniency was itself a defect and is gone; see the correction box below the table |
> | the CPU-fairness phase asserted the submission path rather than the scheduler | **fixed** in the fixture and the assertion. Measured on the five-party stack: `cpu_long` ran for **283 ms** and `cpu-short` was not admitted until **262 ms** after it, leaving a 23 ms overlap in which nothing could overtake anything. The gap belongs to the deployment, not the VM: dev's driver wrote both command files into the mounted control directory and a node read them in one poll, whereas every execution of a wave is now minted by its own authenticated operator call. The fixture had been sized against the mount. `cpu_long` is now 100,000,000 rounds — **3.34 s** and 30,517 yields as measured — and the phase asserts the overtaking it means: the short execution is admitted second, starts while the long one is still running, and finishes before it. Measured after the change: short admitted 257 ms later, finished **2.95 s** earlier. A pass can no longer come from a head start or from two executions that never met |
> | the node never published its **admission** acknowledgement | **fixed** in `NodeSupervisor::prepare`. `prepare` returns a `Preparing` event and `CoordinatorExecutionStream::admit` dropped it, so `Preparing` was constructed and never emitted: the node logged `admitted execution <id>` — the *notice's* outcome — but no execution ever reported the lifecycle transition, and `report_event`'s arm for it was unreachable. dev did publish it: the mounted control plane wrote `prepare`'s return value out as the command's `StandingControlOutcomeV1::Event`. The adversarial campaign's two-offline-parties phase waits for exactly that event and timed out on it (`timed out waiting for admission of b149d2f2… on party0`). `prepare` now publishes the acknowledgement, and publishes it before spawning the preparation task so an execution's events open with `Preparing`. `prepare_launch_and_cleanup_are_isolated` was retargeted onto the stronger claim: the first event is the acknowledgement, and `Ready` is the second |
> | the node never published its **cancellation** acknowledgement | **fixed** in `NodeSupervisor::cancel`, the same gap one notice over: `cancel` returned a `CancelAccepted` event and `stop` dropped it. The stalled-sibling phase waits for a node to acknowledge a cancellation it accepted — which is what distinguishes an execution stopped here from one that had already ended, reported as `is not running here` — and timed out on it (`timed out waiting for cancellation of 3077a763… on party0`). `cancel` now publishes it, ahead of the terminal `Cancelled`; `an_abort_after_the_online_phase_finished_reports_cancelled` asserts that ordering (it was named `a_cancellation_after_the_online_phase_finished_still_completes` until the correction below) |
>
> **Correction (2026-10-13), first row.** The leniency that row describes was itself a defect,
> and it is gone. `finish_terminal` tolerated a cancelled token on a completion because the
> *benign* notice cancelled the token at all — and the thing that says which notice it is,
> `ExecutionNotice::Cancel`'s `outcome`, was discarded by `CoordinatorExecutionStream::apply`,
> which matched `Cancel { execution_id, .. }`. Two consequences: an operator abort landing after
> the online phase produced its metrics was reported as a completion, and an execution the
> coordinator forgot once its retirement quorum was reached *without* a lagging party — eviction
> compacts at `n - t` acknowledgements, not at unanimity — had that party's live instance torn
> down rather than left to finish. Both are fixed at the source.
> `apply` now matches the outcome: `ExecutionOutcome::Finished` retires the identity and touches
> no instance (`NoticeOutcome::Retired { execution_id, still_running }`, the second field read
> from `NodeSupervisor::is_live` so the log says which case it is), while
> `ExecutionOutcome::Aborted(reason)` cancels as before and carries the coordinator's reason into
> the node's log. Every cancellation the supervisor now receives is an order to stop *this* work
> — an abort, a snapshot that no longer names the execution, or shutdown — so `finish_terminal`
> holds the strict rule again: a cancelled token reports `Cancelled`, whatever the interrupted
> work produced first. Pinned by
> `a_finished_cancel_retires_the_identity_without_stopping_the_instance` in `execution_stream.rs`,
> which asserts the instance is still live after the notice, and by
> `an_abort_after_the_online_phase_finished_reports_cancelled`, which is
> `a_cancellation_after_the_online_phase_finished_still_completes` retargeted onto the behaviour
> the fix makes correct — same mechanics, opposite expectation.
> `a_cancellation_during_the_online_phase_cancels` is unchanged. No campaign assertion moved with this: no suite asserts the `is not running here`
> outcome a `Finished` notice used to produce, and the adversarial campaign's stalled-execution
> phase waits for `cancellation accepted` and a terminal `Cancelled` on an execution the operator
> really did abort, which the strict rule makes more reliable rather than less.
>
> The two acknowledgement gaps are one defect with two faces, and neither is cosmetic: the node
> supervisor's event stream is the only account a standing node gives of what it is doing with
> an execution, and the port had reduced it to what the *coordinator's notices* said while the
> two transitions the node itself decides went unpublished. They were found by running
> `docker/test-standing-adversarial.sh`, which no stage had run before this one. It now passes
> end to end: invalid rosters, refused submissions (`NotOperator` from a certificate the
> coordinator never listed, a malformed program hash, a program no node holds), malformed
> datagrams, delayed HoneyBadger and AVSS parties, stalled-sibling progress and its
> operator-requested cancellation, a frozen party across two concurrent online executions, a
> bounded two-party outage, and mesh recovery in the same five processes.
>
> One phase of it had to be **retargeted**, and this is the whole of what changed. That phase
> is also where the admission acknowledgement was caught, in two steps worth keeping apart:
> it first timed out on **party0**, which is not one of the two parties the phase takes
> offline, and that was the missing event; with the event published it got past party0 and
> timed out on **party3**, which is one of them, and that is not a missing event but a
> party that cannot be told anything. "Two offline
> parties fail closed" took the two parties off the standing network with
> `docker network disconnect`, which worked when a mounted directory carried the commands: the
> filesystem did not care about the network, so all five parties were still admitted and all
> five still failed closed. The coordinator is now the one path by which a node is told what to
> run, so a party removed from that network is not an offline party running an execution — it
> is a party that was never told about one, and the phase would have asserted a silence. The
> fault is now injected on the peer addresses only, with the two-band `prio` + `netem loss 100%`
> shape `docker/configure-peer-netem.sh` already uses and the peer list it already publishes
> (`NET_PEER_IPS`, which does not include the coordinator). Every assertion is the one it was:
> all five parties admitted, all five terminal in `Failed`, inside the coordination bound, and
> the mesh recovers afterwards in the same processes. `Harness.disconnect`/`reconnect` are gone
> rather than left unused, and so is the `discover_network` call that only they needed.
>
> **`docker/test-standing-all-examples.sh` could not start, and had not been able to since
> before this effort began.** `compile_catalog` refuses to run unless it finds exactly the whole
> catalog, and the number it was given is `190`, byte-identical to dev's. dev's own tree holds
> **191** `main.stfl` examples: `mpc_sha256_client_io` was added on 2026-09-03 in
> `2cf4cbc feat(client-io): optimize batching and add SHA-256 example`, after
> `7e668ff` wrote the guard, and the count was never raised. The driver therefore answered
> `expected 190 canonical examples, found 191` and stopped before compiling anything — on dev
> as much as here, so this is a defect of the base and not of the port, and it is why no stage
> of this effort had ever seen this campaign run. The guard now names
> `CANONICAL_EXAMPLE_COUNT = 191`, which *adds* the SHA-256 example to the run rather than
> excusing it; the tripwire itself is kept, because its job is to catch a glob that silently
> matches fewer examples than exist. All 191 compile, to 191 unique artifacts, 76 of them with
> dynamic preprocessing demand.
>
> **With the guard corrected, the campaign still cannot complete — for a reason that has nothing
> to do with this change.** All 191 examples compiled, all five standing nodes froze the
> 191-artifact catalog, and then every one of them exited 13 at the third reservoir:
> `Standing node failed: MPC preprocessing failed: Failed to top up preprocessing material in
> chunk 1/1: PRandError(SurpassedFieldCapacity)`.
>
> The third program by program-id order is `matrix/secret/average_fix64`, whose manifest demands
> `prandbits: 64, prandints: 4`. `honeybadger_node_opts`
> (`crates/stoffel-vm/src/net/mpc/helpers.rs`, byte-identical to dev) sets
> `l = 2 * 64 - 16 = 112` and caps it to the field only when `n_prandint > 0 && n_prandbit == 0`.
> `stoffelcrypto`'s PRandInt check does not consult `n_prandbit`: it refuses whenever
> `k + l + 2 + ceil(log2 n) >= min(F::MODULUS_BIT_SIZE, G::MODULUS_BIT_SIZE)`, here
> `8 + 112 + 2 + 3 = 125 >= 64`. The workaround's guard is narrower than the bug it works
> around, so every program that asks for both kinds of material is refused — three of the 191:
> `matrix/secret/average_fix64`, `matrix/secret/scaled_mean_fix64`, `mpc_fixed_div_stress`.
> Neither the reservoir burst capacity nor standing mode is involved: the arithmetic is the same
> for any multiplier and on the one-shot path.
>
> **Not worked around here, deliberately.** Widening the guard to `n_prandint > 0` would run
> those three with `l = 50`, and `l >= 2 * total_bits - fractional_bits` is precisely the width
> secure fixed-point division needs — these three *are* the fixed-point-division examples, one
> of them named `mpc_fixed_div_stress`. The campaign would not catch the damage either:
> `wait_catalog_client` asserts the *number* of outputs a client received, not their values.
> Narrowing fixed-point division to buy a green run is not a trade this stage may make. The fix
> belongs in `stoffelcrypto`'s PRandInt validation, which the `FIXME(mpc-protocols)` in
> `helpers.rs` already anticipates, and until it lands this campaign cannot run its whole
> catalog on any branch.
>
> *Still the state of the suite at stage S6 (2026-10-13), and the attribution now rests on
> diffs rather than on reasoning.* `docker/test-standing-all-examples.sh` fails — confirmed for
> this run by the operator, who reports all 191 examples compiling and then the parties dying in
> reservoir warm-up on `PRandError(SurpassedFieldCapacity)`. The refusal is raised inside the
> `stoffelcrypto` dependency's own PRandInt validation
> (`stoffelcrypto-0.1.1/src/honeybadger/fpmul/prandbitd.rs`, the `SurpassedFieldCapacity`
> return). Three facts place it outside this work: `git diff dev` is **empty** for both
> `crates/stoffel-vm/src/net/mpc/honeybadger/preprocessing.rs` and
> `crates/stoffel-vm/src/net/mpc/helpers.rs` — the file that computes `l` and the file that
> would cap it — and the only change this port makes to `crates/stoffel-vm/src/storage/preproc.rs`
> is **208 added lines, 0 removed, and the only added functions are two tests**
> (`a_preprocessing_item_is_never_served_to_two_executions` and
> `a_preprocessing_item_is_never_served_to_two_concurrent_claimants` — *both deleted on
> 2026-10-15 with the `reserve_at` primitive they drove; see §9.1 V-0. Named here only as the
> record of what this stage measured, not as current coverage*). The arithmetic is also
> independent of standing mode and of the reservoir burst capacity, as the paragraphs above
> establish. **Not to be fixed here and not to be weakened here**: the suite stays as it is, and
> the fix belongs in the dependency.
>
> **Measured instead: the 188 examples the defect does not block.** All 188 compiled, all five
> standing nodes warmed all 188 reservoirs (~20 ms each), and the campaign ran them on that one
> mesh. At the driver's default fan-out of 16, waves 1-3 — 48 examples, 16 concurrent executions
> each — passed. Wave 4 did not, and the failure is the second sighting of §12.B's open coordinator question, from a
> different direction: twelve of that wave's sixteen executions had their nodes' **per-execution**
> coordinator links closed mid-protocol (`execution dd91fd33… failed: JSON error: The background
> task closed Connection was closed: CloseReason { code: 1000 … }`, 51 node-instance failures),
> which is a *graceful* server-side close. The five nodes then retired what they could not
> finish, the coordinator removed the execution, and the client that was still submitting its
> masked inputs was answered `ExecutionNotFound` — on which `stoffel-run`'s client path calls
> `unwrap()` and panics rather than reporting (the coordinator-client round drivers
> `run_hb_coordinator_client_for_field` and `run_avss_offchain_coordinator_client_for_curve` in
> `stoffel-run.rs`, which `unwrap()` every `wait_for_round` / `send_masked_inputs` /
> `obtain_outputs` — `dev`'s code, unchanged by this port; *the line number this paragraph
> carried was moved by stage S2's deletions and is replaced with the symbols, stage S6*).
>
> What the evidence rules out: it is not the per-identity or pool admission limits, which log
> `Refusing connection from …` on refusal and logged nothing (the coordinator printed three
> startup lines and no warning all run). It is not a mismatch between the roster identity and
> the connection identity, which §12.B's V4 box suspected: `NodeRoster::node_identities` and
> `caller_identity` both derive it with `SpkiDer::client_identity`, and the coordinator's
> `capacity_class` is wired to the `mpc_nodes`-aware implementation (`off_chain.rs:4306`,
> `:4335` forward to `CoordinatorRPCServerSharedBase::capacity_class`), which answers `Node` —
> the one class `close_when_idle` never touches. So a Node-class connection is being closed
> gracefully by something that is neither the idle sweeper's documented behaviour nor the
> admission path, and that is where the next investigation starts. It is pre-existing: the
> per-execution coordinator client and the connection layer are both dev's, and this campaign
> had never run.
>
> **At a fan-out of 4 the campaign got further and then wedged on an AES example.** 47 waves of
> four: 56 executions prepared and **54 completed on all five parties**, and then wave 14 stopped
> moving. The two executions that never reached a terminal event are `mpc_aes128_circuit` and
> `mpc_aes128_cbc`; every client of that wave had already exited, party0's last line was
> `proposing ProgramFinished` preceded by a run of
> `stoffelcrypto::honeybadger::mul::multiplication: ignoring stale RBC output for
> cleared/finished …`, and nothing moved afterwards. `mpc_aes128_circuit` hanging in the
> HoneyBadger message layer is a known standing issue of this repository, independent of this
> change and of standing mode; its CBC sibling shares the wave and the mesh with it. Nothing in
> the wedge involves an execution identity, a roster, or the coordinator: the 54 examples that
> ran before it all completed, on the same five processes.
>
> So the campaign cannot complete here for two independent pre-existing reasons — the
> fixed-point PRandInt refusal at warm-up and this deadlock — and the honest summary of what it
> did measure is: **the catalog compiles whole (191/191), its reservoirs warm, and 54 examples
> of it execute and complete across waves of concurrent executions on one standing five-party
> mesh driven entirely by the coordinator.** No stage before this one got a single example
> through this campaign.
>
> Not wired into CI, and this is not a scheduling choice: at the time of this campaign
> `.github/workflows/ci.yml`'s `docker-build` job pinned its coordinator build context to
> `stoffel-mpc-coordinator.git#dffffd6e` at version 0.2.0, which contains no `ExecutionNotice`,
> no `get_node_roster`, no `CoordinatorIncarnation` and no `operator_certs` (measured: 0
> occurrences of each). The VM on this branch requires `=0.3.0` and all four, so that job
> could not build this branch at all, let alone run a campaign on it. Both halves of this change
> have to be published together before either can be wired up.
>
> *Updated 2026-10-13 (stage S6): stage S5 repointed both Docker steps and the Rust jobs at the
> coordinator's `feature/no-bootnode` branch instead of that `0.2.0` commit, so the commit named
> above is no longer what blocks CI. The conclusion is unchanged and the cause is now one thing:
> the coordinator commits this repository is written against are not pushed. §9.F.5 states it
> with the measurement.*

> **Stage V5 repair pass (2026-10-13).** Two defects of the campaign stage above, both found by
> review of what it left behind.
>
> | Defect | State |
> |---|---|
> | the retargeted two-offline-parties phase **deleted** peer shaping instead of restoring it | **fixed** in `docker/standing-concurrency/acceptance.py`. `restore_peer_links` ran `tc qdisc del dev $interface root`, which is the right way to drop the severing qdisc and the wrong way to end the phase: `docker/configure-peer-netem.sh` installs a root qdisc of exactly that shape at node start whenever `NET_RTT_MS`, `NET_EXTRA_RTT_MS`, `NET_LOSS` or `NET_BANDWIDTH` is set, and `docker/standing-concurrency/README.md` documents `NET_RTT_MS=100 PARTY3_EXTRA_RTT_MS=250` for this very stack — naming one of the two parties the phase severs. Run that way, the phase left party3 and party4 unshaped and the mesh-recovery execution immediately after it ran on a faster network than the campaign configured, silently weakening its own assertion. `restore_peer_links` now drops the severing qdisc and then re-runs `/app/configure-peer-netem.sh`, which reads the same `NET_*` environment the node started with (`docker compose exec` carries the service environment), so the party resumes under exactly the configured shape — and under none when none was configured, because the shaper exits without touching `tc` in that case. `sever_peer_links` drops the root qdisc first for the same reason, so the severed shape does not depend on what it replaced — `tc qdisc replace` on a live handle keeps the filters attached to it, and severing a shaped interface had been stacking a second set of peer filters on top of the shaper's. Measured in `stoffel-standing-node:local` at `NET_RTT_MS=100 PARTY3_EXTRA_RTT_MS=250`: start `netem delay 300ms` with five peer filters, sever `netem loss 100%` with five, restore `netem delay 300ms` with five, stable across repeated cycles; the old restore left `noqueue` and none. The in-code comment claiming "this stack does not [ask for peer shaping], so there is no qdisc to preserve" was true only at default environment and is gone |
> | §12.F still described the `main`-based attempt's names | **fixed**: §12.F now carries an as-built correction box in §11.5's style. Seven of its statements were false of this tree — `--standing` for `--standing-node`, a `STOFFEL_STANDING` entrypoint mapping that does not exist, `instances.rs`/`InstanceSupervisor::start`/`stop` for `net/node_supervisor.rs`'s `NodeSupervisor::prepare`/`cancel`, `executions.rs` for `execution_stream.rs`'s `CoordinatorExecutionStream`, `Started`/`Ended` for `Prepare`/`Cancel`/`SnapshotComplete`, `local_runner.rs` passing `--execution-id` per party where party mode forbids the flag, and a one-shot rule that declines every notice after the first where `take_published_execution` declines only a notice naming a different program. §11.5 already had its box and §12.G its correction, which made the omission read as deliberate |

> **Stage V5 repair pass 2 (2026-10-13).** Two defects of the pass above, both found by review of
> what *it* left behind.
>
> | Defect | State |
> |---|---|
> | §12.F's new correction box closed its seventh point with a statement that is false of this tree | **fixed** in §12.F. The box said a declined execution "never reaches `cleanup_execution_resources`, which is the only caller of `retire_execution` (`stoffel-run.rs:7044`)". `:7044` is `node_rpc.retire_execution` — the node's own local retire, not the coordinator method the point reasons about, which sits at `:7058` in that same function — and that function is not the only caller: the coordinator's `retire_execution()` is also called at `:6260` (`run_avss_coordinated_party_for_curve`) and `:10020` (`main`'s HoneyBadger party path), both under `if one_off`, which is exactly the one-shot path the point is about. The conclusion survives, because both one-off sites sit after a completed online phase, but the reason did not, and a §12.F statement that is not true of `feature/no-bootnode-v2` is the precise defect the pass existed to remove. Point 7 now names all three callers and labels `:7044` for what it is |
> | `ExecutionNotice::Cancel`'s `outcome` was discarded | **fixed** in `CoordinatorExecutionStream::apply` and `NodeSupervisor::finish_terminal` — the root cause of the leniency the V4 table's first row introduced. See the correction box under that table for the mechanism, the new `NoticeOutcome::Retired` arm and the two tests |

> **Stage S1 (2026-10-13): the client half of §9 rule 3.** The rows above are V5's; this is
> S1's. It closes the one open item every earlier stage carried forward — §6 blocker B1,
> reported three times as findings 7, 10 and 15.
>
> | Defect | State |
> |---|---|
> | `run_standing_node` extended the roster-pinned mesh transport's certificate allowlist with every `--client-cert-dir` key once the mesh had formed, so a client certificate held node-level network standing on the mesh listener — admitted whichever ALPN it dialed with, and ranked among the parties, as `an_allowlisted_non_node_key_is_ranked_as_a_server_peer` pins | **fixed.** The loop is deleted. A standing node now binds two transports through `net/roster.rs::NodeListeners`, the only place either allowlist is decided: the mesh gets the coordinator's roster from `Roster::install_into` before it binds, and `--client-bind` gets a listener with no allowlist at all, read back from the transport afterwards. The coordinator's per-execution admission is therefore the whole of client authorization. One mux behind both, with the new `ExecutionScannerScope` telling each scanner what it may read. Four new `net/roster.rs` tests, two of them verified to fail against the defect; deployment fan-out in `docker-compose.standing-concurrency.yml` and `docker/standing-concurrency/acceptance.py`. The rule-3 box in §9 carries the detail |
> | `roster.rs`'s module documentation described B1 as open in the present tense | **fixed**: it now describes the split, and points at the tests that pin both halves |

> **Repair of stage S1 (2026-10-13).** Three findings reported at the end of S1.
>
> | Defect | State |
> |---|---|
> | `a_client_route_is_authorized_by_the_per_execution_roster_alone` failed once in three runs of the CI command with the HELLO never reaching the client inbox inside the 10 s budget | **root cause fixed, flake not reproduced.** The reporter's first candidate — `reserve_local_addr`'s port TOCTOU — is ruled out with evidence: quinn binds with plain `std::net::UdpSocket::bind` and sets neither `SO_REUSEADDR` nor `SO_REUSEPORT`, and a duplicate UDP bind is refused with `EADDRINUSE` on this platform, so a collision is loud (`ListenFailed`), never a silent timeout. The second candidate is confirmed as a defect and fixed: `run_connection_scanner` skipped a client connection whose `authenticated_peer_public_key()` was `None`, and that key is a field set once at accept which never becomes readable, while a listener with no allowlist *admits* such a connection — so the skip was permanent, the connection had no reader and no hello deadline, and the symptom is exactly the one reported. Both the scanner and the new accept-time gate now close it. No budget was raised and no assertion weakened. 121 further samples (60 `net::`-only, 60 full lib, 1 full `--all-features` with the CI skips, all at 10-way process concurrency) produced no failure, so the flake itself is unreproduced — see the occupancy box in §9 |
> | §9's rule-3 box claimed `assert_unauthorized_client` had become a stronger assertion; it had not, and no campaign probe reached `UnauthorizedClientCertificate` at all | **fixed.** The box now states the truth and names the two different boundaries. The node logs the refusal (it was swallowed by `Err(_) => continue`), and `assert_unadmitted_client_route_refused` dials every party's `--client-bind` socket directly through the new `client_listener_probe` example, asserts every party reports the refusal, and asserts no party container or process changed |
> | the client-facing listener accepted, retained and serviced unboundedly many unauthenticated connections | **fixed** by `net/client_ingress.rs::ClientIngressGate` — a certificate no registered execution names is refused outright (third repair), plus a total cap, a per-certificate cap and refusal of a certificate with no readable identity, and bounded log volume in the accept loop. Pinned by eight unit tests, three loopback tests, `assert_unadmitted_client_certificate_refused` and `assert_client_connection_flood_refused`. One residual is recorded rather than claimed closed: stoffelnet's own client public-key map is never pruned, and the insert happens inside `accept()` where no policy of ours can reach it |

> **Repair of the S1 repair (2026-10-13).** Two findings reported at the end of the repair
> stage, both against `client_ingress.rs` and both reproduced before being acted on.
>
> | Defect | State |
> |---|---|
> | the caps bound connection slots, but stoffelnet's `client_public_keys` map grows by one SPKI per unauthenticated handshake and nothing prunes it, while this document and `client_ingress.rs` claimed the total cap was "the bound that holds against a determined peer" | **reproduced, and the claim withdrawn rather than papered over.** Reproduced directly: two client connections closed, `cleanup_dead_connections` driven until the transport reported no live client connections, and both public keys still readable through `client_public_key_bytes_by_transport_id`. The insert is inside stoffelnet's `accept()`, strictly before `ClientIngressGate::admit`, and stoffelnet 0.1.1 exposes no way to prune the map, so there is no local fix: the occupancy box above now says what the caps do and do not bound, names the upstream change that would close it, and `roster.rs::the_transports_client_key_table_outlives_its_connections` keeps the record honest by failing when upstream starts pruning |
> | the caps left the lockout they name as their own rationale wide open: certificates are free, so a peer could occupy the whole listener and make the total cap a refusal for every coordinator-admitted client | **fixed**, in two steps. The second repair reserved the slots above a watermark for the certificates a registered execution names, read from the mux the executions already register with through the new `AdmittedClientDirectory` trait — which still left three quarters of the listener to a peer the coordinator never admitted. The third repair took the reservation out and made the admission the rule: a certificate no registered execution names holds no connection at all, so the caps bound the deployment's own clients and nothing an attacker can manufacture. The cost — a client that dials before its execution is registered has to dial again — is paid by `CLIENT_ROUTE_ESTABLISH_BUDGET` in `establish_coordinator_output_client_routes`, and the admission is re-read per accept so the retry is admitted the moment the registration lands. Pinned by the tests listed in §9 above, each verified to fail against the defect it describes |

> **Stage S2 (2026-10-13): there is no coordinator-less client.** The rows above are S1's;
> this is S2's. It closes finding 18, the other item every earlier stage carried forward, and
> supersedes the V5 gap line "direct client mode is still reachable, and with it the fail-open
> client allowlist §E.3 identified".
>
> | Defect | State |
> |---|---|
> | `stoffel-run --client` without `--off-chain-coord` fell through to `run_as_client`, which installed only its own certificate and no peer allowlist — so the leg carrying a client's secret input shares accepted whatever certificate answered the address (§6 blocker B3: stoffelnet's empty allowlist returns `Ok`), and nothing could pin node certificates on that path since `--roster` and `Roster::install_for_client` no longer existed | **fixed by deletion, per §13.** Direct client mode is gone, not guarded: no by-name refusal, no hint, no alias. Client mode requires `--off-chain-coord`, `--coord-cert`, `--cert` and `--key`, and `run_hb_coordinator_client` takes a `CoordinatorEndpoint` instead of an `Option`, so there is no arm left to fall through to. The §E.3 S2 box lists every deleted symbol and every dependent, with the two that needed migrating (`docker/entrypoint.sh` and the SDK's client builder) and the four that did not |
> | the surviving coordinator-mediated client leg had no node pin either: `establish_coordinator_output_client_routes` set the client's own certificate and dialled every `--client-transport-servers` address unpinned | **fixed.** `Roster::install_for_client` (new) makes the coordinator's served roster the client transport's peer allowlist before its first dial, with `install_into`'s B3 read-back shared as `observe_allowlist_enabled`. The roster comes from `client_transport_roster(coord.node_roster())` through `roster_from_served`, the same certificate-to-`Roster` conversion `fetch_node_roster` uses, so a client cannot pin a key the coordinator did not serve. Two loopback tests in `net/roster.rs`, and the module documentation now describes both directions of §9 rule 1 |
> | the SDK's `ClientBuilder::connect` dialled node listeners from a bare `QuicNetworkManager::new()` — no local certificate, no allowlist, no coordinator | **fixed.** It opens the pinned `CoordinatorLink` and keeps the roster it served; `StoffelClient::connect(&[&str])`, `network_manager()` and `transport_client_id()` are deleted. `client_connect_dials_its_coordinator_and_no_node` hands the client a live node listener as both a `--servers` and a node RPC address and asserts it is never dialled |
>
> Not closed, and not this finding: the §9 occupancy box's other residual, the SDK client's
> dial target reaching parties through `--servers` rather than a `--client-bind` constant, is
> addressing, not authorization — every one of those dials is now pinned.

> **Stage S3 (2026-10-13): a snapshot omission is not always an order to stop.** The rows above
> are S2's; this is S3's. It closes finding 20, the last of the defect class stage V5's second
> repair pass closed on the `Cancel` path only.
>
> | Defect | State |
> |---|---|
> | `reconcile_snapshot` cancelled every live instance of the current incarnation the snapshot omitted, including one whose execution that same coordinator had already published as *finished* — so a routine reconnection (the connection under a subscription ends by design) tore down a healthy straggler and, with `finish_terminal`'s leniency removed in the same change that introduced the `Cancel`-path fix, reported it as `Cancelled`. Reachable through all three coordinator removal paths that can outrun a party: unanimous retirement, retention expiry, and capacity eviction at the `n - t` quorum | **fixed** in `crates/stoffel-vm-runner/src/execution_stream.rs`. The map stage V5 added is now `instances: Mutex<HashMap<ExecutionId, InstanceRecord>>`, carrying `InstanceStanding::{Served, Retired}` beside the incarnation; `retire` marks a still-running instance retired, and `reconcile_snapshot` stops only an omitted instance of this incarnation that nothing explains, reporting the rest as `kept` or the new `retired` of `NoticeOutcome::SnapshotReconciled { stopped, kept, retired }`. Two new tests, one per direction, both verified to fail against the defect; no existing assertion weakened. §12.B carries the analysis and says what in its own wording was wrong |
> | §12.B's two halves — "omission is an order to stop" and "an execution this node has not retired is still its work" — read as though the coordinator's per-node snapshot predicate made the node-side rule safe | **corrected in §12.B.** The predicate filters the executions the coordinator still holds, so a removed execution is omitted from every snapshot whatever a node acknowledged. The box states the rule the code now implements — a node stops an omitted instance only when nothing it already knows explains the omission — and withdraws the implication, not the predicate, which is unchanged and still pinned on the coordinator side |
> | finding 1 of the same bundle, re-checked against this file | **already resolved**, by stages V3 and V5 before it was reported: `reconcile_snapshot` and `record_incarnation` implement the scoped snapshot, and `resolve_published_execution` resolves every published client against the startup-frozen catalog, refusing the whole admission otherwise. Nothing changed for it |
> | **S3 repair, same finding:** the fix above covered only the coordinator's *own* removal paths. The node's own retirement acknowledgement is a third benign reason a snapshot omits an execution, and the only one with no notice behind it: `retire_execution` counts the acknowledgement at once while publishing `Cancel { Finished }` only at unanimity, and the node sends its acknowledgement from `PreparedNodeExecution::cleanup`, which `NodeSupervisor` runs before `finish_execution` — so a resubscription in that window classified a live instance `Served` and cancelled it, which is the very symptom `an_abort_after_the_online_phase_finished_reports_cancelled` records | **fixed** at the root cause. The map moved into a shared `InstanceLedger` (`Arc`) held by both `CoordinatorExecutionStream` and `StandingRunnerExecutionHandler`, so the two ways a retirement reaches this node — the published notice and this node's own acknowledgement — record the same `InstanceStanding::Retired`; `cleanup_execution_resources` called `InstanceLedger::retire` *before* sending the acknowledgement, so the omission is explained before it can exist (the row below replaced that bare call with the ledger method that owns the ordering). One new test, `an_instance_this_node_has_acknowledged_survives_the_snapshot_that_omission_causes`, with a dropped-abort instance beside it that still stops — though as first written it reached its ledger state by calling `retire` directly and so could not detect the removal of the one production line it was taken to pin; the row below is where that was made good. §12.B's "two things" enumeration is corrected to three and its residual stated |
> | **S3 repair, attempt 2, same finding:** the repair above left its own behavioural delta untested. The ledger write in `cleanup_execution_resources` was a bare statement next to the acknowledgement, in a *binary* target, and the test beside it recorded the retirement by calling `InstanceLedger::retire` itself — the same state the notice-path test `a_snapshot_omitting_an_execution_no_retirement_explains_still_stops_it` already reached. Reproduced by mutation: with that one line commented out, `cargo test -p stoffel-vm-runner` passed every target (45/57/7, 0 failed) and the new test was reported `ok`, so the original symptom — a successful standing run reporting `Cancelled` — was one deletable line away and the claims that the test had been falsified against it, here and in §12.B, were untrue | **fixed** by moving the ordering itself into the library, where it can be tested and cannot be bypassed. `InstanceLedger::retire` is now private and the execution path reaches it only through `InstanceLedger::acknowledge_retirement(execution_id, acknowledge)`, which writes the record and then awaits the acknowledgement it is given as a closure; `cleanup_execution_resources` sends its node-RPC and coordinator-RPC retirement from inside that closure. The test now drives `acknowledge_retirement` with the resubscription as the acknowledgement and fails both with the ledger write removed and with it ordered after the acknowledgement, so it is no longer a duplicate of the notice-path test; deleting the production call is a compile error, and writing the record beside it instead of through it does not compile either. The false verification claims in §12.B and in the row above are corrected to state exactly which mutation each test was falsified against. No test weakened |

> **Stage S4 (2026-10-13): the restart arm observes the restarted process.** The rows above are
> S3's; this is S4's. It closes finding 14 and settles finding 11. *Recorded here in stage S6 —
> S4 wrote its corrections into §9.H, §12.B's test row and the campaign README but left no box
> in this log, which is the one place a reader looks for per-stage status.*
>
> | Defect | State |
> |---|---|
> | the "retained preprocessing volumes and durable admission index" arm of `docker/standing-concurrency/acceptance.py` was **vacuous**: it scraped `NODE_ADMITTED` lines out of `harness.logs(party)` and asserted each matrix identity appeared, but `logs()` is `docker compose logs` with no `--since`, `kill_nodes()` is `compose kill` and `start_nodes()` is `compose up -d` on the same containers, so the whole pre-kill history is still there and the matrix phase had already waited for exactly those lines. The loop could not fail, while its comment claimed it checked that the index survived the restart | **fixed with a real post-restart probe**, not a reworded comment. One number was made observable: a standing node's readiness line now carries `admitted_identities=<n>`, read from `RetiredExecutionIndex::len()` immediately after the index is opened and before the coordinator stream is read, so it is purely retained history. `assert_admission_index_survived_restart` takes a per-party baseline of startup lines **before** the kill, then requires a startup line past that baseline, a count at least as large as the set of identities the campaign itself watched all five parties admit, and a count strictly greater than the pre-kill line's. It refuses outright if nothing was recorded before the kill, so it cannot pass against a node that reopened nothing; a lost index reports 0 and fails both halves, and a hard-coded constant fails the second. Pinned beneath by `storage::retired_executions::tests::a_reopened_index_reports_every_identity_it_retained`. Observed live across the campaign's three startups of party0: `admitted_identities=0`, then `=8`, then `=19`. The dead `NODE_ADMITTED` regex went with the loop (§13) |
> | finding 11, "20 refused claims in a run" | **reproduced as imprecision, and the document fixed rather than the test.** *The test named below, and the `CursorMismatch` arm it exercised, were deleted on 2026-10-15 with the `reserve_at` primitive; this row is the dated record of a past measurement, not current coverage (§9.1 V-0).* The `CursorMismatch` arm of `a_preprocessing_item_is_never_served_to_two_concurrent_claimants` was instrumented with a local `AtomicUsize` and run six times: 18, 22, 19, 18, 20, 18, all passing; an independent five-run pass on the same host gave 28, 20, 19, 24, 28. The contention is real and the test is right — 28 is the structural maximum, `C(8,2)` — and the only defect was asserting one scheduler-dependent number as if it were deterministic. §10 then stated the measured range and how it was measured. `crates/stoffel-vm/src/storage/preproc.rs` was restored byte-exact after the measurement and is not a file this stage changed. *Superseded 2026-10-15: that test and the `reserve_at` primitive it instrumented are deleted, and §10 point 1 no longer carries the range — the row stands as a record of the measurement, not as a claim about the tree* |

> **Stage S5 (2026-10-13): the branch builds off this machine.** The rows above are S4's; this
> is S5's. It closes findings 0 and 2, and records finding 19 as stale.
>
> | Defect | State |
> |---|---|
> | both `[patch.crates-io]` tables named an absolute path under one developer's home directory, so every host-side `cargo` invocation of either workspace failed on any other machine | **fixed** in `Cargo.toml` and `docker/coordinator-wrapper/Cargo.toml`: the entries are relative to the manifest that carries them and name the coordinator worktree as a sibling checkout. Measured on a relocated copy of the wrapper under a different parent: the absolute form is a hard error (`failed to load source for dependency`, exit 101 — not a silent patch drop), the relative form resolves and the patch binds to the relocated sibling at `0.3.0`. No absolute host path is left anywhere in the tree outside this document. Both lockfiles are unchanged by the edit, `cargo tree -p stoffel-mpc-coordinator-off-chain` resolves through the patch from both workspaces, and the wrapper — `dev`'s one pre-existing build failure — builds |
> | `.github/workflows/ci.yml` disagreed with the manifests: the Rust jobs had no coordinator at all, and the two Docker steps passed `coordinator=` at commit `dffffd6e`, whose `[workspace.package]` version is `0.2.0` and cannot satisfy the tree's `=0.3.0` | **fixed.** The Rust jobs clone the coordinator's `feature/no-bootnode` branch into the sibling path the tables name, and both Docker steps name that branch instead of the `0.2.0` commit. CI's remaining redness has one cause, stated in §9.F.5 and measured: the coordinator commits this repository is written against are not pushed — against `origin/feature/no-bootnode` (`012f5e3`) `cargo check -p stoffel-vm-runner` fails with two `E0432`s for `ExecutionNotice`, `PublishedExecution`, `CoordinatorIncarnation`, `Subscription` and `ExecutionRequest`. The jobs need no further edit once those commits land. A CI step that builds the wrapper is added, because it is its own `[workspace]` and `--workspace` never reached it |
> | §9.F.5 described a **git** patch table and drew five conclusions from it that are false of a path table — among them the stated reason the Rust CI jobs are red (git-pin merge ordering), "Docker resolves the pin over the network", "a git patch never reads that path, so the copy feeds nothing", a `COPY` target under `/Users/gabriel`, and a `docker-build` step "with no `build-contexts`" | **corrected in place** in §9.F.5, with a correction box naming what was rewritten. The as-built shape is now stated: the tables name a path; no image reads either of them, because every Dockerfile that runs `cargo` injects its own table into `.cargo/config.toml` at the path `COPY --from=coordinator` lands (`/opt/stoffel-coordinator`, `/build/coordinator` for the coordinator image), which makes the named context the dependency source and the compose `:?` load-bearing. The pre-commit claim is corrected too, by measurement: the hook refuses the git shape, and `--manifest-scan-only` passes on the path shape because both entries carry a `version =`, so the table needs no `--no-verify`. §9.I's patch-window paragraph and V-b row and §12.H's path block are brought into line |
> | finding 19, the `=0.2.0` half of the same bundle | **stale, nothing changed.** All four requirements already read `=0.3.0` (`crates/stoffel-rust-sdk/Cargo.toml`, `crates/stoffel-vm-runner/Cargo.toml`, `docker/coordinator-wrapper/Cargo.toml`) against a coordinator worktree whose `[workspace.package]` version is `0.3.0`, so cargo does not drop the patch: it resolves to the path and emits no "was not used in the crate graph" warning |
>
> Not done, with the reason: **the coordinator was not vendored in-tree**, which was the first
> option considered. `dev`'s `vendor/stoffel-mpc-coordinator-browser` was a trimmed `0.2.0`
> snapshot that existed only for the browser transport (`browser_rpc.rs`,
> `start_coord_with_browser`, `STOFFEL_BROWSER_NODE_RPC_BIND`), and stage V1 deleted it together
> with its only consumer. Re-creating one at `0.3.0` would copy uncommitted work of a repository
> this port is still editing into this one, and the host build would then stop exercising the
> checkout the Docker stacks build from. **A git pin was not restored either**: it is measurably
> unavailable until the coordinator is pushed, and pushing is not this stage's to do (§12.H
> already calls it a human step).

> **Stage S6 (2026-10-13): the document made true of the tree as it finally stands.** The rows
> above are S5's; this is S6's. As originally run it changed no code; its two repair passes then
> changed two Dockerfiles, recorded in the box below this one, which is the box that holds for
> the Docker build shape. This box covers the documentation pass —
> and it closes the documentation findings 3, 4, 8 and 12 plus the three further instances of
> their classes that triage found, while confirming 5, 6, 13 and 16 as stale.
>
> | Finding | State |
> |---|---|
> | **[3]** §12.B specified node-side resolution for `PreRegistered` only, while the coordinator publishes `AdmissionPolicy::Open` as an asserted part of its contract (`an_abort_cancels_the_execution_on_every_node_running_it`) and `local_runner` registers every local run that way — and a standing node refuses `Open` outright, pinned by `an_open_admission_policy_is_refused_by_a_standing_node`. The contract covered neither the refusal nor the asymmetry | **documented in §12.B**, as a contract boundary rather than a defect: the refusal is the right fail-closed behaviour and follows from the local-resolution rule, because under `Open` there is no published identity for the node's startup-frozen `--client-cert-dir` catalog to resolve a certificate-exact `CertificateIdentity` from. The one-shot/standing asymmetry is stated with its reason — `take_published_execution` inspects program and entry and not the policy — and so is what it costs an operator who submits `Open` to a standing deployment. No code changed |
> | **[4]** citations pointing at unrelated code | **two fixed, and §12's line-numbered citations converted to symbols.** `crates/off-chain/src/lib.rs:2087-2099` was cited in §12.B as the subscription gate and is `RetiredExecutions::acknowledge`; `:2342-2365` was cited twice (§12.B, §12.F) as the retirement quorum and is the subscription's `ReplayStep` handling. Both now name symbols (`sub_executions`' and `event_stream_subscription`'s `not_party` gates; `retire_execution` / `retirement_quorum` / `retirement_quorum_reached`). §12.F's V5 box, §12.A, §12.H and §9.G's trust table carried `stoffel-run.rs` and `join.rs` line numbers that stages S1-S2 moved by ~1,800 lines; all are symbols now, per this document's own citation rule. Audited for this: every `path:line` citation inside §12, and every file path named anywhere in §9 — the remainder resolve, or sit inside a body their own box marks void or history, or name a file the document already states does not exist |
> | **[8]** by-name-refusal prescriptions, which §13 forbids | **three live instances fixed**, the cited one having already been corrected by §E.3's V5 box: §9.1's V-0 bullet ("`--preproc-store` fails by name", "the entrypoint refuses `STOFFEL_PREPROC_STORE`"), §9.1's V-b bullet ("the §E.3 refusal of direct client mode") and §9.F.2's "the entrypoint refuses it". §7's rows V22 and V24 are voided in a box under that table. Code side re-checked and clean: nothing in `docker/entrypoint.sh`, `stoffel-run.rs` or the SDK names a removed flag or a removed mode |
> | **[12]** `--timestamp` documented as "removed everywhere, leaving nothing behind" | **corrected to the truth, and the truth is that removal is open work.** Only `stoffel-run`'s parser arm is gone. The flag is still emitted by `docker/entrypoint.sh` in both roles, by the SDK's coordinator launcher and by `local_runner`; it is a **required** non-zero field on both `OffChainServerConfig` and `OffChainClientConfig`; and `cli_option_takes_value` still lists it, which is what keeps the emitted value from being read as a positional argument and is why that entry cannot go first. §7's V29 row, §9.D.3's row and §9.D.3's correction box — which had called V29 "the one row that is true" — all say so now, and name what a §13 deletion would have to cover |
> | **[8]-class sweep, §9.D.1** | **boxed.** "Startup order … in this order and no other" was the v1 attempt's, with five of its ten steps false of this tree: an `EpochStore` with zero occurrences anywhere under `crates/` or `docker/`, a three-argument `MeshJoin::new` that takes two, an allowlist install attributed to `MeshJoin::new` rather than to `Roster::install_into` / `NodeListeners::bind`, a `JoinRequest.execution_id` that does not exist in a mode that forbids `--execution-id`, and a roster fetch claimed to be standing-mode-only that the one-shot party reaches too. §9.H's row repeating that last claim is corrected with it |
> | **[8]-class sweep, §9.F.2** | **corrected, then corrected again 2026-10-14 (stage V-0's fix).** Its stated justification — "no stack sets `STOFFEL_PREPROC_STORE` any more and the entrypoint refuses it" — was false in both halves, and the entrypoint half stands: `docker/entrypoint.sh` forwards the variable as `--preproc-store` and refuses nothing. The replacement's own first half was wrong, though, and is fixed here and in §9.F.1's point 5: **no** compose file sets `STOFFEL_PREPROC_STORE`; the preproc override passes `--preproc-store` once inside the `--standing-node` command anchor its five parties share. The claim that "no half of V-0 has landed" is also void — V-0 is done (§9.1 V-0, §9.I), by making the write a division rather than by the deletion the old text prescribed |
> | **[8]-class sweep, §14's index** | **rebuilt.** The list of sections carrying a correction named eight and was stale by a dozen; it is a table now. *Corrected by the second repair pass below:* "checked section by section" overstated it — the rebuild still omitted §9.1 and §9.E.2, and labelled §9's Revision 2 table as §7 |
> | **[5], [6], [13], [16]** | **stale, confirmed, nothing re-fixed.** [5]: "PR #22" occurs nowhere and §12's preamble names this branch and both worktrees, warning off the v1 tree. [6]: §9.I's first table is explicitly scoped to the abandoned attempt, and this section now carries a reading instruction saying its boxes are chronological and later ones win — the residual the finding was really about. [13]: `grep -rn MeshInfo crates/` is empty, `net/mesh/join.rs` exists and every mention is past tense; the one cosmetic residue, §12.0's row still calling `net/session.rs` the roster-only mesh, is split and corrected. [16]: §12.F carries its seven-point V5 box, and its `SnapshotReconciled` field list is brought up to stage S3's third set |
>
> Also recorded here rather than left to a reader to reconstruct: **the trust posture as it
> finally stands after stages S1 and S2** (§9.G's and §12.I's boxes — two listeners with one
> writer per allowlist, no client key in the mesh allowlist, no coordinator-less client, every
> client leg pinned to a coordinator-served roster, and the two things those stages did *not*
> close), and **why `docker/test-standing-all-examples.sh` still fails** (the V5 campaign block
> above, now with the diffs that place it in the `stoffelcrypto` dependency: zero diff from
> `dev` in `net/mpc/honeybadger/preprocessing.rs` and `net/mpc/helpers.rs`, and 208 added lines
> in `storage/preproc.rs` whose only added functions are two tests). That suite is neither
> fixed nor weakened here.

> **Repair of stage S6 (2026-10-13): the Docker builds this branch had silently broken.** The
> box above is S6's documentation pass and says it changed no code; these two passes did, and
> this box is the record of record for them. Both are instances of one defect, not two: stage V1
> deleted the in-tree `vendor/stoffel-mpc-coordinator-browser` and repointed the root
> `[patch.crates-io]` at a sibling checkout no image contains, which breaks workspace resolution
> inside **any** image whose injected `.cargo/config.toml` table does not cover the two
> coordinator entries — regardless of what that image builds. §9.F.5 now states that as a rule
> and enumerates all four files that run `cargo`, instead of listing three of them.
>
> | Defect | State |
> |---|---|
> | `Dockerfile.benchmark` wrote `[patch."https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git"]` at both of its `.cargo/config.toml` writes, in the `planner` and `builder` stages. The override is keyed on the patched **source**, so a git-keyed table overrides nothing for entries no manifest resolves through git any more: the manifest's relative sibling path survived into the image and the build died on it. Inherited unchanged from `dev`, where it was harmless because `dev`'s root table named the in-tree vendor directory that `COPY . .` carried in | **fixed**: both headers read `[patch.crates-io]`, matching `Dockerfile`. The entries beneath already named `/opt/stoffel-coordinator/crates/{off-chain,coord-shared}`, where the `coordinator` named context lands. Measured inside the image both ways, by building `--target planner` and resolving at `/build`: git-keyed, `cargo metadata` exits **101** (`patch location /stoffel-mpc-coordinator-roster-admission/crates/off-chain does not contain packages matching stoffel-mpc-coordinator-off-chain`, blamed on `/build/Cargo.toml`); fixed, exit **0** with both crates at `0.3.0` from `/opt`. `docker build -f Dockerfile.benchmark --build-context coordinator=<worktree> .` then runs to completion for the first time in this branch's history, and the runtime image carries `/app/stoffel-run`, `/app/stoffel-coord-ctl` and both `.stflb` programs. Also corrected: the §9.F.5 sentence that fix was meant to make true claimed a config override costs "only a 'was not used' warning", where measurement shows it is **silent** and the manifest path is never read |
> | The same defect's **fourth** instance, which the first pass missed because its sweep was keyed on the git URL: `docker/vm-ebpf-profile.Dockerfile` was already `[patch.crates-io]`-keyed and merely **incomplete**, injecting `stoffelnet` alone before running `cargo build --release -p stoffel-vm --bin vm_ebpf_profile` at `/build`. A crates-io-keyed-but-incomplete table is structurally invisible to a URL grep. The file is unchanged from `dev` and the binary it builds is real (`crates/stoffel-vm/src/bin/vm_ebpf_profile.rs`), so this is V1's regression and not dead weight predating the port | **fixed**, not deleted — although nothing in any compose file, script, CI job or document references the image, §13 governs the removal of the bootnode mechanism and does not reach a working profiling tool. The file now takes a `coordinator` named context beside the `networking` one it already demanded, injects both coordinator entries, copies both external workspaces to `/opt` rather than under `/build` (`Dockerfile`'s stated reason: Cargo would otherwise attach their workspace-inherited manifests to this workspace), and documents both contexts in its header. Measured by replicating its `COPY`/config prelude in an image and resolving at `/build`: **101** before, with the identical patch-location error, **0** after, both coordinator crates at `0.3.0` from `/opt`; then the real file built end to end with both contexts supplied. One pre-existing condition left alone and recorded in §9.F.5: the `stoffelnet` entry does not bind, the operator's sibling checkout being `0.1.0` against a `=0.1.1` requirement, so resolution falls through to the registry and cargo warns — equally true of the `/build/stoffelnet` form it replaced |
>
> Reported alongside these and **already resolved before this box was written**, recorded so the
> cause is not rediscovered: the tracked `.cargo/config.toml` was twice overwritten by the probe
> tooling of **this stage's own repair passes** — first with a scratch coordinator path, then with
> the `stoffelnet = { path = ... }` entry of the `0.1.0`-against-`=0.1.1` measurement recorded in
> the row above — each time destroying the committed
> `[target.'cfg(target_arch = "aarch64")']` rustflags and all nine `[alias]` entries and
> redirecting host `cargo` outside the repository. The **verification pass that followed each
> repair** is what found the damage and restored the file to its committed content, verified by
> hash on both sides of its own gauntlet. An earlier draft of this box had that backwards, naming
> the verification pass as the writer; the correction stands on the verification record's own
> timeline (its green gauntlet predates the second write by a minute) and on the content of that
> write, which is this stage's `stoffelnet` probe and nothing the verification pass had reason to
> run. The Docker evidence above is unaffected: in every image the `RUN`
> that writes `/build/.cargo/config.toml` follows `COPY . .` and overwrites whatever the
> repository carried. A probe that needs its own `[patch]` table belongs in a probe-local
> `CARGO_HOME` or behind `cargo --config`, never in that file.

> **Second repair of stage S6 (2026-10-13): four documentation defects, no code.** The two boxes
> above are S6's documentation pass and its code repair; this one is a documentation pass over
> both, and it changes no code, no test and no Dockerfile. Every claim was reproduced against this
> tree before it was touched.
>
> | Defect | State |
> |---|---|
> | §9.1's V-b "Done when" bullet claimed the wrapper is a workspace "neither `--workspace` nor CI sees", citing `.github/workflows/ci.yml:45`, `:49`. False of this tree in both halves: stage S5 added a dedicated **Build the coordinator wrapper** step, as S5's own box above records, and the cited lines now fall inside the `actions/cache` block | **fixed** at the bullet: `cargo build --workspace` does not reach the wrapper, which is why CI builds it in a step of its own, named rather than line-numbered per this document's citation rule |
> | §9.F.5's Docker bullet still ended "That is why the Docker stacks build on a host with no sibling coordinator checkout, and why the absolute path never broke them" — unqualified, and contradicted by the same bullet's next three paragraphs and by the two images it measures at exit **101** on exactly that manifest path | **fixed**, with the qualifier that already stood on the twin paragraph in this section: the override explains the images whose injected table **covers** both coordinator entries, and the absolute path broke precisely the two whose tables did not, for the whole V1-S4 window |
> | The box above attributed the two `.cargo/config.toml` overwrites to "stage S7's verification" — naming the pass that found and restored the damage as the pass that caused it, against the verification record's own account and timeline, and under a stage name this document does not define (§9.I's log runs V1-S6, and `S7` is already a revision-1 security finding id in §9's Revision 1 table) | **fixed** in that box: the writes are attributed to this stage's own repair-pass probe tooling, the restoration to the verification pass that followed each repair, and the undefined stage name is gone |
> | §14's rebuilt index was incomplete and mis-cited, although its preamble and the S6 row above claimed it was checked section by section: it omitted §9.1 (two S6 corrections plus a stage S2 note) and §9.E.2 (a V1-repair as-built box), and labelled §9's "Revision 2 (2026-09-16)" table as §7, which is prose with no V-numbered rows | **fixed**: both rows added, the Revision 2 row re-labelled with where the void box actually sits, the preamble says the rebuild missed three, and the S6 row's "checked section by section" is qualified. Re-derived mechanically for this, by walking every heading with the correction blocks beneath it: no section carrying a correction is now missing from the table |
>
> Unchanged by this pass, and still true as the boxes above state them:
> `docker/test-standing-all-examples.sh` fails in the `stoffelcrypto` dependency's `PRand` path
> and is neither fixed nor weakened here; the Rust CI jobs stay red until the coordinator commits
> are pushed; V-0 and `--timestamp` removal remain open work.

## 10. Post-audit hardening (2026-09-20)

Four findings from the final audit were resolved against the user's stated requirements.

**1. Preprocessing material is never served to two executions.** The audit read this as an
open hole because stage V-0 (delete `persist_preproc` and the store outright) was never
implemented. Re-examined at the storage layer, the guarantee holds without deleting the feature,
and it rests on three mechanisms:

- **A draw removes.** A stored item reaches a running execution only through
  `PreprocStore::take_bundle_from_reservoir`, which slices the bundle out and then deletes or
  compacts the source **inside the same LMDB write transaction** that yields it, on a
  single-threaded actor. Two takes are therefore disjoint or one is refused, and a crash between
  them cannot re-offer what was handed out. This is the only draw path, on both the one-shot and
  the standing route.
- **A commit divides; it never copies.** Both engines commit through
  `commit_generated_material`, under the invariant that *an item is appended only if the engine
  that generated it keeps none of it*. The only write primitive is `append_items`, which
  accumulates inside one transaction, so what the store holds is by construction material no
  execution has been served.
- **A volume is admitted before it is read** (added 2026-10-15). The two mechanisms above are
  properties of *this* binary's writes; a directory on disk may predate them. Every
  `LmdbPreprocStore` constructor therefore checks a `PreprocVolumeHeader` inside the write
  transaction that opens the database, and refuses a volume that holds content without one —
  such content was written when a commit copied the pool instead of dividing it, so it may
  already have served an execution, and no migration can make it safe. The header also records
  the one standing pool and node that claimed the volume, so a volume cloned into a second pool,
  or shared between two parties, is refused rather than serving the same material twice.

  A header certifies how a volume was *created*, though, not what has been written into it
  since — a volume this binary claimed and a pre-division binary then wrote into was admitted,
  and the draw returned the foreign items. The marker cannot close that, because a pre-division
  binary ignores markers; the material key prefix therefore changed
  (`PREPROC_MATERIAL_NAMESPACE`), and a record under any `CondemnedNamespace` — the pre-division
  material prefix, or the retired reservation namespace — is refused on every open
  (`find_condemned_records`). A prefix such a binary does not know is one it cannot write, so its
  material is both unreadable here and fatal to the volume holding it. §9.1 item 3 states what
  that closes and the one residual it accepts, with the threat model and the reason no
  affordable mechanism closes it.

Disjointness, not refusal, is the property the privacy argument needs: a second execution handed
a *different* slice is fine, handed the *same* slice is a privacy break. It is pinned by
`reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources` and
`two_executions_never_receive_the_same_reservoir_item_content` in
`crates/stoffel-vm/src/storage/preproc.rs` (the second decodes the real correlated material and
compares the field elements, so the claim is about the secrets rather than about slice
arithmetic), at engine level by `a_standing_reservoir_never_hands_two_executions_the_same_item`,
for the concurrent case by `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`,
and end to end by `material_one_execution_used_is_never_handed_to_a_later_execution` and
`client_masks_one_execution_used_are_never_handed_to_a_later_execution` in both engines. Breaking
the pool clear fails the four `a_standing_top_up_*` tests by name, and breaking the division fails
nine across both engines including both end-to-end witnesses. *Corrected 2026-10-15: this sentence
also listed the delete-on-empty and the compaction write-back as failing "them", which is not the
coupling — removing physical removal while the cursor still advances fails four physical-state
tests and none of the identity witnesses. §9.1 V-0 carries both measurements.* The volume rules have their own witnesses:
`an_unmarked_preprocessing_volume_is_refused_rather_than_adopted`,
`an_unmarked_volume_holding_only_reservation_blobs_is_refused_too`,
`a_volume_header_this_binary_cannot_decode_is_refused`,
`a_standing_preprocessing_volume_is_refused_to_every_other_opener`,
`a_standing_pool_cannot_adopt_a_volume_another_opener_marked`,
`a_volume_contaminated_after_it_was_claimed_is_refused` and
`the_material_prefix_cannot_be_confused_with_the_pre_division_one`, each confirmed by deleting
the refusal it rests on. The blob API's share of the property has its own witness,
`the_blob_api_cannot_name_the_material_namespace`, confirmed by adding a `BlobNamespace` variant
that names the material namespace — which fails it on the prefix arithmetic, and, with that
assertion removed too, on the material item itself coming back overwritten.

The concurrent case is reachable because `PreprocKeyScope` is
`(program_hash, field_kind, n, t, node_identity)` and carries **no execution id**, so every
concurrent execution of one program on one node draws from exactly one `PreprocKey`. That is
HAZARD 2 of §11.5, and it is now covered rather than argued.

> **Rewritten 2026-10-15 — the mechanism this section named was never the mechanism.** Every
> version of this point until now credited the guarantee to a compare-and-swap on the consumed
> cursor (`LmdbPreprocStore::reserve_cursor`, reached through `PreprocStore::reserve_at`), and
> recorded as an "honest limitation" that disabling the CAS failed neither of the two tests
> cited here. Both claims have been superseded by measurement. `reserve_at` had **no reachable
> production caller** at all: its only two non-test callers sat in `!is_standing()` branches of
> `net/mpc/honeybadger/reservation.rs` that `init_reservations_for_run` never reached, and a
> one-shot run in fact takes its mask shares straight off the live pool
> (`stoffel-run.rs`'s `precomputed_mask_shares`) and never reads them from the store. The
> limitation was also wrong in the other direction: removing the swap as a *mechanism* — new
> cursor taken from the caller's `expected` rather than from the stored value — did fail both
> tests, with "overlapping preprocessing items: 0..4 and 0..4". They were sound contract tests
> for a primitive nothing called.
>
> `reserve_at`, `reserve_cursor`, `PreprocStoreError::CursorMismatch`, the `!is_standing()`
> branches that called them, and both of those tests are therefore **deleted** from the tree, per
> the repository's "delete means delete" rule. The text above names what carries the property
> instead. Two earlier correction boxes stood here — one fixing the actor-message citation
> (`DbRequest::Reserve` → `DbJob`, 2026-10-12) and one recording that the two tests had been
> written onto `dev` because the property was unpinned on this branch (2026-10-12). Both are
> subsumed: the citation they corrected is to code that no longer exists.

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
pins independently as its golden vector (`net/roster.rs`) and the docker scripts default
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

## 11. Reversing the execution-id flow — coordinator mints, nodes learn

Status: design. Raised by Cordian at the Oct 8 standup as "the major thing", aligned on Oct 7.

> "currently how it is written, it's as if the coordinator was fixed to one execution ID …
> what we talked about multiple times, to revert the flow — commands being passed, that it's
> like from coordinator to nodes and not the other way around as it currently is."

### 11.1 What is true today

> **Corrected 2026-10-12 (stage C1), against `dev` rather than `main`.** Three claims below
> are false of the stack `dev` builds, and the corrections are the premise of §12.
>
> - `register_execution` **is** an RPC method on the coordinator the VM compiles against
>   (`vendor/stoffel-mpc-coordinator-browser/crates/off-chain/src/lib.rs:884`, impl `:1784`,
>   with `retire_execution` at `:887`), and the VM calls it over the wire, per execution, from
>   every one of the n nodes — `register_coordinator_execution`'s upward
>   `coord.register_execution(registration)`, as `dev` had it at base `266a416`. That upward call
>   is exactly the direction
>   this section reverses; it is deleted rather than ported.
> - A standing coordinator is **not** inert. `docker/coordinator-wrapper/src/main.rs` says
>   "Executions are registered dynamically or optionally pre-registered with `--execution-id`",
>   and `docker-compose.standing-concurrency.yml` starts it with no execution id at all.
> - The id does **not** reach a standing node through `STOFFEL_EXECUTION_ID`. That is the
>   one-shot path only. In standing mode the id arrives per execution, in a `Prepare` command
>   file in the mounted control directory (`standing_control.rs:59`, at base `266a416`) — which
>   is the authority the coordinator takes over here.
> - The envelope claim is also false of `dev`: `net/execution_transport.rs` already makes the
>   full 32-byte `ExecutionId` the mandatory wire envelope (magic `STXE`, 38-byte header, zero
>   id refused on decode), so §12.C has no work left in it. `derive_instance_id(roster_digest,
>   program_id, epoch)` does not exist; `net/session.rs:196` has `derive_instance_id(program_id,
>   session_nonce)` and `:212` has `derive_instance_id_for_execution(&ExecutionId)`. There is no
>   roster digest and no epoch anywhere in the derivation, and no `net/mesh/` directory at all.

**The coordinator serves exactly one execution, fixed before it listens.**
`register_execution` is *not* an RPC method: the surface is `start_preprocessing`,
`reserve_input_masks`, `collect_inputs`, `start_mpc`, `send_output`, `finalize`,
`get_node_roster`, `get_execution_summary`, `associate_client`, `get_client_admissions`,
`retire_execution`, `reserve_mask_indices`, `submit_masked_inputs`, `transition`,
`send_output_shares`. Its only non-test caller is `crates/bins/src/bin/run-coord.rs:371`,
in-process, before the listener binds. Once that execution retires its id is refused as
`ExecutionIdRetired`, so a standing coordinator is inert until restarted. That is deliberate
(§C.1) and the library is not the constraint — `DEFAULT_MAX_CONCURRENT_EXECUTIONS` is 1024 and
`state()` is documented for embedders registering while running — but it is the binary every
shipped stack runs.

**The id enters the system through the nodes.** Every node→coordinator RPC takes
`execution_id` as a node-supplied parameter, and the node reads it from its own
`STOFFEL_EXECUTION_ID`. The compose default is a literal constant
(`docker-compose.yml`: `${STOFFEL_EXECUTION_ID:-2222…22}`). Nothing generates it. The
coordinator validates an id it was separately configured with; it never names one. The five
subscriptions (`sub_round`, `sub_reserved_indices`, `sub_masked_inputs`,
`sub_assigned_reserved_indices`/`sub_receive_assigned_mask_shares`, `sub_obtain_output_shares`)
are a real coordinator→node push channel, but each is opened by the node with an id it already
holds, so **no node can learn of an execution it was not configured for.**

**The execution id is not the multiplexing envelope.** That role belongs to a `u64`
`instance_id` which each node derives *locally*:

```rust
// crates/stoffel-vm/src/net/session.rs:42
derive_instance_id(roster_digest, program_id, epoch) -> u64
```

and which `net/mpc/protocol_ids.rs` reduces per protocol to a `u32`. The coordinator's
`ExecutionId` reaches the mesh only as `SessionExecutionId`, a cross-check: each party proposes
the execution it was started for and the join refuses a party proposing another
(`net/mesh/join.rs:220`), with the id committed in the `JoinCommit` digest (`:186`). It does not
feed the envelope.

So two concurrent *different* programs do not mix messages, because `program_id` is inside that
hash — a property of the derivation, not an envelope the coordinator assigned. Two concurrent
executions of the *same* program on one roster are separated only by the epoch, and no shipped
coordinator can host two executions at all.

### 11.2 The change

1. **The coordinator mints the id.** `ExecutionId` gains a minting constructor;
   `ExecutionRegistration.execution_id` stops being an operator input. **Done in stage C1**, as
   `ExecutionId::new()` with a `Default` that delegates to it (§12.A). Note this was true only
   of the coordinator's own `ExecutionId` (`coord-shared/src/lib.rs`); the VM's separate
   `ExecutionId` (`net/session.rs:24`) already had `new()`.
2. **Nodes learn which executions to run** instead of being told at boot. Either a
   `sub_executions` push on the existing subscription machinery, or a
   `get_pending_executions` call made after the roster fetch the node already performs. A node
   authenticates with its roster certificate, so the existing `mpc_nodes.contains(&self.id)`
   gate applies unchanged.
3. **`instance_id` derives from the coordinator's `ExecutionId`.** Already true on `dev`:
   `derive_instance_id_for_execution` (`net/session.rs:212`) derives it under the domain
   context `stoffel-execution-instance-v1`, and the standing path uses it. Nothing to do.
4. **`STOFFEL_EXECUTION_ID` disappears from node configuration**, along with the matching
   `--execution-id` on `stoffel-run`.

### 11.3 What this collapses

> **Void 2026-10-12 against `dev`.** None of what this section collapses exists there. There is
> no `crates/stoffel-vm/src/net/mesh/` directory at all, hence no `epoch.rs`, no `EpochStore`, no
> `agree_epoch`, no `MAX_EPOCH_JUMP`, no `EPOCH_STORE_ENV`, no `--epoch-store` /
> `STOFFEL_EPOCH_STORE` and no compose volumes for them, and no epoch-agreement round to remove.
> These were v1 constructs and are not to be reintroduced; blocker **B5** as stated does not
> apply. There is also no roster digest in any derivation. The section is kept as history.

The epoch store exists purely for `instance_id` freshness: roster and program are constant
across runs, so a locally-derived namespace would repeat (blocker **B5** — the reuse the
bootnode's unilateral random nonce got wrong). A coordinator-minted `ExecutionId` *is*
freshness, from the party that already owns admission. That makes redundant:

- `crates/stoffel-vm/src/net/mesh/epoch.rs` — the LMDB `EpochStore`, `agree_epoch`,
  `MAX_EPOCH_JUMP` and its Byzantine bound, `EPOCH_STORE_ENV`, `epoch_store_path`
- the epoch half of `derive_instance_id`, and the roster digest that is only there because the
  epoch counter is keyed per digest (`session.rs:14-23`)
- `--epoch-store` / `STOFFEL_EPOCH_STORE` and its compose volumes
- the epoch-agreement round in `join.rs` (`:1267`)

One persistent store, one agreement round and one Byzantine bound removed, replaced by a value
the coordinator already has to issue.

### 11.4 Decisions this forces

- **A coordinator becomes mandatory to run a program.** Today `--roster` plus an epoch store can
  form a mesh and run with no coordinator contact (§3). After this, the id has one source and
  that source is the coordinator. This follows from the Oct 7/8 direction and from §8's decision
  that the coordinator is the roster authority, but it is a real reduction in standalone
  operation and should be stated rather than discovered.
- **The `JoinCommit` digest changes meaning.** Parties currently agree on an id each brought
  from its own configuration; afterwards they agree on one they were *told*. The digest should
  still commit to it — that is what catches a coordinator equivocating between parties, and it
  becomes the only check that all n were pointed at the same execution.
- **Ordering.** Nodes must be able to discover executions before the coordinator can usefully
  host more than one; an operator ingress that registers further executions (the follow-up
  scoped from Cordian's `run-coord.rs:54` comment) is pointless without step 2, so it lands
  after it, not before.
- **Open question — what a node does with no execution.** A node that has fetched the roster and
  found no pending execution must either wait on the subscription or exit. Waiting is what a
  standing network wants; exiting is what every current stack and test expects.

### 11.5 Constraint: concurrent, persistent executions — the id is per computation instance

> **Corrected 2026-10-12 against `dev`.** The constraint stands; the survey below does not.
> `dev`'s runner **is** ready: `--standing-node` / `run_standing_node` (`stoffel-run.rs`)
> hosts many concurrent instances over one mesh through `NodeSupervisor` and
> `ExecutionTransportMux`, `OpenMessageRouter::new()` is called **per execution** inside
> `setup_hb_party_for_curve` (its `OpenMessageRouter::new()`) and fed only from that execution's
> own inbox (the pump that `OpenMessageRouter::new()` call installs),
> and `docker-compose.standing-concurrency.yml` with `matrix.json` runs six concurrent
> executions on five parties. So hazard 1 — a get-or-create envelope collision merging two
> computations — is **unreachable**: two executions can never contend for one router key, and
> `net/open_registry/router.rs`'s `u64` get-or-create is harmless and stays. The "transport join
> must stop committing to a single execution" is also already done, and done in the direction
> this section wanted. (`MeshInfo` documented it in those words on `dev`, at
> `net/session.rs:150-166`; stage V2 deleted that type as defined-never-used, and the property is
> now carried by `net/mesh/join.rs`'s `MeshCommit`, whose `session` field is `None` on a standing
> node precisely because many executions ride its one mesh.) And the
> per-execution agreement step this section asks §12 to invent already exists as
> `preprocessing_transcript_exchange` over `ExecutionScopedNetwork` with the domain-separated
> `PreprocessingExchangePhase` enum (`stoffel-run.rs`): extend that enum, do not build a
> new mesh module.
>
> What remains of §11.5 is the one thing it got exactly right: the id belongs to the instance of
> the computation, and **direction** is the gap. On `dev` a node learns of an execution from a
> file in a mount and then pushes `register_execution` *up* to the coordinator
> (`register_coordinator_execution` at base `266a416`). §12.A
> and §12.B reverse that; the envelope needs nothing.

Raised by the user after §11.1-§11.4 were written, and it corrects their framing. There is no
single execution per node. The VM supports **concurrent, persistent** execution: a node process
is long-lived and hosts N computation instances at once, and the id belongs to *the instance of
the computation being run*, not to the node or to the process.

Where each side already stands:

- **The coordinator is ready.** State is per-execution throughout —
  `executions: HashMap<ExecutionId, CoordinatorExecutionState>` (`off-chain/src/lib.rs:1774`) and
  node-side `executions: HashMap<ExecutionId, Arc<Mutex<NodeRPCExecutionState>>>` (`:725`), with
  `DEFAULT_MAX_CONCURRENT_EXECUTIONS = 1024` and a passing
  `one_listener_isolates_and_retires_concurrent_executions` (`tests/off_chain.rs:568`).
- **The VM's routing layer is ready.** `OpenMessageRouter::register_instance(instance_id)`
  (`net/open_registry/router.rs:27`) is get-or-create over a map of `InstanceRegistry`, one per
  `u64` instance, and `MpcInstanceId` (`net/mpc/engine/identity.rs:61`) is already a typed
  per-instance id. This is exactly the multiplexing envelope Cordian described.
- **The runner process is not.** `stoffel-run` builds one `OpenMessageRouter`
  (`stoffel-run.rs`'s one-shot path) and then exactly one engine for one instance, and runs one program.
  That is the gap: the envelope exists, nothing drives more than one envelope at a time.

#### What this corrects in §11.1-§11.4

- **§11.4's open question dissolves.** "A node with no pending execution must wait or exit" was
  the wrong question. For a standing node, *having no execution right now is the normal state*,
  not a condition to resolve. Exiting is a property of the one-shot mode every current stack and
  test uses, which becomes a mode rather than the model.
- **Publication is a stream of executions, not a lookup of one.** A node subscribes and spins up
  an instance per execution it is told about, and tears it down on retirement. Snapshot-then-stream
  is not an optimisation for late joiners; it is the steady state.
- **The transport join is execution-independent.** The mesh is per *roster* — one authenticated
  all-to-all transport carrying many instances, which is what the envelope is for. So agreeing on
  an execution id inside `JoinCommit` (`join.rs:186`, `:220`) is the wrong layer once there are
  many: a node cannot re-join the mesh per computation. Per-execution agreement has to become a
  lightweight step *on top of* a shared mesh, and the transport join must stop committing to a
  single execution. This is the largest structural consequence and §12 must resolve it with
  evidence rather than assertion.

#### Two hazards this creates

1. **`register_instance` is get-or-create, so an envelope collision silently merges two
   computations' message streams** rather than failing. Today that cannot happen: one execution
   per process, and distinct programs hash to distinct ids. With many concurrent executions keyed
   by a `u64` derived from a 32-byte `ExecutionId`, a collision becomes conceivable — astronomically
   unlikely at 64 bits and 1024 concurrent instances, but the failure mode is silent cross-talk
   between two secret computations, which is not a failure mode to leave undetected. Either key the
   registry by the full `ExecutionId` or make a collision a loud refusal.
2. **Preprocessing single-use must hold across *concurrent* instances, not just sequential runs.**
   §10 established that no stored item serves two executions. Under concurrent execution several
   live instances draw from one pool at the same time, which is the same property under more
   pressure. *Corrected 2026-10-15: this said "the compare-and-swap on the consumed cursor is
   what carries it". It never did — that primitive had no production caller and is now deleted.
   What carries it is `take_bundle_from_reservoir`'s physical removal inside the write
   transaction that yields the bundle, and the concurrent case is pinned by
   `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`.*

## 12. Coordinator-minted execution ids — contract

Status: **binding contract** for both repositories, revision 0. §11 states the intent and
records what is true today; this section is what implementers build. A deviation is a change
to this section first.

Implementers work in `stoffel-mpc-coordinator` (worktree
`stoffel-mpc-coordinator-roster-admission`, branch `feature/no-bootnode`) and in this
repository (worktree `StoffelVM-nb2`, branch `feature/no-bootnode-v2`, cut from `dev`).
`StoffelVM-no-bootnode` is the abandoned `main`-based first attempt: read it for intent,
never write to it and never merge it. It builds
on §9, which is unchanged except where §12.D and §12.E say otherwise, and on §10's decisions
about what may be left behind.

It implements one decision and gives way on none of it:

**The execution id belongs to the instance of the computation, it is minted by the
coordinator, and it is the multiplexing envelope.** A node process is long-lived and hosts
many instances at once (§11.5). No layer may assume one execution per node, per process, or
per mesh; for a standing node, having no execution right now is the normal state.

### 12.0 Where each piece lives

> **Corrected 2026-10-12 (stage C1).** Every VM row of this table named a file that does not
> exist on `dev`, because the table was written against the v1 tree. `crates/stoffel-vm/src/net/mesh/`
> is absent in its entirety, `SessionExecutionId` has zero occurrences anywhere under `crates/`,
> and `executions.rs` / `instances.rs` were never created. Worse, three of the rows direct work at
> mechanisms `dev` already has: the envelope is `net/execution_transport.rs`, instance supervision
> is `net/node_supervisor.rs`, and the roster-only mesh was `net/session.rs::MeshInfo` (deleted
> by stage V2 as unused; the property now lives in `net/mesh/join.rs`'s `MeshCommit`). Following
> the old table would have built a second instance supervisor beside `dev`'s and a second envelope
> under one that already carries the full `ExecutionId` on the wire. The table below is the
> corrected one; §12.H voids stages E-3, E-4 and E-5's new modules for the same reason.

| Piece | Repository | File |
|---|---|---|
| `ExecutionId::new` | coordinator | `crates/coord-shared/src/lib.rs` |
| `ExecutionRequest`, `RegisteredExecution`, `register_execution` | coordinator | `crates/off-chain/src/lib.rs` |
| `sub_executions`, `ExecutionNotice`, `runnable_snapshot`, the publication backlog | coordinator | `crates/off-chain/src/lib.rs` |
| `AdmissionPolicy`, `PreRegisteredClient`, `ClientSlotTable` | coordinator | `crates/coord-shared/src/admission.rs` |
| `run-coord` registration and mode flags | coordinator | `crates/bins/src/bin/run-coord.rs` |
| Envelope — **already built, do not rebuild**: `STXE` framing on the full `ExecutionId`, per-execution inboxes, the scanner lease | VM | `crates/stoffel-vm/src/net/execution_transport.rs` |
| Instance supervision — **already built**: `prepare` / `cancel`, `NodeEvent` | VM | `crates/stoffel-vm/src/net/node_supervisor.rs` |
| `ExecutionId`, `derive_instance_id_for_execution` — **already built** | VM | `crates/stoffel-vm/src/net/session.rs` |
| Roster-only mesh — **built by stage V2**, as `MeshCommit { roster_digest, n_parties, threshold, session }` with `session: None` on a standing node. *Corrected 2026-10-13 (stage S6): this row used to name `net/session.rs`, whose `MeshInfo` carried the property and was deleted as unused — see the correction box above, which the row had not been brought into line with* | VM | `crates/stoffel-vm/src/net/mesh/join.rs` |
| The node's two listeners and the single writer of each allowlist — **built in stage S1** | VM | `crates/stoffel-vm/src/net/roster.rs` (`NodeListeners`, `Roster::install_into`, `Roster::install_for_client`), `crates/stoffel-vm/src/net/execution_transport.rs` (`ExecutionScannerScope`) |
| Bounded, admission-gated acceptance on the client-facing listener — **built in the stage S1 repairs** | VM | `crates/stoffel-vm/src/net/client_ingress.rs` (`ClientIngressGate`, `AdmittedClientDirectory`) |
| Per-execution all-parties agreement — **already built**: extend `PreprocessingExchangePhase`, do not add a module | VM | `crates/stoffel-vm-runner/src/bin/stoffel-run.rs` (`preprocessing_transcript_exchange`) |
| Standing preprocessing pool and reservoir — **already built** | VM | `crates/stoffel-vm/src/storage/preproc.rs`, `stoffel-run.rs` (`warm_reservoirs`, `reserve_reservoir_bundle`) |
| `sub_executions` stream client and admission resolution, replacing the mounted control plane — **built in stage V3** | VM | `crates/stoffel-vm-runner/src/execution_stream.rs` (`CoordinatorExecutionStream`, `resolve_published_execution`, the program and client catalogs, and the `InstanceLedger` stage S3 added), `src/bin/stoffel-run.rs` (`run_standing_node`). `standing_control.rs` is deleted. |
| Operator submission and abort, replacing the mount as the authorization boundary — **built in stage V3** | coordinator + VM | `crates/off-chain/src/lib.rs` (`submit_execution`, `abort_execution`, `with_operators`), `crates/stoffel-vm-runner/src/bin/stoffel-coord-ctl.rs`, `docker/coordinator-wrapper/src/main.rs` (`--operator-certs`) |
| Roster-pinned mesh bring-up, replacing the bootnode | VM | `crates/stoffel-vm-runner/src/bin/stoffel-run.rs` (`run_standing_node`), replacing `net/discovery.rs` and `net/discovery/bootnode.rs` |
| Durable execution-id non-reuse index (LMDB, re-homed from the control directory) — **built in stage V3** | VM | `crates/stoffel-vm/src/storage/retired_executions.rs` (`RetiredExecutionIndex`), reached by `stoffel-run --admitted-store` |
| Local runner | VM | `crates/stoffel-vm-runner/src/local_runner.rs` |
| Coordinator wrapper | VM | `docker/coordinator-wrapper/src/main.rs` |

### 12.A Minting

**The constructor.** As built in stage C1:

```rust
// crates/coord-shared/src/lib.rs, beside `from_bytes` / `as_bytes` / `is_zero`
impl ExecutionId {
    /// Draws a fresh execution identity from the operating system's random source.
    ///
    /// Never zero: the all-zero value is reserved, and the node transport refuses it
    /// on the wire, so a minted id that happened to be zero would be unusable rather
    /// than merely unlucky. The draw is repeated while it is zero, so a caller never
    /// has to check.
    pub fn new() -> Self;
}

impl Default for ExecutionId {
    fn default() -> Self { Self::new() }
}
```

**Named `new`, not `generate`.** The design said `generate`, after
`RegistrationNonce::generate` two modules over. It is `new` because the VM has its own
`ExecutionId` (`crates/stoffel-vm/src/net/session.rs`) whose minting constructor is already
`new()` with a `Default` that delegates to it, and the two types are copied byte for byte
across the boundary between the repositories. One name for one operation on both sides of that
copy is worth more than one name for two draws inside one crate. `Default` is there so the type
is not a `new`-without-`Default` outlier.

**Randomness source: `ring::rand::SystemRandom`, not `rand`.** Both are already
`coord-shared` dependencies, so this is a consistency choice rather than a dependency one:
`RegistrationNonce::generate` (`crates/coord-shared/src/admission.rs`) draws exactly
32 bytes for exactly this purpose through `SystemRandom`, two modules over, and the two
32-byte identifiers of one registration should not come from two generators. `ring` is also
the crypto provider every listener installs, so it is already the process's entropy path.

**Random, not derived.** A derived id has to be derived from something, and everything
available at registration is constant across runs: the roster digest never changes for a
coordinator's lifetime (`CoordinatorRPCServerSharedBase::new` fixes it), the program hash is
the content address of a program baked into an image, and the slot table and policy follow
the program. Deriving from those reproduces blocker **B5** exactly — the reuse the epoch
store exists to prevent (§11.3) — only now at the coordinator instead of at each node. Two
concurrent executions of the same program on one roster, which is the case §11.1 says fails
today, would be *identical* under any such derivation.

Randomness also buys a property derivation cannot, and it matters because §12.C makes the id
the message envelope: a minted id is **unpredictable to nodes and clients until the
coordinator publishes it**. A party that could compute a future envelope could pre-position
open-share frames in an execution's `InstanceRegistry` before that execution's parties agree
on it. With 32 OS-random bytes it cannot.

**Registration takes a request without an id and returns the minted one.** As built, with
one field the design did not have: `entry`. The mounted control directory's `Prepare` carried
`(execution_id, program_id, entry, clients)` (`standing_control.rs:57-64`, at base `266a416`;
stage V3 deleted that file), and a node cannot
run a program without knowing which function to call in it, so the entry function moves to the
coordinator with the rest of the admission. It is bounded by `MAX_ENTRY_NAME_BYTES = 256` and
validated non-empty, with `RegistrationError::{EmptyEntry, EntryTooLong}`.

```rust
// crates/off-chain/src/lib.rs
/// Everything that fixes an execution except its identity. This is what an operator
/// supplies; the coordinator supplies the identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    /// `program_hash_of` the compiled program bytes.
    pub program_hash: [u8; 32],
    /// The function the nodes call in that program.
    pub entry: String,
    pub client_slots: ClientSlotTable,
    pub admission: AdmissionPolicy,
    /// Required under `Open`, optional under `PreRegistered`.
    pub deadlines: Option<ExecutionDeadlines>,
}

impl ExecutionRequest {
    /// The rows of the validation table that read no coordinator state, in table order.
    pub fn validate(&self, now: UnixSeconds) -> Result<(), RegistrationError>;
}

/// What the coordinator minted and recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredExecution {
    pub execution_id: ExecutionId,
    pub registration_nonce: RegistrationNonce,
}

impl CoordinatorRPCServerSharedBase {
    pub fn register_execution(
        &mut self,
        request: ExecutionRequest,
    ) -> Result<RegisteredExecution, CoordinatorError>;

    pub fn new_for_execution(
        node_roster: NodeRoster,
        server_spki: SpkiDer,
        request: ExecutionRequest,
    ) -> Result<(Self, RegisteredExecution), CoordinatorError>;
}
```

`ExecutionRegistration` stays as the **stored** immutable record — it is what
`CoordinatorExecutionState.registration: Arc<ExecutionRegistration>` holds and what
`ExecutionSummary` is built from — but it is now the minted id *bound to* the request rather
than a flat copy of its fields:

```rust
pub struct ExecutionRegistration {
    /// Minted by `ExecutionId::new`; never read from a caller.
    pub execution_id: ExecutionId,
    pub request: ExecutionRequest,
}

impl ExecutionRegistration {
    pub fn mint(request: ExecutionRequest) -> Self;
    pub fn validate(&self, now: UnixSeconds) -> Result<(), RegistrationError>;
}
```

Its doc comment said "Registered in-process by the operator; never sent over the wire". That is
no longer true and the comment is gone: §12.B publishes this exact value to the roster, which is
why it is the type that carries everything a node needs.

**The check order of `register_execution`** is unchanged, and that is deliberate. The minting
entry point draws the id and delegates to the private `insert_registration`, which still runs
the original order: an identical live registration answers its nonce; an ended id is
`ExecutionIdRetired`; a different live registration is `ConflictingRegistration`;
`validate`; then, at `DEFAULT_MAX_CONCURRENT_EXECUTIONS`, one evictable execution is evicted or
the registration is `ExecutionCapacityReached` — still *after* validation, so a refused
registration never evicts. Finally it draws the nonce, inserts, wakes the sweeper, and publishes
the execution (§12.B).

```rust
pub fn register_execution(
    &mut self,
    request: ExecutionRequest,
) -> Result<RegisteredExecution, CoordinatorError>;

/// `register_execution` with the identity given rather than minted, for tests that have to
/// name an execution — above all to re-register one this coordinator has already ended.
#[doc(hidden)]
pub fn register_execution_at(
    &mut self,
    execution_id: ExecutionId,
    request: ExecutionRequest,
) -> Result<RegistrationNonce, CoordinatorError>;
```

**Corrected: the three id-order rows and `MintExhausted` are not what was built.** The design
had `register_execution` redraw on collision up to `MAX_MINT_ATTEMPTS = 8` and then refuse with
a new `RegistrationError::MintExhausted`, and declared `ZeroExecutionId`,
`ConflictingRegistration` and `ExecutionIdRetired` unreachable and deleted. All four decisions
are reversed:

- A collision between a freshly minted 32-byte id and an id this process still remembers is not
  bad luck that a redraw fixes — it is a failed random source. Redrawing eight times from a
  broken generator produces eight more collisions and then an error that names the wrong cause.
  So the collision is **refused**, with the existing typed errors, and `MintExhausted` does not
  exist.
- `ZeroExecutionId`, `ConflictingRegistration` and `ExecutionIdRetired` therefore all stay, and
  all stay reachable: through `register_execution_at`, which is how the tests exercise them, and
  as fail-closed guards on the minting path. `ExecutionIdRetired` in particular is an invariant
  this effort must preserve, not retire — an execution identity is single use for as long as the
  coordinator remembers it.

**Corrected: a pre-registered client names its slot, because the publication payload has to
carry what the mount's `Prepare` carried.** `0.3.0` held `PreRegistered { clients:
Vec<ClientIdentity> }` and bound `clients[i]` to slot `i`, so one index served as both the
program's slot and the client's position. The control directory kept them apart, and `dev`'s own
acceptance matrix depends on it: `StandingClientAdmissionV1` was `{ certificate, manifest_slot }`
in a vector whose order the deleted `standing_control.rs` documented as "the execution-local
client ordinal used by the MPC backend", `validate_client_io_admission` requires only that the
*set* of `manifest_slot`s equal the program's set (it survives the mount's deletion, in
`execution_stream.rs`), and
`docker/standing-concurrency/matrix.json`'s `hb-multi-io` row admits `cert1@manifest_slot 1`
at ordinal 0 and `cert0@manifest_slot 0` at ordinal 1 — a permutation — while `avss-multi-io`
runs the same fixture in identity order. That pair is the only coverage of the decoupling, so a
publication payload that forced ordinal `==` slot would make §12.B's replacement of the mount
either impossible or a silent deletion of the property the row exists to test.

So `PreRegistered` now holds `Vec<PreRegisteredClient { identity, client_slot }>`: the vector
position stays the execution-local ordinal, and `client_slot` is the `ClientIndex` the
coordinator reasons about. `ClientIndex` keeps its single meaning — a position in the
`ClientSlotTable`, which is the program's `client_slot` — because the input range, the output
rights, `ClientAdmission`, `associate_client`'s slot check and the frozen `ClientAdmissionSet`
are all in that space and none of them has any use for the ordinal. `CoordinatorExecutionState`
binds each client at the slot it names rather than at its position, the validation table gains
`PreRegisteredSlotOutOfRange` and `DuplicatePreRegisteredSlot` (§C.1), and the key and
duplicate-identity rows now name a `client_slot`. `run-coord` still pre-registers in slot order
from `--client-certs` or `--client-bindings <slot>=<cert>`, since it takes a slot per client and
nothing else; the ordinal freedom is for the standing admissions §12.B publishes.

**`run-coord` stops taking an id.** Done: `--execution-id` and
`parse_nonzero_execution_id` are gone from `crates/bins/src/bin/run-coord.rs`, with no refusal
guard of any kind (§13) — the flag is an ordinary unknown argument, which the binary's own test
asserts alongside the other flags removed earlier. `run-coord` gains `--entry` (default `main`)
and prints what it minted:

```text
Minted execution <64 hex> (registration nonce <64 hex>)
```

**`docker/coordinator-wrapper` is not done, and cannot be until the VM is adapted.** It is its
own cargo workspace, pins `stoffel-mpc-coordinator-off-chain = "=0.2.0"` from crates.io with no
patch table, and already fails to build on `dev` (`start_coord_with_browser` exists only in the
in-tree vendored fork). Pointing it at `0.3.0` is the same change as pointing the VM workspace
there, and that change rewrites `local_runner.rs`'s coordinator bring-up and deletes
`stoffel-run.rs`'s upward `register_execution` — the work the next stage does. See §12.H.

**The VM's own minting duplicate goes — not yet.** `local_runner.rs` mints its own id
(`ExecutionId::new()` at `:178` on `dev`, not the `uuid` pair this section described) and hands
it to the coordinator's constructor. It should take the id back from `register_execution`'s
`RegisteredExecution` instead, and that is part of the VM adaptation the next stage owns: the
vendored `0.2.0` `new_for_execution` takes eight arguments (id, program id, n, t, node keys,
`n_inputs`, `output_clients`, `InputAssignment`) where `0.3.0` takes three (roster, served key,
request), so the call cannot be edited in place — the whole bring-up is rewritten.

> **Both paragraphs above are done, and were stage C1's statement of what was left (corrected
> 2026-10-13, stage S6).** They are kept because they say why each had to wait, but neither is
> true of this tree any more.
>
> - **The wrapper.** `docker/coordinator-wrapper/Cargo.toml` requires `=0.3.0` for both
>   coordinator crates and carries its own `[patch.crates-io]` — its own, because it is its own
>   `[workspace]`, so the root table does not reach it — naming the coordinator worktree
>   relative to that manifest (stage S5, §9.F.5, §12.H). `--browser-bind-addr` and the vendored
>   fork are deleted, which is what fixed `dev`'s one pre-existing build failure, and the
>   wrapper builds. CI builds it as a step of its own for the same reason `--workspace` never
>   reached it.
> - **The minting duplicate.** `local_runner.rs` mints nothing. It passes an `ExecutionRequest`
>   to `HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution` — the three-argument
>   `0.3.0` form — and takes the identity back from the `RegisteredExecution` it answers
>   (`ExecutionId::from_bytes(*registered.execution_id.as_bytes())`, under the comment "the
>   coordinator minted the identity; nothing here invents one"). `ExecutionId::new()` has no
>   occurrence in that file. The upward `register_execution` push is gone with it (§9.I,
>   stage V3).

### 12.B Publication: a stream of executions

A node subscribes **once** and is told about every execution it must run. Snapshot then live
on one channel is the steady state, not a late-joiner optimisation (§11.5).

> **Corrected 2026-10-12 (stage V4 repair), by running the standing campaign for the first
> time.** "Subscribes once" is the *subscription's* lifetime, not the connection's, and the
> first implementation conflated the two. A standing node opens its link before it has a mesh,
> because the link is where the roster comes from, and subscribes only after it has warmed its
> reservoirs — 70-130 s of preprocessing in the five-party stack. By then the connection under
> that link is gone, closed from the server side, and a JSON-RPC client whose connection has
> closed is dead permanently: every later call on it answers
> `the background task closed … restart required`. The node retried `subscribe_executions` on
> that same dead client, with backoff, forever. Every party reached "standing node ready" and
> then never heard of an execution, so nothing the coordinator minted could reach the roster at
> all — the whole point of §12.A and §12.B, defeated by a connection lifetime.
>
> What is **measured** is that the gap is what matters: the same stack with preprocessing short
> enough to subscribe inside the first half-minute subscribes on the first attempt, and with the
> full warm-up it never subscribes. The timescale matches `RpcServerLimits::idle_timeout`, the
> coordinator's 30-second reclaim of a connection with no call in progress and no live
> subscription — though that reclaim is supposed to spare a connection whose certificate is on
> the roster (`CapacityClass::Node`), so either the classification or some other idle close is
> at work, and this was not isolated further: the node must survive the connection ending
> whatever ends it, which is the fix below. Worth a look on the coordinator side independently.
>
> What the design owes a long-lived node, and what it now says: the node **reopens the link**
> rather than retrying a dead one (`CoordinatorLinkSource`, `CoordinatorExecutionStream::run`),
> and every reopen is pinned to the roster digest *that node already accepted*, so recovering a
> connection can never become following a different membership. Only three refusals are fatal —
> a different roster digest, a roster that fails verification, and a server key the pin does not
> admit (`classify_link_failure`, pinned by
> `only_a_different_coordinator_ends_a_standing_node_s_stream`); everything else is the
> coordinator being away, which a standing node waits out. This also closes a case the design
> never addressed: a **coordinator restart** closes every node's connection, and before this fix
> no node could ever re-subscribe.
>
> The idle window itself is left in place rather than engineered around: the first subscribe
> after a long preprocessing warm-up fails once and the reopen succeeds, which is the same path
> a coordinator restart takes, so it is better exercised than a special case that only runs at
> startup would be.

> **Corrected 2026-10-13 (stage V5 repair): the restart case was only half closed, and the
> other half aborted the deployment.** The box above says the reopen "closes a case the design
> never addressed: a **coordinator restart**". It closes the *reconnection*. It does not close
> what the reconnected node is then told. This coordinator holds its executions in memory and
> nothing else — `crates/off-chain` has no durable store, no `heed`, no `redb`, no save or load
> path — so a restarted coordinator has forgotten every identity it ever minted, and its first
> snapshot to each node names nothing. Against §12.B's own rule ("Stop every instance not named
> by the `Prepare`s that preceded it") that empty snapshot is an order to stop everything: five
> long-running executions on a five-party mesh, `compose up -d coordinator`, and all five are
> cancelled on all five parties. The reopen made the hazard reachable rather than creating it,
> and `SnapshotCursor::complete`'s own doc comment named the shape of it ("reconciling against
> nothing would stop every instance the node is running") while guarding only a *second*
> `SnapshotComplete` inside one subscription. It is also a regression against `dev`, where a
> standing node's admissions came from an on-disk control directory that no coordinator restart
> could empty.
>
> **As built: the snapshot says which run of the coordinator took it.**
> `ExecutionNotice::SnapshotComplete` carries a `CoordinatorIncarnation` — 16 random bytes drawn
> in `CoordinatorRPCServerSharedBase::new`, so two runs of the same binary on the same
> configuration never share one — and the node records, per instance, the incarnation that most
> recently named it (`CoordinatorExecutionStream::incarnations`, now the shared `InstanceLedger`
> that stage S3's box below widened and moved it to, tagged at `SnapshotComplete`
> for the snapshot's own `Prepare`s and at arrival for every later one). Reconciliation then
> stops exactly the instances *that* incarnation admitted and did not name, and reports the rest
> as kept (`NoticeOutcome::SnapshotReconciled { stopped, kept }` — stage S3's box below adds a
> third set, `retired`), one log line each. So a
> restarted coordinator's empty snapshot stops nothing, and — the part a per-subscription token
> would get wrong — it still stops nothing on the *next* reconnection to that same restarted
> coordinator, which matters because the connection under a subscription ends routinely.
>
> This is deliberately not "persist the coordinator's executions". A restarted coordinator has
> lost the client connections, the parked sinks and the round state of everything it admitted,
> so reloading the registrations would not resume those executions; what the nodes need from it
> is only that it stop claiming to speak for them. An instance an earlier incarnation admitted
> is therefore left running to finish or to be stopped by name: a `Cancel` carries an identity
> and needs no incarnation to act on, which is pinned by
> `a_cancel_from_a_restarted_coordinator_still_stops_an_older_instance`. The scoped
> reconciliation is pinned by `a_restarted_coordinator_stops_nothing_it_never_admitted`
> (including the second reconnection), the unchanged within-one-run behaviour by
> `completing_the_snapshot_stops_exactly_the_instances_it_omitted`, and the coordinator half by
> `every_snapshot_names_the_run_of_the_coordinator_that_took_it`.
>
> What is still open on the coordinator: nothing here makes a restarted coordinator able to
> *adopt* executions in flight. An operator who restarts one and wants the roster's live work
> stopped must abort each execution by name, and an execution whose coordinator is gone runs to
> completion with no coordinator-mediated client I/O. That is the honest consequence of keeping
> the coordinator's state in memory, and it is recorded here rather than designed around.

As built in stage C1:

```rust
// crates/off-chain/src/lib.rs, in `pub trait CoordinatorRPCBase`
/// Every execution this coordinator wants the roster to run, and every one it wants
/// stopped. Roster nodes only. Snapshot then stream.
///
/// Takes no parameters: the caller's roster certificate is the whole gate, and the roster is
/// process-wide. One subscription serves a node for its lifetime.
#[subscription(name = "sub_executions", unsubscribe = "unsub_executions", item = ExecutionNotice)]
async fn sub_executions(&self) -> SubscriptionResult;
```

```rust
/// One execution a roster node must run, as the coordinator publishes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedExecution {
    pub registration: ExecutionRegistration,
    pub registration_nonce: RegistrationNonce,
}

/// One item of `sub_executions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionNotice {
    /// Run this execution. Sent once per execution per subscription, and carrying the whole
    /// registration, so a node needs no follow-up `get_execution_summary` round trip.
    Prepare(PublishedExecution),
    /// Stop running this execution.
    Cancel {
        execution_id: ExecutionId,
        outcome: ExecutionOutcome,
    },
    /// Every execution the coordinator wanted run as of the start of this subscription has
    /// been sent as a `Prepare`. Sent exactly once per subscription, before any later
    /// notice. Stop every instance not named by the `Prepare`s that preceded it.
    SnapshotComplete,
}
```

*As built, `SnapshotComplete` is `SnapshotComplete { incarnation: CoordinatorIncarnation }`, and
the reconciliation it orders is scoped to that incarnation; see the V5 correction box above.*

The variants are named after the two commands they replace — `standing_control.rs`'s
`StandingControlCommandV1::{Prepare, Cancel}` — because that is the vocabulary the VM side
already implements against, and the point of this stage is that the commands now arrive over an
authenticated RPC from the trusted party instead of appearing as files in a mount. `Prepare`
carries `ExecutionRegistration`, not `ExecutionSummary`: the summary flattens the admission
policy to its `AdmissionPolicyKind`, which loses the pre-registered client identities a node
needs.

**What a node resolves locally, and why the payload does not carry it.** A published
`PreRegisteredClient` carries a `ClientIdentity`, which is the certificate's
`subject_public_key` bit string. That is the right thing to publish — it is the only key the
coordinator itself reasons about — but it is **not** the certificate-exact
`CertificateIdentity` that `execution_transport.rs` matches a client connection against, and it
is not an SPKI DER. The mounted control plane never had to say where that came from, because a
command named a certificate by *filename* and `StandingClientCatalog` resolved the filename into
both halves at once: `coordinator_public_key` from `parsed.public_key().subject_public_key.data`,
and `transport_public_key` from `parsed.public_key().raw`, whose `certificate_identity()` fills
`ResolvedStandingExecutionAdmissionV1.expected_client_certificate_identities`
(`standing_control.rs:93-95`, consumed at `:498-515` and in the `config_digest` preimage — all
at base `266a416`, the file having been deleted by stage V3).

With the mount gone, the rule is: **the certificate material stays local and the published
identity is only a key to look it up by.** The node keeps its startup-frozen
`--client-cert-dir` catalog and re-keys it from filename to the `subject_public_key` it computes
from each local certificate; for each `PreRegisteredClient` it looks that key up and takes the
`CertificateIdentity` from the **local** certificate it found. A published identity the catalog
does not hold is a **refusal** of the whole admission, not a client that is merely absent — the
same fail-closed shape as a `Prepare` naming a program the program catalog does not hold.

**Which admission policies a standing node will serve, and why that is narrower than what the
coordinator publishes** (added 2026-10-13, stage S6 — the rule above specified the
`PreRegistered` path only, and said nothing about the other policy a `Prepare` can carry).
`AdmissionPolicy` has two variants and the coordinator publishes both: an `Open` registration is
a legitimate, asserted part of its contract — `an_abort_cancels_the_execution_on_every_node_running_it`
registers one and asserts the `Prepare` carrying it reaches a subscribed roster node, and
`local_runner` registers every local run as `Open` so a client the deployment never listed can
still bind a slot. A **standing** node nevertheless serves only `PreRegistered`:
`resolve_published_execution` refuses an `Open` admission outright, pinned by
`an_open_admission_policy_is_refused_by_a_standing_node`, with the reason in the error text —
*"a standing node runs only pre-registered admissions: an open policy would let any certificate
holder bind a slot of a program this node holds"*. That is the right fail-closed behaviour and
it follows from the rule above rather than contradicting it: the node's only client authority is
its startup-frozen `--client-cert-dir` catalog, and under `Open` there is no published identity
to look up in it, so there is nothing for the node to resolve a `CertificateIdentity` from and no
certificate-exact route it could authorize. The asymmetry is deliberate and is a property of the
mode, not of the policy:

- **One-shot party.** `take_published_execution` inspects the program hash and the entry function
  and **not** the admission policy, so an `Open` execution runs. It can: its clients are bound by
  the coordinator's own `associate_client` within that one execution's lifetime, and the process
  exists to run that execution and exit.
- **Standing node.** Many programs and many executions share one long-lived process, one mesh and
  one client-facing listener, so an `Open` admission would let any certificate holder bind a slot
  of **any** program in that node's frozen catalog. The node refuses rather than widening what
  its catalog means.

So an operator who submits an `Open` registration to a standing deployment gets a refusal from
every node, logged per node, and the execution dies at the coordinator's own association
deadline. Making `Open` work on a standing node would need the coordinator to tell nodes which
certificates it admitted *after* the fact — a coordinator-surface change, and the same shape as
the still-open item at the end of this section — so it is recorded here as a contract boundary
rather than a defect.

The alternative — reconstructing an SPKI DER from the published bit string in order to derive a
`CertificateIdentity` — is rejected outright. It would have to guess the algorithm identifier
and encoding the issuer used, and the two failure modes are both bad: a mismatch refuses every
client of every execution, and "fixing" that by comparing something weaker than the certificate
identity silently downgrades transport route authorization from certificate-exact to key-only.
Nothing in the published payload is trusted as certificate material; the coordinator names
which of the node's own certificates an execution admits, and nothing more.

This also keeps the `config_digest` computable without new inputs: every party derives it from
the published admission plus its own catalog, so two parties handed divergent admissions still
diverge in the digest, which §12.B's successor stage carries into the existing
`ReservoirAllocationSnapshot` barrier.

**The gate.** `shared.mpc_nodes.contains(&self.id)` or `pending.reject(not_party("subscribe
to executions"))`, in `sub_executions` itself — the same gate `sub_reserved_indices` and
`sub_masked_inputs` apply through `event_stream_subscription`, whose own refusal reads
`not_party("subscribe to reservations and masked inputs")` (both in
`crates/off-chain/src/lib.rs`; *citation corrected 2026-10-13, stage S6 — this named
`lib.rs:2087-2099`, which is `RetiredExecutions::acknowledge`'s bookkeeping and not a gate at
all*), with one difference: `sub_executions` is **not** per-execution, so it does not call
`live_execution` and cannot answer `ExecutionNotFound`. Clients never see it. It draws on the `Node` capacity
class like every other roster-node connection (§9.A), so a flood of client certificates
cannot crowd it out.

**No invisible window, no duplicate: snapshot of the runnable set, then the stream.**
The design here was a 16,384-entry replay log addressed by a caller-supplied `from_seq`, with a
new refusal code for truncation. What was built is simpler and satisfies one requirement the log
does not: *retired and retained executions are never published as runnable*. A `from_seq: 0`
replay hands a fresh subscriber every historical `Started`, including thousands for executions
that ended long ago, and relies on the node to pair each with a later `Ended`. A snapshot of the
runnable set hands it only what it can still contribute to.

Three fields on `CoordinatorRPCServerSharedBase`:

```rust
/// The coordinator-wide publication sequence; every notice takes the next value.
publication_seq: u64,
/// The most recent notices, so a node that has taken its snapshot can catch up on whatever
/// was published while it was still sending that snapshot. Bounded.
publications: VecDeque<PublishedNotice>,
/// Parked `sub_executions` subscriptions, bounded per caller like every other parked list.
execution_sinks: ParkedSinks,

/// Published notices kept for subscribers that are between their snapshot and their park.
pub const MAX_PUBLICATION_BACKLOG: usize = 1024;
```

Every write path that registers an execution, aborts one or calls `remove_execution` publishes
exactly one notice under the state mutex it already holds, which is also what delivers it to
every parked sink. `SubscriptionSink::try_send` only enqueues on the subscriber's own connection
channel — no socket I/O, no await — so publishing under the mutex is what gives every subscriber
one coordinator-wide order, and it is the same "live broadcasts never wait on a subscriber"
rule the reservation and masked-input streams already follow.

The subscription keeps `replay_then_park`'s shape, with a cursor that starts empty:

1. Gate on `mpc_nodes.contains(&self.id)` and `pending.accept().await`, outside the mutex —
   `accept` performs WebSocket I/O and must never run under it.
2. First look: take the snapshot — one `Prepare` per runnable execution, ordered by the
   publication sequence its registration took — and set the cursor to `publication_seq`. Send
   them outside the mutex.
3. Later looks: send every backlog notice after the cursor, advancing it; when none remains,
   park the sink in `execution_sinks` and hold the handler.

An execution is **runnable** when it is live, not aborted, not retained for its output window,
not acknowledged by the retirement quorum, and not in a terminal round: a node joining now can
no longer contribute to anything else.

There is no window, because the final look and the park are **one** critical section: an
execution registered between them would have to take the same mutex, and it publishes after the
park, which reaches the parked sink. There is no duplicate, because the snapshot covers exactly
the executions published up to the cursor and the backlog covers exactly those after it.

**Falling behind ends the stream; it never skips.** Two bounded resources can refuse a notice,
and both are loud. A subscriber whose connection queue is full fails `try_send`, is dropped from
`execution_sinks`, and its handler's stream ends. A subscriber whose cursor is older than the
oldest remembered notice — only reachable if more than `MAX_PUBLICATION_BACKLOG` notices are
published while it is still sending one snapshot — has its stream ended too. Either way it
resubscribes and takes a fresh snapshot; no new error code is needed.

**Corrected: the snapshot has to be authoritative in both directions, so the vocabulary needs a
third notice.** "The stream ends rather than skipping a notice" is true of the stream and false
of the running instance, and `Cancel` is the one notice where the difference matters. The notice
that filled a subscriber's queue is dropped and never redelivered: `publish` drops the entry,
the parked sink's release channel closes, the handler's stream ends, and the fresh subscription
sets its cursor to the current `publication_seq` and takes a snapshot that contains only
`Prepare`s. So without reconciliation a node goes on running an execution the coordinator has
already aborted — and this is not a hypothetical path, it is exactly what
`a_stalled_node_never_blocks_publication_or_another_node` drives on purpose.

`ExecutionNotice::SnapshotComplete` closes every subscription's snapshot, which makes the
omission actionable: a node that reaches it **stops every instance this incarnation of the
coordinator admitted that the snapshot did not name** (the incarnation scope is §12.B's V5
correction box; as this section was written, every instance it was running), exactly as if a
`Cancel` had arrived — which is why the snapshot is computed per subscriber, as the next
correction explains. The marker is what makes the diff
possible at all — a stream of `Prepare`s has no other boundary, so a node cannot otherwise tell
"the snapshot is finished" from "more is coming". One frame per execution is kept rather than
bundling the whole runnable set into one `Snapshot(Vec<_>)`: at
`DEFAULT_MAX_CONCURRENT_EXECUTIONS = 1024` registrations, each carrying a slot table of up to
`MAX_CLIENT_SLOTS`, a single frame would be unbounded against the connection's message size
where per-execution frames are already bounded by the registration bounds of §C.1.

**Corrected again: because omission is an order to stop, the snapshot is per node, and the
predicate is "not acknowledged by this node".** A first implementation filtered the snapshot to
what a node *joining now* could still usefully contribute to, excluding any execution whose
`retirement_acks` had reached the `n - t` quorum or whose round was `ProgramFinished`. Those two
predicates are not the same set as "nobody should be running this", and the gap is precisely the
case the coordinator goes out of its way to support: `retire_execution`'s own contract is that at
`n - t` acknowledgements "its complete round history stays live so a healthy straggler can still
finish", and `retirement_drains_healthy_stragglers_without_pinning_capacity` sets up exactly
n = 5, t = 1, four acknowledgements and asserts the round history survives. A straggler that
resubscribes in that state would have read the omission as the cancellation it missed and killed
work the coordinator was still waiting for.

So `runnable_snapshot` takes the subscriber's `ClientIdentity` and omits an execution only when
it is aborted, when it is being retained purely so late output clients can read their shares
(which already implies unanimous acknowledgement), or when **this** node has acknowledged it.
The retirement quorum and the terminal round carry no weight: an execution this node has not
retired is still its work. The `ExecutionNotice` and `sub_executions` contracts say "every
execution the coordinator still wants *this* node to run", and
`a_terminal_quorum_retired_execution_is_still_published_to_the_party_still_running_it` pins it —
three parties drive the execution to `ProgramFinished`, four retire it, and the fifth's
resubscription still carries its `Prepare` while an acknowledging party's snapshot is empty.

> **Corrected 2026-10-13 (stage S3): the per-node predicate covers only the executions the
> coordinator still holds, so the node has to carry the rest.** The two rules above read as a
> pair — "omission is an order to stop", and "an execution this node has not retired is still
> its work" — and the second looks as though it makes the first safe: if the coordinator never
> omits an execution this node has not acknowledged, every omission a node sees is one it asked
> for. It does not, because `runnable_snapshot` filters the executions the coordinator **still
> holds**, and one it has removed is in no snapshot at all, whatever this node acknowledged.
> Three removal paths reach that state while an instance here is still running: unanimous
> retirement (a party acknowledges during cleanup, so the last one's instance is still unwinding
> when the count completes), expiry of the output-retention window, and capacity eviction, which
> `insert_registration` performs at `retirement_acks.len() >= retirement_quorum()` — `n - t`,
> reachable without a lagging party, which is the very case `retire_execution`'s contract keeps
> the round history alive for.
>
> Each of those paths publishes `Cancel { outcome: Finished }` first, and the node already reads
> that as "retire the identity, leave the instance to its own ending". What was missing is that
> the same fact has to survive into the *next* snapshot. The connection under a subscription ends
> routinely, and on the reconnection that same incarnation's snapshot omits the retired
> execution — which the node read as a dropped `Cancel` and acted on, tearing down a healthy
> straggler and reporting the run of whichever party finished last as `Cancelled`, because stage
> V5's second repair removed `NodeSupervisor::finish_terminal`'s leniency on the stated premise
> that every cancellation the supervisor receives is an order to stop. The `Cancel` path was
> fixed; the snapshot path, which reaches the same code, was not.
>
> **The rule, as built.** A snapshot is authoritative about the set the coordinator serves this
> node, not about why an execution left it, so a node stops an instance the snapshot omits only
> when nothing it already knows explains the omission. **Three** things do, and all three keep
> the instance: another run of the coordinator admitted it (the V5 box above), this coordinator
> has published its retirement, and **this node has acknowledged its own retirement**.
> Everything else stops, which is the dropped-`Cancel` recovery, unweakened — and a live
> instance with no record at all, admitted inside a snapshot whose stream ended before
> `SnapshotComplete` closed it, has no incarnation to match and is kept by the same fail-safe
> default.
>
> The third one is the omission the per-node predicate *causes*, and no notice accompanies it.
> `retire_execution` inserts the acknowledgement immediately (coordinator
> `crates/off-chain/src/lib.rs`) and publishes `Cancel { outcome: Finished }` only at unanimity,
> so for the first n − 1 acknowledging parties `runnable_snapshot` already omits the execution
> from *that* node's snapshot with nothing published behind it. The node sends its
> acknowledgement from inside `PreparedNodeExecution::cleanup`
> (`StandingRunnerExecutionHandler::cleanup_execution_resources` in `bin/stoffel-run.rs`), and
> `NodeSupervisor` runs cleanup before `finish_execution`, so the instance is still live for the
> whole window. A resubscription inside it — the connection under a subscription ends routinely
> — would therefore cancel an execution whose work had already finished and report a successful
> run as `Cancelled`, which is exactly what
> `an_abort_after_the_online_phase_finished_reports_cancelled` shows a cancellation in that
> window does.
>
> **As built.** The per-instance record `InstanceRecord { incarnation, standing }` with
> `InstanceStanding::{Served, Retired}` — where stage V5 kept an incarnation alone — lives in
> `InstanceLedger`, which is what that box's `CoordinatorExecutionStream::incarnations` map has
> become. The ledger is shared (`Arc<InstanceLedger>`) between the stream and the standing
> execution handler, because a retirement reaches the node two ways and only one of them is a
> notice. On the notice path `CoordinatorExecutionStream::retire` marks the standing. On the
> acknowledgement path the *ordering* is the entire content of the fix — the record has to exist
> before the omission it explains can — so the ledger owns that ordering instead of leaving it to
> a call site to keep: `InstanceLedger::retire` is **private**, and the only way the execution
> path can reach it is `InstanceLedger::acknowledge_retirement`, which records the retirement and
> then awaits the acknowledgement it is handed as a closure (a closure rather than a future, so
> the order holds however the caller builds it). `cleanup_execution_resources` sends both its
> node-RPC and its coordinator-RPC retirement from inside that closure, which is what makes the
> ordering reviewable: there is no edit that drops the record while keeping the acknowledgement,
> because deleting the call deletes the acknowledgement with it and writing the record outside
> the method does not compile. `InstanceLedger::judge` decides all three sets under one lock and
> `reconcile_snapshot` reports them as
> `NoticeOutcome::SnapshotReconciled { stopped, kept, retired }`, one log line each.
>
> Pinned by `a_retired_instance_survives_every_later_snapshot_of_the_same_coordinator` (three
> consecutive reconnections keep it, then an abort by name still stops it, because a retired
> identity is not an unstoppable one),
> `a_snapshot_omitting_an_execution_no_retirement_explains_still_stops_it` (two instances of one
> run reconciled together: the retired one kept, the one nothing explains stopped) and
> `an_instance_this_node_has_acknowledged_survives_the_snapshot_that_omission_causes`, which
> drives `acknowledge_retirement` with the resubscription standing in *as* the acknowledgement,
> so its assertion is reached only inside the window the ordering exists for. What each was
> verified against, by mutation: all three fail with the `InstanceStanding::Retired` arm of
> `judge` folded back into the unexplained set, which is the V5 state this box repairs; the third
> additionally fails with `acknowledge_retirement`'s ledger write removed
> (`stopped: [a1, a2], kept: [], retired: []`) and with that write ordered after the
> acknowledgement instead of before it, which is the ordering it is there to pin; and
> `a_snapshot_omitting_an_execution_no_retirement_explains_still_stops_it` together with
> `completing_the_snapshot_stops_exactly_the_instances_it_omitted` and
> `a_restarted_coordinator_stops_nothing_it_never_admitted` fail if an unexplained omission stops
> nothing, so the dropped-`Cancel` recovery is held from both sides.
> `completing_the_snapshot_stops_exactly_the_instances_it_omitted` is otherwise unchanged.
>
> Nothing here changes the coordinator. The per-node predicate stays exactly as the paragraphs
> above state it and
> `a_terminal_quorum_retired_execution_is_still_published_to_the_party_still_running_it` stays
> true; what is withdrawn is the implication that it is sufficient on its own.
>
> **Still open, recorded rather than fixed.** If the `Cancel { outcome: Finished }` notice is
> itself the one a saturated connection drops, the node has no record of the retirement and the
> later omission is indistinguishable from a dropped abort, so the instance is still stopped.
> Closing it needs the coordinator to say, in the snapshot or on request, how an execution it no
> longer serves ended; that is a coordinator-surface change.

The rest of the node-side reconciliation is as the design assumed: `Prepare` is idempotent per
`execution_id` (an instance already running is left alone), and `Cancel` may name an execution
this node never saw a `Prepare` for, so it applies to what it is running and ignores the rest.

**Retirement and abort travel on the same channel.** `remove_execution` already records how
every execution ended, by every path — unanimous retirement, retention expiry, eviction, abort —
and now publishes `ExecutionNotice::Cancel { outcome }` with the `ExecutionOutcome` it recorded.
Because it is the same ordered channel, a node can never see `Cancel` before `Prepare` on one
subscription.

An abort does not wait for removal. `abort_if_due` marks the execution aborted while it is still
live and its nodes are still running it, so it publishes the `Cancel` there — this is the
requirement that cancellation reach a node mid-execution. The execution carries a
`cancel_published` flag so the later removal does not publish a second `Cancel` for the same id.

*As built, the `outcome` is what makes the shared channel safe, and the node reads it: an
`Aborted` `Cancel` is an order to stop and cancels the instance, a `Finished` one retires the
identity and leaves the instance to its own ending. The paragraph above states the coordinator's
half; the node's half was fixed in stage V5's second repair pass, and §9.I's correction box under
the V4 table has it.*

**What bounds concurrent instances per node — still unbuilt after stage V3, and its
justification is gone.**
The coordinator's `DEFAULT_MAX_CONCURRENT_EXECUTIONS = 1024` bounds what *it* hosts and is
preserved unchanged. The node-side cap below does not exist on `dev` — `net/node_supervisor.rs`
has no bound of any kind — and the reason this section gave for it was §12.C's 32-bit
protocol-id collision table, which §12.C no longer needs because the full `ExecutionId` is the
wire envelope. If a per-process instance cap is wanted it is a resource limit, argued as one,
not a cryptographic one. Recorded here as proposed, not as policy:

```rust
// crates/stoffel-vm/src/net/open_registry/router.rs
/// Instances one process hosts at once.
///
/// Not a resource limit — it is what keeps the residual 32-bit protocol-id exposure of
/// §12.C quantified and small. 64 live instances give a birthday collision probability of
/// C(64,2) / 2^32 < 4.7e-7 in the one field this design cannot widen.
pub const MAX_CONCURRENT_INSTANCES: usize = 64;
```

`stoffel-run` takes `--max-instances <n>` (default `MAX_CONCURRENT_INSTANCES`, refused above
it) and the entrypoint maps `STOFFEL_MAX_INSTANCES` onto it.

**At the cap a node queues, it does not refuse.** A `Started` notice for which no slot is free
is appended to a local `VecDeque<ExecutionSummary>` and started when an instance retires.
`sent` still advances, so the stream is never blocked and no later notice is lost. The node
does **not** call `retire_execution` for a queued execution — a retirement acknowledgement is
counted toward a quorum (`retire_execution`, `retirement_quorum` and
`retirement_quorum_reached` in `crates/off-chain/src/lib.rs`; *citation corrected 2026-10-13,
stage S6 — `:2342-2365` is the subscription's `ReplayStep` handling*), so acknowledging work it
has not done would let one node's silence stand in for the mesh's. An execution that is never started is aborted by the
coordinator's own association or input deadline (§9.C.8), which is the existing mechanism and
needs no new timeout.

**While the stream is empty the node runs, idles and waits.** It has joined the mesh (§12.D),
it holds its subscription, and it selects over {the execution stream, per-instance completion,
shutdown}. No timeout, no exit, no error. This is §11.4's open question answered: for a
standing node, no execution is the normal state.

### 12.C The envelope, under concurrency

> **Void 2026-10-12 against `dev`, and must not be implemented.** `dev` already makes the full
> 32-byte `ExecutionId` the mandatory wire envelope: `net/execution_transport.rs` frames every
> message with magic `STXE`, a 38-byte header carrying the whole id, a zero-id refusal on decode,
> per-execution inboxes keyed by the full id, a loud `DuplicateExecution` on a second
> registration, two-level ingress accounting and a single-reader scanner lease. Everything this
> section proposes — `SessionExecutionId`, `try_register_instance`, `OpenRegistryError`,
> widening `instance_id: u64` to 32 bytes across `net/open_registry/wire.rs`, the `u32`
> reservation table, `ProtocolInstanceIdCollision`, `MAX_CONCURRENT_INSTANCES`, a `v2` bump of
> `derive_protocol_instance_id_u32`, and the birthday arithmetic that justified the cap — is
> either absent from `dev` or made unnecessary by that envelope, and implementing it would mean
> reintroducing the v1 mesh layer on top of a tree that deliberately built something else. The
> `u64` instance id and the `u32` protocol id are now interior to one execution's own router and
> carry no cross-execution separation, so their widths do not matter. Kept below as history.

**The envelope is the minted id itself, at every layer the VM owns.**

```rust
// crates/stoffel-vm/src/net/open_registry/router.rs
pub struct OpenMessageRouter {
    registries: DashMap<SessionExecutionId, Weak<InstanceRegistry>>,
    capacity: usize,
}

impl OpenMessageRouter {
    /// Create this execution's registry, or refuse because one is already live.
    ///
    /// Replaces `register_instance`, which was get-or-create. Get-or-create is wrong once a
    /// process hosts many executions: a second claim on a live envelope is either a
    /// collision or a duplicate instance, and merging two computations' message streams is
    /// not a failure mode to resolve silently.
    pub fn try_register_instance(
        &self,
        execution_id: SessionExecutionId,
    ) -> Result<Arc<InstanceRegistry>, OpenRegistryError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpenRegistryError {
    #[error("execution {execution_id} already has a live message registry in this process")]
    InstanceAlreadyRegistered { execution_id: SessionExecutionId },
    #[error("this process already hosts {capacity} instances")]
    InstanceCapacityReached { capacity: usize },
}
```

A `Weak` whose upgrade fails is treated as absent and replaced, exactly as today
(`router.rs:36-41`), which is what makes teardown-then-restart free: dropping the last
`Arc<InstanceRegistry>` releases the envelope.

The wire field widens with the key: `instance_id: u64` becomes
`execution_id: SessionExecutionId` in `OpenRegistryWireMessage::{Single, Batch, Rbc}` and in
`ExpOpenWireMessage` (`crates/stoffel-vm/src/net/open_registry/wire.rs:20-183`), and
`InstanceRegistry::new` takes the same type. The cost is 24 bytes per open-registry frame,
on frames that already carry at least one 48-byte `RobustShare`; batch frames amortise it to
nothing.

**`derive_instance_id` and `INSTANCE_ID_CONTEXT` are deleted, not bumped.** There is no
derivation left at this layer to domain-separate: the envelope *is* the id. A `v3` context
would name a derivation that no longer exists. `crates/stoffel-vm/src/net/session.rs` keeps
only `SessionExecutionId`, loses `UNUSED` (§12.G), and `net/mod.rs:187` re-exports
`SessionExecutionId` alone.

The one derivation that survives changes its input, and *that* is what earns a new context:

```rust
// crates/stoffel-vm/src/net/mpc/protocol_ids.rs
/// `v2` because the input changed shape: `v1` hashed a `u64` instance id, this hashes the
/// 32-byte execution id. Nothing else about the function changed.
const PROTOCOL_INSTANCE_ID_DOMAIN: &[u8] = b"stoffel-mpc-protocol-instance-v2";

pub(crate) fn derive_protocol_instance_id_u32(
    protocol: &[u8],
    execution_id: &SessionExecutionId,
) -> u32;
```

`net/mpc/helpers.rs:22` and `:36` (`honeybadger_protocol_instance_id`,
`avss_protocol_instance_id`) and `net/mpc/avss/session_ids.rs:30` take the id instead of a
`u64`. `MpcInstanceId` (`net/mpc/engine/identity.rs:61`) and `MpcSessionTopology::try_new`
(`:181`) carry `SessionExecutionId`.

**HAZARD 1, resolved: key by the full id, and make the narrow layer loud.**

The choice is not between the two options §11.5 offers; it is both, applied where each
belongs, because the two layers have different owners.

- **Where the VM owns the key, there is no bound to accept.** The registry key and the
  open-registry wire field are ours on both ends, and §9 already declares a breaking release,
  so widening them to the full 32 bytes costs a mechanical change and removes the birthday
  question entirely. Distinct executions have distinct minted ids (§12.A step 2 redraws
  against every id the coordinator remembers), therefore distinct envelopes — **by
  construction, not by probability**. Accepting a 64-bit bound here would mean arguing from
  probability about silent cross-talk between two secret computations, which is the wrong kind
  of argument to make when the alternative is 24 bytes a frame.
- **Where the VM does not own the key, it refuses.** `ProtocolSessionId` is a fixed `u128`
  layout in `stoffelcrypto`, `[reserved 8 | protocol 8 | slot 80 | instance_id 32]`
  (`stoffelcrypto-0.1.1/src/common/mod.rs:488-507`), and `HoneyBadgerMPCNode::process`
  filters incoming frames on `session_id.instance_id() != self.params.instance_id`
  (`src/honeybadger/mod.rs:734`, `:857`). That field is 32 bits and this design cannot widen
  it. **§11.2's claim that "widths are unaffected" is wrong and is corrected here:** the
  reduction's *width* is unaffected, but a `u32` was sufficient when one process ran one
  instance and is not sufficient when it runs many.

  So the node keeps a process-local reservation table beside the router,
  `protocol_ids: DashMap<u32, SessionExecutionId>`, and an instance start that finds its
  derived `u32` already held by another live execution fails with

  ```rust
  #[error(
      "execution {execution_id} reduces to protocol instance id {protocol_instance_id:#010x}, \
       which execution {held_by} is already using in this process; refusing to start it"
  )]
  ProtocolInstanceIdCollision {
      execution_id: SessionExecutionId,
      held_by: SessionExecutionId,
      protocol_instance_id: u32,
  }
  ```

  **What a collision does if it occurs.** The reduction is deterministic and identical at
  every party, so every honest node of the roster refuses the *same* execution — the
  refusal is unanimous, not a partition. The node reports it and does not acknowledge the
  execution (§12.B), the coordinator's deadline sweeper aborts it, and the operator registers
  the work again: the next registration mints a different id and almost certainly does not
  collide. Nothing is merged, and nothing runs under a shared protocol id.

  **The arithmetic, stated rather than waved at.** With `k` live instances in one process the
  collision probability is `C(k,2) / 2^32`: `4.7e-7` at `k = 64`
  (`MAX_CONCURRENT_INSTANCES`), `7.6e-6` at 256, `1.2e-4` at the coordinator's 1024. That is
  why §12.B caps instances per *process* rather than relying on the coordinator's cap, and why
  the cap is 64. **Follow-up, named:** widening
  `ProtocolSessionId::instance_id` to 64 bits in `stoffelcrypto` removes the table, the error
  and the cap's reason to be small; it is a breaking change to a published crate and is out of
  scope here.

**The property claimed for two concurrent executions of the same program on one roster.**
This is the case §11.1 says fails today, and the claim is deliberately two claims:

1. **At every VM-owned layer, their envelopes are distinct by construction.** No open-share,
   batch-open, open-in-exponent or RBC frame of one can be accumulated into the other's
   `InstanceRegistry`: the frame carries the 32-byte minted id, the registry is keyed by it,
   and `try_handle_wire_message` already drops a frame whose instance has no registry
   (`router.rs:119-122`). Nor can one instance's engine be handed the other's registry:
   `try_register_instance` refuses a second claim by name.
2. **At the `stoffelcrypto` protocol-id layer, they are distinct with probability at least
   `1 - C(k,2)/2^32`**, and a collision is refused by name at instance start rather than
   merged. That is weaker, it is the external crate's field width, and it is stated as a
   bound rather than as a property.

Neither claim depends on the program, so two executions of the *same* program are separated
exactly as well as two of different programs — which is the specific thing the
`(roster_digest, program_id, epoch)` derivation could not do.

### 12.D The join becomes execution-independent

> **Built 2026-10-12 (V2), and not the way this section proposed. Read the as-built block at
> the end of this section first; the body below is the design it was built from, and three of
> its prescriptions are void.** In one line: the join commits to the roster, a one-shot party
> commits to its execution *in the same frame*, and none of the barrier-namespace work applies
> because the barrier types this section widens were never built on `dev`.
>
> **Superseded in part, and corrected again after stage V2.** On `dev` the roster-only mesh was
> `MeshInfo` (`net/session.rs:150-166`), which documented that execution and program identity
> deliberately do not appear in it. V2 deleted that type — it was defined and never used — and
> built `net/mesh/join.rs`, whose `MeshCommit { roster_digest, n_parties, threshold, session }`
> carries the same property: `session` is `None` on a standing node, because concurrent programs
> share its one certificate-pinned mesh and carry their own execution ids inside transport
> envelopes, and `Some` only on a one-shot party whose process exists to run one execution. So
> there *is* a `join.rs` and a commit frame on this branch, contrary to the sentence this block
> replaces; what remains true is that there is no per-execution re-join to change. The per-execution agreement step this section builds
> toward exists as `preprocessing_transcript_exchange`'s phase enum (§11.5). One thing the
> bootnode *was* doing has no successor yet and belongs to the mesh stage, not here:
> `net/discovery/bootnode.rs:144-148` centrally refuses a party whose registration differs from
> the pending one on `(execution_id, program_id, entry, n_parties, threshold)`. Deleting the
> bootnode deletes that check.

The mesh is per **roster**: one authenticated all-to-all transport carrying many instances.
A node cannot re-join the mesh per computation, so committing to a single execution inside
`JoinCommit` (`join.rs:186`, `:220`) is the wrong layer once there are many. The evidence is
in the join itself: `join_mesh` checks `request.n_parties` and `request.threshold` against the
roster and refuses a mismatch (`:394-407`), installs the roster as the transport allowlist
(`:409`), ranks this node by roster position (`:411-417`), and dials by rank — every one of
those is a statement about the roster. `program_id`, `entry` and `execution_id` are carried
through the same handshake and used for none of it; they appear only in `SessionProposal`,
`session_digest` and the `MeshSession` the runner reads afterwards.

**What the transport join agrees on: the roster, and nothing else.** `n` and `t` are already
inside `NodeRoster::digest()` — `roster-digest --t 1 --node-certs …` hashes the threshold with
the certificates (§10.2), and `n` is the number of certificates — so agreeing the roster
digest agrees `n` and `t` with it. `program_id` and `entry` **cannot** be in it: one mesh now
carries several programs, so there is no mesh-wide program to agree on. They move to §12.D's
per-execution step, where they belong, because that is the scope in which they are constant.

```rust
// crates/stoffel-vm/src/net/mesh/mod.rs
/// What a node asks for when it wants to join its roster's mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub my_party_id: PartyId,
    pub my_listen: SocketAddr,
    pub n_parties: usize,
    pub threshold: usize,
    pub timeout: Duration,
}

/// The transport every node of one roster shares. Carries no execution, no program and no
/// instance: those are per-execution (§12.D) and many ride one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshTransport {
    pub roster_digest: [u8; 32],
    pub parties: Vec<(PartyId, SocketAddr)>,
    pub n_parties: usize,
    pub threshold: usize,
}

pub trait SessionJoin {
    async fn join(&self, net: &mut QuicNetworkManager, request: JoinRequest)
        -> MeshResult<MeshTransport>;
}
```

`JoinRequest` loses `program_id`, `entry` and `execution_id`; `MeshSession` becomes
`MeshTransport` and loses `program_id`, `entry` and `instance_id`. The five construction
sites are `net/mesh/mod.rs:365` (unit test), `tests/mesh_join_harness.rs:635`, `:1726`,
`:1940` and `stoffel-run.rs:3841`.

**What replaces the execution's place in the digest: the full roster digest, and nothing
else.** `SessionProposal`, `MeshMessage::JoinProposal` and `MeshMessage::JoinCommit` collapse
into one frame, because with the epoch gone (§12.E) there is nothing left to *propose* — every
remaining field is already fixed by the roster each party installed, so the exchange is a
commitment, not a negotiation:

```rust
// crates/stoffel-vm/src/net/mesh/wire.rs
MeshMessage::MeshCommit { roster_digest: [u8; 32] }
```

```rust
// crates/stoffel-vm/src/net/mesh/join.rs
/// Deleted: `session_digest`, `SESSION_DIGEST_CONTEXT`, `SessionProposal`,
/// `SessionProposal::first_divergence`, `SessionField`.
```

`MeshError::{SessionDivergence, CommitDivergence}` are replaced by one variant:

```rust
#[error(
    "party {party_id} committed to roster {got} where this node committed {expected}; \
     the mesh is not one roster"
)]
RosterDigestDivergence { party_id: PartyId, expected: String, got: String },
```

This is strictly stronger than what it replaces at the transport layer: the `MeshReady`
barrier frame compares only the low 64 bits of the roster digest
(`roster_namespace`, `join.rs:241-245`, `MeshError::RosterNamespaceMismatch`), and `MeshCommit`
compares all 32 bytes. `SessionField` disappears because there is one field left and naming it
adds nothing; the enum existed so that adding an agreed field was a compile error, and
`MeshCommit` with one field makes that moot.

**The per-execution agreement step.** One new module, built on the digest-barrier machinery
§9.D.6 already added — which is exactly "a digest every party announces over the shared mesh,
under a per-execution namespace", and is the right primitive precisely because it runs on an
established mesh rather than forming one:

```rust
// crates/stoffel-vm/src/net/mesh/execution.rs  (new)
/// BLAKE3 derive-key context for [`execution_digest`].
///
/// Domain-separated from the coordinator's node-roster digest
/// (`stoffel-coordinator-node-roster-v1`), the program content address
/// (`stoffel-program-v1`) and the per-protocol reduction
/// (`stoffel-mpc-protocol-instance-v2`).
pub const EXECUTION_DIGEST_CONTEXT: &str = "stoffel-execution-agreement-v1";

/// What every party of one execution commits to, over the mesh they already share.
///
/// Canonical: every variable-length field is length-prefixed, every number is fixed-width
/// little-endian.
pub fn execution_digest(
    roster_digest: &[u8; 32],
    execution_id: &SessionExecutionId,
    registration_nonce: &[u8; 32],
    program_id: &[u8; 32],
    entry: &str,
    n_parties: u64,
    threshold: u64,
) -> [u8; 32];
```

It commits to:

| Field | Why it is in the digest |
|---|---|
| `roster_digest` | an execution cannot be agreed across two meshes, and it binds `n` and `t` |
| `execution_id` | the equivocation check: all `n` were pointed at the same execution |
| `registration_nonce` | a re-registration of the same shape is a different agreement; this is already the anti-replay value clients sign (§9.C.7) |
| `program_id` | the content address of the program this node actually loaded, which `n_parties` of one mesh may now differ on |
| `entry` | the entry point, for the same reason |
| `n_parties`, `threshold` | redundant with the roster digest, kept so the digest is readable on its own |

```rust
/// A peer committed to a different execution than this node.
///
/// Where the equivocation check `JoinCommit` used to carry now lives (§11.4). The
/// coordinator pointed the nodes of one mesh at different executions, or at different
/// programs for one execution: no preprocessing is drawn, no mask share released and no
/// input stored for it.
#[error(
    "party {party_id} committed to a different execution than this node; \
     the coordinator is equivocating"
)]
ExecutionDivergence { party_id: PartyId },
```

The step runs as **step 0 of §9.D.7's per-execution sequence**, before preprocessing, before
`get_client_admissions` and before any mask share — the position `JoinCommit` used to occupy.
It is one all-to-all announcement on an established mesh: `n - 1` sends and `n - 1` receives
of a `prefix || execution_id || digest` frame, no dialing, no barrier timeout of its own
beyond `agreement_barrier_timeout()`. A node can run it for many executions concurrently,
which is the whole point.

**Barrier namespaces widen with the envelope.** `DigestBarrierTag::classify` accepts
`prefix || namespace (u64 LE) || digest (32)` (`barrier.rs:390-404`) and
`BarrierTag::classify` accepts `prefix || namespace (u64 LE)` (`:153-166`), with the namespace
being the `u64` instance id at every construction site (`stoffel-run.rs:570`, `:576`,
`:2003`). A 64-bit namespace under a 32-byte envelope would reintroduce the bound §12.C just
removed, so:

- `DigestBarrierTag` gains `ExecutionAgreed` and its frames become
  `prefix || execution_id (32) || digest (32)`.
- `BarrierTag::PreprocessingReady` and `BarrierTag::OutputReady` are per-execution and their
  frames become `prefix || execution_id (32)`. `BarrierTag::MeshReady` is per-process and
  per-roster and keeps `prefix || roster_namespace (u64 LE)`, because the full roster digest is
  committed by `MeshCommit` a moment later and a 64-bit prefix mismatch there is only an early
  refusal.
- `BarrierTag::classify` and `DigestBarrierTag::classify` therefore accept a per-tag length.
  `MeshBarrier::new` and `DigestBarrier::new` take `SessionExecutionId` for the
  per-execution tags.

#### 12.D as built (V2, 2026-10-12)

Three of this section's prescriptions were followed, and three were not.

**Followed.** `JoinRequest` lost `program_id`, `entry` and `execution_id`; `MeshSession` became
`MeshTransport`; `SessionProposal`, `session_digest`'s old shape, `SessionProposal::first_divergence`
and the old `SessionField` are gone; `MeshError::{SessionDivergence, CommitDivergence}` collapsed.
`MeshTransport` carries `roster_digest`, `commit_digest`, `parties`, `n_parties` and `threshold`
— `commit_digest` beside the roster digest because a one-shot mesh commits to more than its
roster and the two values are not the same statement.

**Not followed 1: one frame, not two agreements.** This section proposed
`MeshCommit { roster_digest }` for the transport and a separate `net/mesh/execution.rs` with its
own `execution_digest` and its own all-to-all round for the per-execution agreement. What landed
is one frame carrying an `Option<SessionCommitment>`:

```rust
MeshCommit {
    roster_digest: [u8; 32],
    n_parties: u64,
    threshold: u64,
    session: Option<SessionCommitment>,   // { execution_id, program_id, entry }
}
```

`None` is a standing node: many executions ride its mesh, so the roster is the whole agreement,
exactly as this section argued. `Some` is a one-shot party, whose process exists to run one
execution — so for it there is no second scope to agree in, and a second round would be a round
spent proving something the first round already covered. A standing node committing `None` and a
one-shot party committing `Some` on the same roster are named as diverging on
`SessionField::SessionScope` rather than silently digesting differently.

This keeps both properties the two-round shape was reaching for. Field-by-field comparison names
*which* field diverged (`MeshError::CommitDivergence`), which a digest cannot; and the digest
derived from the peer's fields must still equal this node's
(`MeshError::CommitDigestDivergence`), which catches a field added to the frame but not to the
comparison. `SessionField` therefore survives rather than disappearing: this section expected one
agreed field to be left, and there are seven.

**What §12.D's `execution.rs` is still right about** is the case this stage does not reach: a
*standing* node running many executions needs a per-execution agreement, on an established mesh,
in each execution's own namespace. That is V3's, with the downward execution stream, and
`registration_nonce` belongs in it. V2 built the one-shot half, where the agreement and the join
are the same event.

**Not followed 2: no barrier namespaces widened.** "Barrier namespaces widen with the envelope"
is void. `BarrierTag`, `DigestBarrierTag`, `MeshBarrier`, `DigestBarrier`,
`HB_PREPROCESSING_READY_PREFIX`, `OUTPUT_READY_PREFIX`, `ADMISSIONS_AGREED_PREFIX` and
`INPUTS_AGREED_PREFIX` do not exist on `dev` — they were `main`-only — so there is nothing to
re-namespace. The one barrier V2 needed is `MESH_READY_PREFIX || roster_namespace (u64 LE)`,
written and read inside the handshake, and it keeps the 64-bit namespace for the reason this
section already gave: the full 32 bytes are committed a frame later, so a prefix mismatch there
is only an early refusal.

**Not followed 3: no `MeshRouter` on the receive loops.** B6's premise does not hold on `dev`.
`spawn_receive_loops` and `spawn_receive_loops_split` have no callers outside re-exports, AVSS's
per-connection loops are not on the party path, and every party byte travels an `STXE` envelope
read by `ExecutionConnectionScanner` — which closes the connection on anything else (see the B7
block in §6). A router chained onto those loops would have no reader and could never be reached,
so `net/mesh/router.rs` was not ported. What the peer book needed was a shared handle, and that
is `pex::PeerDirectory`: `seed` / `observe_verified` / `observe_relayed` / `dial_targets` /
`snapshot`, with the `RecordSource` ranking and the `MAX_PEX_SEQ_JUMP` bound intact, because
those are what make an unsigned address safe to act on. `MeshEvent`, `PeerRequest`,
`take_peer_requests`, `peer_book_frame`, the heartbeat map, the per-sender rate limiter and
`try_handle_wire_message` went with the router: the frames they served have no sender and their
callers have no reader. The per-frame record cap survives where the frame is decoded
(`wire::check_record_bound`).

### 12.E Epoch retirement

> **Void 2026-10-12: nothing to retire.** See §11.3 — no epoch store, flag, environment
> variable or agreement round exists on `dev`. Kept as history.

**Deleted outright.** The epoch store exists solely for `instance_id` freshness (blocker
**B5**), and a minted id *is* freshness, from the party that already owns admission (§11.3).

| Deleted | Where |
|---|---|
| `EpochStore`, `agree_epoch`, `MAX_EPOCH_JUMP`, `EPOCH_STORE_ENV`, `epoch_store_path`, `EpochError`, the LMDB environment and its `epochs` database | `crates/stoffel-vm/src/net/mesh/epoch.rs` — the whole module |
| `pub use epoch::{…}` and `pub mod epoch` | `net/mesh/mod.rs:24`, `:41-43` |
| `MeshError::Epoch` | `net/mesh/mod.rs:210-214` |
| `use …epoch::{agree_epoch, EpochStore}`, `MeshJoin.epochs`, `MeshJoin::new`'s third argument, `join_mesh`'s `epochs` parameter, `epochs.propose`, `epochs.commit`, the `epoch` field of `JoinProposal` and of `session_digest`, `agree_epoch` at the agreement | `join.rs:120`, `:308`, `:315`, `:368`, `:391`, `:425`, `:482`, `:182`, `:192`, `:1169`, `:1193`, `:1239`, `:1263`, `:1267` |
| the epoch half of `derive_instance_id`, and the roster digest with it | `net/session.rs` — the whole function goes (§12.C); the roster digest was only there because the counter is keyed per digest, so it leaves with the counter |
| `--epoch-store`, `STOFFEL_EPOCH_STORE`, `epoch_store_flag`, the `EpochStore::open` at startup, the usage text and the examples | `stoffel-run.rs:26`, `:1061-1077`, `:3068-3071`, `:3115`, `:3341-3343`, `:3499-3503`, `:3829`, `:4725-4728`, `:4739`, `:4756-4757`, `:4780-4792` |
| `ServerBuilder::epoch_store`, `configured_epoch_store`, `Server::epoch_store`, the `epoch_store.is_none()` refusal, the `--epoch-store` argument | `crates/stoffel-rust-sdk/src/server.rs:91`, `:128`, `:153`, `:321-323`, `:415-416`, `:602`, `:819`, `:907-917`, `:1004-1005`, `:1212-1213` |
| `epoch_store` / `epoch_stores` in the local runner's layout | `crates/stoffel-vm-runner/src/local_runner.rs:1207`, `:1222`, `:1239`, `:1250`, `:1259-1268`, `:1286`, `:1331`, `:1598`, `:1629`, `:1714-1715` |
| `STOFFEL_EPOCH_STORE` entries and the volumes and comments that exist for them | `docker-compose.yml:282,334,380,426,472`; `docker-compose.mesh.yml:250,287,324,361,398`; `docker-compose.avss.yml:246,253,321,385,449,513`; `docker-compose.benchmark.yml:49,220,254,284,314,344`; `docker-compose.coordinator.reserve-index.yml:95,230,268,297,326,355`; `docker-compose.coordinator.reserve-index.preproc.yml:6,33,40,47,54,61`; `crates/stoffel-lang/examples/docker-compose.mpc.yml:87,177,207,237,267,297`; `crates/stoffel-lang/examples/docker-compose.coordinator.yml:54,221,254,283,312,341` |
| `STOFFEL_EPOCH_STORE` plumbing and the `Epoch Store:` banner line | `docker/entrypoint.sh:191`, `:423-424` |
| `--epoch-store` and `EXECUTION_ID` | `crates/stoffel-lang/examples/run_mpc_local.sh:43`, `:170` |
| the `--epoch-store` sentence | `README.md:472` |
| nothing in `Cargo.toml`: `heed` (`crates/stoffel-vm/Cargo.toml:64`) stays, because `crates/stoffel-vm/src/storage/preproc.rs` is its other user and §10.1 keeps the preprocessing store | — |

Named volumes that existed only to hold an epoch store (`stoffel-epochs` and the `/app/epochs`
mounts of `docker-compose.benchmark.yml` and the two `coordinator.reserve-index` stacks) go
with it. `stoffel-local-store` and `/app/data` stay: they also hold the preprocessing store,
which §10.1 keeps deliberately.

**What must survive, and is not subsumed by a minted id.** One thing, and it is small but it
is real:

`join_mesh` uses the proposed epoch as the PEX sequence number of this node's own record —
`PeerRecord::new(&local, request.my_listen, my_epoch)` (`join.rs:425-426`). `seq` is not a
freshness input to any namespace; it bounds how a **relayed** record may displace a stored one
(`pex.rs:356-358`, `MAX_PEX_SEQ_JUMP = 4096`). It is replaced by a process-local counter on
`SharedMeshRouter`, starting at 1 and incremented on each re-announcement:

```rust
// crates/stoffel-vm/src/net/mesh/pex.rs
/// This node's own announcement counter, per process.
///
/// Weaker than the persisted epoch it replaces, and deliberately so: `PeerBook::observe`
/// rule 2 applies a first-party `Announced` or `Local` record without consulting `seq`
/// (`pex.rs:346-352`), explicitly so that "a node whose counter reset across a restart
/// [can] advertise again immediately". A roster mesh is all-to-all, so every record a node
/// needs about a peer arrives first-hand on that peer's own authenticated connection;
/// relays only fill gaps during discovery, and a gap filled with a stale address costs one
/// mis-aimed pinned probe, which `dial_address_expecting` refuses.
```

Stating it plainly: **across a process restart, a relayed record about this node can no longer
be displaced by `seq` alone.** Rule 2 is what makes that acceptable, and it is a documented
property of the book rather than a consequence of the epoch. No other property of the epoch
store is unsubsumed.

**Tests that die with it** (their contract is the epoch, and the epoch is gone):

| Test | Location |
|---|---|
| `a_fresh_store_proposes_one_and_remembers_what_it_commits` | `net/mesh/epoch.rs` |
| `proposing_does_not_advance_the_counter` | same |
| `epochs_are_kept_per_roster` | same |
| `an_unbounded_proposal_is_refused_rather_than_bricking_the_store` | same |
| `the_agreed_epoch_is_the_largest_proposal_within_the_bound` | same |
| `an_epoch_never_moves_backwards` | same |
| `an_operator_can_fast_forward_past_the_bound` | same |
| `an_epoch_survives_reopening_the_store` | same |
| `an_explicit_path_wins_over_the_environment_default` | same |
| `a_party_proposing_a_wildly_advanced_epoch_is_refused` | `tests/mesh_join_harness.rs:1881` |
| `an_sdk_mesh_server_without_seeds_a_coordinator_pin_or_an_epoch_store_is_refused` | `stoffel-rust-sdk/tests/sdk_usage.rs:2555` — the epoch-store arm only; see below |

`a_party_proposing_a_wildly_advanced_epoch_is_refused` is the clearest case: it exists to pin
`MAX_EPOCH_JUMP`'s Byzantine bound, the bound exists because the agreed value is
`max(proposals)`, and after §12.A nothing is proposed. The bound does not move to another
layer, because the coordinator's mint is not a proposal anyone can inflate. Deleting it
removes no surviving behaviour.

**Tests retargeted** (their contract is freshness or divergence, which survives):

| Test | Location | Retargeted to |
|---|---|---|
| `a_mesh_join_produces_a_fresh_instance_id_per_run` | `tests/mesh_join_harness.rs:926` | §12.J's `two_concurrent_executions_of_one_program_do_not_share_an_envelope`. The property — one roster, one program, one entry, two runs, different envelopes — is the same statement; it is now asserted over two *concurrent* minted ids instead of two sequential epochs, which is strictly the harder case |
| `the_instance_id_depends_on_the_roster_digest` | `net/session.rs` | deleted with `derive_instance_id`; its "must actually differ" half is carried by the test above |
| `a_new_epoch_is_a_new_session_namespace_for_one_program` | `net/session.rs` | same |
| `a_party_started_for_another_execution_is_refused_by_name` | `tests/mesh_join_harness.rs:1830` | §12.J's `parties_pointed_at_different_executions_fail_with_execution_divergence`. The contract — a party pointed at another execution is named and refused — survives; the layer moves from the transport join to the per-execution agreement, and the error from `SessionDivergence { field: ExecutionId }` to `ExecutionDivergence` |
| `a_party_proposing_a_different_session_is_refused_by_name` | `:1822` | kept, narrowed to `Divergence::Roster` at the transport join (`RosterDigestDivergence`), and its `Entry` arm moves to the per-execution test above, since entry is no longer a transport-join field |
| `an_sdk_mesh_server_without_seeds_a_coordinator_pin_or_an_epoch_store_is_refused` | `sdk_usage.rs:2555` | keeps the seeds and coordinator-pin arms, loses the epoch-store arm and the `epoch_store()` assertion at `:2603` |
| `the_mesh_topology_replaces_bootstrap_with_seeds_a_roster_and_an_epoch_store` (already retargeted once, `local_runner.rs:1629`) | `local_runner.rs` | asserts seeds and roster only; the `epochs-party-N` assertions at `:1714-1715` go |

### 12.F Two modes, not one lifecycle

§11.5 dissolves the old open question: exiting is a property of a mode, not of the model.

> **Corrected 2026-10-13 against this tree (stage V5 repair).** The two modes are real and
> built, but every name below them is the `main`-based attempt's, and seven statements of this
> subsection are not true of `feature/no-bootnode-v2`. §11.5 carries the same kind of box; this
> one was missing, which made the stale body read as contract.
>
> 1. **The flag is `--standing-node`, not `--standing`**, and it is dispatched before the
>    client/party/local mode split (`main` dispatches on
>    `is_flag_present(&raw_args, "--standing-node")` into `run_standing_node`), because a
>    standing node is a third mode and not a modifier on the party one.
> 2. **There is no `STOFFEL_STANDING` mapping.** `docker/entrypoint.sh` does not read it and no
>    stack sets it. `docker-compose.standing-concurrency.yml` passes `--standing-node` in the
>    node command itself; the `STOFFEL_STANDING_*` variables that stack does carry name the pool
>    id, the client-certificate directory, the reservoir burst capacity and the extra arguments,
>    not the mode.
> 3. **There is no `crates/stoffel-vm-runner/src/instances.rs` and no `InstanceSupervisor`.**
>    What hosts the instances is `NodeSupervisor` in
>    `crates/stoffel-vm/src/net/node_supervisor.rs` — `prepare`, `cancel`, `live_executions`,
>    `is_live`, `shutdown`, reporting through an `mpsc` of `NodeEvent`/`NodeEventKind` — which
>    `dev` already had and which this change integrates with rather than replacing. There is no
>    `start`/`stop` pair: admission is `prepare`, taking the execution's body as a future, and
>    teardown is `cancel`.
> 4. **There is no `crates/stoffel-vm-runner/src/executions.rs`.** The subscription is
>    `CoordinatorExecutionStream` in `crates/stoffel-vm-runner/src/execution_stream.rs`, with
>    `StandingProgramCatalog`, `StandingClientCatalog`, `SnapshotCursor`, `NoticeOutcome` and
>    `CoordinatorLinkSource` beside it.
> 5. **The notice vocabulary is `Prepare` / `Cancel` / `SnapshotComplete`, not
>    `Started` / `Ended`** (`ExecutionNotice` in `crates/off-chain/src/lib.rs`). An instance is
>    spawned by
>    `ExecutionNotice::Prepare(PublishedExecution)` and torn down by
>    `ExecutionNotice::Cancel { execution_id, outcome }` — where the teardown is the
>    `outcome: Aborted(reason)` case only. The coordinator publishes a `Cancel` for a *finished*
>    execution too, as `outcome: Finished`, because the roster is told of every removal whatever
>    its reason; that one is caused by the parties' own retirement acknowledgements, so a node
>    retires the identity and leaves the instance alone rather than racing its own completion
>    against the notice that completion caused (§9.I, the V4 table's first row and the correction
>    under it). `SnapshotComplete { incarnation }` is the
>    third notice and has no counterpart in the body below: it reconciles the opening snapshot,
>    stopping the instances *this* incarnation admitted and its snapshot did not name and keeping
>    those another incarnation admitted (`NoticeOutcome::SnapshotReconciled`, which stage S3
>    widened from `{ stopped, kept }` to `{ stopped, kept, retired }` — see §12.B's S3 box for
>    the third set and why it exists).
> 6. **No party is passed `--execution-id`, and `local_runner.rs` passes none.** Party mode
>    *forbids* the flag (`validate_forbidden_cli_parameters("party mode", …)` in
>    `stoffel-run.rs`); the string does not occur in `local_runner.rs` at all. The mode
>    table's parenthesis about `:617-619` describes the flow stage V3 reversed. The flag survives
>    in client mode only, where it is required, because a client joins an execution the
>    coordinator already minted.
> 7. **The one-shot rule is narrower than "takes the first notice and declines the rest".** As
>    built, `take_published_execution` (`stoffel-run.rs`) declines a `Prepare` that names a
>    *different program* and keeps reading — a one-shot party may be started before its execution
>    is registered, and the opening snapshot may hold other programs' executions — *refuses* a
>    `Prepare` for its program with a different entry function, and ignores `Cancel` and
>    `SnapshotComplete`, having nothing yet to cancel. The log line is
>    `[party] declining execution <hex>: it names program <hex>, and this party holds <hex>`.
>    The body's text, which names the execution it is "already running", describes a rule that
>    was never built. The conclusion below holds — a declined execution is never acknowledged —
>    but not for the reason first given here. The coordinator's `retire_execution()` has three
>    callers in `stoffel-run.rs`: `cleanup_execution_resources`, `run_avss_coordinated_party_for_curve`
>    (the AVSS one-off party path) and `main` (the HoneyBadger one-off party path); the latter two
>    are gated on `if one_off` after the online phase completed. All three are reached only for an
>    execution this process actually ran, so a declined one reaches none of them. The
>    `node_rpc.retire_execution` call in the first of those functions is this node's own local
>    retire, a different method that no retirement quorum counts; the coordinator-facing one
>    beside it is sent from inside `InstanceLedger::acknowledge_retirement` (§12.B's S3 box).
>
> One further difference, in the "coordinator connection drops" paragraph: the stream does
> reconnect with bounded exponential backoff while live instances keep running, as designed, but
> it **takes a fresh snapshot** rather than replaying with `from_seq: sent`
> (`CoordinatorExecutionStream::run` in `execution_stream.rs`), and `SnapshotComplete`'s
> reconciliation (point 5) is what
> makes that safe. A node that loses a *per-execution* coordinator link, as opposed to the
> subscription, still has no recovery — see §9.I's open gaps.

**Selection.** An explicit flag, defaulting to the behaviour every current stack has:

```text
--standing        Serve executions as the coordinator publishes them, and keep running when
                  there are none. Without it, this node runs one execution and exits.
```

`docker/entrypoint.sh` maps `STOFFEL_STANDING` (`1`/`true`/`yes`) onto it. The default is
one-shot because silence must keep meaning what it means today: every compose stack, every
script and every test in both repositories expects a node that exits.

**One-shot.** Subscribes, takes the **first** `Started` notice, runs that execution, calls
`retire_execution`, exits with the program's exit code. Offered several executions it
instantiates exactly one and logs each further notice as declined, by name:

```text
[party 3] declining execution <64 hex>: this node is one-shot and is already running <64 hex>
```

It **does not** call `retire_execution` for a declined execution. A retirement
acknowledgement is counted toward the retirement quorum (`retire_execution` and
`retirement_quorum` in `crates/off-chain/src/lib.rs`; *citation corrected 2026-10-13, stage
S6 — `:2342-2365` is the subscription's `ReplayStep` handling, not the quorum*), so
acknowledging an execution it never ran would
let its silence stand in for the mesh's and let a one-off coordinator start draining an
execution no node has performed. Declined executions are aborted by the coordinator's own
deadlines (§9.C.8).

**Standing.** Joins the mesh, subscribes, and serves instances as they arrive. With none, it
idles: no timeout, no exit, no error.

**Which existing stacks and tests map onto which.**

| Mode | Stacks and tests |
|---|---|
| One-shot (default, unchanged behaviour) | every node service of `docker-compose.yml`, `docker-compose.avss.yml`, `docker-compose.benchmark.yml`, `docker-compose.coordinator.reserve-index.yml`, `docker-compose.coordinator.reserve-index.preproc.yml`, `docker-compose.coordinator.reserve-index.oneshot-preproc.yml`, `crates/stoffel-lang/examples/docker-compose.mpc.yml`, `crates/stoffel-lang/examples/docker-compose.coordinator.yml`; `docker/test-coordinator-reserve-index.sh`, `docker/test-coordinator-preproc-store.sh`, `docker/test-oneshot-preproc-store.sh`; `crates/stoffel-lang/examples/run_mpc_local.sh`; `crates/stoffel-vm-runner/src/local_runner.rs` (it passes `--execution-id` per party at `:617-619` and waits for each child to exit at `:1427`); every `crates/stoffel-rust-sdk/tests/sdk_usage.rs` server test |
| Standing | §12.J's concurrency tests only, and the persistent network of `docs/design/persistent-mpc-network-plan.md`, which is what the mode exists for |

**Instance lifecycle inside a standing process.**

```rust
// crates/stoffel-vm-runner/src/instances.rs  (new)
/// Every instance this process hosts, on one shared mesh transport and one shared
/// `OpenMessageRouter`.
pub struct InstanceSupervisor { /* … */ }

impl InstanceSupervisor {
    /// Start an instance for `summary`. Idempotent per `execution_id`.
    pub async fn start(&self, summary: ExecutionSummary) -> Result<(), InstanceError>;
    /// Tear `execution_id` down, whatever it was doing.
    pub async fn stop(&self, execution_id: ExecutionId, reason: StopReason);
}
```

- **What spawns an instance.** `ExecutionNotice::Started`, through `InstanceSupervisor::start`,
  once a slot is free (§12.B). `start` reserves the envelope
  (`try_register_instance`) and the `u32` protocol id (§12.C), runs the per-execution
  agreement (§12.D) on the shared mesh, builds this execution's engine, VM and MPC runner,
  and spawns its task. Everything per-roster — the transport, the roster, the party index, the
  coordinator link, the `OpenMessageRouter`, the preprocessing store — is shared and built
  once per process.
- **What tears it down.** `ExecutionNotice::Ended`, or the instance's own completion. Teardown
  aborts the task, drops the last `Arc<InstanceRegistry>` (which frees the router slot through
  the `Weak`), releases the `u32` reservation, drops the per-execution barriers, and — on local
  completion only — calls `retire_execution`. Teardown on `Ended` sends no acknowledgement: the
  execution has already left the coordinator's state.
- **What happens when the coordinator connection drops.** Today a node whose coordinator link
  drops exits 13. **That does not survive concurrency, and the change is deliberate:** the
  link is per-process and shared by N instances, so letting it kill the process would end N
  computations because of one connection. In a standing process the stream client
  (`crates/stoffel-vm-runner/src/executions.rs`) reconnects with bounded exponential backoff
  and re-subscribes with `from_seq: sent`, replaying what it missed; live instances keep
  running, because the mesh is a separate transport that the coordinator is not on. An
  instance that needs the coordinator for its next step — a round, the frozen admissions, the
  masked inputs — blocks where it already blocks and is aborted by that execution's own
  deadline, which is the existing mechanism. **A one-shot node keeps today's behaviour
  exactly:** its link dropping before its single execution finished exits 13, because there is
  nothing else in the process to protect, and that is what the current tests assert.

### 12.G Configuration removed

Nothing in this list leaves a trace behind it (§13): no refusal-by-name guard, no
`fail_removed_flag` entry, no hint text, whether or not it shipped. A removed flag is an
ordinary unknown argument and a removed environment variable is simply ignored.

| Removed |
|---|
| `--execution-id` on `stoffel-run` in party mode — **done in stage V3**. It stays in client mode; see the correction below |
| `STOFFEL_EXECUTION_ID` for the `party` role in `docker/entrypoint.sh` and in every compose party environment — **done in stage V3** |
| `OffChainServerConfig::execution_id` and `OffChainServerConfigBuilder::execution_id` in the Rust SDK — **done in stage V3** |
| `--execution-id` on `docker/coordinator-wrapper` |
| `--execution-id` on the coordinator's `run-coord`, with `parse_nonzero_execution_id` — **done in stage C1** |
| `--control-dir` on `stoffel-run`, and the standing control directory's whole command vocabulary — **done in stage V3** |

> **Corrected 2026-10-12 (stage V3): `--execution-id` cannot be removed from client mode, and
> the row that said it could was wrong about who learns an execution from the coordinator.**
> `sub_executions` is roster-gated — `shared.mpc_nodes.contains(&self.id)` or
> `not_party("subscribe to executions")` — and a client is deliberately not on the node roster
> (§9.E). The coordinator has no client-facing way to name an execution either: every client
> method takes an `execution_id` it is already expected to hold, and nothing enumerates
> executions for a non-node. So removing the flag from client mode would leave a client with no
> way to say which execution it is joining and no mechanism to replace it, which is a deletion
> without a successor rather than a removal.
>
> What is true, and is what the flow reversal required, is that **no node** is configured with
> an execution identity. A party takes the identity from the coordinator that minted it before
> the mesh commits to it (`take_published_execution` in `stoffel-run.rs`), and party mode now
> *forbids* `--execution-id` through the ordinary per-mode validation that already forbids it in
> local mode — that is mode validation, not a refusal-by-name guard for a removed thing, and the
> flag it names still exists. The operator that submitted the execution passes the identity the
> coordinator minted to its clients, which is what `stoffel-coord-ctl submit` prints.
>
> One consequence for the one-shot compose stacks: a client service's
> `STOFFEL_EXECUTION_ID` has no useful default any more, because no constant is ever minted. The
> stacks default it to empty and `docker/entrypoint.sh` refuses a coordinator client without it,
> which also keeps the coordinator startable on its own — it has to be, since the identity does
> not exist until the coordinator has been asked to mint one.

An earlier revision of this section carried "Shipped in a release?" and "Guard" columns, and
argued from them that `run-coord --execution-id` — the one entry that did ship, at coordinator
`v0.2.0` — deserved clap's own by-name message as a redirect. §13 supersedes that test: the
guard is the last remaining trace of the thing being deleted, and it advertises a mechanism
nobody should use, whether or not a release carried it. The columns and the argument are gone;
what a release carried is recorded in the coordinator's CHANGELOG, which already states that
`0.2.0` and `0.3.0` do not interoperate in either direction and that no shim is offered.

The epoch rows of this table (`--epoch-store`, `STOFFEL_EPOCH_STORE`,
`ServerBuilder::epoch_store`) are void: none of it exists on `dev`. See §11.3.

**`docker/entrypoint.sh`, as built.** The `STOFFEL_COORD_ADDR` ⇒ `STOFFEL_EXECUTION_ID`
requirement is **kept and narrowed to the client role**, not lost: `validate_env` demands a
nonzero 64-hex identity when `STOFFEL_ROLE=client` and `STOFFEL_COORD_ADDR` is set, and the
`party` branch names no identity at all. That is the correction block above, in the script. The
`STOFFEL_COORD_ADDR` ⇒ `STOFFEL_COORD_CERT` requirement is §9.A and holds for both roles, with
the entrypoint supplying `/app/ids/server_cert.crt` as the default pin. `README.md`'s party flow
names no execution identity and its client flow names the one the coordinator minted.

`SessionExecutionId::UNUSED` and `stoffel-run`'s `UNUSED_EXECUTION_ID` /
`resolve_coord_execution_id` go: a coordinator is mandatory (§9.E.3 and §11.4), there is no
coordinator-less run to carry a reserved value for, and the value had no other purpose.

> **Void 2026-10-12 against `dev`, like the epoch rows above.** None of those three names has
> ever existed on `dev`: `UNUSED_EXECUTION_ID` and `resolve_coord_execution_id` appear neither
> at base `266a416` nor on this branch, and `SessionExecutionId` is the v1 type §12.C records as
> absent. The *property* they were to deliver is what this branch enforces instead, from the
> other end: party mode refuses `--execution-id` outright, and a run without a coordinator is
> refused at argument validation, so there is no reserved value to carry.

### 12.H Migration order

Each stage leaves both repositories building and their tests passing. The VM is compiled
against the local coordinator path wherever a stage needs coordinator changes that the pushed
commit does not have.

> **Corrected 2026-10-12 (stage C1).** Stages E-1 and E-2 landed together, as one coordinator
> stage, in the forms §12.A and §12.B now describe (no `MintExhausted`, no retired
> `RegistrationError` variants, no `ExecutionLog`/`from_seq`/`ExecutionLogTruncated`). E-3 and
> E-4 are **void**: they are work against `net/mesh/*` and `SessionExecutionId`, none of which
> exist on `dev`, and both solve problems `dev` already solved in `net/execution_transport.rs`
> and in `net/session.rs` (whose `MeshInfo` stage V2 then deleted as unused, replacing it with
> `net/mesh/join.rs`'s `MeshCommit`). Executing them would mean reintroducing the v1 mesh layer on
> top of a tree that deliberately built something else. **E-5's two new modules are void for the
> same reason**: `executions.rs` and `instances.rs` do not exist, and the instance supervisor they
> would contain is already `net/node_supervisor.rs`, which hosts many concurrent instances over
> one mesh. E-5's row below is rewritten accordingly, and so is §12.0's table — building from the
> originals would have produced a second supervisor beside `dev`'s.
>
> **The patch tables were repointed in stage V1, and the paragraph below is wrong about where
> they used to point.** Before V1 the VM's `Cargo.toml` `[patch.crates-io]` pointed at the
> in-tree vendored snapshot `vendor/stoffel-mpc-coordinator-browser` at version `0.2.0` — not at
> a git pin — and `docker/coordinator-wrapper/Cargo.toml` had no patch table at all, because it
> is its own `[workspace]`. Both now point at a sibling checkout of the coordinator worktree
> and are **left** repointed (an absolute path until stage S5 made it relative, §9.F.5). The repoint was also a **version bump**: `=0.2.0` in
> `crates/stoffel-vm-runner/Cargo.toml`, `crates/stoffel-rust-sdk/Cargo.toml` and the wrapper
> had to become `=0.3.0`, or cargo drops the patch with "was not used in the crate graph" and
> silently resolves the registry copy — which is why the earlier docker builds compiled registry
> crates while printing the mounted worktrees' revisions as provenance. The two injected tables
> in `Dockerfile` and `docker/coordinator.Dockerfile` use a bare `path =` with no version
> requirement, so the manifest bump is what makes them bind; they need no edit of their own, but
> `STOFFEL_COORDINATOR_CONTEXT` must now be a `0.3.0` checkout.
>
> The vendored fork went with the repoint rather than being left as a fallback: it existed only
> for `start_coord_with_browser`, the wrapper's `--browser-bind-addr` was its only caller, and
> that call did not compile at all on `dev`. Deleting both fixed the one pre-existing build
> failure in the tree.
>
> **New finding, and it reorders everything after this stage:** `dev`'s **standing** stack still
> forms its mesh through the bootnode. `run_standing_node` spawns `run_bootnode_with_config`
> in-process under `--leader` (moving the party listener to `bind.port() + 1000`) or else requires
> `--bootstrap`, then calls `register_and_wait_for_session` with `execution_id = --pool-id` and the
> synthetic program `__standing_node_pool_v1` (`stoffel-run.rs` at base `266a416`);
> `docker-compose.standing-concurrency.yml:124-213`, **at that same base**, wired
> `LEADER_ARGS: --leader` on party0 and `--bootstrap 172.33.0.10:9000` on parties 1-4. (Both
> citations are of the base, not of this branch: stage V2 deleted the bootnode and the stack now
> passes `--standing-node` with a `--client-bind` socket per party.) So the bootnode cannot be deleted before
> `run_standing_node` has a roster-pinned dial path: doing so breaks the standing node, the
> standing compose and all three standing suites in one step, which are the only end-to-end proof
> of concurrency this port has. Party identities are already available locally
> (`--party-cert-dir`, `install_expected_server_public_keys`), so the replacement is address
> resolution plus an all-to-all dial, not a new agreement protocol — but it has to land first.
>
> Measured during C1: with the three pins bumped and the root table repointed, the VM does not
> build. `local_runner.rs` and `stoffel-run.rs` use a `0.2.0` surface that `0.3.0` does not have
> — `new_for_execution` with eight arguments, `InputAssignment`, `InputClientRange`,
> `request_shutdown`, the flat `ExecutionRegistration`, and the upward RPC `register_execution`.
> Adapting them is the same work as teaching the node to learn its executions from
> `sub_executions`, so the repoint lands in that stage, together with dropping
> `--browser-bind-addr` from the wrapper and deleting the vendored fork. C1 therefore left the VM
> worktree untouched rather than half-converted.

| Stage | Repository | What lands | Leaves building | Compiled against |
|---|---|---|---|---|
| **E-1** | coordinator | `ExecutionId::generate`, `ExecutionRequest`, `RegisteredExecution`, the new `register_execution` order, `MintExhausted`, the three retired `RegistrationError` variants, `run-coord` without `--execution-id` | coordinator builds, its tests pass | — |
| **E-2** | coordinator | `ExecutionNotice`, `ExecutionLog`, `execution_sinks`, `sub_executions`, `ExecutionLogTruncated = 42`, notices appended on every register and remove path | coordinator builds, its tests pass | — |
| **E-3** | VM | the envelope: `SessionExecutionId`-keyed `OpenMessageRouter`, `try_register_instance`, `OpenRegistryError`, the widened wire fields, `protocol_ids` v2, the `u32` reservation table, `MAX_CONCURRENT_INSTANCES`. `derive_instance_id` deleted | VM builds; its MPC and open-registry tests pass | **the local coordinator path**, because `ExecutionId::generate` and `ExecutionRequest` are E-1 and are not in the pushed coordinator commit |
| **E-4** | VM | the join: `JoinRequest` / `MeshTransport` reduced, `MeshCommit`, `RosterDigestDivergence`, `net/mesh/execution.rs`, `ExecutionAgreed`, `ExecutionDivergence`, the widened barrier namespaces. Epoch store deleted (§12.E) | VM builds; the mesh harness passes in its retargeted form | the local coordinator path |
| **E-5** — **landed as stage V3** | VM + coordinator | the `sub_executions` stream client (`crates/stoffel-vm-runner/src/execution_stream.rs`) driving `dev`'s existing `NodeSupervisor`; `resolve_admission` re-sourced from the stream as `resolve_published_execution` with the catalogs kept; the mounted control plane, `--control-dir` and the whole command vocabulary deleted; the durable non-reuse index re-homed into `crates/stoffel-vm/src/storage/retired_executions.rs` behind `--admitted-store`; party-mode `--execution-id`, the `party` role's `STOFFEL_EXECUTION_ID` and the SDK's `OffChainServerConfig::execution_id` deleted; `acceptance.py` and `all_examples.py` retargeted in the same stage. **Two things the row did not anticipate:** the coordinator needed an operator-facing `submit_execution` / `abort_execution` and an operator identity set, because nothing else could start an execution on a standing coordinator once the node stopped registering one upwards; and client-mode `--execution-id` had to stay (§12.G). `UNUSED_EXECUTION_ID` and `resolve_coord_execution_id` did not exist on `dev` and needed no deletion. | VM and coordinator build; `local_coordinator_e2e`'s eight five-party runs, the 18 CLI and 13 SDK ignored tests and 1795 workspace tests pass; the standing campaigns are retargeted but not run (V5) | the local coordinator path |
| **E-6** | VM | compose stacks, `docker/entrypoint.sh`, `docker/test-*.sh`, `run_mpc_local.sh`, the SDK builder, `local_runner`, `README.md`, `CHANGELOG.md`; the coordinator's `CHANGELOG.md` in its own repo | both repositories build; the docker e2e stacks run | the local coordinator path |
| **E-7** | both | §12.J's tests | both repositories build; everything passes | the local coordinator path until the coordinator commit is pushed, then the git pin is restored and re-pinned |

**Where the VM must be compiled against the local coordinator path.** *Corrected 2026-10-13
(stage S6): the sentence that follows was written in the present tense about a state that ended
at stage V1, and neither line number it carried names a git entry any more — `Cargo.toml:19-21`
is the comment above the path table, and `docker/coordinator-wrapper/Cargo.toml:24-26` is three
`[dependencies]` lines, the wrapper's own table being further down.* Before V1 the VM consumed the coordinator through a
`[patch.crates-io]` entry that could not contain E-1's or E-2's changes — on `dev` a path entry
naming the in-tree vendored `0.2.0` snapshot, and in the first attempt a git pin on the pushed
coordinator commit. From **E-3 onward**, both patch tables are repointed at the local path:

```toml
[patch.crates-io]
stoffel-mpc-coordinator-shared = { version = "0.3.0", path = "../stoffel-mpc-coordinator-roster-admission/crates/coord-shared" }
stoffel-mpc-coordinator-off-chain = { version = "0.3.0", path = "../stoffel-mpc-coordinator-roster-admission/crates/off-chain" }
```

The path is relative to the manifest carrying it, so the wrapper's table — its own, because it
is its own `[workspace]` — reads `../../../stoffel-mpc-coordinator-roster-admission/...`. It
was absolute under one developer's home directory from V1 until stage S5 made it relative; both
forms require the coordinator worktree beside this one, but only the absolute one made every
`cargo` invocation off that host a hard error (§9.F.5).

They stay repointed for the whole sequence. Restoring the git form and re-pinning to the
pushed coordinator commit is the last step, after the coordinator branch is pushed, and it is
a human step — §9.F.5 already records that the coordinator `0.3.0` train is unpublished, that
the patch table is temporary, and that the pushed tip measurably lacks the `sub_executions`
surface this repository is written against.

### 12.I Trust

§3 names three things the coordinator is trusted for: membership, executions, admission. The
count does not change. What changes is how much "executions" covers, and §3's "not trusted
for" list loses an entry.

> **Where this leaves the posture after stages S1 and S2 (added 2026-10-13, stage S6).** §12's
> trust delta is about the *envelope*, and it is unchanged by those stages. What they changed is
> who may hold a connection, and in both directions it is now the coordinator and only the
> coordinator:
>
> - **Into a node.** A standing node has two listeners, and `net/roster.rs::NodeListeners` is
>   the only writer of either allowlist. The mesh listener is given the coordinator's served
>   roster before it binds and never anything else — no client certificate enters it, which was
>   §6 blocker B1 until stage S1 — and the client-facing listener carries no certificate
>   allowlist at all, so the whole of client authorization is the per-execution admission the
>   coordinator published, enforced on the route (`register_with_client_identities`) and, since
>   the S1 repairs, at accept time by `client_ingress.rs::ClientIngressGate`, which holds no
>   connection for a certificate no registered execution names.
> - **Out of a client.** There is no coordinator-less client (§15's decision). A client reaches
>   a node only after the coordinator admitted it, and it pins that leg to the roster the
>   coordinator served (`Roster::install_for_client`); stage S2 deleted the direct path that had
>   no way to pin anything.
>
> So the sentence this subsection already makes about the envelope — "the party that decides
> which executions exist also decides which message namespace each one occupies" — now has a
> transport counterpart: **the party that decides which executions exist also decides every
> connection a client may hold.** That is a concentration of trust, not a reduction of it, and
> it is deliberate (§15): the alternative measured in stage S2 was a client pinning nothing. The
> trade is stated in full in §9.G's trust-posture box and in §3, which already records that
> trusting the coordinator's roster is trusting it with client input privacy.

**Delta against §3 and §9.G, to be applied to both.**

- **§3's "It is not trusted for … `instance_id` (a local epoch plus the roster digest,
  §9.D.5)" is deleted.** The coordinator now *owns* the envelope. This is the substantive
  trust change in §12 and it should be read as one sentence: the party that decides which
  executions exist also decides which message namespace each one occupies.
- **What a malicious coordinator gains.** It can mint any id it likes, including one chosen
  rather than drawn — nothing a node can check distinguishes a drawn id from a chosen one.
  Concretely it gains: (a) a predictable envelope, so it could tell a colluding node a future
  execution's envelope in advance; and (b) the ability to point two executions at colliding
  `u32` protocol ids deliberately, which under §12.C is a loud, unanimous refusal rather than
  cross-talk, so the gain is denial of service, which it already has. It does **not** gain the
  ability to merge two honest executions' message streams: the VM registry is keyed by the
  full 32 bytes, so two distinct ids are two distinct registries whatever the coordinator
  intended, and two *identical* ids are one execution by definition.
- **What a malicious coordinator loses.** Nothing. §9.G's row already says it cannot "force
  `instance_id` reuse"; after §12 that line is true for a different reason — a node runs the
  envelope it was given, and reuse means re-registering an id the coordinator's own `ended`
  memory refuses — but the outcome is unchanged. §9.G's claim that it cannot "choose … an
  `instance_id`" is **deleted**: it now chooses it, and what used to be a per-node local epoch
  is gone.
- **What a malicious node can no longer do.** It can no longer bring an execution id of its
  own. Today every node→coordinator RPC takes a node-supplied `execution_id` and a node reads
  it from `STOFFEL_EXECUTION_ID`; a node could therefore name any execution the coordinator
  hosts — which the per-execution gates already limited to reading what roster nodes may read,
  but which also meant a misconfigured node could silently join the wrong execution and a
  malicious one could probe for ids. After §12, a node's view of which executions exist comes
  from one authenticated stream, so the set of ids it can name is the set it was told, and a
  node that is told nothing can name nothing. It also loses the epoch proposal: §12.E deletes
  `max(proposals)` and with it the Byzantine bound `MAX_EPOCH_JUMP` existed to enforce, so one
  roster member can no longer brick honest nodes' persistent counters. That is a real
  reduction in what `t` corrupt nodes can do, and it is the clearest security win in §12.
- **What the loss of coordinator-free operation means** (§11.4, first bullet). Before §9, a
  roster plus an epoch store could form a mesh and run with no coordinator contact. §9.E.3
  already removed that path, and §12 removes its last foundation: there is no longer any local
  source for the envelope, so no node can construct one. Consequences, stated rather than
  discovered: a deployment whose coordinator is unreachable cannot *start* an execution, and
  after §12.F it can no longer start one even with every node already running and meshed.
  Executions already live keep running on the mesh while the coordinator is away (§12.F) —
  which is new and is the one thing that got better — but their rounds, admissions, inputs and
  outputs all go through the coordinator, so they finish only if it returns before their
  deadlines. The coordinator is a single point of failure for starting work and a liveness
  dependency for finishing it. It is not a confidentiality single point of failure beyond what
  §3 already records.

### 12.J Tests

No test is deleted to make this section pass. A test whose contract dies with the epoch store
or the node-supplied id is deleted with it and listed in §12.E; a test covering surviving
behaviour is retargeted and listed there too.

**Coordinator repository.** As built in stage C1. Nothing in the suite was weakened or
skipped; `run-coord`'s `execution_id_validation_rejects_zero` is the one test deleted, because
it tested the parser of the flag that is gone.

| Test | Location | Asserts |
|---|---|---|
| `a_minted_execution_id_is_never_zero_and_never_repeats` | `crates/coord-shared/src/lib.rs` | `ExecutionId::new()` is never `is_zero()` and two draws differ; the same for `Default` |
| `registering_mints_an_identity_the_operator_never_supplies` | `crates/off-chain/tests/off_chain.rs` | `register_execution(ExecutionRequest)` answers a `RegisteredExecution` whose id is nonzero and live, and whose nonce is the live registration's; two registrations of the *same* request give two different ids and two different nonces, both live at once; a request that fails validation (`EmptyEntry`, `EntryTooLong`) mints nothing; and a minted id that has ended is refused with `ExecutionIdRetired` however it is presented again |
| `the_coordinator_publishes_minted_executions_to_the_roster` | same | a node subscribing to `sub_executions` before anything is registered gets an empty snapshot — `SnapshotComplete` and nothing else — rather than being refused, then receives the `Prepare` for the first registration, carrying the whole registration and its nonce; a node subscribing *after* that registration is told immediately, exactly once, and its snapshot closes; a second registration reaches both; unanimous retirement sends `Cancel { Finished }` to both; a node subscribing after that is told about the live execution and **not** the ended one; and a non-roster certificate is refused with `NotParty` |
| `a_fresh_snapshot_tells_a_node_which_of_its_running_executions_to_stop` | same | a node takes both runnable executions and `SnapshotComplete`, loses its stream, and one of the two is retired while it has no subscription — the `Cancel` a full queue drops, which nothing redelivers; resubscribing names the live execution and closes, so the difference between what the node is running and the snapshot is exactly the lost cancellation |
| `a_terminal_quorum_retired_execution_is_still_published_to_the_party_still_running_it` | same | n = 5, t = 1: three parties drive an execution to `ProgramFinished` and four retire it, so the round history is being kept alive for the fifth; the fifth's resubscription still carries its `Prepare`, while a party that acknowledged gets an empty snapshot. Pins the per-node snapshot predicate, and fails against the earlier "what a node joining now could contribute to" filter |
| `a_pre_registered_client_owns_the_slot_it_names_not_its_position` | same | ordinal 0 names slot 1 and ordinal 1 names slot 0; each client's `ClientAdmission` carries the input range and output rights of the slot it **named**, not of its position |
| `an_abort_cancels_the_execution_on_every_node_running_it` | same | an `Open` execution whose association deadline nothing meets is published, then cancelled with `Cancel { Aborted(AssociationDeadline) }` while it is still live and its nodes are still running it; the later removal does not publish a second `Cancel` |
| `a_stalled_node_never_blocks_publication_or_another_node` | same | one roster node subscribes and never reads; 40 registrations — well past the per-connection message buffer — each complete without waiting on it, every one reaches a second, reading node in publication order, and the state mutex is never held by the stalled subscriber |
| `one_listener_isolates_and_retires_concurrent_executions` | same | **retargeted**: unchanged assertions, registering through `register_execution_at` because the test names its two ids |
| `registration_checks_state_in_order_and_never_evicts_for_a_refused_one` | same | **retargeted** the same way: every arm survives, including the identical-live, conflicting and retired arms, because §12.A keeps them |
| `deleted_methods_are_not_rpc_methods` | same | unchanged: `register_execution` is still not an RPC method, and `sub_executions` *is* one, so nothing is added |

Two rows of the original table are void. `a_mint_avoids_live_retired_and_ended_ids` asserted
`MintExhausted` and a stubbed draw, and `a_truncated_execution_log_is_refused_by_name` asserted
`ExecutionLogTruncated`; neither mechanism was built (§12.A, §12.B).
`an_execution_registered_during_the_subscription_handshake_is_delivered_exactly_once` is
**not written**: `DeliveryHooks::after_subscription_accept` pauses between `accept()` and the
first look, which is before the snapshot, so pausing there proves nothing about the
snapshot-to-park window. Reaching that window needs a hook between the snapshot and the next
look; the exactly-once property is currently argued structurally (both are one critical
section) and covered end to end by the publication test above.

**VM repository.** The table below was written against the v1 tree and most of it is void:
`concurrent_instances.rs`, `instances.rs`, `tests/standing_node.rs`, `mesh_join_harness.rs`,
`SessionExecutionId`, `try_register_instance`, `OpenRegistryError` and
`ProtocolInstanceIdCollision` do not exist on `dev`. What `dev` has instead is
`docker/standing-concurrency/acceptance.py`'s concurrency and adversarial campaigns, which
already assert concurrent isolation, stalled siblings, frozen parties and bounded outages on a
live five-party mesh, plus the reservoir tests in `storage/preproc.rs`. Of the two properties
this section listed as genuinely open, the reservoir's *concurrent*-claimant disjointness is
**now covered** — `two_executions_never_receive_the_same_reservoir_item_content` for the item
content two draws receive, and `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`
for two live engines contending on one scope; §10 point 1 records both. *Retargeted 2026-10-15:
this cited `a_preprocessing_item_is_never_served_to_two_concurrent_claimants` and
`a_preprocessing_item_is_never_served_to_two_executions`, which drove the deleted `reserve_at`
cursor and went with it.* The `u16` exec-counter pressure that concurrent instances plus
background refill create is still open. The rest is listed here as history.

**What does pin §12.B's node side, as built** (added 2026-10-13, stage S6 — the void table
below named none of it, so the contract had no test index on this branch). All in
`crates/stoffel-vm-runner/src/execution_stream.rs`:

| Rule of §12.B | Test |
|---|---|
| a `Prepare` resolves against the startup-frozen program and client catalogs | `a_published_execution_resolves_against_the_local_catalogs` |
| the published ordinal is independent of the program's `manifest_slot` | `the_execution_local_ordinal_is_independent_of_the_program_slot` |
| a published client identity the local catalog does not hold refuses the whole admission | `a_published_client_this_node_holds_no_certificate_for_refuses_the_execution`, with `two_client_certificates_with_one_key_refuse_the_catalog` on the catalog itself |
| a program or entry the catalog does not hold is refused | `a_published_program_or_entry_the_catalog_does_not_hold_is_refused` |
| a standing node serves `PreRegistered` admissions only | `an_open_admission_policy_is_refused_by_a_standing_node` |
| the reserved zero identity is refused | `the_zero_execution_identity_is_refused` |
| every committed field moves the `config_digest` | `the_config_digest_moves_whenever_any_committed_field_does` |
| snapshot and live stream are separated by the cursor | `the_snapshot_cursor_separates_the_snapshot_from_the_live_stream` |
| `Prepare` starts one instance and is idempotent; a refused one starts nothing | `a_published_prepare_starts_one_instance_and_a_replay_does_not`, `a_published_execution_this_node_refuses_starts_nothing` |
| `Cancel { Aborted }` tears down; an unknown id is ordinary; `Cancel { Finished }` retires the identity and leaves the instance | `a_cancel_tears_down_a_live_instance_and_an_unknown_one_is_ordinary`, `a_finished_cancel_retires_the_identity_without_stopping_the_instance` |
| `SnapshotComplete` stops exactly the omitted instances of **this** incarnation, and a later `Prepare` survives it | `completing_the_snapshot_stops_exactly_the_instances_it_omitted`, `a_prepare_after_the_snapshot_survives_the_reconciliation` |
| a restarted coordinator's empty snapshot stops nothing it never admitted, while a `Cancel` by name still does | `a_restarted_coordinator_stops_nothing_it_never_admitted`, `a_cancel_from_a_restarted_coordinator_still_stops_an_older_instance` |
| an omission a retirement explains keeps the instance; one nothing explains still stops it | `a_retired_instance_survives_every_later_snapshot_of_the_same_coordinator`, `a_snapshot_omitting_an_execution_no_retirement_explains_still_stops_it`, `an_instance_this_node_has_acknowledged_survives_the_snapshot_that_omission_causes` |
| only a different coordinator ends the stream | `only_a_different_coordinator_ends_a_standing_node_s_stream`, in `bin/stoffel-run.rs` beside `classify_link_failure` |

| Test | Location | Asserts |
|---|---|---|
| `two_concurrent_executions_of_one_program_do_not_share_an_envelope` | `crates/stoffel-vm/src/tests/concurrent_instances.rs` (new) | **the headline test.** One roster, one program, one entry, one `stoffel-run`-shaped standing process per party; the coordinator registers two executions of the *same* `ExecutionRequest`, so they differ in nothing but their minted ids. Both run simultaneously on each node process and produce **different, correct results** from different client inputs. Asserts: the two `InstanceRegistry` handles are different objects under different keys; no frame of one appears in the other's accumulators; the two `u32` protocol ids differ; and each execution's output is the one its own inputs imply. Retargets `a_mesh_join_produces_a_fresh_instance_id_per_run` (`mesh_join_harness.rs:926`) onto the concurrent case |
| `a_second_claim_on_a_live_envelope_is_refused_by_name` | `crates/stoffel-vm/src/net/open_registry/tests.rs` | `try_register_instance` twice on one `SessionExecutionId` gives `OpenRegistryError::InstanceAlreadyRegistered`; dropping the first `Arc` makes the second claim succeed; a claim past `MAX_CONCURRENT_INSTANCES` gives `InstanceCapacityReached`. This is HAZARD 1's resolution asserted directly: get-or-create would have returned the same registry and passed silently |
| `a_colliding_protocol_instance_id_is_refused_rather_than_shared` | `crates/stoffel-vm-runner/src/instances.rs` | with the `u32` reservation table pre-loaded so a second execution's derived id is taken, `InstanceSupervisor::start` fails with `ProtocolInstanceIdCollision` naming both executions and the `u32`; the first instance keeps running; the second is not acknowledged to the coordinator |
| `a_node_starts_an_execution_it_learned_after_it_subscribed` | `crates/stoffel-vm-runner/src/tests/standing_node.rs` (new) | a standing node with an empty stream idles — no exit, no error, no timeout, for longer than any current join or round budget — then starts an instance on the first notice and returns to idling when it ends |
| `retiring_one_instance_leaves_the_other_running` | same | two live instances in one process; `ExecutionNotice::Ended` for one tears it down, frees its envelope and its `u32`, and leaves the other's registry, barriers and task untouched; the torn-down instance's envelope can then be claimed again |
| `a_dropped_coordinator_link_does_not_kill_live_instances` | same | the coordinator listener is stopped and restarted under a standing node with two live instances: the stream client reconnects, re-subscribes from `sent`, replays nothing it already saw, and both instances are still running. The one-shot arm of the same test asserts the unchanged exit 13 |
| `parties_pointed_at_different_executions_fail_with_execution_divergence` | `crates/stoffel-vm/src/tests/mesh_join_harness.rs` | three parties on one mesh; the third is pointed at a different execution. Every party fails with `MeshError::ExecutionDivergence { party_id }`, at the per-execution agreement, before any preprocessing is drawn or mask share released. **Retargets** `a_party_started_for_another_execution_is_refused_by_name` (`:1830`) from `SessionDivergence { field: ExecutionId }` at the transport join to the new layer and error |
| `a_party_committing_to_another_roster_is_refused_by_name` | same | **retargets** `a_party_proposing_a_different_session_is_refused_by_name` (`:1822`): the transport join's only remaining divergence is the roster, and it is named with `RosterDigestDivergence` over all 32 bytes. Its `Divergence::Entry` arm moves into the test above, because `entry` is per-execution now |
| `one_mesh_carries_two_programs` | same | two executions of **different** programs agreed on one `MeshTransport`, each with its own `execution_digest`, with one transport join and no re-join. This is the structural claim of §12.D asserted rather than assumed |
| `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them` | `crates/stoffel-vm/src/net/mpc/honeybadger/preprocessing.rs` | **built.** HAZARD 2 is the concurrent case, and it is reachable: `PreprocKeyScope` is keyed by `(program_hash, field_kind, n, t, node_identity)` and **not** by execution, so two concurrent executions of one program on one node draw from exactly one `PreprocKey`. Two engines commit into one scope and each then draws, and the test asserts that neither execution's retained material reaches the store and that the two draws share no item. `two_executions_never_receive_the_same_reservoir_item_content` is the storage-layer arm, comparing decoded field elements rather than cursor ranges. *Retargeted 2026-10-15: this row named `a_preprocessing_item_is_never_served_to_two_concurrent_claimants` and `a_preprocessing_item_is_never_served_to_two_executions`, which drove `reserve_at` — a primitive with no production caller, now deleted along with both tests. The row's old "honest limitation" paragraph, that disjointness was structural and the CAS not load-bearing, went with it: see §10 point 1's rewrite box* |
| `an_instance_envelope_is_the_minted_id_with_no_reduction` | `crates/stoffel-vm/src/net/session.rs` | `SessionExecutionId` round-trips its 32 bytes into the registry key and out of an `OpenRegistryWireMessage`, unchanged; there is no `derive_instance_id` to call. Replaces `the_instance_id_depends_on_the_roster_digest` and `a_new_epoch_is_a_new_session_namespace_for_one_program`, whose derivation no longer exists |
| `protocol_instance_ids_are_domain_separated` / `…_are_stable_for_full_width_vm_instance_ids` | `crates/stoffel-vm/src/net/mpc/protocol_ids.rs` | **retargeted** to the 32-byte input and the `v2` context: still deterministic, still separated between `b"honeybadger"` and `b"avss"`, and now also different for two execution ids differing in one byte |

#### 11.6 The preprocessing pool is NOT shared across concurrent instances

> **Refuted 2026-10-12 against `dev`, and kept only as history.** `dev` already built the
> per-node shared pool this section demands: `standing_preproc_pool_program_id(pool_id,
> program_id)` (`stoffel-run.rs`) namespaces the LMDB keys per deployment and program,
> `reservoirs: BTreeMap<[u8; 32], Arc<StandingReservoirState>>` (a field of the standing node's
> state, same file) is warmed once per program by `warm_reservoirs` and shared by every
> concurrent execution of it, and
> `take_bundle_from_reservoir` (`storage/preproc.rs:512`) hands each execution its own
> non-`Clone` `OwnedPreprocBundle` inside one LMDB write transaction, under a per-program lane.
> The reservoir is sized `--reservoir-burst-capacity + 1` executions deep and tops up per node,
> not per instance. So the conclusion below — that the second claimant must run a full
> preprocessing round of its own — is false of `dev`. The premise about the key struct is still
> true: `PreprocKeyScope` carries no execution id, which is exactly why the pool *can* be
> shared. Of this section's two test requirements, the first — single-use across concurrent
> claimants — is now built (§10 point 1,
> `two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them`; *retargeted
> 2026-10-15 from `a_preprocessing_item_is_never_served_to_two_concurrent_claimants`, deleted
> with the `reserve_at` cursor it drove*). The second, the `u16` preprocessing exec counters
> under concurrent regeneration pressure, is still live.

Checked, because §11.5 hazard 2 assumed the §10 single-use property was the only interaction. It
is not. The pool itself is per-instance:

- `PreprocKeyScope` is `(program_hash, field_kind, n, t, node_identity)`
  (`storage/preproc.rs:146-152`) — **no instance id**. So every instance of one program on one
  roster, under one node identity, addresses the *same store keys*.
- The live material, `node.preprocessing_material`, belongs to the HoneyBadger node, which the
  engine constructs and owns (`net/mpc/honeybadger.rs:165`), and `preproc_store` is a field on the
  engine too (`:51`), set per engine by `set_preproc_store` (called from `stoffel-run.rs`).
- The engine is per instance — it registers its envelope with
  `open_message_router.register_instance(instance_id)` (`honeybadger.rs:174`).

So N concurrent instances means N engines, N independent live pools, and all of them contending
on one set of store keys. The §10 destructive take keeps claims **disjoint**, so single-use still
holds — that property is safe. What does not hold is sharing: the second claimant gets
`Insufficient` and must run a full preprocessing round of its own. *Corrected 2026-10-15: this
credited "the §10 compare-and-swap" and `CursorMismatch`. The compare-and-swap had no production
caller and is deleted; what makes two claims disjoint is that
`take_bundle_from_reservoir` removes what it hands out inside the same write transaction.*

That defeats the point of a standing network. The persistent-network plan is "preprocess ahead,
top up between runs, pay only the online cost"; with a per-instance pool there is no pool to
preprocess *into* that a later instance can draw from, and two concurrent instances of one program
each pay full preprocessing. The `Arc<dyn PreprocStore>` handle is cloneable and could be shared
today — it is the live material, sitting inside the MPC node, that cannot be.

§12 must therefore say where the pool lives once a process hosts many instances: a per-node pool
keyed by `(program, field, n, t, identity)` that instances draw from under the existing CAS, with
top-up driven once per node rather than once per instance. Two properties must survive the change
and be tested, not assumed: single-use across **concurrent** claimants (§11.5 hazard 2) — built,
see §10 point 1 — and the `u16`-widened preprocessing exec counters that already caused one
session-id-reuse deadlock when they wrapped, which is still untested; concurrent instances
multiply the regeneration pressure that exposed it.

## 13. Project rule: removal means deletion (2026-10-12)

Stated by the user, and it supersedes the narrower rule §10 recorded and the shim decision in §8:

> "since we're deleting/removing this means we don't care about breaking changes and we shouldn't
> specify functionality is deprecated"

So anything this effort removes is **deleted outright**. No `#[deprecated]` items, no
refusal-by-name guards, no `fail_removed_flag` entries, no "X was removed, use Y instead" hint
text, no deprecated aliases. A removed flag becomes an ordinary unknown argument; a removed
environment variable is simply ignored. Breaking changes are fine and are not designed around.

§10 justified a guard on the grounds that one exists to redirect someone whose working
configuration a release broke, and concluded that `Invitation` deserved none because it never
reached a release. The conclusion was right; the test was too generous. The rule is simpler: the
guard is the one remaining trace of the thing we deleted, and it advertises a mechanism nobody
should use. That holds whether or not the thing shipped.

This document may record that a mechanism existed and was removed — that is history, and it is
why §8, §9.C.3 and §10 still name the bootnode, `Invitation` and the control directory. The *code*
must not mention them.

## 14. Why there are two branches, and what each one is

This effort has been attempted twice, and both attempts exist as separate pull requests. The
relationship matters for reading either one.

**Attempt 1 — `claude/bootnode-elimination-mesh-146b80`, cut from `main`, abandoned.** It is
complete on its own terms and it is where most of §1-§12 was written and audited. It is not
merged and will not be: `dev` diverged too far (43 conflicting files, and 62 conflict hunks in
`stoffel-run.rs` alone), and — the decisive part — `dev` spent that time *developing* the
bootnode the attempt deleted, alongside an execution-scoped transport, a node supervisor, a
standing preprocessing pool and reservoir, a mounted standing control plane and three docker
acceptance campaigns. A merge would have had to re-derive all of it inside the conflict.

**Attempt 2 — `feature/no-bootnode-v2`, cut from `dev` at `266a416`, this branch.** The same
design, re-executed stage by stage on top of `dev`'s machinery rather than against it:

- `net/execution_transport.rs` is **consumed, not replaced.** Its `STXE` frame carries the full
  38-byte `ExecutionId` header with per-execution inboxes, which is a better answer than the
  `u64` envelope §11-§12 proposed; `register_instance`'s `u64` keying was deliberately left
  alone, and §11.5's hazard 1 is unreachable rather than fixed.
- `NodeSupervisor`, `returned_share.rs`, `client_io_planner.rs`, `client_value_codec.rs`, the
  standing pool and reservoir in `storage/preproc.rs`, and the `docker/standing-concurrency`
  campaigns are all `dev`'s, kept and extended. §11.6's demand for a shared per-node pool was
  already built on `dev`, and the section is kept only as history.
- `standing_control.rs`'s mounted control directory is **replaced**, not paralleled, by
  `execution_stream.rs` over the coordinator's `sub_executions` subscription — the user's
  decision that "the coordinator is meant to be the trusted party". The acceptance drivers were
  retargeted onto `stoffel-coord-ctl`, not weakened.
- The execution-id flow runs **downward** throughout (§12, and Cordian's standing requirement):
  the coordinator mints every identity and publishes it to the roster, no node is configured
  with one, and a node registers an execution only with its own RPC listener.

Where §1-§12 was written against `main` and is false of `dev`, the code wins and the disagreement
is recorded as a correction in place. **The index of those corrections, as it stands after stage
S6 (2026-10-13) and its repair passes** — this list used to name eight sections and was stale by a
dozen; S6's rebuild missed three more, added here:

| Section | Carries |
|---|---|
| §6 (blockers) and §9's rule-3 section | B1 closed by stage S1, B3 by stage S2; the rule-3 box carries both |
| §9's "Revision 2 (2026-09-16)" table | an S6 box voiding rows V22, V24 and V29 (the box sits under that table; §7 is prose and carries no V-numbered rows) |
| §9.1 (build order) | an S6 box on the V-0 bullet, an inline S6 correction inside the V-b bullet — extended by S6's repair pass, which replaced its CI claim — and a stage S2 note on V-c; the V-0 bullet's closeout list amends its own items 3, 5, 6 and 7 in place, item 7's being a 2026-10-16 correction of the AVSS coverage claim that its item 11 then measures |
| §9.D.1 | an S6 box: five of the ten startup steps are the v1 attempt's |
| §9.D.2, §9.D.3 | correction boxes, and §D.3's hint table is kept only as the record (§13) |
| §9.D.5, §9.D.6 | void as contracts |
| §9.E.2 | a V1-repair as-built box over the removals it lists |
| §9.E.3 | a V5 correction and a stage S2 box: direct client mode is **deleted** |
| §9.F.0 | a V4 measurement of which of its four rules landed, and which did not |
| §9.F.1, §9.F.2, §9.F.3, §9.F.5 | correction boxes; §F.2's is S6's, §F.5's is S5's plus a 2026-10-16 sharpening of why the Rust CI jobs are red (the coordinator half is uncommitted, not unpushed; extended the same day by a second pass that measured the shape of that red run — `cargo fmt` passes, clippy is where it goes red, no Docker job fails on a pull request, and the missing coordinator surface is wider than the five type names; and by a third pass that ruled out repointing the clone over every pushed ref of that repository, named the breaking enum payload change the five `E0609`s come from, measured the clearing commit sufficient as well as necessary, and measured `-p stoffel-vm --lib` green against the pushed tip that reds the workspace; and by a fourth pass that corrected two of the third pass's own measurements — the pickaxe claim needed whole-word anchors, since plain `-S PreRegisteredClient` matches the committed `DuplicatePreRegisteredClient`, and the wrapper fails on **two** errors rather than one, which adds `with_operators` to the missing-surface inventory as a sixth item no runner-side build surfaces), and §F.5 also points at §9.I's "Repair of stage S6" box for the two Dockerfile fixes recorded in its Docker bullet |
| §9.G | an S1/S2 trust-posture box |
| §9.H | a V5 measurement of which planned tests exist, with S6 corrections to two rows |
| §9.I | the chronological per-stage log, with its own reading instruction |
| §10 | superseded in part by §13 |
| §11.1, §11.3, §11.5 | correction boxes |
| §11.6 | refuted against `dev`, kept as history |
| §12.0, §12.A | C1 and S6 correction boxes |
| §12.B | V4, V5 and S3 boxes, plus S6's admission-policy block and two citation corrections |
| §12.C, §12.E | void, kept as history |
| §12.D | a V2 as-built block |
| §12.F | a V5 seven-point box |
| §12.G | a V3 correction, plus void rows |
| §12.H | C1, V1 and S6 corrections |
| §12.I | an S1/S2 posture box |
| §12.J | a measurement of what of the VM table exists, plus S6's as-built index of the tests that pin §12.B's node side |

§9.I is the per-stage status of record for this branch, read forward; the first table in it is
attempt 1's and is marked superseded.

The coordinator side is **one** branch serving both attempts: `feature/no-bootnode` in
`stoffel-mpc-coordinator`, at version `0.3.0`, which already contained everything on that
repository's `dev` and needed no rebase. Both VM branches consume it through
`[patch.crates-io]`; on this branch those tables (root `Cargo.toml` and
`docker/coordinator-wrapper/Cargo.toml`) point at a **local path**, relative to the manifest
that carries it since stage S5, and are left that way until `0.3.0` is published (§9.F.5,
§12.H). Every host-side `cargo` invocation of either workspace therefore requires the
coordinator worktree checked out beside this one.

## 15. Decision: all client connections are dictated by the coordinator (2026-10-13)

Stated by the user while resolving the unpinned direct-client finding. There is **no
coordinator-less client**. A client reaches a node only after the coordinator says so, and it learns
which node certificates to accept from the roster the coordinator serves — never from local
configuration, never from whatever answers an address.

So direct client mode is deleted outright, not pinned. The two options looked distinct but converge:
pinning a direct client would require it to fetch the roster from a coordinator, at which point it
is a coordinator-mediated client with extra steps. What it actually removed was a fail-open leg —
`stoffel-run --client` without `--off-chain-coord` fell through to `run_as_client`, which had no way
to verify a node's certificate, on the one connection carrying the client's secret input shares.

Consequences, recorded rather than discovered later:

- `--off-chain-coord` plus the coordinator certificate pin is the only way a client reaches a node.
- Every dependent moves to the coordinator-mediated path: the runner and CLI client tests, the SDK's
  client builder, `stoffel-cli`, `local_runner`, the compose stacks and the docker scripts. A
  dependent that cannot be migrated is a finding, not a reason to keep the path.
- A client is admitted per execution (§9), so this composes with open admission: a client whose
  identity nobody knew in advance still joins, it simply does so through the coordinator.
- Per §13 the deletion leaves nothing behind — no guard, no hint, no alias — and the breaking change
  is accepted.
