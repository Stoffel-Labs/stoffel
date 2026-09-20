//! `join_mesh`: forming a session with no bootstrap process at all.
//!
//! Stage 5 of `docs/design/bootnode-elimination.md` added this as the first
//! bootnode-free path, beside the bootnode join it was measured against. Stage 8
//! deleted the bootnode, so [`MeshJoin`] is now the only
//! [`crate::net::mesh::SessionJoin`] there is.
//!
//! # What replaced what
//!
//! | Deleted bootnode | Mesh |
//! |---|---|
//! | the bootnode's `tls_ids` relay | the certificate allowlist, installed first |
//! | `STOFFEL_AUTH_TOKEN` | membership *is* the roster, enforced per connection by mTLS |
//! | address directory | `--peers` seeds plus whatever the peer book holds |
//! | quorum wait | [`crate::net::mesh::wait_until_mesh_connected`] |
//! | first-registrant-wins session params | all-to-all `JoinProposal` / `JoinCommit` |
//! | random `instance_id` nonce | a monotone LMDB epoch ([`crate::net::mesh::epoch`]) |
//!
//! One caveat on the address row, because it is the one an operator can get
//! wrong: a **first** mesh forms out of dials alone. The peer book is exchanged
//! inside the handshake below, which runs after the connectivity barrier, so it
//! cannot supply an address the mesh needs in order to form — it is what lets a
//! *later* join in the same process start from less. The seed list a first join
//! runs on has to cover every pair, and — since a pair is dialed from **one**
//! end only (see `dials_towards`) — it has to cover it *in the dialer's
//! direction*: for any two parties, the one whose transport-derived id is
//! higher must hold a hint for the other. Derived ids are BLAKE3 digests, so an
//! operator cannot read that order off a config file. Listing all `n - 1` peers
//! everywhere satisfies it whatever the order turns out to be, which is what
//! every shipped stack does and what `build_session_join` asks for when a list
//! is shorter.
//!
//! There is deliberately **no** escape hatch for the other direction. An
//! earlier revision let the non-dialing side dial anyway once a rank had been
//! missing long enough, so that the requirement could stay stated over pairs
//! rather than over directions. That re-created exactly the duplicate
//! connection the tournament exists to prevent — see `dials_towards` for the
//! teardown it causes — and it did so in the one shape a deployment really
//! produces: a party that starts late (a compose service gated on another's
//! healthcheck) is grace-dialed by the peers that gave up waiting at the same
//! moment it dials them. Liveness recovered that way is bought with a
//! one-in-three handshake failure, so the rule is absolute and a short seed
//! list fails as a named discovery timeout instead.
//!
//! # The divergence the bootnode never checked
//!
//! The deleted bootnode's `handle_register` compared an arriving party's
//! **`program_id` only** against the pending session. A party that registered
//! with a different `n`, a different threshold or a different entry point was
//! admitted, and then ran a protocol parameterised differently from everyone
//! else's. Nothing downstream noticed: a wrong threshold is not a decode error,
//! it is a silently wrong reconstruction.
//!
//! The mesh checks every field twice. Each `JoinProposal` is compared
//! field-by-field so the failure names *which* field diverged
//! ([`MeshError::SessionDivergence`]), and then every party commits to a single
//! [`session_digest`] over all of them — including the agreed epoch — which
//! must be byte-identical at all `n` parties or the join aborts
//! ([`MeshError::CommitDivergence`]). Nothing MPC-shaped is sent before that
//! check passes.
//!
//! # Why this does not use stoffelnet's built-in consensus
//!
//! `QuicNetworkManager` has `set_expected_parties` / `set_expected_clients`,
//! which arm an automatic all-to-all digest agreement
//! (`maybe_start_consensus` → `execute_consensus`, `quic.rs:2972-3186`). It
//! looks like exactly this handshake, and it must not be used here. Three
//! reasons, all verified against `stoffelnet-0.1.1`:
//!
//! 1. **It races every application receive loop.** `execute_consensus` collects
//!    peer digests with a bare `conn.receive()` (`quic.rs:3116`) on the *shared*
//!    per-peer connection, from a task spawned out of `accept()`/`connect()`. It
//!    is not the sole reader, so it and `spawn_receive_loops_split` steal frames
//!    from each other.
//! 2. **A failed gate blocks every send, permanently.** `Network::send` awaits
//!    `await_consensus_gate` first (`quic.rs:3500`), which returns
//!    `Err(SendError)` for as long as the gate is `Failed` (`quic.rs:3202`) —
//!    and `consensus_started` is a one-shot latch, so nothing ever re-runs it.
//! 3. **Arming half of it is worse than arming none.** `maybe_start_consensus`
//!    returns early unless *both* `expected_parties` and `expected_clients` are
//!    set (`quic.rs:2973-2978`), while `set_expected_parties` alone moves the
//!    gate to `Pending` (`quic.rs:1425`). A node that set only the party count
//!    would block on its first `send` forever, with no error anywhere.
//!
//! The handshake below is the same *idea* run where it is safe: after the
//! barrier, in lock-step, on connections this function is the sole reader of,
//! and with no effect on the send path.
//!
//! # Reading a framed stream safely
//!
//! Every read here is `tokio::time::timeout(remaining, conn.receive())` under
//! **one** deadline for the whole handshake, and blowing that deadline fails the
//! join. That is deliberate. `QuicPeerConnection::receive` reads a length prefix
//! and then a body from a `RecvStream` held under a mutex, so a read cancelled
//! part-way leaves the stream positioned mid-frame and every later read
//! desynchronised. The only safe timeout is one that ends the exchange, so
//! there is exactly one, and it is fatal.
//!
//! The same rule is why PEX is exchanged *inside* the handshake rather than
//! during discovery. Before the connectivity barrier, connections are still
//! being deduplicated by stoffelnet's simultaneous-connect tie-breaker
//! (`quic.rs:2280-2300`, `:3411-3441`), so a frame can be written to a
//! connection that is about to be closed in favour of the peer's. After the
//! barrier the connection set has settled, and a peer book exchanged there is
//! what lets the *next* join start from a single seed — not this one, which
//! still has to form out of the hints it was given.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stoffelnet::network_utils::{Network, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;

use crate::net::mesh::barrier::{wait_until_mesh_connected, BarrierTag};
use crate::net::mesh::dial::dial_address_expecting;
use crate::net::mesh::epoch::{agree_epoch, EpochStore};
use crate::net::mesh::pex::{PeerRecord, SeedHints};
use crate::net::mesh::roster::Roster;
use crate::net::mesh::router::SharedMeshRouter;
use crate::net::mesh::wire::{self, MeshMessage, MAX_PEER_RECORDS_PER_MESSAGE};
use crate::net::mesh::{JoinRequest, MeshError, MeshResult, MeshSession, SessionJoin};
use crate::net::session::{derive_instance_id, SessionExecutionId};

/// BLAKE3 derive-key context for [`session_digest`].
///
/// Domain-separated so a session digest can never collide with the
/// coordinator's node-roster digest (`stoffel-coordinator-node-roster-v1`), the
/// program id (`stoffel-program-v1`) or the `instance_id` derivation
/// (`stoffel-session-instance-v2`). `v2` because the digest gained the
/// execution id (design doc §9.D.5).
pub const SESSION_DIGEST_CONTEXT: &str = "stoffel-mesh-session-v2";

/// One field of the session every party has to agree on.
///
/// An enum rather than a `&'static str` so that adding an agreed field is a
/// compile error at [`session_digest`] and at the comparison below, not a
/// silently unchecked addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionField {
    RosterDigest,
    /// The coordinator execution the party was started for. A party joined
    /// under another one would pass the join and then wait forever on rounds of
    /// an execution no other party is in.
    ExecutionId,
    ProgramId,
    Entry,
    PartyCount,
    Threshold,
}

impl std::fmt::Display for SessionField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::RosterDigest => "roster",
            Self::ExecutionId => "execution id",
            Self::ProgramId => "program id",
            Self::Entry => "entry point",
            Self::PartyCount => "party count",
            Self::Threshold => "threshold",
        };
        formatter.write_str(name)
    }
}

/// The value every party commits to.
///
/// Canonical: every variable-length field is length-prefixed and every number
/// is fixed-width little-endian, so no two distinct sessions can produce the
/// same byte stream. The execution id is fixed-width too, and sits immediately
/// after the roster digest.
pub fn session_digest(
    roster_digest: &[u8; 32],
    execution_id: &SessionExecutionId,
    program_id: &[u8; 32],
    entry: &str,
    n_parties: u64,
    threshold: u64,
    epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SESSION_DIGEST_CONTEXT);
    hasher.update(roster_digest);
    hasher.update(execution_id.as_bytes());
    hasher.update(program_id);
    hasher.update(&(entry.len() as u64).to_le_bytes());
    hasher.update(entry.as_bytes());
    hasher.update(&n_parties.to_le_bytes());
    hasher.update(&threshold.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// The fields of one `JoinProposal` that every party must propose identically.
///
/// The epoch is not among them: each party proposes its own, and the agreed
/// value is bounded by [`agree_epoch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionProposal {
    pub(crate) roster_digest: [u8; 32],
    pub(crate) execution_id: SessionExecutionId,
    pub(crate) program_id: [u8; 32],
    pub(crate) entry: String,
    pub(crate) n_parties: u64,
    pub(crate) threshold: u64,
}

impl SessionProposal {
    /// The first field, in [`SessionField`]'s comparison order, in which
    /// `theirs` proposes another session than `self`.
    ///
    /// Field-by-field, so the failure names what diverged. This is the check the
    /// deleted bootnode's `handle_register` never made: it compared
    /// `program_id` alone.
    pub(crate) fn first_divergence(&self, theirs: &Self) -> Option<SessionField> {
        if theirs.roster_digest != self.roster_digest {
            Some(SessionField::RosterDigest)
        } else if theirs.execution_id != self.execution_id {
            Some(SessionField::ExecutionId)
        } else if theirs.program_id != self.program_id {
            Some(SessionField::ProgramId)
        } else if theirs.entry != self.entry {
            Some(SessionField::Entry)
        } else if theirs.n_parties != self.n_parties {
            Some(SessionField::PartyCount)
        } else if theirs.threshold != self.threshold {
            Some(SessionField::Threshold)
        } else {
            None
        }
    }
}

/// The pre-session namespace the `MeshReady` barrier travels under.
///
/// There is no `instance_id` yet — agreeing one is what the handshake does — so
/// the barrier is namespaced by the only thing the parties have already agreed
/// on: the roster they are pinned to.
pub fn roster_namespace(roster_digest: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&roster_digest[..8]);
    u64::from_le_bytes(bytes)
}

/// The budgets a mesh join runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshJoinTimeouts {
    /// Whole discovery phase: dialing seeds and whatever the book learns.
    pub discovery: Duration,
    /// One dial attempt.
    pub dial: Duration,
    /// Delay between discovery rounds.
    pub discovery_round: Duration,
    /// The connectivity barrier, once discovery has stopped dialing.
    pub barrier: Duration,
    /// How long the mesh has to stay complete before the handshake starts.
    ///
    /// stoffelnet resolves a simultaneous connect by closing one of the two
    /// connections, and it does so on whichever side observes the duplicate
    /// second — so a node that races into the handshake the instant it first
    /// sees `n - 1` peers can have a connection replaced underneath it by a
    /// peer that was still dialing. Requiring the mesh to be *stably* complete
    /// costs one sleep and shrinks that window to the settle interval.
    ///
    /// It is not what closes it. `dials_towards` is: a pair is dialed from
    /// one end only, so two roster members never open two connections to each
    /// other and the tie-breaker never runs between them at all. What this
    /// interval is still worth is the case that has nothing to do with
    /// duplicates — a peer whose connection drops between the moment the mesh
    /// first looks complete and the moment the handshake starts. Re-reading the
    /// missing set after a settle catches that, and the round says so and keeps
    /// dialing.
    pub settle: Duration,
    /// One `accept()` before the accept loop re-checks whether it is done.
    pub accept_poll: Duration,
    /// The whole lock-step handshake, sends and reads together.
    pub handshake: Duration,
}

impl Default for MeshJoinTimeouts {
    fn default() -> Self {
        Self {
            // The same order of magnitude as the deleted bootnode path's 60s
            // accept budget inside a 90s join: a mesh forms as fast as its slowest
            // member starts, and in compose that is an image pull.
            discovery: Duration::from_secs(90),
            dial: Duration::from_secs(10),
            discovery_round: Duration::from_millis(500),
            barrier: Duration::from_secs(30),
            settle: Duration::from_millis(500),
            accept_poll: Duration::from_secs(1),
            handshake: Duration::from_secs(60),
        }
    }
}

/// [`SessionJoin`] over a pinned roster and a set of address hints.
///
/// Cheap to clone — everything shared is behind an `Arc` — because the
/// characterization harness runs one join per party task from a single value,
/// the way the runner runs one per process.
#[derive(Debug, Clone)]
pub struct MeshJoin {
    roster: Roster,
    seeds: SeedHints,
    epochs: Arc<EpochStore>,
    router: Option<SharedMeshRouter>,
    timeouts: MeshJoinTimeouts,
}

impl MeshJoin {
    /// Join the session `roster` defines, starting from `seeds`.
    pub fn new(roster: Roster, seeds: SeedHints, epochs: Arc<EpochStore>) -> Self {
        Self {
            roster,
            seeds,
            epochs,
            router: None,
            timeouts: MeshJoinTimeouts::default(),
        }
    }

    /// Fold learned peers into `router`'s book, and dial what it already holds.
    ///
    /// The PEX half of the join, and worth being precise about what it buys. A
    /// book entry pairs an address with the SPKI that claims it, so a book the
    /// join starts with gives discovery *aimed* probes rather than bare
    /// addresses. What it does not do is rescue a short `--peers` list on a
    /// first join: books are exchanged inside the handshake, after the
    /// connectivity barrier, so the mesh has to have formed before any of that
    /// gossip exists. A first mesh still forms out of the seeds alone.
    ///
    /// Without a router the join dials the seeds and nothing else, which is
    /// what a deployment that passes a full `--peers` list wants — and is why
    /// PEX stays independently revertible (design doc §8).
    pub fn with_router(mut self, router: SharedMeshRouter) -> Self {
        self.router = Some(router);
        self
    }

    pub fn with_timeouts(mut self, timeouts: MeshJoinTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    pub fn seeds(&self) -> &SeedHints {
        &self.seeds
    }
}

#[async_trait::async_trait]
impl SessionJoin for MeshJoin {
    async fn join(
        &self,
        net: &mut QuicNetworkManager,
        request: JoinRequest,
    ) -> MeshResult<MeshSession> {
        join_mesh(
            net,
            &self.roster,
            &self.seeds,
            self.epochs.as_ref(),
            self.router.as_ref(),
            self.timeouts,
            request,
        )
        .await
    }
}

/// Form a session from a pinned roster and a set of address hints.
///
/// `net` must already be listening: the address a peer dials is
/// [`JoinRequest::my_listen`], which the caller chose when it bound, and
/// `listen()` cannot be called twice on one manager (it replaces the endpoint,
/// and `set_local_certificate_der` refuses after one exists). The precondition
/// is checked rather than assumed — a manager with no local public key has no
/// certificate to be ranked by, and [`MeshError::LocalNotInRoster`] says so
/// before anything is dialed.
#[allow(clippy::too_many_arguments)]
pub async fn join_mesh(
    net: &mut QuicNetworkManager,
    roster: &Roster,
    seeds: &SeedHints,
    epochs: &EpochStore,
    router: Option<&SharedMeshRouter>,
    timeouts: MeshJoinTimeouts,
    request: JoinRequest,
) -> MeshResult<MeshSession> {
    let n = roster.n();
    if request.n_parties != n {
        return Err(MeshError::RosterSize {
            announced: request.n_parties,
            roster: n,
        });
    }
    if request.threshold != roster.t() {
        return Err(MeshError::RosterThreshold {
            announced: request.threshold,
            roster: roster.t(),
        });
    }

    // The allowlist goes in before anything else touches the transport: it
    // takes `&mut`, it is refused once a peer outside the roster is already
    // connected (`quic.rs:1300-1307`), and until it is in place the accept path
    // authorizes peers by pre-seeded transport id — the relay this whole
    // migration deletes.
    roster.install_into(net)?;

    let local = net
        .get_public_key()
        .cloned()
        .ok_or(MeshError::LocalNotInRoster)?;
    let my_rank = roster.index_of(&local).ok_or(MeshError::LocalNotInRoster)?;

    // This node's own address is first-hand knowledge, so it is seeded as
    // `RecordSource::Local` and no gossiped claim can displace it.
    let my_epoch = epochs.propose(&roster.digest())?;
    let my_record = PeerRecord::new(&local, request.my_listen, my_epoch);
    if let Some(router) = router {
        router.seed(my_record.clone());
    }

    // The accept loop spans discovery *and* the handshake. Stopping it at the
    // end of discovery is not safe: a peer that is still dialing would have its
    // connection aborted mid-handshake, and this node would be the one that
    // caused it.
    let shutdown = CancellationToken::new();
    let accepting = spawn_accept_loop(net.clone(), my_rank, shutdown.clone(), timeouts);

    let formed = async {
        discover_peers(net, roster, seeds, router, my_rank, n, timeouts).await?;
        wait_until_mesh_connected(net, n, timeouts.barrier).await?;

        // Party indices come from sorted SPKIs, so the rank the roster assigns
        // and the rank the transport derives must be the same number.
        let assigned = net.assign_party_ids();
        let transport_rank = net.local_party_id();
        if transport_rank != my_rank {
            return Err(MeshError::RankMismatch {
                roster_rank: my_rank,
                transport_rank,
            });
        }
        eprintln!(
            "[mesh party {my_rank}] mesh formed: {n} parties, {assigned} connection indices \
             assigned"
        );

        let handshake = handshake(
            net,
            roster,
            router,
            my_rank,
            my_epoch,
            my_record,
            &request,
            timeouts.handshake,
        );
        tokio::time::timeout(timeouts.handshake, handshake)
            .await
            .map_err(|_| MeshError::HandshakeTimeout {
                waited: timeouts.handshake,
            })?
    }
    .await;

    shutdown.cancel();
    let _ = accepting.await;
    let outcome = formed?;

    // Only now, with every party committed to the same digest, is the epoch
    // this node's history. A join that failed anywhere above leaves the counter
    // where it was, so a crashing peer cannot ratchet honest stores forward.
    epochs.commit(&roster.digest(), outcome.epoch)?;

    eprintln!(
        "[mesh party {my_rank}] session agreed: epoch={}, instance_id={}, digest={}",
        outcome.epoch,
        outcome.instance_id,
        hex::encode(&outcome.digest[..8])
    );

    Ok(MeshSession {
        program_id: request.program_id,
        instance_id: outcome.instance_id,
        entry: request.entry,
        parties: outcome.parties,
        n_parties: n,
        threshold: roster.t(),
    })
}

/// Dial until this node holds a live connection to every peer, or the discovery
/// budget runs out.
///
/// The caller runs the accept loop (see [`join_mesh`]); this dials on the
/// original manager while that loop accepts on a clone. Clones share the
/// connection and public-key maps, so what the loop accepts is visible here.
///
/// # Every dial is pinned to a rank this node is missing
///
/// The naive shape — "dial every address that has not answered yet" — is
/// unsound under a staggered start, and the failure is not a slow join, it is a
/// *dead* one. An address whose first dial failed because that party had not
/// bound yet stays unidentified for the rest of discovery, even after the party
/// comes up and connects *inbound*. This node then re-dials it on every
/// subsequent round while it is still missing somebody else, and an unpinned
/// re-dial of an already-connected peer is exactly what
/// `connect_as_server_inner`'s simultaneous-connect deduplication resolves by
/// **closing a live connection** (`quic.rs:2266-2288`, and symmetrically
/// `:3411-3441` on the peer's accept path). If the peer has already left the
/// barrier, the connection that dies is the one carrying its join handshake.
/// Settling the mesh before the handshake narrows that window; it does not
/// close it.
///
/// So discovery never dials "an address". It dials **a rank it does not hold,
/// at an address that might be that rank**, through
/// [`dial_address_expecting`]. Two consequences, and they are the whole fix:
///
/// 1. A rank this node already holds is never dialed, so the dial that used to
///    kill a live connection is never issued. This rests entirely on
///    [`missing_ranks`] being exact under *partial* connectivity — it reads
///    each connection's authenticated certificate rather than looking a rank up
///    in the transport, whose index order is the sort of the keys seen so far
///    and therefore skewed until the mesh is complete. A missing set that
///    over-reports would re-dial held peers, and the pin below could not refuse
///    those probes, because they would be correctly aimed.
/// 2. A pinned dial that reaches the wrong party is refused before the
///    transport opens a stream or deduplicates anything, so even a mis-aimed
///    probe cannot disturb a connection either side is holding. This covers the
///    hints that carry no identity; it does *not* cover (1), and treating it as
///    if it did is how a re-dial of a held peer gets shipped.
///
/// # And every dial is one half of a tournament
///
/// (1) and (2) together are still not enough, and the gap is what made a
/// five-party mesh fail roughly one run in three. `missing_ranks` is exact, but
/// it is a *snapshot*: a round reads it once and then spends up to one dial
/// timeout per hint issuing probes. A peer whose inbound connection is accepted
/// during that window is held by this node and still listed as missing, so the
/// round dials it — correctly aimed, so the pin cannot refuse it — and the
/// peer's accept path resolves the duplicate by closing the connection it is
/// holding (`quic.rs:3411-3441`). If the peer has already left the barrier,
/// what dies is the connection carrying its join handshake, which surfaces as
/// `Cannot receive: connection is Closed` on one side and a handshake timeout
/// on the other. Re-reading the missing set immediately before each dial
/// narrows that window; it cannot close it, because the peer's dial can also
/// land *during* this node's own dial handshake.
///
/// So a pair is dialed from **one** end only, chosen by [`dials_towards`]. No
/// duplicate connection between roster members is ever created, so the
/// tie-breaker never runs, so it can never close a live connection. The
/// direction is the one stoffelnet's own tie-breaker would have picked, which
/// is what makes the change invisible to everything downstream: the surviving
/// connection is the same connection either way.
///
/// The tournament costs something, and it is paid on purpose: a pair whose
/// higher-derive_id member holds no hint for the other is never dialed at all,
/// where an undirected rule would have let the other end cover it. There is no
/// timed escape hatch for that — see the module docs for why the one that
/// existed had to go — so a short seed list surfaces as a named discovery
/// timeout, which [`dial_duties`] gives the material for.
///
/// # Aiming the probes
///
/// A rank whose address is known — attributed by an earlier successful probe,
/// or paired with its SPKI in the peer book — is probed directly, under a
/// budget of one dial timeout per *missing rank*: a rank can be aimed at from
/// both the attribution map and the peer book, and both entries can be stale.
/// The remaining `--peers` hints carry no identity, so a round then walks every
/// (missing rank, hint) pair from a rotating cursor, under a budget of one dial
/// timeout per hint: the same wall-clock a round of one-dial-per-address used
/// to cost.
///
/// A probe that *succeeds* also puts its rank on a one-round cooldown. On a
/// healthy mesh that is free — a rank that connects and stays connected stops
/// being missing and is never probed again — and it bounds the one case that is
/// not healthy: a peer whose connection dies immediately after every handshake
/// would otherwise be re-probed with no sleep, because a round that made
/// progress re-plans immediately.
///
/// That budget is what makes walking the whole pair space affordable. A probe
/// aimed at the wrong party that *is* listening is refused in one handshake, so
/// once the mesh is up a single round identifies everything in milliseconds. A
/// probe at an address where nobody is listening costs the full dial timeout,
/// so while parties are still starting the budget cuts the round short after as
/// many dials as there are hints — and nothing would have connected anyway. The
/// cursor advances by one per round so a truncated round resumes where it
/// stopped instead of re-walking the same prefix.
#[allow(clippy::too_many_arguments)]
async fn discover_peers(
    net: &mut QuicNetworkManager,
    roster: &Roster,
    seeds: &SeedHints,
    router: Option<&SharedMeshRouter>,
    my_rank: PartyId,
    n: usize,
    timeouts: MeshJoinTimeouts,
) -> MeshResult<()> {
    // Having nothing to dial is only an error for a node that has something to
    // dial *to*. Under the tournament the member with the lowest derived id
    // wins no pair, so it issues no dial in a healthy mesh and a seed list is
    // genuinely optional for it — refusing it here would make the minimum
    // directional seed plan unjoinable for exactly one party, which is not a
    // configuration mistake but the plan working as intended. Every other node
    // still fails fast rather than spending the whole discovery budget
    // discovering it was handed no addresses.
    let all_peers: Vec<PartyId> = (0..n).filter(|rank| *rank != my_rank).collect();
    let duties = dial_duties(roster, my_rank, &all_peers);
    if !duties.is_empty()
        && seeds.is_empty()
        && router
            .map(|book| book.dial_targets().is_empty())
            .unwrap_or(true)
    {
        return Err(MeshError::NoSeeds);
    }

    let deadline = Instant::now() + timeouts.discovery;
    // Address to the roster rank whose certificate answered there. Used to
    // *aim* a later probe, not to suppress one: a rank whose connection is lost
    // has to be re-dialed, and its address is the one thing already known.
    let mut attributed: BTreeMap<SocketAddr, PartyId> = BTreeMap::new();
    // Where the rotation over (missing rank x unidentified hint) resumes.
    let mut cursor: usize = 0;
    // Earliest time a rank may be probed again after a probe that *succeeded*.
    // A rank that connects and stays connected is never probed again anyway —
    // it stops being missing — so this costs nothing on a healthy mesh. It
    // bounds the one case that is not healthy: a peer whose connection dies
    // immediately after every handshake, which would otherwise be re-probed
    // without a sleep for the whole discovery budget.
    let mut cooldown: BTreeMap<PartyId, Instant> = BTreeMap::new();

    loop {
        let mut missing = missing_ranks(net, roster, my_rank, n).await;
        if missing.is_empty() {
            // Stably complete, not momentarily complete: a connection can drop
            // between the moment the mesh first looks complete and the moment
            // the handshake starts, and the handshake has exactly one fatal
            // deadline, so it is much cheaper to notice here.
            sleep(timeouts.settle).await;
            missing = missing_ranks(net, roster, my_rank, n).await;
            if missing.is_empty() {
                return Ok(());
            }
            eprintln!(
                "[mesh party {my_rank}] mesh lost {} peer(s) while settling; still dialing",
                missing.len()
            );
        }

        // The completion check above is over *every* peer; the dialing below is
        // over this node's half of the tournament only, and over nothing else,
        // ever. A rank this node is not the dialer for is waited on, never
        // probed — not after a delay, not as a last resort before the deadline.
        // Every relaxation of that is a duplicate connection, and a duplicate
        // connection is a torn-down handshake.
        let mut dialable = dial_duties(roster, my_rank, &missing);

        let (aimed, unidentified) = probe_targets(roster, seeds, router, &attributed, &dialable);
        // `dialable` can be empty, and `aimed`/`unidentified` can both be empty,
        // and neither is an error. The member with the lowest derived id wins no
        // pair and so dials nothing at all, by design; any node can also be out
        // of unspent hints for the ranks it does win. The round then does
        // nothing and the accept loop does the work. Only the discovery deadline
        // decides that the rest are not coming, and when it does it separates
        // the ranks this node owed a dial from the ranks that owed one to it —
        // the two halves have different fixes.
        let mut progress = false;

        // Ranks whose address is already known: one exact probe each, under a
        // budget of one dial timeout per *missing rank* — not per known
        // address, because a rank can be aimed at from both the attribution map
        // and the peer book and both entries can be stale. Without the budget a
        // rank that keeps dropping right after it connects is re-probed as fast
        // as loopback allows, since a successful probe skips the inter-round
        // sleep below.
        let aimed_deadline = Instant::now()
            + timeouts
                .dial
                .saturating_mul(u32::try_from(dialable.len()).unwrap_or(u32::MAX));
        for (rank, addr) in aimed {
            if Instant::now() >= aimed_deadline {
                break;
            }
            if !dialable.contains(&rank) || !may_probe(&cooldown, rank) {
                continue;
            }
            // The tournament is what keeps this dial from ever racing a peer's
            // handshake. Re-reading the one rank here is the cheap half of the
            // same guard: a rank can also be held because an *earlier* probe in
            // this same round connected it without reporting success (a probe
            // that succeeded at the transport and then failed its pin, say), and
            // re-dialing a peer this node already holds is churn even when it
            // cannot produce a duplicate.
            if holds_rank(net, roster, rank).await {
                dialable.retain(|candidate| *candidate != rank);
                continue;
            }
            if probe_rank_at(
                net,
                roster,
                router,
                my_rank,
                rank,
                addr,
                timeouts,
                &mut attributed,
            )
            .await
            {
                progress = true;
                cooldown.insert(rank, Instant::now() + timeouts.discovery_round);
                dialable.retain(|candidate| *candidate != rank);
            }
        }

        // Hints with no identity yet: every (missing rank, hint) pair is a
        // candidate, walked from the rotating cursor and truncated by a round
        // budget of one dial timeout per hint — the same wall-clock a round of
        // one-dial-per-address used to cost.
        //
        // The budget is what makes trying every pair affordable. A probe aimed
        // at the wrong party that *is* listening is refused in one handshake, so
        // when the mesh is up a single round walks all of the pairs in
        // milliseconds and discovery converges at once. A probe at an address
        // where nobody is listening costs the whole dial timeout, so when
        // parties are still starting the budget stops the round after as many
        // dials as there are hints — and nothing would have connected anyway.
        // The cursor advances by one so a truncated round resumes where it
        // stopped rather than re-walking the same prefix.
        if !dialable.is_empty() && !unidentified.is_empty() {
            let ranks = dialable.clone();
            let pairs = unidentified.len() * ranks.len();
            let round_deadline = Instant::now()
                + timeouts
                    .dial
                    .saturating_mul(u32::try_from(unidentified.len()).unwrap_or(u32::MAX));

            for step in 0..pairs {
                if dialable.is_empty() || Instant::now() >= round_deadline {
                    break;
                }
                let (rank_index, hint_index) =
                    probe_pair(cursor, step, unidentified.len(), ranks.len());
                let addr = unidentified[hint_index];
                let rank = ranks[rank_index];
                if !dialable.contains(&rank) || attributed.contains_key(&addr) {
                    continue;
                }
                if !may_probe(&cooldown, rank) {
                    continue;
                }
                if holds_rank(net, roster, rank).await {
                    dialable.retain(|candidate| *candidate != rank);
                    continue;
                }
                if probe_rank_at(
                    net,
                    roster,
                    router,
                    my_rank,
                    rank,
                    addr,
                    timeouts,
                    &mut attributed,
                )
                .await
                {
                    progress = true;
                    cooldown.insert(rank, Instant::now() + timeouts.discovery_round);
                    dialable.retain(|candidate| *candidate != rank);
                }
            }
            cursor = cursor.wrapping_add(1);
        }

        if Instant::now() >= deadline {
            // Name the two halves separately, because they have different
            // fixes and an operator cannot tell them apart from a config file:
            // derived ids are BLAKE3 digests, so which end of a pair dials is
            // not readable off `--peers`.
            let mine = dial_duties(roster, my_rank, &missing);
            let theirs: Vec<PartyId> = missing
                .iter()
                .copied()
                .filter(|rank| !mine.contains(rank))
                .collect();
            eprintln!(
                "[mesh party {my_rank}] discovery gave up still missing parties {missing:?}. \
                 This node is the dialer for {mine:?}: each of those must be reachable at one of \
                 this node's --peers hints. Parties {theirs:?} must dial this node themselves: \
                 each of them must list this node in its own --peers. Passing every party the \
                 full n-1 peer list satisfies both halves whatever the derived-id order is."
            );
            return Err(MeshError::MeshIncomplete {
                expected: n,
                waited: timeouts.discovery,
            });
        }
        // A round that connected somebody has changed what is missing and what
        // is attributed; re-plan immediately rather than idling for a peer that
        // is already here. The deadline is checked *first* so that a peer whose
        // connection keeps dropping and being re-probed cannot spin here past
        // the discovery budget.
        if progress {
            continue;
        }
        sleep(timeouts.discovery_round).await;
    }
}

/// This node's half of the tournament, out of the ranks it is still missing.
///
/// Pulled out of [`discover_peers`] as a pure function for one reason: it is
/// the single place a rank becomes dialable, and it is the place a future
/// "just this once" relaxation would be written. Keeping it addressable lets
/// `discovery_only_ever_dials_its_half_of_the_tournament` assert the partition
/// over the real filter rather than over [`dials_towards`] alone — the gap that
/// let a timed escape hatch ship under a green tournament test.
pub(crate) fn dial_duties(roster: &Roster, my_rank: PartyId, missing: &[PartyId]) -> Vec<PartyId> {
    missing
        .iter()
        .copied()
        .filter(|rank| dials_towards(roster, my_rank, *rank))
        .collect()
}

/// Which end of a pair dials: the one whose transport-derived id is higher.
///
/// A mesh has no bootstrap ordering to lean on, so without a rule every node
/// dials every node it is missing and every pair is dialed twice. stoffelnet
/// deduplicates that by closing one of the two connections
/// (`quic.rs:2262-2288` on the dialer, `:3411-3441` on the acceptor), and the
/// connection it closes is a *live* one — which is fine while both ends are
/// still in discovery and fatal once either has left the barrier and is
/// streaming its join handshake. A pair that is only ever dialed from one end
/// never reaches that code at all.
///
/// The order is stoffelnet's own, not the roster's. `NodePublicKey::derive_id`
/// is a BLAKE3 of the SPKI, so it is unrelated to the lexicographic SPKI sort
/// that ranks the roster, and it is the order the tie-breaker uses: the higher
/// derived id keeps its **outgoing** connection. Dialing in that direction
/// means the connection this tournament produces is byte-for-byte the one the
/// tie-breaker would have left standing, so nothing downstream — `missing_ranks`,
/// the barrier, `peer_connections`, the router — can tell the difference.
///
/// Equal derived ids would leave a pair undialed from both ends, so the SPKI
/// bytes break that tie. Two roster members with the same derived id are
/// already indistinguishable to the transport (they share a compact party id),
/// so this only makes the degenerate case fail as a hang rather than silently.
pub(crate) fn dials_towards(roster: &Roster, my_rank: PartyId, peer_rank: PartyId) -> bool {
    let (Some(mine), Some(theirs)) = (roster.key_of(my_rank), roster.key_of(peer_rank)) else {
        // A rank with no roster entry cannot be dialed at all; saying "not my
        // turn" keeps the decision in one place.
        return false;
    };
    match mine.derive_id().cmp(&theirs.derive_id()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => mine.0 > theirs.0,
    }
}

/// Whether this node holds a live connection to `rank` *right now*.
///
/// The single-rank form of [`missing_ranks`], read the same way — from each
/// connection's authenticated certificate, never from a rank lookup — and used
/// immediately before a dial so that a peer accepted since the round's snapshot
/// is not dialed back.
async fn holds_rank(net: &QuicNetworkManager, roster: &Roster, rank: PartyId) -> bool {
    for (_, conn) in net.get_all_server_connections() {
        let holds = conn
            .authenticated_peer_public_key()
            .and_then(|key| roster.index_of(&key))
            .map(|seen| seen == rank)
            .unwrap_or(false);
        if holds && conn.is_connected().await {
            return true;
        }
    }
    false
}

/// Whether `rank` has served out the cooldown a successful probe puts on it.
fn may_probe(cooldown: &BTreeMap<PartyId, Instant>, rank: PartyId) -> bool {
    cooldown
        .get(&rank)
        .map(|until| Instant::now() >= *until)
        .unwrap_or(true)
}

/// The (rank, hint) pair a round's `step`th probe aims at.
///
/// Extracted and pure because the *rotation* is the part that fails silently:
/// a scheme that advances the cursor by the number of hints re-derives the same
/// pairing every round whenever the two counts share a factor — three hints and
/// three missing ranks, the default three-party mesh — and discovery then runs
/// its whole budget out without ever trying the pairing that would have
/// connected. See `the_probe_rotation_covers_every_pair`.
fn probe_pair(cursor: usize, step: usize, hints: usize, ranks: usize) -> (usize, usize) {
    let index = (cursor + step) % (hints * ranks);
    (index / hints, index % hints)
}

/// Split what is dialable into "we know which rank is here" and "we do not".
///
/// The peer book contributes to the first half rather than the second: a
/// `PeerRecord` pairs an address with the SPKI that claims it, and the roster
/// turns that SPKI into a rank. A relayed record is still only a hint — the pin
/// is what makes acting on it safe — but it is an *aimed* hint, which is worth
/// strictly more than a bare address.
fn probe_targets(
    roster: &Roster,
    seeds: &SeedHints,
    router: Option<&SharedMeshRouter>,
    attributed: &BTreeMap<SocketAddr, PartyId>,
    missing: &[PartyId],
) -> (Vec<(PartyId, SocketAddr)>, Vec<SocketAddr>) {
    let mut aimed: BTreeSet<(PartyId, SocketAddr)> = BTreeSet::new();
    let mut identified: BTreeSet<SocketAddr> = BTreeSet::new();

    for (addr, rank) in attributed {
        identified.insert(*addr);
        if missing.contains(rank) {
            aimed.insert((*rank, *addr));
        }
    }
    if let Some(router) = router {
        for (key, addr) in router.dial_targets() {
            let Some(rank) = roster.index_of(&key) else {
                continue;
            };
            identified.insert(addr);
            if missing.contains(&rank) {
                aimed.insert((rank, addr));
            }
        }
    }

    let unidentified: Vec<SocketAddr> = seeds
        .addrs()
        .iter()
        .copied()
        .filter(|addr| !identified.contains(addr))
        .collect();

    (aimed.into_iter().collect(), unidentified)
}

/// One pinned dial: admit `addr` only if it answers as the roster's `rank`.
///
/// Returns whether this node now holds `rank`. A refusal is not an error — an
/// address hint carries no identity, so a probe aimed at the wrong party is an
/// ordinary outcome of discovery, and the certificate that refused it is what
/// kept the probe harmless.
#[allow(clippy::too_many_arguments)]
async fn probe_rank_at(
    net: &mut QuicNetworkManager,
    roster: &Roster,
    router: Option<&SharedMeshRouter>,
    my_rank: PartyId,
    rank: PartyId,
    addr: SocketAddr,
    timeouts: MeshJoinTimeouts,
    attributed: &mut BTreeMap<SocketAddr, PartyId>,
) -> bool {
    let Some(expected) = roster.key_of(rank).cloned() else {
        return false;
    };
    let Ok(conn) = dial_address_expecting(net, addr, &expected, timeouts.dial).await else {
        return false;
    };

    // The pin already proved this, so a disagreement here would mean the
    // transport handed back a connection to somebody else — `Ok` from the
    // deduplication branch is the one path that returns a connection this dial
    // did not establish (`quic.rs:2280-2298`). Checking the certificate that
    // was actually authenticated, rather than the one asked for, is what makes
    // the attribution a fact instead of an intention.
    match conn
        .authenticated_peer_public_key()
        .and_then(|key| roster.index_of(&key))
    {
        Some(seen) if seen == rank => {
            eprintln!("[mesh party {my_rank}] {addr} is party {rank}");
            attributed.insert(addr, rank);
            if let Some(router) = router {
                // First-hand: this node chose the address and the certificate
                // at the other end proved who answered, which is the same
                // binding a peer's own `PeerAnnounce` carries.
                router.observe_announced(PeerRecord::new(&expected, addr, 0));
            }
            true
        }
        other => {
            eprintln!(
                "[mesh party {my_rank}] {addr} was pinned to party {rank} but the transport \
                 returned a connection to {other:?}"
            );
            false
        }
    }
}

/// Roster ranks this node does not hold a *live* connection to.
///
/// # Identity first, never by rank
///
/// The obvious implementation — ask `get_connection_by_party_id(rank)` for each
/// rank — is wrong everywhere discovery runs, and wrong in the direction that
/// costs a live connection. stoffelnet resolves that index through
/// `get_sorted_public_keys()` (`quic.rs:1856-1879`): the local key plus the
/// peers whose certificates have actually been *seen so far*, sorted.
/// [`Roster::install_into`] populates `allowed_peer_public_keys` and never
/// `peer_public_keys` (`quic.rs:1273-1322`), so throughout discovery that list
/// is a strict subset of the roster. Sort order survives subsetting, so a peer
/// the roster ranks `r` sits at some partial index `p <= r`, and the lookup at
/// `r` returns a *different* peer's connection — or `None` — as soon as any
/// lower-ranked member is still unknown. The rank is then reported missing
/// while it is live, and discovery re-dials a peer it already holds. That probe
/// is correctly aimed, so the certificate pin cannot refuse it: it passes the
/// comparison at `quic.rs:2203-2219`, reaches `open_bi` at `:2221` and the
/// simultaneous-connect tie-breaker at `:2266`, and when this node's derived id
/// is the higher one the peer's accept path closes the connection it was
/// holding (`:3411-3441`). Pinning protects the *mis-aimed* probe; only an
/// exact missing set protects the correctly-aimed one.
///
/// So the connections are enumerated and each one's **authenticated**
/// certificate is mapped back through the roster. That answer does not depend
/// on how many peers are known, which is the property discovery needs and the
/// one rank lookup cannot provide. See
/// `the_missing_set_is_read_from_certificates_not_from_rank_lookups`.
///
/// Note [`peer_connections`] does index by rank, and is right to: it runs after
/// the barrier, where the key set is complete, and it treats a disagreement as
/// an error rather than as absence.
///
/// # Liveness, not acquaintance
///
/// Also deliberately stronger than `is_fully_connected`, which counts
/// `peer_public_keys` — a map written when a peer authenticates and never
/// cleared when its connection closes. A node whose duplicate connection was
/// closed by the tie-breaker still counts there, so the cheap predicate can
/// report a complete mesh over a dead socket.
pub(crate) async fn missing_ranks(
    net: &QuicNetworkManager,
    roster: &Roster,
    my_rank: PartyId,
    n: usize,
) -> Vec<PartyId> {
    let mut held: BTreeSet<PartyId> = BTreeSet::new();
    for (_, conn) in net.get_all_server_connections() {
        let Some(rank) = conn
            .authenticated_peer_public_key()
            .and_then(|key| roster.index_of(&key))
        else {
            // The loopback entry, or a peer outside the roster. Neither can
            // satisfy a rank.
            continue;
        };
        if rank == my_rank || rank >= n || held.contains(&rank) {
            continue;
        }
        if conn.is_connected().await {
            held.insert(rank);
        }
    }

    (0..n)
        .filter(|rank| *rank != my_rank && !held.contains(rank))
        .collect()
}

/// Accept inbound peers until the join tells it to stop.
fn spawn_accept_loop(
    mut acceptor: QuicNetworkManager,
    my_rank: PartyId,
    shutdown: CancellationToken,
    timeouts: MeshJoinTimeouts,
) -> tokio::task::JoinHandle<usize> {
    tokio::spawn(async move {
        let mut accepted = 0usize;
        loop {
            if shutdown.is_cancelled() {
                return accepted;
            }
            tokio::select! {
                _ = shutdown.cancelled() => return accepted,
                result = tokio::time::timeout(timeouts.accept_poll, acceptor.accept()) => {
                    match result {
                        Ok(Ok(conn)) => {
                            accepted += 1;
                            eprintln!(
                                "[mesh party {my_rank}] accepted a peer from {}",
                                conn.remote_address()
                            );
                        }
                        // A rejected handshake is the allowlist working. It is
                        // not a reason to stop accepting.
                        Ok(Err(reason)) => {
                            eprintln!("[mesh party {my_rank}] accept refused: {reason}");
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    })
}

/// What the lock-step handshake agreed.
struct Agreement {
    epoch: u64,
    instance_id: u64,
    digest: [u8; 32],
    parties: Vec<(PartyId, SocketAddr)>,
}

/// The all-to-all agreement, in lock-step, on connections this task owns.
#[allow(clippy::too_many_arguments)]
async fn handshake(
    net: &QuicNetworkManager,
    roster: &Roster,
    router: Option<&SharedMeshRouter>,
    my_rank: PartyId,
    my_epoch: u64,
    my_record: PeerRecord,
    request: &JoinRequest,
    budget: Duration,
) -> MeshResult<Agreement> {
    let n = roster.n();
    let roster_digest = roster.digest();
    let mut parties: Vec<(PartyId, SocketAddr)> = vec![(my_rank, request.my_listen)];
    let mine = SessionProposal {
        roster_digest,
        execution_id: request.execution_id,
        program_id: request.program_id,
        entry: request.entry.clone(),
        n_parties: n as u64,
        threshold: roster.t() as u64,
    };

    let peers = peer_connections(net, roster, my_rank, n)?;

    // ---- send: readiness, then what we know, then what we propose ----------
    let ready = BarrierTag::MeshReady;
    let mut ready_frame = ready.prefix().to_vec();
    ready_frame.extend_from_slice(&roster_namespace(&roster_digest).to_le_bytes());

    let book_frame = wire::encode(&MeshMessage::PeerBook {
        records: local_book(router, &my_record),
    })?;
    let proposal = MeshMessage::JoinProposal {
        roster_digest: mine.roster_digest,
        execution_id: mine.execution_id,
        program_id: mine.program_id,
        entry: mine.entry.clone(),
        n_parties: mine.n_parties,
        threshold: mine.threshold,
        epoch: my_epoch,
    };
    let proposal_frame = wire::encode(&proposal)?;

    for (rank, conn) in &peers {
        send_to(
            *rank,
            conn.as_ref(),
            "announcing mesh readiness",
            &ready_frame,
        )
        .await?;
        send_to(*rank, conn.as_ref(), "sending the peer book", &book_frame).await?;
        send_to(
            *rank,
            conn.as_ref(),
            "sending the join proposal",
            &proposal_frame,
        )
        .await?;
    }

    // ---- read: the same three, in the same order --------------------------
    let expected_namespace = roster_namespace(&roster_digest);
    let mut epochs = vec![my_epoch];
    for (rank, conn) in &peers {
        let payload = read_from(*rank, conn.as_ref(), budget).await?;
        match BarrierTag::classify(&payload) {
            Some((BarrierTag::MeshReady, namespace)) if namespace == expected_namespace => {}
            Some((BarrierTag::MeshReady, namespace)) => {
                return Err(MeshError::RosterNamespaceMismatch {
                    party_id: *rank,
                    expected: expected_namespace,
                    got: namespace,
                })
            }
            _ => {
                return Err(MeshError::UnexpectedFrame {
                    party_id: *rank,
                    expected: "MeshReady",
                    got: "another frame",
                })
            }
        }

        let book = read_message(*rank, conn.as_ref(), budget, "PeerBook").await?;
        let MeshMessage::PeerBook { records } = book else {
            return Err(MeshError::UnexpectedFrame {
                party_id: *rank,
                expected: "PeerBook",
                got: book.kind(),
            });
        };
        let announced = absorb_book(router, roster, records);
        parties.push((
            *rank,
            announced
                .get(rank)
                .copied()
                .unwrap_or_else(|| conn.remote_address()),
        ));

        let message = read_message(*rank, conn.as_ref(), budget, "JoinProposal").await?;
        let MeshMessage::JoinProposal {
            roster_digest: peer_roster,
            execution_id,
            program_id,
            entry,
            n_parties,
            threshold,
            epoch,
        } = message
        else {
            return Err(MeshError::UnexpectedFrame {
                party_id: *rank,
                expected: "JoinProposal",
                got: message.kind(),
            });
        };

        let theirs = SessionProposal {
            roster_digest: peer_roster,
            execution_id,
            program_id,
            entry,
            n_parties,
            threshold,
        };
        if let Some(field) = mine.first_divergence(&theirs) {
            return Err(MeshError::SessionDivergence {
                party_id: *rank,
                field,
            });
        }
        epochs.push(epoch);
    }

    // ---- agree, commit, verify -------------------------------------------
    let epoch = agree_epoch(my_epoch.saturating_sub(1), &epochs)?;
    let instance_id = derive_instance_id(&roster_digest, &request.program_id, epoch);
    let digest = session_digest(
        &roster_digest,
        &request.execution_id,
        &request.program_id,
        &request.entry,
        n as u64,
        roster.t() as u64,
        epoch,
    );
    let commit_frame = wire::encode(&MeshMessage::JoinCommit {
        proposal_digest: digest,
        instance_id,
    })?;

    for (rank, conn) in &peers {
        send_to(
            *rank,
            conn.as_ref(),
            "sending the join commitment",
            &commit_frame,
        )
        .await?;
    }
    for (rank, conn) in &peers {
        let message = read_message(*rank, conn.as_ref(), budget, "JoinCommit").await?;
        let MeshMessage::JoinCommit {
            proposal_digest,
            instance_id: peer_instance_id,
        } = message
        else {
            return Err(MeshError::UnexpectedFrame {
                party_id: *rank,
                expected: "JoinCommit",
                got: message.kind(),
            });
        };
        if proposal_digest != digest || peer_instance_id != instance_id {
            return Err(MeshError::CommitDivergence {
                party_id: *rank,
                expected: format!("{}/{instance_id}", hex::encode(&digest[..8])),
                got: format!("{}/{peer_instance_id}", hex::encode(&proposal_digest[..8])),
            });
        }
    }

    parties.sort_by_key(|(rank, _)| *rank);
    Ok(Agreement {
        epoch,
        instance_id,
        digest,
        parties,
    })
}

/// The connection for every peer, checked against the roster.
///
/// `get_connection_by_party_id` resolves a rank through
/// `get_sorted_public_keys`, which at full connectivity is the roster's own
/// order — but "at full connectivity" is an assumption, so the certificate the
/// connection actually authenticated is compared against the roster's rank for
/// it. A mismatch means this node would address a peer under the wrong index,
/// which no layer below would report.
fn peer_connections(
    net: &QuicNetworkManager,
    roster: &Roster,
    my_rank: PartyId,
    n: usize,
) -> MeshResult<Vec<(PartyId, Arc<dyn PeerConnection>)>> {
    (0..n)
        .filter(|rank| *rank != my_rank)
        .map(|rank| {
            let conn = net
                .get_connection_by_party_id(rank)
                .ok_or(MeshError::PeerConnectionMissing { party_id: rank })?;
            let presented = conn
                .authenticated_peer_public_key()
                .and_then(|key| roster.index_of(&key));
            if presented != Some(rank) {
                return Err(MeshError::PeerIdentityMismatch {
                    party_id: rank,
                    presented,
                });
            }
            Ok((rank, conn))
        })
        .collect()
}

/// What this node offers the mesh about where everybody is.
fn local_book(router: Option<&SharedMeshRouter>, my_record: &PeerRecord) -> Vec<PeerRecord> {
    let mut records = vec![my_record.clone()];
    if let Some(router) = router {
        for record in router.book_snapshot(MAX_PEER_RECORDS_PER_MESSAGE) {
            if record.spki != my_record.spki {
                records.push(record);
            }
        }
    }
    records.truncate(MAX_PEER_RECORDS_PER_MESSAGE);
    records
}

/// Fold a peer's book in, and report the roster rank of every address it named.
///
/// Records for SPKIs outside the roster are dropped here as well as by a pinned
/// book: a roster-pinned mesh has no use for an address it can never dial.
fn absorb_book(
    router: Option<&SharedMeshRouter>,
    roster: &Roster,
    records: Vec<PeerRecord>,
) -> BTreeMap<PartyId, SocketAddr> {
    let mut announced = BTreeMap::new();
    for record in records {
        let Some(rank) = roster.index_of(&record.public_key()) else {
            continue;
        };
        announced.insert(rank, record.advertise_addr);
        if let Some(router) = router {
            // Relayed, not announced: a peer book is hearsay about third
            // parties, so it fills gaps but never displaces a first-hand entry.
            router.observe_relayed(record);
        }
    }
    announced
}

async fn send_to(
    rank: PartyId,
    conn: &dyn PeerConnection,
    operation: &'static str,
    payload: &[u8],
) -> MeshResult<()> {
    conn.send(payload)
        .await
        .map_err(|reason| MeshError::PeerExchange {
            party_id: rank,
            operation,
            reason,
        })
}

async fn read_from(
    rank: PartyId,
    conn: &dyn PeerConnection,
    budget: Duration,
) -> MeshResult<Vec<u8>> {
    tokio::time::timeout(budget, conn.receive())
        .await
        .map_err(|_| MeshError::HandshakeTimeout { waited: budget })?
        .map_err(|reason| MeshError::PeerExchange {
            party_id: rank,
            operation: "reading a handshake frame",
            reason,
        })
}

async fn read_message(
    rank: PartyId,
    conn: &dyn PeerConnection,
    budget: Duration,
    expected: &'static str,
) -> MeshResult<MeshMessage> {
    let payload = read_from(rank, conn, budget).await?;
    wire::try_decode(&payload)?.ok_or(MeshError::UnexpectedFrame {
        party_id: rank,
        expected,
        got: "a frame that is not mesh control traffic",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROSTER: [u8; 32] = [1u8; 32];
    const PROGRAM: [u8; 32] = [2u8; 32];
    const EXECUTION: SessionExecutionId = SessionExecutionId::from_bytes([3u8; 32]);

    fn digest_of(entry: &str, n: u64, t: u64, epoch: u64) -> [u8; 32] {
        session_digest(&ROSTER, &EXECUTION, &PROGRAM, entry, n, t, epoch)
    }

    /// Every field the parties agree on has to move the digest, or the
    /// `JoinCommit` comparison would pass on a session they do not share.
    #[test]
    fn every_agreed_field_changes_the_session_digest() {
        let base = digest_of("main", 5, 1, 7);

        assert_ne!(
            base,
            session_digest(&[9u8; 32], &EXECUTION, &PROGRAM, "main", 5, 1, 7)
        );
        assert_ne!(
            base,
            session_digest(
                &ROSTER,
                &SessionExecutionId::from_bytes([9u8; 32]),
                &PROGRAM,
                "main",
                5,
                1,
                7
            )
        );
        assert_ne!(
            base,
            session_digest(&ROSTER, &EXECUTION, &[9u8; 32], "main", 5, 1, 7)
        );
        assert_ne!(base, digest_of("other", 5, 1, 7));
        assert_ne!(base, digest_of("main", 4, 1, 7));
        assert_ne!(base, digest_of("main", 5, 2, 7));
        assert_ne!(base, digest_of("main", 5, 1, 8));
        assert_eq!(base, digest_of("main", 5, 1, 7));
    }

    /// Length-prefixing the entry is what stops two different sessions from
    /// hashing the same bytes.
    #[test]
    fn the_entry_cannot_be_shifted_into_the_counts() {
        assert_ne!(digest_of("ab", 5, 1, 7), digest_of("a", 5, 1, 7));
        assert_ne!(digest_of("main", 5, 1, 7), digest_of("mai", 5, 1, 7));
    }

    /// The digest must not collide with the other three BLAKE3 constructions in
    /// this crate over the same inputs.
    #[test]
    fn the_session_digest_is_domain_separated_from_the_other_digests() {
        let mut plain = blake3::Hasher::new();
        plain.update(&ROSTER);
        plain.update(&PROGRAM);
        assert_ne!(*plain.finalize().as_bytes(), digest_of("", 0, 0, 0));
        for other in [
            crate::net::mesh::roster::ROSTER_DIGEST_CONTEXT,
            crate::net::session::INSTANCE_ID_CONTEXT,
            "stoffel-program-v1",
            "stoffel-mesh-session-v1",
        ] {
            assert_ne!(SESSION_DIGEST_CONTEXT, other);
        }
    }

    fn proposal() -> SessionProposal {
        SessionProposal {
            roster_digest: ROSTER,
            execution_id: EXECUTION,
            program_id: PROGRAM,
            entry: "main".to_owned(),
            n_parties: 5,
            threshold: 1,
        }
    }

    /// A party started for another coordinator execution proposes the same
    /// roster, program and parameters, and is still not in this session: the
    /// join refuses it by name, right after the roster.
    #[test]
    fn a_party_proposing_another_execution_is_refused_at_the_join() {
        let mine = proposal();
        let theirs = SessionProposal {
            execution_id: SessionExecutionId::from_bytes([4u8; 32]),
            ..proposal()
        };

        assert_eq!(
            mine.first_divergence(&theirs),
            Some(SessionField::ExecutionId)
        );
        assert_eq!(mine.first_divergence(&proposal()), None);
        // Compared right after the roster digest, before every other field.
        let everything_differs = SessionProposal {
            roster_digest: [8u8; 32],
            execution_id: SessionExecutionId::from_bytes([4u8; 32]),
            program_id: [8u8; 32],
            entry: "other".to_owned(),
            n_parties: 7,
            threshold: 2,
        };
        assert_eq!(
            mine.first_divergence(&everything_differs),
            Some(SessionField::RosterDigest)
        );
        let all_but_the_roster = SessionProposal {
            roster_digest: ROSTER,
            ..everything_differs
        };
        assert_eq!(
            mine.first_divergence(&all_but_the_roster),
            Some(SessionField::ExecutionId)
        );
        assert_eq!(
            MeshError::SessionDivergence {
                party_id: 2,
                field: SessionField::ExecutionId,
            }
            .to_string(),
            "party 2 proposed a different execution id; this is not one session"
        );
    }

    /// The `MeshReady` namespace is the roster, so two rosters are two
    /// namespaces and a cross-roster peer is refused at the first frame.
    #[test]
    fn two_rosters_announce_two_namespaces() {
        assert_ne!(roster_namespace(&ROSTER), roster_namespace(&[2u8; 32]));
        assert_eq!(roster_namespace(&ROSTER), roster_namespace(&ROSTER));
    }

    /// Every (missing rank, unidentified hint) pair has to be reachable, even
    /// when each round's budget is exhausted after `hints` probes.
    ///
    /// This is the property that broke: the first rotation advanced the cursor
    /// by `hints`, which for `hints == ranks` produces the identical pairing
    /// every round. A three-party mesh whose SPKI order does not happen to match
    /// its `--peers` order then never tries the pairing it needs, and discovery
    /// fails with `MeshIncomplete` on a fully healthy network.
    #[test]
    fn the_probe_rotation_covers_every_pair() {
        for hints in 1..=5usize {
            for ranks in 1..=5usize {
                let mut seen = BTreeSet::new();
                // Worst case: the round budget stops after one probe per hint.
                for round in 0..(hints * ranks) {
                    for step in 0..hints {
                        seen.insert(probe_pair(round, step, hints, ranks));
                    }
                }
                assert_eq!(
                    seen.len(),
                    hints * ranks,
                    "rotation over {hints} hint(s) and {ranks} rank(s) missed a pair"
                );
            }
        }
    }

    /// The rotation this replaced, spelled out, so the test above is not
    /// vacuous: it pairs hint `step` with rank `(cursor + step) % ranks` and
    /// advances the cursor by the number of hints, which for `hints == ranks`
    /// collapses to pairing hint `i` with rank `i` forever.
    ///
    /// Three hints and three missing ranks is the default three-party mesh, and
    /// a roster orders parties by SPKI while `--peers` is written in whatever
    /// order the operator likes — so "hint i is rank i" is a coincidence, not a
    /// configuration. This is what made a healthy three-party mesh time out.
    #[test]
    fn the_rotation_this_replaced_starves_pairs() {
        let (hints, ranks) = (3usize, 3usize);
        let mut seen = BTreeSet::new();
        let mut cursor = 0usize;
        for _ in 0..(hints * ranks) {
            for step in 0..hints {
                seen.insert(((cursor + step) % ranks, step));
            }
            cursor += hints;
        }
        assert_eq!(
            seen.len(),
            3,
            "the replaced rotation was expected to reach only the diagonal"
        );
    }

    /// A key whose SPKI bytes are `[tag; 32]`, distinct per tag.
    fn key(tag: u8) -> stoffelnet::network_utils::NodePublicKey {
        stoffelnet::network_utils::NodePublicKey(vec![tag; 32])
    }

    fn roster_of(tags: &[u8]) -> Roster {
        Roster::from_node_keys(tags.iter().copied().map(key).collect(), 1)
            .expect("build a roster from distinct keys")
    }

    /// The property that makes a mesh safe to form: for every pair, **exactly
    /// one** side dials.
    ///
    /// Both sides dialing is what let stoffelnet's simultaneous-connect
    /// tie-breaker close a connection a peer was already streaming its join
    /// handshake over — a five-party mesh failed about one run in three on that
    /// — and neither side dialing is a pair that never connects.
    #[test]
    fn the_mesh_dial_partition_is_a_tournament() {
        for size in 3..=8usize {
            let tags: Vec<u8> = (0..size as u8).map(|index| index * 7 + 1).collect();
            let roster = roster_of(&tags);
            for a in 0..size {
                for b in 0..size {
                    if a == b {
                        continue;
                    }
                    assert_ne!(
                        dials_towards(&roster, a, b),
                        dials_towards(&roster, b, a),
                        "ranks {a} and {b} of a {size}-node roster must be dialed from exactly \
                         one end"
                    );
                }
            }
        }
    }

    /// The direction is stoffelnet's, not the roster's: the higher *derived*
    /// id dials, because that is the side whose outgoing connection the
    /// transport's tie-breaker keeps (`quic.rs:2262-2288`). Anchoring the
    /// tournament anywhere else would still be a tournament, but the surviving
    /// connection would no longer be the dialer's.
    #[test]
    fn the_dialer_is_the_side_the_transport_tie_breaker_would_keep() {
        let roster = roster_of(&[3, 11, 29, 47, 61]);
        for rank in 0..roster.n() {
            for peer in 0..roster.n() {
                if rank == peer {
                    continue;
                }
                let mine = roster.key_of(rank).expect("rank in roster").derive_id();
                let theirs = roster.key_of(peer).expect("peer in roster").derive_id();
                assert_eq!(
                    dials_towards(&roster, rank, peer),
                    mine > theirs,
                    "rank {rank} must dial rank {peer} exactly when its derived id is higher"
                );
            }
        }
    }

    /// The partition asserted over the filter discovery actually runs.
    ///
    /// [`the_mesh_dial_partition_is_a_tournament`] pins [`dials_towards`], and
    /// a green [`dials_towards`] is exactly what let a timed escape hatch ship
    /// beside it: discovery marked a rank dialable on `dials_towards(..) ||
    /// missing_for_long_enough`, so the invariant the module claims — that no
    /// duplicate connection between roster members is ever created — was false
    /// while every test of it passed. This one asserts the partition over
    /// [`dial_duties`], the single place a rank becomes dialable, so a second
    /// disjunct cannot be added without failing a test.
    ///
    /// The missing set is *every* peer, which is the state a node starts in and
    /// the state a late-starting party's peers sit in: the whole point is that
    /// even then, this node dials only its half.
    #[test]
    fn discovery_only_ever_dials_its_half_of_the_tournament() {
        for size in 3..=8usize {
            let tags: Vec<u8> = (0..size as u8).map(|index| index * 7 + 1).collect();
            let roster = roster_of(&tags);
            let mut dialed: BTreeSet<(PartyId, PartyId)> = BTreeSet::new();
            for rank in 0..size {
                let missing: Vec<PartyId> = (0..size).filter(|peer| *peer != rank).collect();
                for duty in dial_duties(&roster, rank, &missing) {
                    assert!(
                        dials_towards(&roster, rank, duty),
                        "rank {rank} must never be handed a duty it does not win: {duty}"
                    );
                    dialed.insert((rank, duty));
                }
            }
            for a in 0..size {
                for b in (a + 1)..size {
                    assert_ne!(
                        dialed.contains(&(a, b)),
                        dialed.contains(&(b, a)),
                        "pair ({a}, {b}) of a {size}-node roster must be dialed from exactly one \
                         end, even when both ends are missing everybody"
                    );
                }
            }
        }
    }

    /// A rank already held is not a duty, so a round re-planned after a peer
    /// arrives stops dialing it. Cheap, but it is the property that keeps a
    /// re-plan from being churn.
    #[test]
    fn a_rank_that_is_no_longer_missing_is_no_longer_a_duty() {
        let roster = roster_of(&[3, 11, 29, 47, 61]);
        for rank in 0..roster.n() {
            let all: Vec<PartyId> = (0..roster.n()).filter(|peer| *peer != rank).collect();
            let duties = dial_duties(&roster, rank, &all);
            for held in &duties {
                let remaining: Vec<PartyId> =
                    all.iter().copied().filter(|peer| peer != held).collect();
                assert!(
                    !dial_duties(&roster, rank, &remaining).contains(held),
                    "rank {rank} must not keep dialing {held} once it holds it"
                );
            }
        }
    }

    /// Roster rank is a lexicographic SPKI sort and `derive_id` is a BLAKE3 of
    /// the same bytes, so the two orders are unrelated. The tournament has to
    /// be anchored on the second one, and this pins that they really do differ
    /// — otherwise the test above would pass for the wrong reason.
    #[test]
    fn roster_rank_order_is_not_derived_id_order() {
        let roster = roster_of(&[3, 11, 29, 47, 61]);
        let derived: Vec<usize> = (0..roster.n())
            .map(|rank| roster.key_of(rank).expect("rank in roster").derive_id())
            .collect();
        assert!(
            derived.windows(2).any(|pair| pair[0] > pair[1]),
            "if derived ids happened to be rank-ordered, pick different fixture keys: {derived:?}"
        );
    }

    #[test]
    fn a_session_field_names_itself_in_the_divergence_error() {
        let error = MeshError::SessionDivergence {
            party_id: 3,
            field: SessionField::Threshold,
        };
        assert_eq!(
            error.to_string(),
            "party 3 proposed a different threshold; this is not one session"
        );
    }
}
