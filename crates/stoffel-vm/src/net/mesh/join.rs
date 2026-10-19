//! `join_mesh`: forming a mesh with no bootstrap process at all.
//!
//! `docs/design/bootnode-elimination.md` §5, §6, §12.D. [`MeshJoin`] is the
//! only [`SessionJoin`] there is.
//!
//! # What a join rests on
//!
//! | Question | Answer |
//! |---|---|
//! | who are the parties | the coordinator's roster, installed as the transport's certificate allowlist before anything is dialed |
//! | is this peer admitted | its certificate, checked per connection by mTLS; there is no bearer credential anywhere |
//! | where are the parties | `--peers` seeds plus whatever the peer book holds — hints only, since every dial pins a certificate |
//! | is the mesh complete | [`wait_until_mesh_connected`], over authenticated peer keys rather than configured ones |
//! | is this one mesh, and one computation | all-to-all [`wire::MeshMessage::MeshCommit`] equality |
//! | is the MPC namespace fresh | the coordinator-minted execution id, hashed per execution |
//!
//! One caveat on the address row, because it is the one an operator can get
//! wrong: a **first** mesh forms out of dials alone. The peer book is exchanged
//! inside the handshake below, which runs after the connectivity barrier, so it
//! cannot supply an address the mesh needs in order to form — it is what lets a
//! *later* join in the same process start from less. The seed list a first join
//! runs on has to cover every pair, and — since a pair is dialed from **one**
//! end only (see [`dials_towards`]) — it has to cover it *in the dialer's
//! direction*: for any two parties, the one whose transport-derived id is
//! higher must hold a hint for the other. Derived ids are BLAKE3 digests, so an
//! operator cannot read that order off a config file. Listing all `n - 1` peers
//! everywhere satisfies it whatever the order turns out to be, which is what
//! every shipped stack does.
//!
//! There is deliberately **no** escape hatch for the other direction. An
//! earlier revision let the non-dialing side dial anyway once a rank had been
//! missing long enough, so that the requirement could stay stated over pairs
//! rather than over directions. That re-created exactly the duplicate
//! connection the tournament exists to prevent — see [`dials_towards`] for the
//! teardown it causes — and it did so in the one shape a deployment really
//! produces: a party that starts late (a compose service gated on another's
//! healthcheck) is grace-dialed by the peers that gave up waiting at the same
//! moment it dials them. Liveness recovered that way is bought with a
//! one-in-three handshake failure, so the rule is absolute and a short seed
//! list fails as a named discovery timeout instead.
//!
//! # Why every field is checked, and checked twice
//!
//! Comparing the program alone is not enough. A party running with a different
//! `n`, a different threshold or a different entry point runs a protocol
//! parameterised differently from everyone else's, and nothing downstream
//! notices: a wrong threshold is not a decode error, it is a silently wrong
//! reconstruction.
//!
//! So the mesh checks every field twice. Each commitment is compared
//! field-by-field so the failure names *which* field diverged
//! ([`MeshError::CommitDivergence`]), and then the [`session_digest`] derived
//! from it must be byte-identical at all `n` parties
//! ([`MeshError::CommitDigestDivergence`]) — which is what catches a field
//! added to the frame but not to the comparison. Nothing MPC-shaped is sent
//! before both checks pass.
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
//!    is not the sole reader, so it and the execution transport's scanner steal
//!    frames from each other.
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
//! Every read here is `tokio::time::timeout(budget, conn.receive())` under
//! **one** deadline for the whole handshake, and blowing that deadline fails
//! the join. That is deliberate. `QuicPeerConnection::receive` reads a length
//! prefix and then a body from a `RecvStream` held under a mutex, so a read
//! cancelled part-way leaves the stream positioned mid-frame and every later
//! read desynchronised. The only safe timeout is one that ends the exchange, so
//! there is exactly one, and it is fatal.
//!
//! The same rule is why the peer book is exchanged *inside* the handshake
//! rather than during discovery. Before the connectivity barrier, connections
//! are still being deduplicated by stoffelnet's simultaneous-connect
//! tie-breaker, so a frame can be written to a connection that is about to be
//! closed in favour of the peer's. After the barrier the connection set has
//! settled — and the handshake is the *last* place a mesh control frame may
//! travel at all, because the execution transport takes the read side of every
//! connection afterwards and closes anything that is not its own envelope.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stoffelnet::network_utils::{Network, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;

use crate::net::mesh::dial::dial_address_expecting;
use crate::net::mesh::pex::{PeerDirectory, PeerRecord, SeedHints};
use crate::net::mesh::wire::{
    self, classify_mesh_ready, mesh_ready_frame, roster_namespace, MeshMessage, SessionCommitment,
    MAX_PEER_RECORDS_PER_MESSAGE,
};
use crate::net::mesh::{JoinRequest, MeshError, MeshResult, MeshTransport, SessionJoin};
use crate::net::roster::Roster;

/// BLAKE3 derive-key context for [`session_digest`].
///
/// Domain-separated so a commitment digest can never collide with the
/// coordinator's node-roster digest (`stoffel-coordinator-node-roster-v1`), the
/// program content address (`stoffel-program-v1`) or the per-execution instance
/// id (`stoffel-execution-instance-v1`).
pub const SESSION_DIGEST_CONTEXT: &str = "stoffel-mesh-commit-v1";

/// How often the connectivity barrier re-checks.
///
/// The predicate is a map length, so polling is cheap.
pub const MESH_BARRIER_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// One field of the commitment every party has to agree on.
///
/// An enum rather than a `&'static str` so that adding an agreed field is a
/// compile error at [`session_digest`] and at the comparison below, not a
/// silently unchecked addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionField {
    Roster,
    PartyCount,
    Threshold,
    /// One party committed to an execution and another to none: one of them is
    /// a standing node and the other a one-shot party, on the same roster.
    SessionScope,
    /// The coordinator execution the party was started for. A party joined
    /// under another one would pass the join and then wait forever on rounds of
    /// an execution no other party is in.
    ExecutionId,
    ProgramId,
    Entry,
}

impl std::fmt::Display for SessionField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Roster => "roster",
            Self::PartyCount => "party count",
            Self::Threshold => "threshold",
            Self::SessionScope => "commitment scope: one execution, or a standing mesh",
            Self::ExecutionId => "execution id",
            Self::ProgramId => "program id",
            Self::Entry => "entry point",
        };
        formatter.write_str(name)
    }
}

/// What every party commits to.
///
/// Canonical: every variable-length field is length-prefixed and every number
/// is fixed-width little-endian, so no two distinct commitments can produce the
/// same byte stream. A standing mesh's commitment covers the roster, `n` and
/// `t`; a one-shot party's covers the execution as well, after a one-byte
/// discriminant that keeps the two shapes from colliding.
pub fn session_digest(
    roster_digest: &[u8; 32],
    n_parties: u64,
    threshold: u64,
    session: Option<&SessionCommitment>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SESSION_DIGEST_CONTEXT);
    hasher.update(roster_digest);
    hasher.update(&n_parties.to_le_bytes());
    hasher.update(&threshold.to_le_bytes());
    match session {
        None => {
            hasher.update(&[0u8]);
        }
        Some(session) => {
            hasher.update(&[1u8]);
            hasher.update(session.execution_id.as_bytes());
            hasher.update(&session.program_id);
            hasher.update(&(session.entry.len() as u64).to_le_bytes());
            hasher.update(session.entry.as_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// This node's commitment, as it is compared against a peer's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Commitment {
    roster_digest: [u8; 32],
    n_parties: u64,
    threshold: u64,
    session: Option<SessionCommitment>,
}

impl Commitment {
    /// The first field, in [`SessionField`]'s declaration order, in which
    /// `theirs` committed to something other than `self`.
    ///
    /// Field-by-field, so the failure names what diverged rather than
    /// reporting an opaque digest mismatch.
    fn first_divergence(&self, theirs: &Self) -> Option<SessionField> {
        if theirs.roster_digest != self.roster_digest {
            return Some(SessionField::Roster);
        }
        if theirs.n_parties != self.n_parties {
            return Some(SessionField::PartyCount);
        }
        if theirs.threshold != self.threshold {
            return Some(SessionField::Threshold);
        }
        match (&self.session, &theirs.session) {
            (None, None) => None,
            (None, Some(_)) | (Some(_), None) => Some(SessionField::SessionScope),
            (Some(mine), Some(theirs)) => {
                if theirs.execution_id != mine.execution_id {
                    Some(SessionField::ExecutionId)
                } else if theirs.program_id != mine.program_id {
                    Some(SessionField::ProgramId)
                } else if theirs.entry != mine.entry {
                    Some(SessionField::Entry)
                } else {
                    None
                }
            }
        }
    }

    fn digest(&self) -> [u8; 32] {
        session_digest(
            &self.roster_digest,
            self.n_parties,
            self.threshold,
            self.session.as_ref(),
        )
    }
}

/// Wait until this node holds an authenticated public key for every other
/// party, or `timeout` elapses.
///
/// `n` is the full party count including self.
///
/// # Why this is not a party count
///
/// A quorum wait cannot be built on `Network::parties()`, which stoffelnet
/// implements as `self.nodes.iter()` — the *configured* node list.
/// Mesh formation fills that list before it dials anything, so
/// `parties().len() >= n` is already true the moment the addresses are
/// installed, whether or not a single QUIC handshake has completed. As a
/// barrier it asserts nothing.
///
/// `is_fully_connected` (`quic.rs:1976`) is
/// `peer_public_keys.len() >= n - 1 && local_public_key.is_some()`.
/// `peer_public_keys` is written only after a peer's certificate has been
/// extracted and authorized, on the accept path (`quic.rs:3407`) and on the
/// connect paths alike, and the map is `Arc`-shared across `net.clone()`, so
/// connections made by a spawned accept loop count here. Passing this barrier
/// therefore means n-1 authenticated peers, which is what the MPC layer needs.
///
/// Only *server* peers land in `peer_public_keys`; MPC clients are tracked in
/// `client_public_keys` (`quic.rs:3369`), so a client connecting early cannot
/// satisfy the barrier on a missing node's behalf.
pub async fn wait_until_mesh_connected(
    net: &QuicNetworkManager,
    n: usize,
    timeout: Duration,
) -> MeshResult<()> {
    let start = Instant::now();
    loop {
        if net.is_fully_connected(n) {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(MeshError::MeshIncomplete {
                expected: n,
                waited: timeout,
            });
        }
        sleep(MESH_BARRIER_POLL_INTERVAL).await;
    }
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
    /// It is not what closes it. [`dials_towards`] is: a pair is dialed from
    /// one end only, so two roster members never open two connections to each
    /// other and the tie-breaker never runs between them at all. What this
    /// interval is still worth is the case that has nothing to do with
    /// duplicates — a peer whose connection drops between the moment the mesh
    /// first looks complete and the moment the handshake starts.
    pub settle: Duration,
    /// One `accept()` before the accept loop re-checks whether it is done.
    pub accept_poll: Duration,
    /// The whole lock-step handshake, sends and reads together.
    pub handshake: Duration,
}

impl Default for MeshJoinTimeouts {
    fn default() -> Self {
        Self {
            // A mesh forms as fast as its slowest member starts, and in
            // compose that is an image pull, so the budget is minutes rather
            // than seconds.
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
/// Cheap to clone — everything shared is behind an `Arc` — so one value can
/// serve several party tasks in a test harness the way it serves one process in
/// the runner.
#[derive(Debug, Clone)]
pub struct MeshJoin {
    roster: Roster,
    seeds: SeedHints,
    peers: Option<PeerDirectory>,
    timeouts: MeshJoinTimeouts,
}

impl MeshJoin {
    /// Join the mesh `roster` defines, starting from `seeds`.
    pub fn new(roster: Roster, seeds: SeedHints) -> Self {
        Self {
            roster,
            seeds,
            peers: None,
            timeouts: MeshJoinTimeouts::default(),
        }
    }

    /// Fold learned peers into `peers`, and aim discovery at what it already
    /// holds.
    ///
    /// The PEX half of the join, and worth being precise about what it buys. A
    /// book entry pairs an address with the SPKI that claims it, so a book the
    /// join starts with gives discovery *aimed* probes rather than bare
    /// addresses, and leaves the reconnect supervisor a set of pinned targets
    /// afterwards. What it does not do is rescue a short `--peers` list on a
    /// first join: books are exchanged inside the handshake, after the
    /// connectivity barrier, so the mesh has to have formed before any of that
    /// exists.
    ///
    /// Without a directory the join dials the seeds and nothing else, which is
    /// what a deployment that passes a full `--peers` list wants.
    pub fn with_peer_directory(mut self, peers: PeerDirectory) -> Self {
        self.peers = Some(peers);
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
    ) -> MeshResult<MeshTransport> {
        join_mesh(
            net,
            &self.roster,
            &self.seeds,
            self.peers.as_ref(),
            self.timeouts,
            request,
        )
        .await
    }
}

/// Form a mesh from a pinned roster and a set of address hints.
///
/// `net` must already be listening: the address a peer dials is
/// [`JoinRequest::my_listen`], which the caller chose when it bound, and
/// `listen()` cannot be called twice on one manager. The precondition is
/// checked rather than assumed — a manager with no local public key has no
/// certificate to be ranked by, and [`MeshError::LocalNotInRoster`] says so
/// before anything is dialed.
pub async fn join_mesh(
    net: &mut QuicNetworkManager,
    roster: &Roster,
    seeds: &SeedHints,
    peers: Option<&PeerDirectory>,
    timeouts: MeshJoinTimeouts,
    request: JoinRequest,
) -> MeshResult<MeshTransport> {
    let n = roster.n();
    if request.n_parties != n {
        return Err(MeshError::RosterSize {
            configured: request.n_parties,
            roster: n,
        });
    }
    if request.threshold != roster.t() {
        return Err(MeshError::RosterThreshold {
            configured: request.threshold,
            roster: roster.t(),
        });
    }

    // The allowlist goes in before anything else touches the transport: it
    // takes `&mut`, it is refused once a peer outside the roster is already
    // connected (`quic.rs:1300-1307`), and until it is in place the accept path
    // has no certificate to authorize a peer against — the relay this whole
    // migration deletes.
    roster.install_into(net)?;

    let local = net
        .get_public_key()
        .cloned()
        .ok_or(MeshError::LocalNotInRoster)?;
    let my_rank = roster.index_of(&local).ok_or(MeshError::LocalNotInRoster)?;

    // This node's own address is first-hand knowledge, so it is seeded as
    // `RecordSource::Local` and no relayed claim can displace it.
    //
    // `seq: 0`, always, and that is deliberate rather than a placeholder. There
    // is no per-node monotone counter on this branch — freshness is the
    // coordinator's minted execution id, not a stored epoch (§12.E) — so there
    // is nothing honest to put here. The consequence is bounded and worth
    // stating: among *relayed* records, `seq` only ever ties, so the first
    // relayed address for a peer is the one a book keeps
    // (`PexOutcome::Stale`). It cannot strand anybody, because rank beats `seq`
    // — a dial this node makes itself lands as `RecordSource::Verified` and
    // replaces the relayed entry without consulting the counter, and the seed
    // hints a first join runs on are `RecordSource::Local` and outrank both.
    let my_record = PeerRecord::new(&local, request.my_listen, 0);
    if let Some(peers) = peers {
        peers.seed(my_record.clone());
    }

    // The accept loop spans discovery *and* the handshake. Stopping it at the
    // end of discovery is not safe: a peer that is still dialing would have its
    // connection aborted mid-handshake, and this node would be the one that
    // caused it.
    let shutdown = CancellationToken::new();
    let accepting = spawn_accept_loop(net.clone(), my_rank, shutdown.clone(), timeouts);

    let formed = async {
        discover_peers(net, roster, seeds, peers, my_rank, n, timeouts).await?;
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

        let exchange = handshake(
            net,
            roster,
            peers,
            my_rank,
            my_record,
            &request,
            timeouts.handshake,
        );
        tokio::time::timeout(timeouts.handshake, exchange)
            .await
            .map_err(|_| MeshError::HandshakeTimeout {
                waited: timeouts.handshake,
            })?
    }
    .await;

    shutdown.cancel();
    let _ = accepting.await;
    let outcome = formed?;

    eprintln!(
        "[mesh party {my_rank}] mesh agreed: roster={}, commitment={}",
        hex::encode(&roster.digest()[..8]),
        hex::encode(&outcome.digest[..8])
    );

    Ok(MeshTransport {
        roster_digest: roster.digest(),
        commit_digest: outcome.digest,
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
/// re-dial of an already-connected peer is exactly what stoffelnet's
/// simultaneous-connect deduplication resolves by **closing a live
/// connection** (`quic.rs:2266-2288`, and symmetrically `:3411-3441` on the
/// peer's accept path). If the peer has already left the barrier, the
/// connection that dies is the one carrying its join handshake.
///
/// So discovery never dials "an address". It dials **a rank it does not hold,
/// at an address that might be that rank**, through
/// [`dial_address_expecting`]. Two consequences, and they are the whole fix:
///
/// 1. A rank this node already holds is never dialed. This rests entirely on
///    [`missing_ranks`] being exact under *partial* connectivity — it reads
///    each connection's authenticated certificate rather than looking a rank up
///    in the transport, whose index order is the sort of the keys seen so far
///    and therefore skewed until the mesh is complete.
/// 2. A pinned dial that reaches the wrong party is refused before the
///    transport opens a stream or deduplicates anything, so even a mis-aimed
///    probe cannot disturb a connection either side is holding. This covers the
///    hints that carry no identity; it does *not* cover (1), and treating it as
///    if it did is how a re-dial of a held peer gets shipped.
///
/// # And every dial is one half of a tournament
///
/// (1) and (2) together are still not enough, and the gap is what made a
/// five-party mesh fail roughly one run in three. [`missing_ranks`] is exact,
/// but it is a *snapshot*: a round reads it once and then spends up to one dial
/// timeout per hint issuing probes. A peer whose inbound connection is accepted
/// during that window is held by this node and still listed as missing, so the
/// round dials it — correctly aimed, so the pin cannot refuse it — and the
/// peer's accept path resolves the duplicate by closing the connection it is
/// holding. Re-reading the missing set immediately before each dial narrows
/// that window; it cannot close it, because the peer's dial can also land
/// *during* this node's own dial handshake.
///
/// So a pair is dialed from **one** end only, chosen by [`dials_towards`]. No
/// duplicate connection between roster members is ever created, so the
/// tie-breaker never runs, so it can never close a live connection. The
/// direction is the one stoffelnet's own tie-breaker would have picked, which
/// is what makes the change invisible to everything downstream.
///
/// The tournament costs something, and it is paid on purpose: a pair whose
/// higher-`derive_id` member holds no hint for the other is never dialed at
/// all, where an undirected rule would have let the other end cover it. There
/// is no timed escape hatch for that — see the module docs — so a short seed
/// list surfaces as a named discovery timeout, which [`dial_duties`] gives the
/// material for.
async fn discover_peers(
    net: &mut QuicNetworkManager,
    roster: &Roster,
    seeds: &SeedHints,
    peers: Option<&PeerDirectory>,
    my_rank: PartyId,
    n: usize,
    timeouts: MeshJoinTimeouts,
) -> MeshResult<()> {
    // Having nothing to dial is only an error for a node that has something to
    // dial *to*. Under the tournament the member with the lowest derived id
    // wins no pair, so it issues no dial in a healthy mesh and a seed list is
    // genuinely optional for it — refusing it here would make the minimum
    // directional seed plan unjoinable for exactly one party, which is the plan
    // working as intended, not a configuration mistake. Every other node still
    // fails fast rather than spending the whole discovery budget discovering it
    // was handed no addresses.
    let all_peers: Vec<PartyId> = (0..n).filter(|rank| *rank != my_rank).collect();
    let duties = dial_duties(roster, my_rank, &all_peers);
    if !duties.is_empty()
        && seeds.is_empty()
        && peers
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

        let (aimed, unidentified) = probe_targets(roster, seeds, peers, &attributed, &dialable);
        // `dialable` can be empty, and `aimed`/`unidentified` can both be
        // empty, and neither is an error. The member with the lowest derived id
        // wins no pair and so dials nothing at all, by design; any node can
        // also be out of unspent hints for the ranks it does win. The round
        // then does nothing and the accept loop does the work.
        let mut progress = false;

        // Ranks whose address is already known: one exact probe each, under a
        // budget of one dial timeout per *missing rank* — not per known
        // address, because a rank can be aimed at from both the attribution map
        // and the peer book and both entries can be stale.
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
            // this same round connected it without reporting success, and
            // re-dialing a peer this node already holds is churn even when it
            // cannot produce a duplicate.
            if holds_rank(net, roster, rank).await {
                dialable.retain(|candidate| *candidate != rank);
                continue;
            }
            if probe_rank_at(
                net,
                roster,
                peers,
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
        // at the wrong party that *is* listening is refused in one handshake,
        // so when the mesh is up a single round walks all of the pairs in
        // milliseconds. A probe at an address where nobody is listening costs
        // the whole dial timeout, so when parties are still starting the budget
        // stops the round after as many dials as there are hints — and nothing
        // would have connected anyway.
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
                    peers,
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
            // Name the two halves separately, because they have different fixes
            // and an operator cannot tell them apart from a config file:
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
/// Pulled out of this module's peer-discovery loop as a pure function for one
/// reason: it is the single place a rank becomes dialable, and it is the place
/// a future "just this once" relaxation would be written. Keeping it
/// addressable lets
/// `discovery_only_ever_dials_its_half_of_the_tournament` assert the partition
/// over the real filter rather than over [`dials_towards`] alone.
pub fn dial_duties(roster: &Roster, my_rank: PartyId, missing: &[PartyId]) -> Vec<PartyId> {
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
/// tie-breaker would have left standing, so nothing downstream can tell the
/// difference.
///
/// Equal derived ids would leave a pair undialed from both ends, so the SPKI
/// bytes break that tie. Two roster members with the same derived id are
/// already indistinguishable to the transport (they share a compact party id),
/// and the roster refuses that case outright
/// ([`crate::net::roster::RosterError::DuplicateNode`]), so this only keeps the
/// decision total.
pub fn dials_towards(roster: &Roster, my_rank: PartyId, peer_rank: PartyId) -> bool {
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
/// Extracted and pure because the *rotation* is the part that fails silently: a
/// scheme that advances the cursor by the number of hints re-derives the same
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
/// [`PeerRecord`] pairs an address with the SPKI that claims it, and the roster
/// turns that SPKI into a rank. A relayed record is still only a hint — the pin
/// is what makes acting on it safe — but it is an *aimed* hint, which is worth
/// strictly more than a bare address.
fn probe_targets(
    roster: &Roster,
    seeds: &SeedHints,
    peers: Option<&PeerDirectory>,
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
    if let Some(peers) = peers {
        for (key, addr) in peers.dial_targets() {
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
    peers: Option<&PeerDirectory>,
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
            if let Some(peers) = peers {
                // First-hand: this node chose the address and the certificate
                // at the other end proved who answered.
                peers.observe_verified(PeerRecord::new(&expected, addr, 0));
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
/// is correctly aimed, so the certificate pin cannot refuse it. Pinning
/// protects the *mis-aimed* probe; only an exact missing set protects the
/// correctly-aimed one.
///
/// So the connections are enumerated and each one's **authenticated**
/// certificate is mapped back through the roster. That answer does not depend
/// on how many peers are known, which is the property discovery needs and the
/// one rank lookup cannot provide.
///
/// Note [`peer_connections`] does index by rank, and is right to: it runs after
/// the barrier, where the key set is complete, and it treats a disagreement as
/// an error rather than as absence.
///
/// # Liveness, not acquaintance
///
/// Also deliberately stronger than `is_fully_connected`, which counts
/// `peer_public_keys` — a map written when a peer authenticates and never
/// cleared when its connection closes.
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
    digest: [u8; 32],
    parties: Vec<(PartyId, SocketAddr)>,
}

/// The all-to-all agreement, in lock-step, on connections this task owns.
async fn handshake(
    net: &QuicNetworkManager,
    roster: &Roster,
    peers: Option<&PeerDirectory>,
    my_rank: PartyId,
    my_record: PeerRecord,
    request: &JoinRequest,
    budget: Duration,
) -> MeshResult<Agreement> {
    let n = roster.n();
    let roster_digest = roster.digest();
    let mut parties: Vec<(PartyId, SocketAddr)> = vec![(my_rank, request.my_listen)];
    let mine = Commitment {
        roster_digest,
        n_parties: n as u64,
        threshold: roster.t() as u64,
        session: request.session.clone(),
    };
    let digest = mine.digest();

    let connections = peer_connections(net, roster, my_rank, n)?;

    // ---- send: readiness, then what we know, then what we commit to --------
    let expected_namespace = roster_namespace(&roster_digest);
    let ready_frame = mesh_ready_frame(expected_namespace);
    let book_frame = wire::encode(&MeshMessage::PeerBook {
        records: local_book(peers, &my_record),
    })?;
    let commit_frame = wire::encode(&MeshMessage::MeshCommit {
        roster_digest: mine.roster_digest,
        n_parties: mine.n_parties,
        threshold: mine.threshold,
        session: mine.session.clone(),
    })?;

    for (rank, conn) in &connections {
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
            "sending the mesh commitment",
            &commit_frame,
        )
        .await?;
    }

    // ---- read: the same three, in the same order --------------------------
    for (rank, conn) in &connections {
        let payload = read_from(*rank, conn.as_ref(), budget).await?;
        match classify_mesh_ready(&payload) {
            Some(namespace) if namespace == expected_namespace => {}
            Some(namespace) => {
                return Err(MeshError::RosterNamespaceMismatch {
                    party_id: *rank,
                    expected: expected_namespace,
                    got: namespace,
                })
            }
            None => {
                return Err(MeshError::UnexpectedFrame {
                    party_id: *rank,
                    expected: "a mesh-ready announcement",
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
        let announced = absorb_book(peers, roster, records);
        parties.push((
            *rank,
            announced
                .get(rank)
                .copied()
                .unwrap_or_else(|| conn.remote_address()),
        ));

        let message = read_message(*rank, conn.as_ref(), budget, "MeshCommit").await?;
        let MeshMessage::MeshCommit {
            roster_digest: peer_roster,
            n_parties,
            threshold,
            session,
        } = message
        else {
            return Err(MeshError::UnexpectedFrame {
                party_id: *rank,
                expected: "MeshCommit",
                got: message.kind(),
            });
        };

        let theirs = Commitment {
            roster_digest: peer_roster,
            n_parties,
            threshold,
            session,
        };
        if let Some(field) = mine.first_divergence(&theirs) {
            return Err(MeshError::CommitDivergence {
                party_id: *rank,
                field,
            });
        }
        // The catch-all behind the field comparison: a field added to the frame
        // without being added to `first_divergence` still diverges here, and
        // the comparison is over all 32 bytes rather than the 64-bit namespace
        // the ready frame carried.
        let peer_digest = theirs.digest();
        if peer_digest != digest {
            return Err(MeshError::CommitDigestDivergence {
                party_id: *rank,
                expected: hex::encode(digest),
                got: hex::encode(peer_digest),
            });
        }
    }

    parties.sort_by_key(|(rank, _)| *rank);
    Ok(Agreement { digest, parties })
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
fn local_book(peers: Option<&PeerDirectory>, my_record: &PeerRecord) -> Vec<PeerRecord> {
    let mut records = vec![my_record.clone()];
    if let Some(peers) = peers {
        for record in peers.snapshot(MAX_PEER_RECORDS_PER_MESSAGE) {
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
    peers: Option<&PeerDirectory>,
    roster: &Roster,
    records: Vec<PeerRecord>,
) -> BTreeMap<PartyId, SocketAddr> {
    let mut announced = BTreeMap::new();
    for record in records {
        let Some(rank) = roster.index_of(&record.public_key()) else {
            continue;
        };
        announced.insert(rank, record.advertise_addr);
        if let Some(peers) = peers {
            // Relayed, not verified: a peer book is hearsay about third
            // parties, so it fills gaps but never displaces a first-hand entry.
            peers.observe_relayed(record);
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
    use crate::net::mesh::pex::PexLimits;
    use crate::net::session::ExecutionId;
    use stoffelnet::network_utils::NodePublicKey;

    fn key(byte: u8) -> NodePublicKey {
        NodePublicKey(vec![byte; 32])
    }

    fn roster_of(bytes: &[u8]) -> Roster {
        Roster::from_node_keys(bytes.iter().copied().map(key).collect(), 1)
            .expect("build a test roster")
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}")
            .parse()
            .expect("parse loopback address")
    }

    fn session() -> SessionCommitment {
        SessionCommitment {
            execution_id: ExecutionId::from_bytes([9u8; 32]),
            program_id: [7u8; 32],
            entry: "main".to_string(),
        }
    }

    fn commitment(session: Option<SessionCommitment>) -> Commitment {
        Commitment {
            roster_digest: [1u8; 32],
            n_parties: 3,
            threshold: 1,
            session,
        }
    }

    /// Every pair is dialed from exactly one end. Two ends dialing is the
    /// duplicate connection that made a five-party mesh fail about one run in
    /// three, so the partition is the property, not the ordering rule.
    #[test]
    fn exactly_one_end_of_every_pair_dials() {
        let roster = roster_of(&[1, 2, 3, 4, 5]);

        for left in 0..roster.n() {
            for right in 0..roster.n() {
                if left == right {
                    continue;
                }
                assert_ne!(
                    dials_towards(&roster, left, right),
                    dials_towards(&roster, right, left),
                    "parties {left} and {right} both dial, or neither does"
                );
            }
        }
    }

    /// The direction is stoffelnet's own tie-breaker order — the higher
    /// `derive_id` keeps its outgoing connection — so the surviving connection
    /// is the one the transport would have left standing anyway.
    #[test]
    fn the_dialer_is_the_higher_derived_id() {
        let roster = roster_of(&[1, 2, 3]);

        for left in 0..roster.n() {
            for right in 0..roster.n() {
                if left == right {
                    continue;
                }
                let mine = roster.key_of(left).expect("roster entry").derive_id();
                let theirs = roster.key_of(right).expect("roster entry").derive_id();
                assert_eq!(dials_towards(&roster, left, right), mine > theirs);
            }
        }
    }

    /// A rank outside the roster is never dialed, so an out-of-range index
    /// cannot become a dial duty.
    #[test]
    fn a_rank_outside_the_roster_is_never_dialed() {
        let roster = roster_of(&[1, 2, 3]);

        assert!(!dials_towards(&roster, 0, 99));
        assert!(!dials_towards(&roster, 99, 0));
        assert!(dial_duties(&roster, 0, &[99]).is_empty());
    }

    /// `dial_duties` is the only place a rank becomes dialable, and it is a
    /// strict subset of what the tournament allows: the test is over the real
    /// filter, because a timed escape hatch once shipped under a green
    /// `dials_towards` test.
    #[test]
    fn discovery_only_ever_dials_its_half_of_the_tournament() {
        let roster = roster_of(&[1, 2, 3, 4, 5]);

        for my_rank in 0..roster.n() {
            let missing: Vec<PartyId> = (0..roster.n()).filter(|rank| *rank != my_rank).collect();
            let duties = dial_duties(&roster, my_rank, &missing);

            for rank in &duties {
                assert!(
                    dials_towards(&roster, my_rank, *rank),
                    "party {my_rank} took a dial duty for {rank} it does not own"
                );
            }
            for rank in missing {
                assert_eq!(
                    duties.contains(&rank),
                    dials_towards(&roster, my_rank, rank),
                    "party {my_rank}'s duty for {rank} disagrees with the tournament"
                );
            }
        }
    }

    /// Exactly one member of any roster wins no pair, so a seed list is
    /// genuinely optional for it and `NoSeeds` must not be raised there.
    #[test]
    fn exactly_one_member_owes_no_dial() {
        let roster = roster_of(&[1, 2, 3, 4, 5]);

        let owing_none = (0..roster.n())
            .filter(|my_rank| {
                let missing: Vec<PartyId> =
                    (0..roster.n()).filter(|rank| rank != my_rank).collect();
                dial_duties(&roster, *my_rank, &missing).is_empty()
            })
            .count();

        assert_eq!(owing_none, 1);
    }

    /// The rotation has to reach every (rank, hint) pair. Advancing the cursor
    /// by the hint count re-derives the same pairing whenever the two counts
    /// share a factor — three hints and three ranks, the default three-party
    /// mesh — and discovery then burns its whole budget without ever trying the
    /// pairing that would have connected.
    #[test]
    fn the_probe_rotation_covers_every_pair() {
        for hints in 1..=4usize {
            for ranks in 1..=4usize {
                let mut seen = BTreeSet::new();
                for cursor in 0..(hints * ranks) {
                    for step in 0..(hints * ranks) {
                        seen.insert(probe_pair(cursor, step, hints, ranks));
                    }
                }
                assert_eq!(
                    seen.len(),
                    hints * ranks,
                    "{hints} hints x {ranks} ranks did not cover every pair"
                );
                for (rank_index, hint_index) in seen {
                    assert!(rank_index < ranks);
                    assert!(hint_index < hints);
                }
            }
        }
    }

    /// A single round's walk visits every pair exactly once, so a round that
    /// runs to completion never re-probes a pair while leaving another untried.
    #[test]
    fn one_round_visits_every_pair_exactly_once() {
        let (hints, ranks) = (3usize, 3usize);
        let mut seen = BTreeSet::new();

        for step in 0..(hints * ranks) {
            assert!(
                seen.insert(probe_pair(7, step, hints, ranks)),
                "a round re-probed a pair"
            );
        }
        assert_eq!(seen.len(), hints * ranks);
    }

    /// The roster is the only authority for `n` and `t`: a node configured for
    /// anything else is refused before a socket is touched.
    #[tokio::test]
    async fn a_configured_party_count_that_is_not_the_roster_is_refused() {
        let roster = roster_of(&[1, 2, 3]);
        let mut net = QuicNetworkManager::with_node_id(0);
        let request = JoinRequest {
            my_party_id: 0,
            my_listen: addr(9000),
            n_parties: 4,
            threshold: 1,
            session: None,
            timeout: Duration::from_secs(1),
        };

        assert_eq!(
            join_mesh(
                &mut net,
                &roster,
                &SeedHints::default(),
                None,
                MeshJoinTimeouts::default(),
                request,
            )
            .await,
            Err(MeshError::RosterSize {
                configured: 4,
                roster: 3
            })
        );
    }

    #[tokio::test]
    async fn a_configured_threshold_that_is_not_the_roster_is_refused() {
        let roster = roster_of(&[1, 2, 3]);
        let mut net = QuicNetworkManager::with_node_id(0);
        let request = JoinRequest {
            my_party_id: 0,
            my_listen: addr(9000),
            n_parties: 3,
            threshold: 2,
            session: None,
            timeout: Duration::from_secs(1),
        };

        assert_eq!(
            join_mesh(
                &mut net,
                &roster,
                &SeedHints::default(),
                None,
                MeshJoinTimeouts::default(),
                request,
            )
            .await,
            Err(MeshError::RosterThreshold {
                configured: 2,
                roster: 1
            })
        );
    }

    /// Comparing the program alone would admit a party proposing another `n`,
    /// threshold or entry point, which then runs a differently parameterised
    /// protocol that nothing downstream reports.
    #[test]
    fn a_commitment_names_the_first_field_that_diverged() {
        let mine = commitment(Some(session()));

        let mut other_roster = mine.clone();
        other_roster.roster_digest = [2u8; 32];
        assert_eq!(
            mine.first_divergence(&other_roster),
            Some(SessionField::Roster)
        );

        let mut other_n = mine.clone();
        other_n.n_parties = 5;
        assert_eq!(
            mine.first_divergence(&other_n),
            Some(SessionField::PartyCount)
        );

        let mut other_t = mine.clone();
        other_t.threshold = 2;
        assert_eq!(
            mine.first_divergence(&other_t),
            Some(SessionField::Threshold)
        );

        let mut other_execution = mine.clone();
        other_execution.session = Some(SessionCommitment {
            execution_id: ExecutionId::from_bytes([1u8; 32]),
            ..session()
        });
        assert_eq!(
            mine.first_divergence(&other_execution),
            Some(SessionField::ExecutionId)
        );

        let mut other_program = mine.clone();
        other_program.session = Some(SessionCommitment {
            program_id: [8u8; 32],
            ..session()
        });
        assert_eq!(
            mine.first_divergence(&other_program),
            Some(SessionField::ProgramId)
        );

        let mut other_entry = mine.clone();
        other_entry.session = Some(SessionCommitment {
            entry: "other".to_string(),
            ..session()
        });
        assert_eq!(
            mine.first_divergence(&other_entry),
            Some(SessionField::Entry)
        );

        assert_eq!(mine.first_divergence(&mine.clone()), None);
    }

    /// A standing node and a one-shot party on one roster are not in one mesh,
    /// and the mismatch is named rather than silently digesting differently.
    #[test]
    fn a_standing_commitment_and_a_one_shot_commitment_diverge_by_scope() {
        let standing = commitment(None);
        let one_shot = commitment(Some(session()));

        assert_eq!(
            standing.first_divergence(&one_shot),
            Some(SessionField::SessionScope)
        );
        assert_eq!(
            one_shot.first_divergence(&standing),
            Some(SessionField::SessionScope)
        );
        assert_eq!(standing.first_divergence(&standing.clone()), None);
    }

    /// The digest is the catch-all: equal fields must digest equally, and any
    /// difference the comparison can name must move the digest too, or the
    /// backstop would not be one.
    #[test]
    fn the_digest_moves_whenever_any_committed_field_does() {
        let mine = commitment(Some(session()));
        let mut digests = BTreeSet::new();
        digests.insert(mine.digest());

        let mut variants = Vec::new();
        let mut other = mine.clone();
        other.roster_digest = [2u8; 32];
        variants.push(other);
        let mut other = mine.clone();
        other.n_parties = 5;
        variants.push(other);
        let mut other = mine.clone();
        other.threshold = 2;
        variants.push(other);
        variants.push(commitment(None));
        let mut other = mine.clone();
        other.session = Some(SessionCommitment {
            execution_id: ExecutionId::from_bytes([1u8; 32]),
            ..session()
        });
        variants.push(other);
        let mut other = mine.clone();
        other.session = Some(SessionCommitment {
            program_id: [8u8; 32],
            ..session()
        });
        variants.push(other);
        let mut other = mine.clone();
        other.session = Some(SessionCommitment {
            entry: "other".to_string(),
            ..session()
        });
        variants.push(other);

        for variant in variants {
            assert!(
                digests.insert(variant.digest()),
                "{variant:?} digests the same as another commitment"
            );
        }
        assert_eq!(mine.digest(), mine.clone().digest());
    }

    /// The entry point is length-prefixed, so no two distinct commitments can
    /// produce one byte stream by splitting a concatenation differently.
    #[test]
    fn the_commitment_encoding_is_canonical() {
        let left = session_digest(
            &[1u8; 32],
            3,
            1,
            Some(&SessionCommitment {
                entry: "ab".to_string(),
                ..session()
            }),
        );
        let right = session_digest(
            &[1u8; 32],
            3,
            1,
            Some(&SessionCommitment {
                entry: "a".to_string(),
                ..session()
            }),
        );

        assert_ne!(left, right);
    }

    /// The commitment digest is domain-separated from the roster digest it
    /// covers, so the two can never be confused on the wire or in a log line.
    #[test]
    fn the_commitment_digest_is_not_the_roster_digest() {
        let roster = roster_of(&[1, 2, 3]);
        let digest = session_digest(&roster.digest(), roster.n() as u64, roster.t() as u64, None);

        assert_ne!(digest, roster.digest());
    }

    /// The ready frame's namespace is derived from the roster digest, so a peer
    /// pinned to another roster is refused before a commitment is decoded.
    #[test]
    fn the_ready_namespace_separates_two_rosters() {
        let left = roster_of(&[1, 2, 3]);
        let right = roster_of(&[4, 5, 6]);

        assert_ne!(
            roster_namespace(&left.digest()),
            roster_namespace(&right.digest())
        );
    }

    /// A node that offers its book offers its own address first, and never a
    /// duplicate of itself, because the receiver keys records by SPKI.
    #[test]
    fn a_local_book_leads_with_this_node_and_does_not_repeat_it() {
        let directory = PeerDirectory::pinned_to(vec![key(1), key(2)], PexLimits::default());
        let mine = PeerRecord::new(&key(1), addr(9001), 0);
        directory.seed(mine.clone());
        directory.observe_verified(PeerRecord::new(&key(2), addr(9002), 0));

        let book = local_book(Some(&directory), &mine);

        assert_eq!(book.first(), Some(&mine));
        assert_eq!(
            book.iter()
                .filter(|record| record.spki == mine.spki)
                .count(),
            1
        );
        assert_eq!(book.len(), 2);
    }

    /// A book offered without a directory is just this node's own address: a
    /// deployment that passes a full `--peers` list needs nothing more.
    #[test]
    fn a_local_book_without_a_directory_is_this_node_alone() {
        let mine = PeerRecord::new(&key(1), addr(9001), 0);

        assert_eq!(local_book(None, &mine), vec![mine]);
    }

    /// A relayed record for an identity outside the roster is dropped: a
    /// roster-pinned mesh has no use for an address it can never dial.
    #[test]
    fn absorbing_a_book_keeps_only_roster_members() {
        let roster = roster_of(&[1, 2, 3]);
        let directory = PeerDirectory::pinned_to(roster.nodes().to_vec(), PexLimits::default());
        let stranger = key(9);

        let announced = absorb_book(
            Some(&directory),
            &roster,
            vec![
                PeerRecord::new(roster.key_of(1).expect("roster entry"), addr(9002), 1),
                PeerRecord::new(&stranger, addr(9009), 1),
            ],
        );

        assert_eq!(announced.len(), 1);
        assert_eq!(announced.get(&1), Some(&addr(9002)));
        assert_eq!(directory.source_of(&stranger), None);
        assert_eq!(
            directory.source_of(roster.key_of(1).expect("roster entry")),
            Some(crate::net::mesh::pex::RecordSource::Relayed)
        );
    }

    /// The seam is a trait object, and a caller holding one can still say which
    /// join it built.
    #[test]
    fn a_mesh_join_reports_itself() {
        let join = MeshJoin::new(
            roster_of(&[1, 2, 3]),
            SeedHints::new(vec![addr(9001)], None),
        );

        assert!(format!("{join:?}").contains("MeshJoin"));
        assert_eq!(join.roster().n(), 3);
        assert_eq!(join.seeds().len(), 1);
    }
}
