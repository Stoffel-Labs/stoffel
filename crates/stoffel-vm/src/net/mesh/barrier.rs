//! The mesh's two barriers: local connectivity, and all-to-all rendezvous.
//!
//! Stage 2 of `docs/design/bootnode-elimination.md` (§2, row "Quorum barrier")
//! contributed [`wait_until_mesh_connected`], which asks *this* node's
//! transport a local question. Stage 5 adds [`MeshBarrier`], which asks every
//! other node a question they have to answer on the wire.
//!
//! # `MeshBarrier` generalizes one pattern that already worked
//!
//! `stoffel-run.rs` reached "every party finished preprocessing" by hand: a
//! constant prefix, an `if raw_msg.starts_with(..)` arm inside the message
//! pump that diverted matching frames into an `mpsc`, a broadcast of
//! `prefix || instance_id.to_le_bytes()`, and a `HashSet` of distinct senders
//! under a `tokio::time::timeout`. That is the bootnode's
//! `SessionAnnounce`/`SessionAck` pair rebuilt correctly — peer-to-peer,
//! namespaced by `instance_id`, with no coordinator — and it is the only
//! rendezvous in the tree that has ever worked.
//!
//! [`MeshBarrier`] is that pattern with the four pieces named and the point it
//! marks turned into a [`BarrierTag`], so a second rendezvous is a new variant
//! rather than a second ad-hoc prefix. The `PreprocessingReady` bytes are
//! unchanged, deliberately: migrating the runner onto this type must not alter
//! a single byte it puts on the wire.
//!
//! # Why the tag is a top-level prefix and not a [`crate::net::mesh::MeshMessage`]
//!
//! A `MeshMessage` is consumed by [`crate::net::mesh::MeshRouter`] *inside* the
//! receive loop, before the loop forwards anything to its channel. The code
//! waiting on a barrier is not the router — it is the task draining that
//! channel — so a barrier modelled as a control frame would be swallowed by
//! the router and counted as a dropped event. Barrier frames therefore carry
//! their own reserved prefix (blocker B7 lists all eight,
//! `crate::net::mesh::wire::ReservedPrefix`) and fall through every router to
//! the loop that is counting them.
//!
//! # Why this is not a party count
//!
//! The deleted `net::discovery::wait_until_min_parties` polled
//! `Network::parties()`, which stoffelnet implements as `self.nodes.iter()`
//! (`quic.rs:3598`) — the *configured* node list. Mesh formation fills that list
//! from the announced address list before it dials anything, so
//! `parties().len() >= n` is already true the moment the addresses are
//! installed, whether or not a single QUIC handshake has completed. As a
//! barrier it asserts nothing.
//!
//! [`wait_until_mesh_connected`] polls `QuicNetworkManager::is_fully_connected`
//! (`quic.rs:1976`) instead, which is
//! `peer_public_keys.len() >= n - 1 && local_public_key.is_some()`.
//! `peer_public_keys` is written only after a peer's certificate has been
//! extracted and authorized, on the accept path (`quic.rs:3407`) and on the
//! connect paths (`:2097`, `:2253`, `:2648`) alike, and the map is `Arc`-shared
//! across `net.clone()`, so connections made by a spawned accept loop count
//! here. Passing this barrier therefore means n-1 authenticated peers, which is
//! what the MPC layer actually needs and what mesh formation used to assume.
//!
//! Only *server* peers land in `peer_public_keys`; MPC clients are tracked in
//! `client_public_keys` (`quic.rs:3369`), so a client connecting early cannot
//! satisfy the barrier on a missing node's behalf.

use std::time::Duration;

use dashmap::{DashMap, DashSet};
use stoffelnet::network_utils::{Network, PartyId};
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

use crate::net::mesh::wire::{
    ADMISSIONS_AGREED_PREFIX, HB_PREPROCESSING_READY_PREFIX, INPUTS_AGREED_PREFIX,
    MESH_READY_PREFIX, OUTPUT_READY_PREFIX,
};
use crate::net::mesh::{MeshError, MeshResult};

/// How often the barrier re-checks connectivity.
///
/// Inherited from the party-count wait this replaced, whose cadence was never a
/// problem; the predicate is a `DashMap::len`, so polling is cheap.
pub const MESH_BARRIER_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wait until this node holds an authenticated public key for every other
/// party, or `timeout` elapses.
///
/// `n` is the full party count including self.
pub async fn wait_until_mesh_connected(
    net: &QuicNetworkManager,
    n: usize,
    timeout: Duration,
) -> MeshResult<()> {
    let start = tokio::time::Instant::now();
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

/// A point in a run that every party has to reach before any party moves on.
///
/// One variant per rendezvous, so adding a barrier is adding a variant — not
/// adding a fifth untyped `&[u8]` constant to the shared stream. Each tag's
/// bytes are registered in [`crate::net::mesh::wire::ReservedPrefix`] and the
/// mutual-disjointness invariant (blocker B7) is asserted over that table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BarrierTag {
    /// Every party holds every other party's authenticated key and has settled
    /// its connection set.
    ///
    /// Announced by [`crate::net::mesh::join_mesh`] once
    /// [`wait_until_mesh_connected`] has passed and `assign_party_ids` has run.
    /// Its namespace is *not* an `instance_id` — there is no session yet — it
    /// is the low 64 bits of the roster digest, which is the only thing the
    /// parties have agreed on at that point. That makes the frame a cheap early
    /// membership check: a peer pinned to a different roster announces a
    /// different namespace and is refused before a `JoinProposal` is ever
    /// written.
    MeshReady,
    /// Every party's preprocessing material is in place.
    ///
    /// The one this type was generalized from. Namespaced by `instance_id`.
    PreprocessingReady,
    /// Every party has published its share of the run's outputs.
    ///
    /// Namespaced by `instance_id`. Declared here with the other two because
    /// the output phase is the third place the runner waits on every peer; it
    /// is wired up with the output path, not by the join.
    OutputReady,
}

impl BarrierTag {
    /// Every tag, so a test can quantify over them.
    pub const ALL: [Self; 3] = [Self::MeshReady, Self::PreprocessingReady, Self::OutputReady];

    /// The reserved prefix this tag's frames carry.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Self::MeshReady => MESH_READY_PREFIX,
            Self::PreprocessingReady => HB_PREPROCESSING_READY_PREFIX,
            Self::OutputReady => OUTPUT_READY_PREFIX,
        }
    }

    /// The tag `payload` carries, with its namespace, or `None` if it carries
    /// none.
    ///
    /// `None` is a fall-through, never an error: the payload belongs to another
    /// reader on the same framed stream.
    pub fn classify(payload: &[u8]) -> Option<(Self, u64)> {
        for tag in Self::ALL {
            let prefix = tag.prefix();
            if payload.len() != prefix.len() + std::mem::size_of::<u64>()
                || !payload.starts_with(prefix)
            {
                continue;
            }
            let mut namespace = [0u8; 8];
            namespace.copy_from_slice(&payload[prefix.len()..]);
            return Some((tag, u64::from_le_bytes(namespace)));
        }
        None
    }
}

/// The one thing a barrier needs of a transport: reach a peer by party index.
///
/// Narrower than [`Network`] on purpose. A barrier announces and counts; it
/// neither connects, broadcasts, nor looks anything up, and depending on the
/// full trait would make it untestable without standing up a QUIC mesh — which
/// would be a test of the transport, not of the rendezvous.
#[async_trait::async_trait]
pub trait BarrierTransport: Sync {
    /// Deliver `payload` to the party at index `recipient`.
    async fn deliver(&self, recipient: PartyId, payload: &[u8]) -> Result<(), String>;
}

#[async_trait::async_trait]
impl<N> BarrierTransport for N
where
    N: Network + Sync,
{
    async fn deliver(&self, recipient: PartyId, payload: &[u8]) -> Result<(), String> {
        self.send(recipient, payload)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// An all-to-all rendezvous on one [`BarrierTag`] in one namespace.
///
/// Two halves that run on different tasks, which is why the type exists rather
/// than a pair of free functions:
///
/// * [`MeshBarrier::record`] is called from the receive loop, for every frame
///   it reads, and answers "was this mine?". It is synchronous and allocation
///   free on the miss path so it can sit in front of the MPC message pump.
/// * [`MeshBarrier::wait`] is called from the task that has reached the point.
///   It announces this node's arrival to every peer and then blocks until
///   `n - 1` *distinct* peers have announced theirs.
///
/// Frames from the wrong namespace are counted as a miss, not as an arrival: an
/// `instance_id` is the MPC session namespace (`net/mpc/protocol_ids.rs`), and
/// a barrier that accepted a stale run's frame would release early.
#[derive(Debug)]
pub struct MeshBarrier {
    tag: BarrierTag,
    namespace: u64,
    n: usize,
    local: PartyId,
    /// Peers that have announced. Kept on the barrier rather than inside
    /// [`MeshBarrier::wait`] so that a wait which timed out has not thrown away
    /// what it already learned: an arrival is a fact about the run, not about
    /// one call.
    arrived: DashSet<PartyId>,
    /// Wakes a waiter. Carries no state — [`MeshBarrier::arrived`] is the
    /// state — so a wakeup that nobody is waiting for costs a queue slot and
    /// loses nothing.
    wakeups_tx: mpsc::UnboundedSender<()>,
    wakeups_rx: Mutex<mpsc::UnboundedReceiver<()>>,
}

impl MeshBarrier {
    /// A barrier on `tag`, in `namespace`, for an `n`-party session.
    ///
    /// `local` is this node's own party index; a frame that claims to come from
    /// it is ignored, matching the `sender_id != my_id` guard the runner
    /// applied by hand.
    ///
    /// The arrival queue is unbounded on purpose. It is fed from the receive
    /// loop, and a bounded queue whose consumer has not reached
    /// [`MeshBarrier::wait`] yet would either block that loop — stalling the
    /// QUIC socket it drains, the cross-party deadlock
    /// `spawn_receive_loops_split` documents — or drop an arrival that is never
    /// re-sent. Its depth is bounded in practice by the party count: a peer
    /// announces once per barrier.
    pub fn new(tag: BarrierTag, namespace: u64, n: usize, local: PartyId) -> Self {
        let (wakeups_tx, wakeups_rx) = mpsc::unbounded_channel();
        Self {
            tag,
            namespace,
            n,
            local,
            arrived: DashSet::new(),
            wakeups_tx,
            wakeups_rx: Mutex::new(wakeups_rx),
        }
    }

    /// How many distinct peers have announced their arrival.
    pub fn arrived(&self) -> usize {
        self.arrived.len()
    }

    pub fn tag(&self) -> BarrierTag {
        self.tag
    }

    pub fn namespace(&self) -> u64 {
        self.namespace
    }

    /// The frame this node announces its own arrival with.
    pub fn frame(&self) -> Vec<u8> {
        let prefix = self.tag.prefix();
        let mut frame = Vec::with_capacity(prefix.len() + std::mem::size_of::<u64>());
        frame.extend_from_slice(prefix);
        frame.extend_from_slice(&self.namespace.to_le_bytes());
        frame
    }

    /// Record `payload` if it is this barrier's arrival frame.
    ///
    /// Returns `true` when the frame was consumed, so a receive loop can write
    /// `if barrier.record(sender, &data) { continue; }` and keep the frame away
    /// from the MPC engine — which is what the hand-rolled version did, and the
    /// reason a barrier tag has to be disjoint from every other prefix on the
    /// stream.
    pub fn record(&self, sender: PartyId, payload: &[u8]) -> bool {
        match BarrierTag::classify(payload) {
            Some((tag, namespace)) if tag == self.tag && namespace == self.namespace => {
                if sender != self.local && self.arrived.insert(sender) {
                    // Only fails once the barrier itself has been dropped, at
                    // which point nobody is waiting to be woken.
                    let _ = self.wakeups_tx.send(());
                }
                true
            }
            // A frame for this tag in another namespace is still this reader's
            // frame — it is a stale or foreign run's rendezvous, and handing it
            // to the MPC engine would be worse than dropping it.
            Some((tag, _)) if tag == self.tag => true,
            _ => false,
        }
    }

    /// Announce this node's arrival to every peer, then wait for the rest.
    ///
    /// A single-party session has nobody to wait for and returns immediately
    /// without sending.
    pub async fn wait<T>(&self, net: &T, timeout: Duration) -> MeshResult<()>
    where
        T: BarrierTransport + ?Sized,
    {
        let expected = self.n.saturating_sub(1);
        if expected == 0 {
            return Ok(());
        }

        let frame = self.frame();
        for peer in 0..self.n {
            if peer == self.local {
                continue;
            }
            net.deliver(peer, &frame)
                .await
                .map_err(|reason| MeshError::BarrierUnannounceable {
                    tag: self.tag,
                    party_id: peer,
                    reason,
                })?;
        }

        let mut wakeups = self.wakeups_rx.lock().await;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Checked before every wait, and `record` inserts into `arrived`
            // *before* it sends the wakeup, so an arrival that lands between
            // two iterations is seen by the next check rather than lost.
            if self.arrived.len() >= expected {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            // Every sender is held by this barrier, so the channel can only
            // close once `self` is gone — impossible while `&self` is borrowed
            // here. Reported as a failure rather than as completion so a future
            // refactor cannot turn it into a silent pass.
            if tokio::time::timeout(remaining, wakeups.recv())
                .await
                .map(|wakeup| wakeup.is_none())
                .unwrap_or(true)
            {
                return Err(MeshError::BarrierIncomplete {
                    tag: self.tag,
                    reached: self.arrived.len(),
                    expected,
                    waited: timeout,
                });
            }
        }
    }
}

/// A rendezvous whose frames carry a value every peer must agree on.
///
/// `docs/design/bootnode-elimination.md` §9.D.6. [`MeshBarrier`] cannot carry
/// one: [`BarrierTag::classify`] accepts only `prefix + 8` bytes, a same-tag
/// frame from another namespace is consumed without error, and nothing
/// remembers what a peer announced. These two tags cover data the coordinator
/// serves each node separately, so they are where a coordinator that tells
/// different nodes different things is caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestBarrierTag {
    /// The frozen admission set and the summary it was provisioned from (§9.C.7).
    AdmissionsAgreed,
    /// The masked inputs the coordinator delivered (§9.C.7).
    InputsAgreed,
}

/// Bytes of the digest a [`DigestBarrier`] frame carries.
pub const DIGEST_BARRIER_DIGEST_LEN: usize = 32;

impl DigestBarrierTag {
    /// Every tag, so a test can quantify over them.
    pub const ALL: [Self; 2] = [Self::AdmissionsAgreed, Self::InputsAgreed];

    /// The reserved prefix this tag's frames carry.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Self::AdmissionsAgreed => ADMISSIONS_AGREED_PREFIX,
            Self::InputsAgreed => INPUTS_AGREED_PREFIX,
        }
    }

    /// `prefix || namespace (u64 LE) || digest (32 bytes)` at exactly that
    /// length, else `None` — a fall-through, never an error.
    pub fn classify(payload: &[u8]) -> Option<(Self, u64, [u8; DIGEST_BARRIER_DIGEST_LEN])> {
        for tag in Self::ALL {
            let prefix = tag.prefix();
            if payload.len()
                != prefix.len() + std::mem::size_of::<u64>() + DIGEST_BARRIER_DIGEST_LEN
                || !payload.starts_with(prefix)
            {
                continue;
            }
            let body = &payload[prefix.len()..];
            let mut namespace = [0u8; 8];
            namespace.copy_from_slice(&body[..8]);
            let mut digest = [0u8; DIGEST_BARRIER_DIGEST_LEN];
            digest.copy_from_slice(&body[8..]);
            return Some((tag, u64::from_le_bytes(namespace), digest));
        }
        None
    }

    /// The frame announcing `digest` in `namespace`.
    pub fn frame(self, namespace: u64, digest: &[u8; DIGEST_BARRIER_DIGEST_LEN]) -> Vec<u8> {
        let prefix = self.prefix();
        let mut frame = Vec::with_capacity(
            prefix.len() + std::mem::size_of::<u64>() + DIGEST_BARRIER_DIGEST_LEN,
        );
        frame.extend_from_slice(prefix);
        frame.extend_from_slice(&namespace.to_le_bytes());
        frame.extend_from_slice(digest);
        frame
    }

    /// The divergence error this tag reports for `party_id`.
    fn divergence(self, party_id: PartyId) -> MeshError {
        match self {
            Self::AdmissionsAgreed => MeshError::AdmissionDivergence { party_id },
            Self::InputsAgreed => MeshError::InputDivergence { party_id },
        }
    }
}

/// What one peer has announced on a [`DigestBarrier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Announced {
    Digest([u8; DIGEST_BARRIER_DIGEST_LEN]),
    /// The peer announced two different digests: it disagrees with itself, so
    /// it cannot agree with this node either.
    Conflicting,
}

/// An all-to-all agreement on one 32-byte digest, on one [`DigestBarrierTag`],
/// in one namespace.
///
/// Same two halves as [`MeshBarrier`]: [`DigestBarrier::record`] runs in the
/// receive loop, [`DigestBarrier::wait`] in the task that has computed its own
/// digest. A peer's frame can arrive before this node computed its own, so
/// every announcement is stored on the barrier.
#[derive(Debug)]
pub struct DigestBarrier {
    tag: DigestBarrierTag,
    namespace: u64,
    n: usize,
    local: PartyId,
    /// A peer's first digest, or `Conflicting` once it has announced two
    /// different ones.
    announced: DashMap<PartyId, Announced>,
    wakeups_tx: mpsc::UnboundedSender<()>,
    wakeups_rx: Mutex<mpsc::UnboundedReceiver<()>>,
}

impl DigestBarrier {
    /// A barrier on `tag`, in `namespace`, for an `n`-party session in which
    /// this node is party `local`.
    pub fn new(tag: DigestBarrierTag, namespace: u64, n: usize, local: PartyId) -> Self {
        let (wakeups_tx, wakeups_rx) = mpsc::unbounded_channel();
        Self {
            tag,
            namespace,
            n,
            local,
            announced: DashMap::new(),
            wakeups_tx,
            wakeups_rx: Mutex::new(wakeups_rx),
        }
    }

    pub fn tag(&self) -> DigestBarrierTag {
        self.tag
    }

    pub fn namespace(&self) -> u64 {
        self.namespace
    }

    /// Receive-loop half. `true` for any frame of this tag, which the loop
    /// drops; a frame in this namespace from a peer is stored whether or not
    /// [`DigestBarrier::wait`] has started.
    pub fn record(&self, sender: PartyId, payload: &[u8]) -> bool {
        match DigestBarrierTag::classify(payload) {
            Some((tag, namespace, digest)) if tag == self.tag => {
                if namespace == self.namespace && sender != self.local && sender < self.n {
                    let changed = match self.announced.entry(sender) {
                        dashmap::mapref::entry::Entry::Vacant(vacant) => {
                            vacant.insert(Announced::Digest(digest));
                            true
                        }
                        dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                            match *occupied.get() {
                                Announced::Digest(first) if first != digest => {
                                    occupied.insert(Announced::Conflicting);
                                    true
                                }
                                _ => false,
                            }
                        }
                    };
                    if changed {
                        // Fails only once the barrier is gone, when nobody waits.
                        let _ = self.wakeups_tx.send(());
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Announces `own` to every peer, then waits for every peer's
    /// announcement. The lowest-numbered peer that announced a different
    /// digest, or two digests, fails the wait with the tag's divergence error.
    pub async fn wait<T>(
        &self,
        net: &T,
        own: [u8; DIGEST_BARRIER_DIGEST_LEN],
        timeout: Duration,
    ) -> MeshResult<()>
    where
        T: BarrierTransport + ?Sized,
    {
        let expected = self.n.saturating_sub(1);
        if expected == 0 {
            return Ok(());
        }

        let frame = self.tag.frame(self.namespace, &own);
        for peer in 0..self.n {
            if peer == self.local {
                continue;
            }
            net.deliver(peer, &frame).await.map_err(|reason| {
                MeshError::DigestBarrierUnannounceable {
                    tag: self.tag,
                    party_id: peer,
                    reason,
                }
            })?;
        }

        let mut wakeups = self.wakeups_rx.lock().await;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // `record` stores before it wakes, so an announcement landing
            // between two checks is seen by the next one.
            let mut reached = 0usize;
            for peer in (0..self.n).filter(|peer| *peer != self.local) {
                match self.announced.get(&peer).map(|entry| *entry) {
                    Some(Announced::Digest(digest)) if digest == own => reached += 1,
                    Some(_) => return Err(self.tag.divergence(peer)),
                    None => {}
                }
            }
            if reached >= expected {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if tokio::time::timeout(remaining, wakeups.recv())
                .await
                .map(|wakeup| wakeup.is_none())
                .unwrap_or(true)
            {
                return Err(MeshError::DigestBarrierIncomplete {
                    tag: self.tag,
                    reached,
                    expected,
                    waited: timeout,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    use stoffelnet::network_utils::Network;
    use stoffelnet::transports::quic::NetworkManager;

    use super::*;
    use crate::tests::test_utils::init_crypto_provider;

    /// A [`Network`] that records what a barrier announced and connects
    /// nothing.
    ///
    /// The barrier's own logic — distinct senders, namespace matching, the
    /// self-announcement guard — is independent of the transport, and a real
    /// QUIC mesh would test the transport rather than the barrier.
    #[derive(Debug, Default)]
    struct NoopNetwork {
        sent: std::sync::atomic::AtomicUsize,
    }

    impl NoopNetwork {
        fn sent(&self) -> usize {
            self.sent.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl BarrierTransport for NoopNetwork {
        async fn deliver(&self, _recipient: PartyId, _payload: &[u8]) -> Result<(), String> {
            self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    fn reserve_local_addr() -> SocketAddr {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind UDP socket on localhost");
        socket.local_addr().expect("get local socket address")
    }

    /// The whole reason this function exists instead of a party count: the
    /// deleted `wait_until_min_parties` polled `Network::parties()`, which
    /// installing addresses satisfies immediately and which proves nothing about
    /// connectivity.
    #[tokio::test]
    async fn installed_addresses_satisfy_the_party_count_but_not_the_barrier() {
        init_crypto_provider();
        let mut net = QuicNetworkManager::new();
        net.listen(reserve_local_addr())
            .await
            .expect("listen on loopback");

        net.add_node_with_party_id(1, reserve_local_addr());
        net.add_node_with_party_id(2, reserve_local_addr());
        assert!(
            net.parties().len() >= 2,
            "the configured node list is what a party count counts, and it is \
             already full"
        );

        let error = wait_until_mesh_connected(&net, 2, Duration::from_millis(50))
            .await
            .expect_err("no peer has handshaked, so the mesh is not connected");
        assert_eq!(
            error,
            MeshError::MeshIncomplete {
                expected: 2,
                waited: Duration::from_millis(50),
            }
        );
    }

    /// A single-party mesh has no peers to authenticate, so the barrier reduces
    /// to "this node has its own certificate" — and passes once it is listening.
    #[tokio::test]
    async fn a_listening_node_alone_satisfies_a_one_party_mesh() {
        init_crypto_provider();
        let mut net = QuicNetworkManager::new();
        net.listen(reserve_local_addr())
            .await
            .expect("listen on loopback");

        wait_until_mesh_connected(&net, 1, Duration::from_millis(50))
            .await
            .expect("a listening node holds its own public key");
    }

    /// The migration's whole safety claim: moving the runner onto
    /// [`MeshBarrier`] must not change one byte it puts on the wire.
    #[test]
    fn the_preprocessing_frame_is_byte_identical_to_the_one_the_runner_hand_rolled() {
        let instance_id = 77779u64;
        let barrier = MeshBarrier::new(BarrierTag::PreprocessingReady, instance_id, 3, 0);

        let mut hand_rolled =
            Vec::with_capacity(HB_PREPROCESSING_READY_PREFIX.len() + std::mem::size_of::<u64>());
        hand_rolled.extend_from_slice(HB_PREPROCESSING_READY_PREFIX);
        hand_rolled.extend_from_slice(&instance_id.to_le_bytes());

        assert_eq!(barrier.frame(), hand_rolled);
    }

    #[test]
    fn every_tag_round_trips_through_classify() {
        for tag in BarrierTag::ALL {
            let barrier = MeshBarrier::new(tag, 1234, 2, 0);
            assert_eq!(
                BarrierTag::classify(&barrier.frame()),
                Some((tag, 1234)),
                "{tag:?} must classify as itself"
            );
        }
    }

    /// The tags share a stream with the MPC data plane, so anything that is not
    /// a barrier frame has to fall through rather than be mistaken for one.
    #[test]
    fn a_foreign_payload_classifies_as_no_barrier() {
        assert_eq!(BarrierTag::classify(b""), None);
        assert_eq!(BarrierTag::classify(b"MSH1\x00\x00\x00\x00"), None);
        // The right prefix with the wrong length is not a barrier frame either:
        // a namespace is exactly eight bytes.
        let mut truncated = HB_PREPROCESSING_READY_PREFIX.to_vec();
        truncated.extend_from_slice(&[0u8; 4]);
        assert_eq!(BarrierTag::classify(&truncated), None);
    }

    /// A barrier releases on `n - 1` *distinct* peers, so one loud peer cannot
    /// stand in for a silent one.
    #[tokio::test]
    async fn a_repeated_arrival_does_not_stand_in_for_a_missing_party() {
        let barrier = MeshBarrier::new(BarrierTag::PreprocessingReady, 9, 3, 0);
        let frame = barrier.frame();

        assert!(barrier.record(1, &frame));
        assert!(barrier.record(1, &frame));

        let error = barrier
            .wait(&NoopNetwork::default(), Duration::from_millis(50))
            .await
            .expect_err("one peer twice is not two peers");
        assert_eq!(
            error,
            MeshError::BarrierIncomplete {
                tag: BarrierTag::PreprocessingReady,
                reached: 1,
                expected: 2,
                waited: Duration::from_millis(50),
            }
        );

        assert!(barrier.record(2, &frame));
        barrier
            .wait(&NoopNetwork::default(), Duration::from_millis(50))
            .await
            .expect("the second distinct peer releases the barrier");
    }

    /// An `instance_id` is the MPC session namespace, so a previous run's
    /// barrier frame must be consumed — it is this reader's frame — without
    /// counting as an arrival.
    #[tokio::test]
    async fn a_frame_from_another_instance_is_consumed_but_does_not_release() {
        let barrier = MeshBarrier::new(BarrierTag::PreprocessingReady, 9, 2, 0);
        let stale = MeshBarrier::new(BarrierTag::PreprocessingReady, 8, 2, 0).frame();

        assert!(
            barrier.record(1, &stale),
            "a stale frame is still this reader's frame; handing it to the MPC engine is worse"
        );
        assert!(matches!(
            barrier
                .wait(&NoopNetwork::default(), Duration::from_millis(50))
                .await,
            Err(MeshError::BarrierIncomplete { reached: 0, .. })
        ));
    }

    /// Two barriers sharing one stream must not consume each other's frames.
    #[test]
    fn a_barrier_leaves_another_tags_frames_alone() {
        let preprocessing = MeshBarrier::new(BarrierTag::PreprocessingReady, 9, 2, 0);
        let output = MeshBarrier::new(BarrierTag::OutputReady, 9, 2, 0);

        assert!(!preprocessing.record(1, &output.frame()));
        assert!(!output.record(1, &preprocessing.frame()));
    }

    /// A node cannot satisfy its own barrier.
    #[tokio::test]
    async fn a_node_does_not_count_its_own_announcement() {
        let barrier = MeshBarrier::new(BarrierTag::MeshReady, 5, 2, 1);
        assert!(barrier.record(1, &barrier.frame()));
        assert!(matches!(
            barrier
                .wait(&NoopNetwork::default(), Duration::from_millis(50))
                .await,
            Err(MeshError::BarrierIncomplete { reached: 0, .. })
        ));
    }

    /// A one-party session has nobody to announce to and nobody to wait for.
    #[tokio::test]
    async fn a_single_party_barrier_passes_without_sending() {
        let net = NoopNetwork::default();
        MeshBarrier::new(BarrierTag::PreprocessingReady, 1, 1, 0)
            .wait(&net, Duration::from_millis(50))
            .await
            .expect("a one-party barrier has nothing to wait for");
        assert_eq!(net.sent(), 0);
    }

    /// Without a local certificate there is nothing to authenticate peers
    /// against, so even a one-party mesh must not pass.
    #[tokio::test]
    async fn a_node_without_a_local_certificate_never_passes() {
        init_crypto_provider();
        let net = QuicNetworkManager::new();

        let error = wait_until_mesh_connected(&net, 1, Duration::from_millis(50))
            .await
            .expect_err("a manager that never listened has no local public key");
        assert!(matches!(
            error,
            MeshError::MeshIncomplete { expected: 1, .. }
        ));
    }
    #[test]
    fn a_digest_frame_classifies_as_itself_and_no_other_barrier() {
        for tag in DigestBarrierTag::ALL {
            let frame = tag.frame(4321, &[9u8; 32]);
            assert_eq!(
                DigestBarrierTag::classify(&frame),
                Some((tag, 4321, [9u8; 32]))
            );
            assert_eq!(BarrierTag::classify(&frame), None);
            // A digest frame without its digest is not a digest frame.
            assert_eq!(DigestBarrierTag::classify(&frame[..frame.len() - 1]), None);
        }
        let plain = MeshBarrier::new(BarrierTag::PreprocessingReady, 1, 2, 0).frame();
        assert_eq!(DigestBarrierTag::classify(&plain), None);
    }

    #[tokio::test]
    async fn every_peer_announcing_the_same_digest_releases_the_barrier() {
        let net = NoopNetwork::default();
        let barrier = DigestBarrier::new(DigestBarrierTag::AdmissionsAgreed, 7, 3, 0);
        let own = [1u8; 32];
        // Announced before this node computed its own digest.
        assert!(barrier.record(1, &DigestBarrierTag::AdmissionsAgreed.frame(7, &own)));
        assert!(barrier.record(2, &DigestBarrierTag::AdmissionsAgreed.frame(7, &own)));
        barrier
            .wait(&net, own, Duration::from_millis(50))
            .await
            .expect("every peer agreed");
        assert_eq!(net.sent(), 2);
    }

    #[tokio::test]
    async fn a_peer_with_another_digest_is_named_as_divergent() {
        let barrier = DigestBarrier::new(DigestBarrierTag::AdmissionsAgreed, 7, 3, 0);
        assert!(barrier.record(2, &DigestBarrierTag::AdmissionsAgreed.frame(7, &[2u8; 32])));
        assert_eq!(
            barrier
                .wait(
                    &NoopNetwork::default(),
                    [1u8; 32],
                    Duration::from_millis(50)
                )
                .await,
            Err(MeshError::AdmissionDivergence { party_id: 2 })
        );

        let inputs = DigestBarrier::new(DigestBarrierTag::InputsAgreed, 7, 2, 1);
        assert!(inputs.record(0, &DigestBarrierTag::InputsAgreed.frame(7, &[2u8; 32])));
        assert_eq!(
            inputs
                .wait(
                    &NoopNetwork::default(),
                    [1u8; 32],
                    Duration::from_millis(50)
                )
                .await,
            Err(MeshError::InputDivergence { party_id: 0 })
        );
    }

    #[tokio::test]
    async fn a_peer_announcing_two_digests_cannot_agree() {
        let barrier = DigestBarrier::new(DigestBarrierTag::InputsAgreed, 7, 2, 0);
        let own = [1u8; 32];
        assert!(barrier.record(1, &DigestBarrierTag::InputsAgreed.frame(7, &own)));
        assert!(barrier.record(1, &DigestBarrierTag::InputsAgreed.frame(7, &[3u8; 32])));
        // Re-announcing the first digest does not undo the conflict.
        assert!(barrier.record(1, &DigestBarrierTag::InputsAgreed.frame(7, &own)));
        assert_eq!(
            barrier
                .wait(&NoopNetwork::default(), own, Duration::from_millis(50))
                .await,
            Err(MeshError::InputDivergence { party_id: 1 })
        );
    }

    #[tokio::test]
    async fn foreign_namespaces_self_announcements_and_other_tags_do_not_count() {
        let barrier = DigestBarrier::new(DigestBarrierTag::AdmissionsAgreed, 7, 2, 0);
        let own = [1u8; 32];
        assert!(
            barrier.record(1, &DigestBarrierTag::AdmissionsAgreed.frame(8, &[5u8; 32])),
            "another namespace's frame is still this reader's frame"
        );
        assert!(barrier.record(0, &DigestBarrierTag::AdmissionsAgreed.frame(7, &own)));
        assert!(!barrier.record(1, &DigestBarrierTag::InputsAgreed.frame(7, &own)));
        assert_eq!(
            barrier
                .wait(&NoopNetwork::default(), own, Duration::from_millis(50))
                .await,
            Err(MeshError::DigestBarrierIncomplete {
                tag: DigestBarrierTag::AdmissionsAgreed,
                reached: 0,
                expected: 1,
                waited: Duration::from_millis(50),
            })
        );
    }

    #[tokio::test]
    async fn an_announcement_arriving_during_the_wait_releases_it() {
        let barrier =
            std::sync::Arc::new(DigestBarrier::new(DigestBarrierTag::InputsAgreed, 7, 2, 0));
        let own = [4u8; 32];
        let recorder = barrier.clone();
        let announce = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            recorder.record(1, &DigestBarrierTag::InputsAgreed.frame(7, &own))
        });
        barrier
            .wait(&NoopNetwork::default(), own, Duration::from_secs(5))
            .await
            .expect("the late announcement agrees");
        assert!(announce.await.expect("recorder task"));
    }
}
