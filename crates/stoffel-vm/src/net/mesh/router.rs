//! The mesh control plane's receive side.
//!
//! Stage 4 of `docs/design/bootnode-elimination.md`. [`MeshRouter`] is the
//! second router on the shared framed stream, and its shape deliberately
//! mirrors [`crate::net::open_registry::OpenMessageRouter`]:
//! `try_handle_wire_message(authenticated_sender_id, payload) -> Result<bool,
//! String>`, `Ok(false)` for "not mine". That is not cosmetic — it is what lets
//! it be dropped into a chain of such calls at every receive loop without
//! restructuring any of them.
//!
//! # Blocker B6: seven sites, not two
//!
//! HoneyBadger has four receive loops (`net/hb_server.rs` accept loop, dial
//! loop, `spawn_receive_loops`, `spawn_receive_loops_split`) and AVSS does not
//! use any of them — it runs its own per-connection loops
//! (`net/avss_server.rs::spawn_message_loops` and `..._split`) and calls
//! `try_handle_wire_message` directly. A mesh frame arriving at a loop with no
//! [`MeshRouter`] installed falls through to
//! `engine.process_wrapped_message_with_network`, i.e. the AVSS engine is asked
//! to parse a `PeerAnnounce` as a protocol message.
//!
//! The seventh is the one the blocker's own wording hides: the production AVSS
//! *party* path does not go through `AvssQuicServer` at all.
//! `stoffel-run.rs::setup_avss_party_for_curve` spawns its own per-peer loop
//! over `net.get_all_server_connections()`. It is a party-to-party loop, not a
//! client or coordinator one, so it must install the router like the other six;
//! `every_receive_loop_offers_its_payloads_to_the_mesh_router` covers the six in
//! this crate and `stoffel-run.rs`'s own
//! `the_avss_party_receive_loop_offers_its_payloads_to_the_mesh_router` covers
//! the seventh, because a library test cannot `include_str!` across a crate
//! boundary without breaking `cargo publish`.
//!
//! # What this router decides, and what it only records
//!
//! PEX is *state* — the book is the whole point — so [`MeshMessage::PeerAnnounce`]
//! and [`MeshMessage::PeerBook`] are folded in here, and [`MeshMessage::Heartbeat`]
//! updates a liveness stamp. Everything a later stage owns — the join
//! handshake, program chunks, barriers — is forwarded to the owner as a
//! [`MeshEvent`] and not otherwise interpreted, because interpreting it would be
//! implementing Stage 5 inside Stage 4.
//!
//! The event sink is optional and bounded. A receive loop installs a router so
//! that control frames stop reaching the MPC engine; if nobody is draining
//! events, the correct behavior is to drop them with a counter, not to grow an
//! unbounded queue behind a loop that will never read it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::Mutex;
use stoffelnet::network_utils::{NodePublicKey, PartyId};
use tokio::sync::mpsc;

use crate::net::mesh::pex::{PeerBook, PeerRecord, PexLimits, PexOutcome, RecordSource};
use crate::net::mesh::wire::{self, MeshMessage, MeshWireError};
use crate::net::open_registry::UNKNOWN_SENDER_ID;

/// Default depth of the event sink.
///
/// Generous for a control plane whose frames are one per peer per event, and
/// small enough that a stalled consumer is visible as drops rather than as
/// unbounded growth.
pub const DEFAULT_MESH_EVENT_CAPACITY: usize = 1024;

/// A control frame this router does not itself act on, handed to its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshEvent {
    /// The transport-authenticated sender. Never [`UNKNOWN_SENDER_ID`]: an
    /// unauthenticated frame is rejected before an event is built.
    pub sender: PartyId,
    pub message: MeshMessage,
}

/// What one router has seen, for tests and for operational visibility.
///
/// Counters rather than logs because the property Stage 4 has to establish —
/// "mesh frames are consumed here and do not reach the MPC engine" — is a
/// statement about counts at seven specific sites.
#[derive(Debug, Default)]
pub struct MeshRouterCounters {
    consumed: AtomicU64,
    rejected: AtomicU64,
    learned: AtomicU64,
    refreshed: AtomicU64,
    ignored_records: AtomicU64,
    events_dropped: AtomicU64,
}

impl MeshRouterCounters {
    /// Frames recognized and handled.
    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }
    /// Frames that carried the mesh tag and were refused.
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
    /// Peers this router had never heard of.
    pub fn learned(&self) -> u64 {
        self.learned.load(Ordering::Relaxed)
    }
    /// Address updates applied to peers already known.
    pub fn refreshed(&self) -> u64 {
        self.refreshed.load(Ordering::Relaxed)
    }
    /// Records dropped as stale, inadmissible, or over the book's cap.
    pub fn ignored_records(&self) -> u64 {
        self.ignored_records.load(Ordering::Relaxed)
    }
    /// Events dropped because nothing was draining the sink.
    pub fn events_dropped(&self) -> u64 {
        self.events_dropped.load(Ordering::Relaxed)
    }
}

/// Routes mesh control frames off the shared stream.
#[derive(Debug)]
pub struct MeshRouter {
    book: Mutex<PeerBook>,
    /// Sender party id to the last `unix_millis` it stamped a heartbeat with.
    heartbeats: DashMap<PartyId, u64>,
    /// Senders that asked for a peer book and have not been answered.
    ///
    /// The router cannot answer: it holds no connection, by design — it is
    /// called from inside a receive loop that owns the connection it read from.
    /// The owner drains this with [`MeshRouter::take_peer_requests`].
    ///
    /// Keyed by sender, so a peer that asks a thousand times before anybody
    /// drains still occupies one slot: the answer to "send me your book" is the
    /// same whenever it is finally sent, so a queue of repeats is pure growth.
    /// With one slot per authenticated sender the queue is bounded by the size
    /// of the certificate allowlist rather than by how fast a Byzantine member
    /// can talk.
    peer_requests: Mutex<BTreeMap<PartyId, usize>>,
    events: Option<mpsc::Sender<MeshEvent>>,
    counters: MeshRouterCounters,
}

/// An unanswered [`MeshMessage::PeerRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRequest {
    pub sender: PartyId,
    /// Records the sender asked for, already clamped to what one frame holds.
    pub max_records: usize,
}

impl Default for MeshRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshRouter {
    /// A router that keeps a book and drops the events nobody asked for.
    pub fn new() -> Self {
        Self::with_book(PeerBook::default(), None)
    }

    /// A router pinned to the roster's SPKIs, which is the default deployment.
    pub fn pinned_to<I>(keys: I, limits: PexLimits) -> Self
    where
        I: IntoIterator<Item = NodePublicKey>,
    {
        Self::with_book(PeerBook::pinned_to(keys, limits), None)
    }

    /// A router whose non-PEX frames are delivered to the returned receiver.
    pub fn with_events(book: PeerBook, capacity: usize) -> (Self, mpsc::Receiver<MeshEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self::with_book(book, Some(tx)), rx)
    }

    fn with_book(book: PeerBook, events: Option<mpsc::Sender<MeshEvent>>) -> Self {
        Self {
            book: Mutex::new(book),
            heartbeats: DashMap::new(),
            peer_requests: Mutex::new(BTreeMap::new()),
            events,
            counters: MeshRouterCounters::default(),
        }
    }

    pub fn counters(&self) -> &MeshRouterCounters {
        &self.counters
    }

    /// Whether this router's peer book refuses SPKIs outside a fixed set.
    ///
    /// An unpinned router lets any transport-authenticated peer put arbitrary
    /// identities in the book, so a server that has a roster should be able to
    /// assert that it actually installed it.
    pub fn is_pinned(&self) -> bool {
        self.book.lock().is_pinned()
    }

    /// Consume a payload if it is a mesh control frame.
    ///
    /// Signature-compatible with
    /// [`crate::net::open_registry::OpenMessageRouter::try_handle_wire_message`]
    /// so the two can be chained at a receive loop. `Ok(false)` means "not a
    /// mesh frame, keep offering it"; `Err` means "a mesh frame this router
    /// refused" and must **not** be treated as a fall-through, or the engine is
    /// handed bytes already known to be control traffic.
    ///
    /// This form says nothing about *which certificate* the frame arrived
    /// under, so an announcement it carries is treated as hearsay
    /// ([`RecordSource::Relayed`]). A receive loop that holds the connection
    /// should call [`MeshRouter::try_handle_wire_message_from`] instead.
    pub fn try_handle_wire_message(
        &self,
        authenticated_sender_id: usize,
        payload: &[u8],
    ) -> Result<bool, String> {
        self.try_handle_wire_message_from(authenticated_sender_id, None, payload)
    }

    /// Consume a payload if it is a mesh control frame, knowing who sent it.
    ///
    /// `peer_key` is the sender's TLS-authenticated DER `SubjectPublicKeyInfo`,
    /// i.e. `PeerConnection::authenticated_peer_public_key` (stoffelnet
    /// `quic.rs:147`) for the connection the bytes were read from. It is what
    /// binds a [`MeshMessage::PeerAnnounce`] to its announcer:
    ///
    /// * `Some(key)` and the record names that key — the peer is speaking about
    ///   itself, so the record is [`RecordSource::Announced`].
    /// * `Some(key)` and the record names *somebody else* — refused. "I am
    ///   reachable at" is not a statement anyone can make on another party's
    ///   behalf, and accepting it is exactly how one roster member pins an
    ///   honest party's address to a dead host (see [`crate::net::mesh::pex`]).
    /// * `None` — this transport reported no certificate identity
    ///   (`use_tls: false`, or a test connection), so the claim is
    ///   unverifiable and is demoted to [`RecordSource::Relayed`], which can
    ///   fill a gap but never displace a first-hand entry.
    pub fn try_handle_wire_message_from(
        &self,
        authenticated_sender_id: usize,
        peer_key: Option<&NodePublicKey>,
        payload: &[u8],
    ) -> Result<bool, String> {
        let message = match wire::try_decode(payload) {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(false),
            Err(error) => {
                self.counters.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(self.reject(error.to_string()));
            }
        };

        // Same rule the open registry applies (`open_registry/router.rs`): a
        // connection whose certificate produced no party identity cannot be
        // allowed to move this node's view of who is where.
        if authenticated_sender_id == UNKNOWN_SENDER_ID {
            self.counters.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(
                "mesh control frame rejected: sender identity not authenticated".to_string(),
            );
        }

        let now = Instant::now();

        // Charge the per-sender window before any state is touched, for every
        // frame this router keeps state for — not only the ones carrying
        // records. `PeerRequest` and `Heartbeat` each write a map entry, and an
        // arm that mutates without paying is the cheap thing to point a flood
        // at.
        //
        // The frames forwarded as `MeshEvent`s are deliberately *not* charged:
        // they are already bounded by the event sink's capacity and its drop
        // counter, and a 16-frames-per-10s budget would throttle the chunked
        // program transfer `MeshMessage::ProgramChunk` exists for down to
        // uselessness.
        if let Some(records) = quota_cost(&message) {
            self.charge(authenticated_sender_id, records, now)?;
        }

        match message {
            MeshMessage::PeerAnnounce { record } => {
                let source = match peer_key {
                    Some(key) if key.0 == record.spki => RecordSource::Announced,
                    Some(_) => {
                        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
                        return Err(self.reject(format!(
                            "peer {authenticated_sender_id} announced an address for a public key \
                             that is not the one its certificate proved"
                        )));
                    }
                    None => RecordSource::Relayed,
                };
                self.absorb(vec![record], source, now);
            }
            MeshMessage::PeerBook { records } => {
                self.absorb(records, RecordSource::Relayed, now);
            }
            MeshMessage::PeerRequest { max_records } => {
                let limit = self.book.lock().limits().max_records_per_message;
                let wanted = (max_records as usize).min(limit);
                // One pending request per sender; a later, larger ask widens
                // the answer rather than queueing a second one.
                self.peer_requests
                    .lock()
                    .entry(authenticated_sender_id)
                    .and_modify(|pending| *pending = (*pending).max(wanted))
                    .or_insert(wanted);
            }
            MeshMessage::Heartbeat { unix_millis, .. } => {
                self.heartbeats.insert(authenticated_sender_id, unix_millis);
            }
            other => self.emit(MeshEvent {
                sender: authenticated_sender_id,
                message: other,
            }),
        }

        self.counters.consumed.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Charge one control frame against `sender`'s fixed window.
    fn charge(&self, sender: PartyId, records: usize, now: Instant) -> Result<(), String> {
        if let Err(rejection) = self.book.lock().admit(sender, records, now) {
            self.counters.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(self.reject(rejection.to_string()));
        }
        Ok(())
    }

    /// Fold already-charged records into the book.
    fn absorb(&self, records: Vec<PeerRecord>, source: RecordSource, now: Instant) {
        let mut book = self.book.lock();
        for record in records {
            match book.observe(record, source, now) {
                PexOutcome::Learned => {
                    self.counters.learned.fetch_add(1, Ordering::Relaxed);
                }
                PexOutcome::Refreshed => {
                    self.counters.refreshed.fetch_add(1, Ordering::Relaxed);
                }
                PexOutcome::Stale
                | PexOutcome::Outranked
                | PexOutcome::SeqJumpTooLarge
                | PexOutcome::NotAdmissible
                | PexOutcome::Full => {
                    self.counters
                        .ignored_records
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Rendered rejection text, prefixed the way the open registry's is.
    fn reject(&self, reason: String) -> String {
        format!("mesh control frame rejected: {reason}")
    }

    fn emit(&self, event: MeshEvent) {
        let Some(sender) = self.events.as_ref() else {
            self.counters.events_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if sender.try_send(event).is_err() {
            self.counters.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Announce this node's own address to the mesh.
    ///
    /// The frame a caller sends on every connection it holds; `seq` must be
    /// monotone per node, or receivers treat the announcement as a replay.
    pub fn announce(
        public_key: &NodePublicKey,
        advertise_addr: SocketAddr,
        seq: u64,
    ) -> Result<Vec<u8>, MeshWireError> {
        wire::encode(&MeshMessage::PeerAnnounce {
            record: PeerRecord::new(public_key, advertise_addr, seq),
        })
    }

    /// The frame that answers one [`PeerRequest`], or `None` when the book has
    /// nothing live to say.
    pub fn peer_book_frame(&self, request: PeerRequest) -> Option<Result<Vec<u8>, MeshWireError>> {
        let records = self
            .book
            .lock()
            .snapshot(request.max_records, Instant::now());
        if records.is_empty() {
            return None;
        }
        Some(wire::encode(&MeshMessage::PeerBook { records }))
    }

    /// Take the peer-book requests seen since the last call, one per sender.
    pub fn take_peer_requests(&self) -> Vec<PeerRequest> {
        std::mem::take(&mut *self.peer_requests.lock())
            .into_iter()
            .map(|(sender, max_records)| PeerRequest {
                sender,
                max_records,
            })
            .collect()
    }

    /// How many senders have an unanswered [`PeerRequest`] pending.
    pub fn pending_peer_requests(&self) -> usize {
        self.peer_requests.lock().len()
    }

    /// Live `(identity, address)` pairs the reconnect supervisor can dial.
    pub fn dial_targets(&self) -> Vec<(NodePublicKey, SocketAddr)> {
        self.book.lock().dial_targets(Instant::now())
    }

    /// The last heartbeat stamp seen from `peer`.
    pub fn last_heartbeat(&self, peer: PartyId) -> Option<u64> {
        self.heartbeats.get(&peer).map(|entry| *entry.value())
    }

    /// Drop book entries past their TTL. Returns how many went.
    pub fn expire_peers(&self) -> usize {
        self.book.lock().expire(Instant::now())
    }

    /// A bounded, live snapshot of the book, for a caller that is about to put
    /// it on the wire itself.
    ///
    /// [`MeshRouter::peer_book_frame`] answers a *request*; this is what a node
    /// offers unprompted, and the mesh join uses it for the one peer-book frame
    /// it sends per peer during its handshake.
    pub fn book_snapshot(&self, max: usize) -> Vec<PeerRecord> {
        self.book.lock().snapshot(max, Instant::now())
    }

    /// Fold in a record a peer relayed about somebody else.
    ///
    /// The same [`RecordSource::Relayed`] standing a gossiped `PeerBook` gets
    /// through [`MeshRouter::try_handle_wire_message`]: it can fill a gap, and
    /// it can never displace a first-hand entry. Exposed so that a caller which
    /// reads a peer book *outside* a receive loop — the join handshake owns its
    /// connections and does its own reading — lands the records in the same
    /// book under the same rules rather than keeping a second one.
    pub fn observe_relayed(&self, record: PeerRecord) -> PexOutcome {
        self.book
            .lock()
            .observe(record, RecordSource::Relayed, Instant::now())
    }

    /// Fold in a record for a peer whose identity *this node* verified.
    ///
    /// The standing [`RecordSource::Announced`] describes — an SPKI bound to an
    /// address by a TLS handshake — is not only reachable through a peer's own
    /// `PeerAnnounce` frame. A node that dials an address and reads the
    /// certificate at the far end has made the same observation first-hand, and
    /// more directly: it chose the address. [`crate::net::mesh::join_mesh`]
    /// records every address it successfully dials this way, which is what
    /// makes the book useful to the reconnect supervisor and to the next join
    /// even when a peer's book frame never arrives.
    ///
    /// Not [`RecordSource::Local`]: that rank means "configured, and gossip may
    /// never override it", and an address discovered at runtime is exactly the
    /// thing a later first-hand observation *should* be able to move.
    pub fn observe_announced(&self, record: PeerRecord) -> PexOutcome {
        self.book
            .lock()
            .observe(record, RecordSource::Announced, Instant::now())
    }

    /// Seed the book with what this node already knows, e.g. the roster's own
    /// addresses or a `--peers` hint that has since been identified.
    ///
    /// Recorded as [`RecordSource::Local`]: what the operator configured is not
    /// overridable by gossip, whatever `seq` a gossiper claims.
    pub fn seed(&self, record: PeerRecord) -> PexOutcome {
        self.book
            .lock()
            .observe(record, RecordSource::Local, Instant::now())
    }
}

/// How many records a frame costs its sender, or `None` if it is not charged.
///
/// `Some(0)` is a real answer: a `PeerRequest` or `Heartbeat` carries no
/// records but still costs one frame of the sender's window, because each one
/// writes an entry in this router.
fn quota_cost(message: &MeshMessage) -> Option<usize> {
    match message {
        MeshMessage::PeerAnnounce { .. } => Some(1),
        MeshMessage::PeerBook { records } => Some(records.len()),
        MeshMessage::PeerRequest { .. } | MeshMessage::Heartbeat { .. } => Some(0),
        MeshMessage::JoinProposal { .. }
        | MeshMessage::JoinCommit { .. }
        | MeshMessage::ProgramRequest { .. }
        | MeshMessage::ProgramChunk { .. } => None,
    }
}

/// A router shared by one runtime's receive loops, as the servers hold it.
pub type SharedMeshRouter = Arc<MeshRouter>;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::net::mesh::wire::{MAX_PEER_RECORDS_PER_MESSAGE, MESH_CTRL_PREFIX};
    use crate::net::open_registry::encode_single_share_wire_message;

    fn key(byte: u8) -> NodePublicKey {
        NodePublicKey(vec![byte; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}")
            .parse()
            .expect("parse loopback address")
    }

    fn announce(byte: u8, port: u16, seq: u64) -> Vec<u8> {
        MeshRouter::announce(&key(byte), addr(port), seq).expect("encode announcement")
    }

    /// The one property every one of the six install sites depends on: a frame
    /// belonging to another router is reported as not-mine, without error, so
    /// the chain continues.
    #[test]
    fn an_open_registry_frame_is_not_consumed() {
        let router = MeshRouter::new();
        let foreign = encode_single_share_wire_message(1, 0, "Fr", 1, &[7u8; 8])
            .expect("encode an open-registry frame");

        assert_eq!(
            router.try_handle_wire_message(1, &foreign),
            Ok(false),
            "an OPN1 frame must fall through to the open registry"
        );
        assert_eq!(router.counters().consumed(), 0);
    }

    #[test]
    fn an_announcement_is_consumed_and_lands_in_the_book() {
        let router = MeshRouter::new();

        assert_eq!(
            router.try_handle_wire_message(2, &announce(1, 9001, 1)),
            Ok(true)
        );
        assert_eq!(router.counters().consumed(), 1);
        assert_eq!(router.counters().learned(), 1);
        assert_eq!(router.dial_targets(), vec![(key(1), addr(9001))]);
    }

    /// An unauthenticated connection must not be able to move this node's view
    /// of where its peers are, even though a wrong address only costs a failed
    /// handshake.
    #[test]
    fn an_unauthenticated_sender_cannot_gossip() {
        let router = MeshRouter::new();

        let error = router
            .try_handle_wire_message(UNKNOWN_SENDER_ID, &announce(1, 9001, 1))
            .expect_err("an unauthenticated mesh frame");
        assert!(error.contains("not authenticated"), "{error}");
        assert!(router.dial_targets().is_empty());
        assert_eq!(router.counters().rejected(), 1);
    }

    /// A tagged frame that fails its bounds is an error, not a fall-through:
    /// returning `Ok(false)` would pass control bytes to the MPC engine.
    #[test]
    fn a_corrupt_mesh_frame_is_refused_rather_than_passed_on() {
        let router = MeshRouter::new();
        let mut payload = MESH_CTRL_PREFIX.to_vec();
        payload.extend_from_slice(&[0xff; 12]);

        let error = router
            .try_handle_wire_message(1, &payload)
            .expect_err("a tagged but corrupt frame");
        assert!(error.starts_with("mesh control frame rejected"), "{error}");
        assert_eq!(router.counters().consumed(), 0);
    }

    /// The attack an unsigned `PeerAnnounce` would otherwise make free: a
    /// roster member claiming, on its own authenticated connection, to be
    /// speaking for another party. "I am reachable at" is not a statement
    /// anyone can make on somebody else's behalf, and believing it once with an
    /// unbeatable `seq` would partition the victim out of the mesh.
    #[test]
    fn an_announcement_for_another_partys_key_is_refused() {
        let router = MeshRouter::new();
        let forged = MeshRouter::announce(&key(1), addr(6661), u64::MAX).expect("encode");

        let error = router
            .try_handle_wire_message_from(5, Some(&key(5)), &forged)
            .expect_err("party 5 announcing party 1's address");
        assert!(error.contains("certificate proved"), "{error}");
        assert!(router.dial_targets().is_empty());
        assert_eq!(router.counters().rejected(), 1);
        assert_eq!(router.counters().consumed(), 0);

        // The same frame from its actual owner is an ordinary announcement.
        let honest = MeshRouter::announce(&key(1), addr(9001), 1).expect("encode");
        assert_eq!(
            router.try_handle_wire_message_from(1, Some(&key(1)), &honest),
            Ok(true)
        );
        assert_eq!(router.dial_targets(), vec![(key(1), addr(9001))]);
    }

    /// A transport that cannot report a certificate identity (`use_tls: false`,
    /// or a test connection) cannot bind the record to its announcer, so the
    /// claim is hearsay and must not outrank what this node configured.
    #[test]
    fn an_announcement_without_a_certificate_identity_is_only_hearsay() {
        let router = MeshRouter::new();
        // Party 1 said where it is, on its own authenticated connection.
        router
            .try_handle_wire_message_from(1, Some(&key(1)), &announce(1, 9001, 1))
            .expect("the owner's own announcement");

        // The same claim arriving with no certificate identity behind it —
        // `use_tls: false`, or a transport that reports none — is unverifiable,
        // so it is demoted to hearsay and cannot displace the first-hand entry,
        // whatever `seq` it carries.
        assert_eq!(
            router.try_handle_wire_message(2, &announce(1, 6661, u64::MAX)),
            Ok(true),
            "the frame is consumed; its content is what is not believed"
        );
        assert_eq!(router.dial_targets(), vec![(key(1), addr(9001))]);
        assert_eq!(router.counters().ignored_records(), 1);

        // The owner itself still moves freely.
        assert_eq!(
            router.try_handle_wire_message_from(1, Some(&key(1)), &announce(1, 9101, 2)),
            Ok(true)
        );
        assert_eq!(router.dial_targets(), vec![(key(1), addr(9101))]);
    }

    /// `--peers` and the roster are the operator speaking, and the rank order
    /// says the network does not get to argue with them. Worth pinning
    /// explicitly, because it is the one place where a *correct* first-hand
    /// announcement is deliberately refused.
    #[test]
    fn a_seeded_address_outranks_even_a_first_hand_announcement() {
        let router = MeshRouter::new();
        router.seed(PeerRecord::new(&key(1), addr(9001), 1));

        assert_eq!(
            router.try_handle_wire_message_from(1, Some(&key(1)), &announce(1, 9101, 99)),
            Ok(true)
        );
        assert_eq!(router.dial_targets(), vec![(key(1), addr(9001))]);
        assert_eq!(router.counters().ignored_records(), 1);
    }

    /// A `PeerRequest` writes router state, so it is charged like gossip, and
    /// repeats from one sender collapse instead of queueing. Without both, an
    /// authenticated-but-Byzantine member grows the pending queue for the life
    /// of the process — nothing drains it until a connection-owning caller
    /// does.
    #[test]
    fn repeat_peer_requests_from_one_sender_collapse_and_are_charged() {
        let limits = PexLimits {
            max_messages_per_window: 4,
            ..PexLimits::default()
        };
        let router = MeshRouter::with_book(PeerBook::new(limits), None);
        let small = wire::encode(&MeshMessage::PeerRequest { max_records: 2 }).expect("encode");
        let large = wire::encode(&MeshMessage::PeerRequest { max_records: 9 }).expect("encode");

        assert_eq!(router.try_handle_wire_message(3, &small), Ok(true));
        assert_eq!(router.try_handle_wire_message(3, &large), Ok(true));
        assert_eq!(router.try_handle_wire_message(3, &small), Ok(true));
        assert_eq!(router.pending_peer_requests(), 1, "one slot per sender");

        // A fourth frame exhausts the window; the flood stops costing memory
        // long before it stops being sent.
        assert_eq!(router.try_handle_wire_message(3, &small), Ok(true));
        let error = router
            .try_handle_wire_message(3, &small)
            .expect_err("the fifth request inside the window");
        assert!(error.contains("gossip frames"), "{error}");

        let requests = router.take_peer_requests();
        assert_eq!(
            requests,
            vec![PeerRequest {
                sender: 3,
                max_records: 9
            }],
            "the widest ask survives the collapse"
        );
        assert_eq!(router.pending_peer_requests(), 0);
    }

    /// A heartbeat writes a liveness entry, so it pays the window too.
    #[test]
    fn heartbeats_are_charged_against_the_senders_window() {
        let limits = PexLimits {
            max_messages_per_window: 1,
            ..PexLimits::default()
        };
        let router = MeshRouter::with_book(PeerBook::new(limits), None);
        let frame = wire::encode(&MeshMessage::Heartbeat {
            seq: 1,
            unix_millis: 1_700_000_000_000,
        })
        .expect("encode heartbeat");

        assert_eq!(router.try_handle_wire_message(6, &frame), Ok(true));
        assert!(router.try_handle_wire_message(6, &frame).is_err());
    }

    /// The frames Stage 5 owns are bounded by the event sink, not by the gossip
    /// window: charging a chunked program transfer 16 frames per 10 seconds
    /// would make `ProgramChunk` unusable for the thing it exists for.
    #[test]
    fn forwarded_events_are_not_charged_against_the_gossip_window() {
        let limits = PexLimits {
            max_messages_per_window: 1,
            ..PexLimits::default()
        };
        let (router, mut events) = MeshRouter::with_events(PeerBook::new(limits), 64);
        let chunk = wire::encode(&MeshMessage::ProgramChunk {
            program_id: [7u8; 32],
            chunk_index: 0,
            chunk_count: 1,
            bytes: vec![1, 2, 3],
        })
        .expect("encode chunk");

        for _ in 0..8 {
            assert_eq!(router.try_handle_wire_message(2, &chunk), Ok(true));
        }
        assert_eq!(router.counters().rejected(), 0);
        for _ in 0..8 {
            events.try_recv().expect("every chunk was forwarded");
        }
    }

    #[test]
    fn a_flooding_peer_is_rate_limited() {
        let limits = PexLimits {
            max_messages_per_window: 2,
            ..PexLimits::default()
        };
        let router = MeshRouter::pinned_to([key(1), key(2), key(3)], limits);

        assert_eq!(
            router.try_handle_wire_message(7, &announce(1, 9001, 1)),
            Ok(true)
        );
        assert_eq!(
            router.try_handle_wire_message(7, &announce(2, 9002, 1)),
            Ok(true)
        );
        let error = router
            .try_handle_wire_message(7, &announce(3, 9003, 1))
            .expect_err("the third frame inside the window");
        assert!(error.contains("gossip frames"), "{error}");
    }

    #[test]
    fn a_pinned_router_ignores_records_outside_its_roster() {
        let router = MeshRouter::pinned_to([key(1)], PexLimits::default());

        assert_eq!(
            router.try_handle_wire_message(1, &announce(9, 9009, 1)),
            Ok(true)
        );
        assert_eq!(router.counters().learned(), 0);
        assert_eq!(router.counters().ignored_records(), 1);
        assert!(router.dial_targets().is_empty());
    }

    #[test]
    fn a_peer_request_is_queued_and_answered_from_the_book() {
        let router = MeshRouter::new();
        router
            .try_handle_wire_message(1, &announce(1, 9001, 1))
            .expect("announce");

        let request = wire::encode(&MeshMessage::PeerRequest { max_records: 4 })
            .expect("encode a peer request");
        assert_eq!(router.try_handle_wire_message(2, &request), Ok(true));

        let requests = router.take_peer_requests();
        assert_eq!(
            requests,
            vec![PeerRequest {
                sender: 2,
                max_records: 4
            }]
        );
        assert!(
            router.take_peer_requests().is_empty(),
            "taking drains the queue"
        );

        let frame = router
            .peer_book_frame(requests[0])
            .expect("the book has a live record")
            .expect("encode the book frame");
        let decoded = wire::try_decode(&frame)
            .expect("decode the book frame")
            .expect("the frame carries the mesh tag");
        assert_eq!(
            decoded,
            MeshMessage::PeerBook {
                records: vec![PeerRecord::new(&key(1), addr(9001), 1)]
            }
        );
    }

    /// An absurd `max_records` must not let a requester ask for a frame nobody
    /// can encode.
    #[test]
    fn a_peer_request_is_clamped_to_one_frames_worth() {
        let router = MeshRouter::new();
        let request = wire::encode(&MeshMessage::PeerRequest {
            max_records: u32::MAX,
        })
        .expect("encode a peer request");

        router.try_handle_wire_message(2, &request).expect("handle");
        let requests = router.take_peer_requests();
        assert_eq!(
            requests[0].max_records,
            PexLimits::default().max_records_per_message
        );
    }

    #[test]
    fn a_heartbeat_updates_liveness_without_an_event() {
        let (router, mut events) = MeshRouter::with_events(PeerBook::default(), 4);
        let frame = wire::encode(&MeshMessage::Heartbeat {
            seq: 1,
            unix_millis: 1_700_000_000_000,
        })
        .expect("encode heartbeat");

        assert_eq!(router.try_handle_wire_message(3, &frame), Ok(true));
        assert_eq!(router.last_heartbeat(3), Some(1_700_000_000_000));
        assert_eq!(router.last_heartbeat(4), None);
        assert!(events.try_recv().is_err(), "heartbeats are not events");
    }

    /// The frames a later stage owns are handed on verbatim rather than
    /// interpreted here.
    #[test]
    fn the_frames_stage_four_does_not_own_are_forwarded_as_events() {
        let (router, mut events) = MeshRouter::with_events(PeerBook::default(), 8);
        let request = MeshMessage::ProgramRequest {
            program_id: [9u8; 32],
            chunk_index: 3,
        };
        let frame = wire::encode(&request).expect("encode program request");

        assert_eq!(router.try_handle_wire_message(4, &frame), Ok(true));
        assert_eq!(
            events.try_recv().expect("one event"),
            MeshEvent {
                sender: 4,
                message: request
            }
        );
    }

    /// A router installed only to keep control frames off the engine has no
    /// consumer, and must not accumulate one anyway.
    /// Blocker B6, as a structural regression guard.
    ///
    /// The failure this stage has to prevent is *silent*: a receive loop that
    /// never offers its payloads to the mesh router forwards control frames to
    /// the MPC engine, and nothing anywhere reports it — the AVSS loops even
    /// swallow "process failed" errors by name. There is no runtime assertion
    /// that can see all six loops at once, because four of them only exist
    /// inside spawned tasks on live connections, so the invariant is asserted
    /// over the source instead: HoneyBadger has four loops
    /// (accept, `connect_to_peers`, `spawn_receive_loops`,
    /// `spawn_receive_loops_split`) and AVSS has two
    /// (`spawn_message_loops`, `spawn_message_loops_split`).
    #[test]
    fn every_receive_loop_offers_its_payloads_to_the_mesh_router() {
        fn dispatch_sites(source: &str) -> usize {
            // Whitespace-insensitive: two of these calls are line-wrapped by
            // rustfmt, and a formatting change must not silence the guard.
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .matches("mesh_router.try_handle_wire_message_from(")
                .count()
        }

        assert_eq!(
            dispatch_sites(include_str!("../hb_server.rs")),
            4,
            "HoneyBadger has four receive loops; each must consume mesh frames"
        );
        assert_eq!(
            dispatch_sites(include_str!("../avss_server.rs")),
            2,
            "AVSS runs its own loops and does not use spawn_receive_loops_split"
        );
    }

    /// A five-party mesh, simulated over real encoded frames.
    ///
    /// The two properties Stage 4's gossip has to deliver are reachability
    /// (a node that is told about one live party ends up knowing all of them)
    /// and the claim §2 makes about unsigned records ("forged address fails the
    /// cert check", so a lying gossiper costs a wasted dial and nothing more).
    /// Neither is observable from a single router, so this drives a whole mesh:
    /// every exchange goes through `wire::encode` and
    /// `try_handle_wire_message`, and a dial is modelled as succeeding only when
    /// the address in the book is the address its owner actually listens on —
    /// which is what `connect_as_server_with_expected_public_key` enforces for
    /// real.
    mod convergence {
        use super::*;

        /// The roster, as SPKI first bytes. Addresses are `9000 + byte`.
        const ROSTER: [u8; 5] = [1, 2, 3, 4, 5];

        fn port_of(byte: u8) -> u16 {
            9000 + u16::from(byte)
        }

        /// Gossip limits with the rate window widened.
        ///
        /// The fixed-window limiter is covered by
        /// `a_flooding_peer_is_rate_limited`; here it would only make the
        /// number of simulated rounds load-bearing.
        fn sim_limits() -> PexLimits {
            PexLimits {
                max_messages_per_window: 256,
                ..PexLimits::default()
            }
        }

        struct Node {
            byte: u8,
            router: MeshRouter,
        }

        impl Node {
            fn new(byte: u8) -> Self {
                Self {
                    byte,
                    router: MeshRouter::pinned_to(ROSTER.iter().copied().map(key), sim_limits()),
                }
            }

            fn party(&self) -> PartyId {
                usize::from(self.byte)
            }

            fn own_addr(&self) -> SocketAddr {
                addr(port_of(self.byte))
            }

            /// "I am reachable here", with a per-node monotone `seq`.
            fn announcement(&self, seq: u64) -> Vec<u8> {
                MeshRouter::announce(&key(self.byte), self.own_addr(), seq)
                    .expect("encode an announcement")
            }

            /// Everything live this node would answer a `PeerRequest` with.
            fn book_frame(&self) -> Option<Vec<u8>> {
                self.router
                    .peer_book_frame(PeerRequest {
                        sender: self.party(),
                        max_records: MAX_PEER_RECORDS_PER_MESSAGE,
                    })
                    .map(|frame| frame.expect("encode a peer book"))
            }

            /// Roster members this node holds an address for, other than itself.
            fn known_peers(&self) -> BTreeSet<u8> {
                self.router
                    .dial_targets()
                    .into_iter()
                    .filter_map(|(peer, _)| peer.0.first().copied())
                    .filter(|byte| *byte != self.byte)
                    .collect()
            }

            fn address_for(&self, byte: u8) -> Option<SocketAddr> {
                self.router
                    .dial_targets()
                    .into_iter()
                    .find(|(peer, _)| peer.0.first().copied() == Some(byte))
                    .map(|(_, address)| address)
            }

            /// Deliver a frame as the transport would: the sender's party id
            /// *and* the certificate identity its handshake proved.
            fn deliver(&self, from: &Node, frame: &[u8]) -> Result<bool, String> {
                self.router
                    .try_handle_wire_message_from(from.party(), Some(&key(from.byte)), frame)
            }

            fn seed_with(&self, byte: u8, seq: u64) {
                self.router
                    .seed(PeerRecord::new(&key(byte), addr(port_of(byte)), seq));
            }
        }

        /// One honest gossip round.
        ///
        /// Each node contacts every peer whose address it believes it has. A
        /// contact only lands when that address is where the peer really is:
        /// a record naming the right SPKI at the wrong address fails the
        /// pinned handshake, so no bytes are exchanged in either direction.
        fn gossip_round(nodes: &[Node], seq: u64) {
            for node in nodes {
                for (peer_key, address) in node.router.dial_targets() {
                    let Some(byte) = peer_key.0.first().copied() else {
                        continue;
                    };
                    if byte == node.byte {
                        continue;
                    }
                    let Some(peer) = nodes.iter().find(|candidate| candidate.byte == byte) else {
                        continue;
                    };
                    if peer.own_addr() != address {
                        // Wrong address for the right identity: the dial finds
                        // nobody, or finds a certificate that is not the pinned
                        // one. Either way it carries no gossip.
                        continue;
                    }

                    peer.deliver(node, &node.announcement(seq))
                        .expect("an announcement between roster members");
                    if let Some(frame) = node.book_frame() {
                        peer.deliver(node, &frame)
                            .expect("a peer book between roster members");
                    }
                    // The dialer hears back on the same connection.
                    node.deliver(peer, &peer.announcement(seq))
                        .expect("the answering announcement");
                    if let Some(frame) = peer.book_frame() {
                        node.deliver(peer, &frame).expect("the answering peer book");
                    }
                }
            }
        }

        /// What the peer book converges to when it is gossiped: four nodes are
        /// told about one party and nothing else, and every book fills itself in.
        ///
        /// Read this as a property of the **book**, not a promise about
        /// `--peers`. [`crate::net::mesh::join_mesh`] exchanges books inside its
        /// handshake, which runs *after* the connectivity barrier, so a book
        /// this complete is what a *later* join starts from — it is not
        /// available to the dials that have to form the mesh in the first place.
        /// The seed list a first join runs on still has to cover every pair.
        #[test]
        fn the_mesh_converges_from_a_single_seed() {
            let nodes: Vec<Node> = ROSTER.iter().copied().map(Node::new).collect();

            // Every node is given exactly one hint, and it is the same one.
            // Node 1 is given nothing at all: it learns only by being dialed.
            for node in nodes.iter().skip(1) {
                node.seed_with(1, 1);
                assert_eq!(node.known_peers(), BTreeSet::from([1]));
            }
            assert!(nodes[0].known_peers().is_empty());

            for round in 1..=3u64 {
                gossip_round(&nodes, round);
            }

            for node in &nodes {
                let expected: BTreeSet<u8> = ROSTER
                    .iter()
                    .copied()
                    .filter(|byte| *byte != node.byte)
                    .collect();
                assert_eq!(
                    node.known_peers(),
                    expected,
                    "node {} did not converge on the roster",
                    node.byte
                );
                for byte in expected {
                    assert_eq!(
                        node.address_for(byte),
                        Some(addr(port_of(byte))),
                        "node {} holds the wrong address for {byte}",
                        node.byte
                    );
                }
            }
        }

        /// A roster member lies. It gossips an address that is not where party 1
        /// is, with a `seq` no honest announcement can outbid, and an SPKI that
        /// is not in the roster at all.
        ///
        /// The forgery must not be believed — an invented SPKI never enters a
        /// pinned book, and a forged address must not displace the one its owner
        /// announces first-hand — and the honest mesh must still converge around
        /// the liar.
        #[test]
        fn a_forged_gossiped_address_is_rejected_and_the_mesh_still_converges() {
            let honest: Vec<Node> = ROSTER
                .iter()
                .copied()
                .filter(|byte| *byte != 5)
                .map(Node::new)
                .collect();
            let liar = Node::new(5);
            let forged_addr = addr(6661);
            let invented = NodePublicKey(vec![99u8; 32]);

            for node in honest.iter().skip(1) {
                node.seed_with(1, 1);
            }

            let forgery = wire::encode(&MeshMessage::PeerBook {
                records: vec![
                    // The right identity at an address it does not hold, with a
                    // sequence number no honest re-announcement can beat.
                    PeerRecord::new(&key(1), forged_addr, u64::MAX),
                    // An identity that is not in the roster at all.
                    PeerRecord::new(&invented, addr(6699), 7),
                ],
            })
            .expect("encode the forged book");

            // The same lie in first-person form: the liar claims, on its own
            // authenticated connection, to *be* party 1.
            let impersonation = MeshRouter::announce(&key(1), forged_addr, u64::MAX)
                .expect("encode the impersonating announcement");

            for round in 1..=3u64 {
                // The liar reaches everyone every round, before the honest
                // exchange, so a believed forgery would partition the mesh.
                for node in &honest {
                    node.deliver(&liar, &forgery)
                        .expect("a roster member's frame is accepted, its content is not");
                    let refused = node
                        .deliver(&liar, &impersonation)
                        .expect_err("announcing another party's key is refused outright");
                    assert!(refused.contains("certificate proved"), "{refused}");
                }
                gossip_round(&honest, round);
            }

            for node in &honest {
                assert!(
                    !node
                        .router
                        .dial_targets()
                        .iter()
                        .any(|(peer, _)| *peer == invented),
                    "node {} admitted an SPKI outside the roster",
                    node.byte
                );
                assert!(
                    node.router.counters().ignored_records() > 0,
                    "node {} never refused any forged record",
                    node.byte
                );

                if node.byte != 1 {
                    assert_eq!(
                        node.address_for(1),
                        Some(addr(port_of(1))),
                        "node {} believed the forged address for party 1",
                        node.byte
                    );
                }

                let expected: BTreeSet<u8> = ROSTER
                    .iter()
                    .copied()
                    .filter(|byte| *byte != node.byte && *byte != 5)
                    .collect();
                assert!(
                    expected.is_subset(&node.known_peers()),
                    "node {} did not converge on the honest roster: {:?}",
                    node.byte,
                    node.known_peers()
                );
            }
        }
    }

    #[test]
    fn events_are_dropped_with_a_counter_when_nothing_drains_them() {
        let router = MeshRouter::new();
        let frame = wire::encode(&MeshMessage::JoinCommit {
            proposal_digest: [1u8; 32],
            instance_id: 5,
        })
        .expect("encode a commit");

        assert_eq!(router.try_handle_wire_message(1, &frame), Ok(true));
        assert_eq!(router.counters().events_dropped(), 1);
    }
}
