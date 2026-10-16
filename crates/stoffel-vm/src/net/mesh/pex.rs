//! Peer exchange: addresses as gossip, not as a secret.
//!
//! `docs/design/bootnode-elimination.md` §2, row "Peer address directory".
//! stoffelnet's accept path rejects an unknown inbound server peer unless a
//! certificate allowlist is configured, so something has to establish peer
//! identities before any address is useful.
//! [`crate::net::roster::Roster`] installs that allowlist from the
//! coordinator's node certificates, which leaves addresses carrying no
//! authority at all — and that is what makes them ordinary gossip.
//!
//! # Why an unsigned record is sound
//!
//! A [`PeerRecord`] carries no signature, and does not need one, because it is
//! never believed. Every dial made from this book goes through
//! `connect_as_server_with_expected_public_key` (stoffelnet `quic.rs:2162`),
//! which closes the connection when the certificate the far end presents is not
//! the SPKI the record named. A forged address therefore fails closed at the
//! TLS handshake, so believing one *costs* a dial. Signing records would
//! authenticate a claim whose only consumer already authenticates it
//! end-to-end.
//!
//! # Why "a wasted dial" is not the whole story
//!
//! Failing closed bounds what a forged address *achieves*, not what it
//! *displaces*. A book that ranked records by `seq` alone would let one roster
//! member relay another party's SPKI at a dead address with `seq: u64::MAX`,
//! which no honest re-announcement can ever outbid — the victim is then
//! undialable in every other node's book until the liar stops talking, which is
//! a partition, not a wasted dial. Three bounds close that, and they are the
//! reason this module is more than a map:
//!
//! * [`RecordSource`] ranks *how* a record arrived. A record only replaces an
//!   entry held from an equally or less trusted source, so a relayed claim
//!   cannot overwrite what this node verified for itself, nor what it
//!   configured.
//! * [`MAX_PEX_SEQ_JUMP`] bounds how far a relayed record may advance a counter
//!   in one step.
//! * A book built with [`PeerBook::pinned_to`] refuses any SPKI outside the
//!   roster outright, which is every SPKI that was not going to be dialed
//!   anyway, and the per-frame record cap lives in
//!   [`crate::net::mesh::wire`] where the frame is decoded.
//!
//! With those in place the original claim holds again: a lying peer costs a
//! wasted dial, and nothing it says survives contact with the party it lied
//! about.
//!
//! # Why entries expire
//!
//! A record is a liveness hint with no revocation. Without a TTL the book would
//! accumulate every address every party has ever advertised, and a reconnect
//! supervisor walking it would keep dialing hosts that are long gone.
//! [`PeerBook::expire`] drops what has not been refreshed within
//! [`PexLimits::ttl`].

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NodePublicKey;

use crate::net::mesh::wire::MAX_PEER_RECORDS_PER_MESSAGE;

/// How long an unrefreshed record stays in the book.
pub const DEFAULT_PEX_TTL: Duration = Duration::from_secs(300);

/// Distinct peers one book will hold.
///
/// Far above any roster, because the book is also allowed to carry peers this
/// node has not been told about yet; it exists to bound memory, not membership.
pub const DEFAULT_PEX_MAX_PEERS: usize = 1024;

/// How far one relayed record may advance a peer's counter in a single step.
///
/// `seq` is chosen by whoever writes the record, so an unbounded comparison
/// lets a liar claim `u64::MAX` once and win every future comparison forever.
/// Relayed records are the only ones this applies to (see [`RecordSource`]), and
/// the bound turns "permanently unbeatable" into "a few thousand steps ahead",
/// which a first-hand observation overtakes by outranking it rather than by
/// counting past it.
pub const MAX_PEX_SEQ_JUMP: u64 = 4096;

/// One node's claim about where it can be reached.
///
/// `spki` is the DER `SubjectPublicKeyInfo` stoffelnet authorizes against —
/// `cert.public_key().raw`, not the bare BIT STRING (blocker B2) — carried as
/// bytes because [`NodePublicKey`] is not `Serialize`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerRecord {
    pub spki: Vec<u8>,
    pub advertise_addr: SocketAddr,
    /// The announcer's own monotone counter.
    ///
    /// Only orders records of equal [`RecordSource`], and only at
    /// [`RecordSource::Relayed`] — see [`PeerBook::observe`].
    pub seq: u64,
}

impl PeerRecord {
    pub fn new(public_key: &NodePublicKey, advertise_addr: SocketAddr, seq: u64) -> Self {
        Self {
            spki: public_key.0.clone(),
            advertise_addr,
            seq,
        }
    }

    /// The identity a dial must pin to when it uses this record's address.
    pub fn public_key(&self) -> NodePublicKey {
        NodePublicKey(self.spki.clone())
    }
}

/// The bounds one book enforces on what it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PexLimits {
    pub max_records_per_message: usize,
    pub ttl: Duration,
    pub max_peers: usize,
}

impl Default for PexLimits {
    fn default() -> Self {
        Self {
            max_records_per_message: MAX_PEER_RECORDS_PER_MESSAGE,
            ttl: DEFAULT_PEX_TTL,
            max_peers: DEFAULT_PEX_MAX_PEERS,
        }
    }
}

/// How this node came to hold a record, least trusted first.
///
/// Gossip carries no signature (see the module header), so the only thing that
/// distinguishes a true address from an invented one is *who established it and
/// how*. A relayed record — one that reached this node inside somebody else's
/// [`crate::net::mesh::wire::MeshMessage::PeerBook`] — is a third-hand claim,
/// and must never be able to overwrite what this node configured or verified
/// itself. Without this ordering one Byzantine roster member relaying
/// `seq: u64::MAX` for another party's SPKI pins that party's address to a dead
/// host in every honest book *permanently*.
///
/// Derived `Ord` follows declaration order, so `Relayed < Verified < Local`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordSource {
    /// Seen inside another peer's peer-book frame. Third-hand by construction,
    /// so it may fill a gap the book has but never displace a first-hand entry,
    /// and `seq` may only advance it by [`MAX_PEX_SEQ_JUMP`] at a time.
    Relayed,
    /// This node dialed the address and the certificate at the far end proved
    /// who answered.
    ///
    /// First-hand, and more directly than any frame could be: this node chose
    /// the address, and `PeerConnection::authenticated_peer_public_key`
    /// (stoffelnet `quic.rs:147`) is the exact DER `SubjectPublicKeyInfo` the
    /// peer proved possession of. Not [`Self::Local`], because an address
    /// discovered at run time is exactly the thing a later first-hand
    /// observation *should* be able to move.
    Verified,
    /// Configured locally — `--peers`, this node's own listen address, or
    /// anything it knew before it spoke to anyone. Relayed claims never
    /// override it.
    Local,
}

/// What one record did to the book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PexOutcome {
    /// A peer the book had never heard of.
    Learned,
    /// A peer already in the book, moved or re-stamped by a record the book
    /// was willing to believe.
    Refreshed,
    /// A relayed record at or below the `seq` the book already holds.
    Stale,
    /// The book holds this peer from a more trusted source than this record's.
    Outranked,
    /// A relayed record whose `seq` jumps more than [`MAX_PEX_SEQ_JUMP`] past
    /// what the book holds — the `u64::MAX` brick, refused.
    SeqJumpTooLarge,
    /// The book is pinned to a roster and this SPKI is not in it.
    NotAdmissible,
    /// The book is at [`PexLimits::max_peers`] and this is a new peer.
    Full,
}

#[derive(Debug, Clone)]
struct BookEntry {
    record: PeerRecord,
    refreshed_at: Instant,
    source: RecordSource,
}

/// What this node knows about where its peers are.
///
/// Not authoritative about *membership* — that is the roster — and not
/// authoritative about addresses either, since every address it hands out is
/// re-checked by the TLS handshake of the dial that uses it.
#[derive(Debug)]
pub struct PeerBook {
    limits: PexLimits,
    /// `Some` pins the book to a roster: an SPKI outside it is
    /// [`PexOutcome::NotAdmissible`].
    admissible: Option<BTreeSet<Vec<u8>>>,
    entries: HashMap<Vec<u8>, BookEntry>,
}

impl Default for PeerBook {
    fn default() -> Self {
        Self::new(PexLimits::default())
    }
}

impl PeerBook {
    /// A book that will learn about any peer.
    pub fn new(limits: PexLimits) -> Self {
        Self {
            limits,
            admissible: None,
            entries: HashMap::new(),
        }
    }

    /// A book that will only learn about the given SPKIs.
    ///
    /// Under the coordinator's node roster this is the whole admissible set, so
    /// a flood of invented SPKIs costs one set lookup each and nothing else.
    pub fn pinned_to<I>(keys: I, limits: PexLimits) -> Self
    where
        I: IntoIterator<Item = NodePublicKey>,
    {
        Self {
            limits,
            admissible: Some(keys.into_iter().map(|key| key.0).collect()),
            entries: HashMap::new(),
        }
    }

    pub fn limits(&self) -> PexLimits {
        self.limits
    }

    /// Whether this book refuses SPKIs outside a fixed admissible set.
    pub fn is_pinned(&self) -> bool {
        self.admissible.is_some()
    }

    /// Fold one record into the book.
    ///
    /// `source` decides what `seq` cannot: `seq` is chosen by whoever wrote the
    /// record, so a liar picks `u64::MAX` and wins every comparison forever.
    /// The three rules, in order:
    ///
    /// 1. **Rank first.** A record may only replace an entry held from an
    ///    equally or less trusted source ([`RecordSource`]), so no relayed
    ///    claim displaces what this node verified or configured.
    /// 2. **A first-hand statement always applies.** At equal rank, a
    ///    [`RecordSource::Verified`] or [`RecordSource::Local`] record replaces
    ///    what is held without consulting `seq`, because this node established
    ///    it and it is therefore current by construction. This is also what
    ///    refreshes the TTL on an unchanged re-observation.
    /// 3. **A relay may fill a gap, not overwrite one.** At equal rank a
    ///    [`RecordSource::Relayed`] record must beat the stored `seq`, and by no
    ///    more than [`MAX_PEX_SEQ_JUMP`].
    pub fn observe(
        &mut self,
        record: PeerRecord,
        source: RecordSource,
        now: Instant,
    ) -> PexOutcome {
        if let Some(admissible) = &self.admissible {
            if !admissible.contains(&record.spki) {
                return PexOutcome::NotAdmissible;
            }
        }

        match self.entries.get_mut(&record.spki) {
            Some(entry) => {
                if source < entry.source {
                    return PexOutcome::Outranked;
                }
                if source == entry.source && source == RecordSource::Relayed {
                    if record.seq <= entry.record.seq {
                        return PexOutcome::Stale;
                    }
                    if record.seq > entry.record.seq.saturating_add(MAX_PEX_SEQ_JUMP) {
                        return PexOutcome::SeqJumpTooLarge;
                    }
                }
                entry.record = record;
                entry.refreshed_at = now;
                entry.source = source;
                PexOutcome::Refreshed
            }
            None => {
                if self.entries.len() >= self.limits.max_peers {
                    return PexOutcome::Full;
                }
                self.entries.insert(
                    record.spki.clone(),
                    BookEntry {
                        record,
                        refreshed_at: now,
                        source,
                    },
                );
                PexOutcome::Learned
            }
        }
    }

    /// How this node came to hold its record for `key`, if it holds one.
    pub fn source_of(&self, key: &NodePublicKey) -> Option<RecordSource> {
        self.entries.get(&key.0).map(|entry| entry.source)
    }

    /// Drop everything not refreshed within the TTL. Returns how many went.
    pub fn expire(&mut self, now: Instant) -> usize {
        let ttl = self.limits.ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.duration_since(entry.refreshed_at) < ttl);
        before - self.entries.len()
    }

    /// Live records, in SPKI order so two nodes offering the same book offer it
    /// the same way.
    ///
    /// `max` is clamped to [`PexLimits::max_records_per_message`] so a snapshot
    /// can always be encoded as one frame.
    pub fn snapshot(&self, max: usize, now: Instant) -> Vec<PeerRecord> {
        let ttl = self.limits.ttl;
        let mut live: Vec<PeerRecord> = self
            .entries
            .values()
            .filter(|entry| now.duration_since(entry.refreshed_at) < ttl)
            .map(|entry| entry.record.clone())
            .collect();
        live.sort_by(|left, right| left.spki.cmp(&right.spki));
        live.truncate(max.min(self.limits.max_records_per_message));
        live
    }

    /// Live `(identity, address)` pairs, for a dialer that pins both.
    ///
    /// Every live entry, in SPKI order — deliberately *not* routed through
    /// [`PeerBook::snapshot`]. That clamp exists so a book fits in one
    /// [`crate::net::mesh::wire::MeshMessage::PeerBook`] frame
    /// ([`MAX_PEER_RECORDS_PER_MESSAGE`]); applying it here would silently hand
    /// a dialer a deterministic 64-entry prefix of a larger book and leave the
    /// tail of the mesh permanently unreconnected. A wire bound is not a
    /// local-iteration bound.
    pub fn dial_targets(&self, now: Instant) -> Vec<(NodePublicKey, SocketAddr)> {
        let ttl = self.limits.ttl;
        let mut targets: Vec<(NodePublicKey, SocketAddr)> = self
            .entries
            .values()
            .filter(|entry| now.duration_since(entry.refreshed_at) < ttl)
            .map(|entry| (entry.record.public_key(), entry.record.advertise_addr))
            .collect();
        targets.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        targets
    }

    /// The live address for one identity, if the book has one.
    pub fn address_of(&self, key: &NodePublicKey, now: Instant) -> Option<SocketAddr> {
        self.entries.get(&key.0).and_then(|entry| {
            (now.duration_since(entry.refreshed_at) < self.limits.ttl)
                .then_some(entry.record.advertise_addr)
        })
    }

    /// Records held, expired or not.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The peer book as the join and the reconnect supervisor share it.
///
/// A handle rather than a router: on `dev` there is no post-join mesh control
/// plane to route (see [`crate::net::mesh::wire`]), so the only thing shared
/// between the join that fills this book and the supervisor that dials out of
/// it is the book itself.
#[derive(Debug, Clone, Default)]
pub struct PeerDirectory {
    book: Arc<Mutex<PeerBook>>,
}

impl PeerDirectory {
    /// A directory that will learn about any peer.
    pub fn new() -> Self {
        Self {
            book: Arc::new(Mutex::new(PeerBook::default())),
        }
    }

    /// A directory pinned to the roster's SPKIs, which is the default
    /// deployment.
    pub fn pinned_to<I>(keys: I, limits: PexLimits) -> Self
    where
        I: IntoIterator<Item = NodePublicKey>,
    {
        Self {
            book: Arc::new(Mutex::new(PeerBook::pinned_to(keys, limits))),
        }
    }

    /// Whether this directory refuses SPKIs outside a fixed set.
    pub fn is_pinned(&self) -> bool {
        self.book.lock().is_pinned()
    }

    /// Record something this node configured. Relayed claims never override it.
    pub fn seed(&self, record: PeerRecord) -> PexOutcome {
        self.book
            .lock()
            .observe(record, RecordSource::Local, Instant::now())
    }

    /// Record a peer whose identity *this node* verified by dialing it.
    pub fn observe_verified(&self, record: PeerRecord) -> PexOutcome {
        self.book
            .lock()
            .observe(record, RecordSource::Verified, Instant::now())
    }

    /// Record something a peer relayed about a third party: it may fill a gap,
    /// and it can never displace a first-hand entry.
    pub fn observe_relayed(&self, record: PeerRecord) -> PexOutcome {
        self.book
            .lock()
            .observe(record, RecordSource::Relayed, Instant::now())
    }

    /// Live `(identity, address)` pairs a dialer can aim at.
    pub fn dial_targets(&self) -> Vec<(NodePublicKey, SocketAddr)> {
        self.book.lock().dial_targets(Instant::now())
    }

    /// A bounded, live snapshot, for a caller about to put it on the wire.
    pub fn snapshot(&self, max: usize) -> Vec<PeerRecord> {
        self.book.lock().snapshot(max, Instant::now())
    }

    /// How this node came to hold its record for `key`.
    pub fn source_of(&self, key: &NodePublicKey) -> Option<RecordSource> {
        self.book.lock().source_of(key)
    }

    /// Drop entries past their TTL. Returns how many went.
    pub fn expire(&self) -> usize {
        self.book.lock().expire(Instant::now())
    }

    /// Records held, expired or not.
    pub fn len(&self) -> usize {
        self.book.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.book.lock().is_empty()
    }
}

/// The addresses `--peers` supplied, as hints and nothing more.
///
/// Seed hints are deliberately not membership: membership is the roster, and
/// every dial made from a hint pins a roster certificate, so a wrong or hostile
/// address costs one failed handshake. Self is dropped and duplicates collapse,
/// both because a compose file that lists every party to every party is the
/// common case and a node dialing itself is a wasted connection with a
/// confusing log line.
///
/// A **missing** hint is not equally cheap, and this is the part that is easy to
/// get backwards. A first mesh forms out of dials alone:
/// [`crate::net::mesh::join_mesh`] exchanges peer books inside its handshake,
/// which runs *after* the connectivity barrier, so a relayed record cannot
/// supply an address the mesh needs in order to form — it is what a *later*
/// join starts from. The requirement on a first join is per pair, and
/// directional: for any two parties, the one whose transport-derived id is
/// higher must hold a hint for the other (see
/// `crate::net::mesh::join::dials_towards`). Listing all `n - 1` peers
/// everywhere always satisfies it; a shorter list is accepted and warned about,
/// not rejected, because the edges it leaves out may be covered from the other
/// side.
///
/// An address on its own cannot be entered in a [`PeerBook`] — a record needs
/// the SPKI to pin the dial to, and that is only known once a handshake has
/// happened, which is why these stay a plain address list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedHints {
    addrs: Vec<SocketAddr>,
}

impl SeedHints {
    /// Build hints from `--peers`, dropping `own` and any repeat.
    ///
    /// Order is preserved: the first hint that answers is the fastest path into
    /// the mesh, and operators put the most reliable party first.
    pub fn new<I>(hints: I, own: Option<SocketAddr>) -> Self
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut seen = BTreeSet::new();
        let addrs = hints
            .into_iter()
            .filter(|addr| Some(*addr) != own)
            .filter(|addr| seen.insert(*addr))
            .collect();
        Self { addrs }
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> NodePublicKey {
        NodePublicKey(vec![byte; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}")
            .parse()
            .expect("parse loopback address")
    }

    fn record(byte: u8, port: u16, seq: u64) -> PeerRecord {
        PeerRecord::new(&key(byte), addr(port), seq)
    }

    /// The `u64::MAX` brick: a relayed record cannot pin an honest party's
    /// address out of reach, because a relay may only advance a counter by
    /// [`MAX_PEX_SEQ_JUMP`] at a time.
    #[test]
    fn a_relayed_record_cannot_jump_a_counter_arbitrarily_far() {
        let mut book = PeerBook::default();
        let now = Instant::now();

        assert_eq!(
            book.observe(record(1, 9001, 1), RecordSource::Relayed, now),
            PexOutcome::Learned
        );
        assert_eq!(
            book.observe(record(1, 9999, u64::MAX), RecordSource::Relayed, now),
            PexOutcome::SeqJumpTooLarge
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9001)));
    }

    /// Rank is consulted before `seq`, so no relayed claim displaces what this
    /// node verified for itself whatever counter it carries.
    #[test]
    fn a_relayed_record_never_displaces_a_first_hand_entry() {
        let mut book = PeerBook::default();
        let now = Instant::now();

        book.observe(record(1, 9001, 0), RecordSource::Verified, now);
        assert_eq!(
            book.observe(record(1, 9999, u64::MAX), RecordSource::Relayed, now),
            PexOutcome::Outranked
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9001)));

        book.observe(record(1, 9002, 0), RecordSource::Local, now);
        assert_eq!(
            book.observe(record(1, 9003, 7), RecordSource::Verified, now),
            PexOutcome::Outranked
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9002)));
    }

    /// A first-hand observation replaces what is held without consulting `seq`,
    /// which is what lets a node that restarted advertise again immediately.
    #[test]
    fn a_first_hand_record_applies_without_beating_a_counter() {
        let mut book = PeerBook::default();
        let now = Instant::now();

        book.observe(record(1, 9001, 500), RecordSource::Verified, now);
        assert_eq!(
            book.observe(record(1, 9002, 0), RecordSource::Verified, now),
            PexOutcome::Refreshed
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9002)));
    }

    /// A pinned book is the whole defence against an invented identity: the
    /// roster says who exists, so an SPKI outside it is refused on one lookup.
    #[test]
    fn a_pinned_book_refuses_an_identity_outside_the_roster() {
        let mut book = PeerBook::pinned_to(vec![key(1)], PexLimits::default());
        let now = Instant::now();

        assert!(book.is_pinned());
        assert_eq!(
            book.observe(record(1, 9001, 0), RecordSource::Relayed, now),
            PexOutcome::Learned
        );
        assert_eq!(
            book.observe(record(2, 9002, 0), RecordSource::Relayed, now),
            PexOutcome::NotAdmissible
        );
        assert_eq!(book.len(), 1);
    }

    /// `dial_targets` must not inherit the wire frame's record cap, or the tail
    /// of a book larger than one frame would never be dialed.
    #[test]
    fn dial_targets_are_not_clamped_to_one_frame() {
        let mut book = PeerBook::default();
        let now = Instant::now();
        let over = MAX_PEER_RECORDS_PER_MESSAGE + 5;

        for index in 0..over {
            let identity = NodePublicKey(index.to_le_bytes().to_vec());
            book.observe(
                PeerRecord::new(&identity, addr(9000 + index as u16), 0),
                RecordSource::Verified,
                now,
            );
        }

        assert_eq!(book.dial_targets(now).len(), over);
        assert_eq!(
            book.snapshot(usize::MAX, now).len(),
            MAX_PEER_RECORDS_PER_MESSAGE
        );
    }

    #[test]
    fn entries_expire_and_stop_being_offered() {
        let limits = PexLimits {
            ttl: Duration::from_millis(1),
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);
        let now = Instant::now();

        book.observe(record(1, 9001, 0), RecordSource::Verified, now);
        let later = now + Duration::from_millis(5);

        assert!(book.snapshot(8, later).is_empty());
        assert_eq!(book.address_of(&key(1), later), None);
        assert_eq!(book.expire(later), 1);
        assert!(book.is_empty());
    }

    #[test]
    fn the_book_is_bounded_by_max_peers() {
        let limits = PexLimits {
            max_peers: 1,
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);
        let now = Instant::now();

        book.observe(record(1, 9001, 0), RecordSource::Verified, now);
        assert_eq!(
            book.observe(record(2, 9002, 0), RecordSource::Verified, now),
            PexOutcome::Full
        );
    }

    /// The directory is a shared handle: what the join folds in is what the
    /// reconnect supervisor dials.
    #[test]
    fn a_directory_shares_one_book_across_clones() {
        let directory = PeerDirectory::pinned_to(vec![key(1)], PexLimits::default());
        let other = directory.clone();

        assert_eq!(directory.seed(record(1, 9001, 0)), PexOutcome::Learned);
        assert_eq!(other.dial_targets(), vec![(key(1), addr(9001))]);
        assert_eq!(other.source_of(&key(1)), Some(RecordSource::Local));
    }

    #[test]
    fn seed_hints_drop_self_and_duplicates_and_keep_order() {
        let hints = SeedHints::new(
            vec![addr(9003), addr(9001), addr(9003), addr(9002)],
            Some(addr(9002)),
        );

        assert_eq!(hints.addrs(), &[addr(9003), addr(9001)]);
        assert_eq!(hints.len(), 2);
    }
}
