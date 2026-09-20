//! Peer exchange: addresses as gossip, not as a secret.
//!
//! Stage 4 of `docs/design/bootnode-elimination.md` (§2, row "Peer address
//! directory"). The bootnode's directory existed because stoffelnet's accept
//! path rejects an unknown inbound server peer unless a certificate allowlist
//! is configured, so somebody had to relay identities. Stage 3 installed that
//! allowlist ([`crate::net::mesh::roster::Roster`]), and this module is what the
//! relay collapses into once it is in place.
//!
//! # Why an unsigned record is sound
//!
//! A [`PeerRecord`] carries no signature, and does not need one, because it is
//! never believed. Every dial made from this book goes through
//! `connect_as_server_with_expected_public_key` (stoffelnet `quic.rs:2162`),
//! which closes the connection when the certificate the far end presents is not
//! the SPKI the record named. A forged address therefore fails closed at the TLS
//! handshake, so believing one *costs* a dial. Signing records would
//! authenticate a claim whose only consumer already authenticates it end-to-end.
//!
//! # Why "a wasted dial" is not the whole story
//!
//! Failing closed bounds what a forged address *achieves*, not what it
//! *displaces*. A book that ranked records by `seq` alone would let one roster
//! member gossip another party's SPKI at a dead address with `seq: u64::MAX`,
//! which no honest re-announcement can ever outbid — the victim is then
//! undialable in every other node's book until the liar stops talking, which is
//! a partition, not a wasted dial. Three bounds close that, and they are the
//! reason this module is more than a map:
//!
//! * [`RecordSource`] ranks *how* a record arrived. A record only replaces an
//!   entry held from an equally or less trusted source, so gossip cannot
//!   overwrite what a peer said about itself over its own authenticated
//!   connection, nor what the operator configured.
//! * [`MAX_PEX_SEQ_JUMP`] bounds how far a relayed record may advance a
//!   counter in one step — the same shape as blocker B5's bound on the join
//!   epoch, for the same reason.
//! * [`PeerBook::admit`] rate-limits per sender and caps records per frame, and
//!   a book built with [`PeerBook::pinned_to`] refuses any SPKI outside the
//!   roster outright, which under the default static roster is every SPKI that
//!   was not going to be dialed anyway.
//!
//! With those in place the original claim holds again: a lying gossiper costs a
//! wasted dial, and nothing it says survives contact with the party it lied
//! about.
//!
//! # Why entries expire
//!
//! A record is a liveness hint with no revocation. Without a TTL the book would
//! accumulate every address every party has ever advertised, and a reconnect
//! supervisor walking it would keep dialing hosts that are years gone.
//! [`PeerBook::expire`] drops what has not been refreshed within
//! [`PexLimits::ttl`]; a live peer re-announces well inside it.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{NodePublicKey, PartyId};

use crate::net::mesh::wire::MAX_PEER_RECORDS_PER_MESSAGE;

/// How long an unrefreshed record stays in the book.
pub const DEFAULT_PEX_TTL: Duration = Duration::from_secs(300);

/// Length of the rate-limiter's fixed window.
pub const DEFAULT_PEX_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Gossip frames one sender may deliver per window.
pub const DEFAULT_PEX_MESSAGES_PER_WINDOW: u32 = 16;

/// Distinct peers one book will hold.
///
/// Far above any roster, because the book is also allowed to carry peers this
/// node has not been told about yet; it exists to bound memory, not membership.
pub const DEFAULT_PEX_MAX_PEERS: usize = 1024;

/// How far one relayed record may advance a peer's counter in a single step.
///
/// The same shape as blocker B5's bound on the join epoch, and for the same
/// reason: `seq` is chosen by whoever writes the record, so an unbounded
/// comparison lets a liar claim `u64::MAX` once and win every future
/// comparison forever. Relayed records are the only ones this applies to (see
/// [`RecordSource`]), and the bound turns "permanently unbeatable" into "a few
/// thousand steps ahead", which an honest announcement overtakes by outranking
/// it rather than by counting past it.
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
    /// [`RecordSource::Relayed`] — see [`PeerBook::observe`]. It is written by
    /// whoever wrote the record, so it can never be the thing that decides a
    /// contest between a peer and someone lying about it.
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
    pub max_messages_per_window: u32,
    pub window: Duration,
    pub ttl: Duration,
    pub max_peers: usize,
}

impl Default for PexLimits {
    fn default() -> Self {
        Self {
            max_records_per_message: MAX_PEER_RECORDS_PER_MESSAGE,
            max_messages_per_window: DEFAULT_PEX_MESSAGES_PER_WINDOW,
            window: DEFAULT_PEX_RATE_WINDOW,
            ttl: DEFAULT_PEX_TTL,
            max_peers: DEFAULT_PEX_MAX_PEERS,
        }
    }
}

/// Why a whole gossip frame was refused before any of its records were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PexRejection {
    #[error("peer {sender} sent {seen} gossip frames within {window:?} (max {max})")]
    RateLimited {
        sender: PartyId,
        seen: u32,
        max: u32,
        window: Duration,
    },
    #[error("gossip frame from peer {sender} carries {count} records (max {max})")]
    TooManyRecords {
        sender: PartyId,
        count: usize,
        max: usize,
    },
}

/// How this node came to hold a record, least trusted first.
///
/// Gossip carries no signature (see the module header), so the only thing that
/// distinguishes a true address from an invented one is *who said it and how*.
/// A relayed record — one that reached this node inside somebody else's
/// [`crate::net::mesh::wire::MeshMessage::PeerBook`] — is a third-hand claim,
/// and must never be able to overwrite what the operator configured or what the
/// peer said about itself. Without this ordering one Byzantine roster member
/// gossiping `seq: u64::MAX` for another party's SPKI pins that party's address
/// to a dead host in every honest book *permanently*, because no honest
/// announcement can ever outbid `u64::MAX` — which partitions an honest node
/// out of the mesh rather than merely costing a wasted dial.
///
/// Derived `Ord` follows declaration order, so `Relayed < Announced < Local`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordSource {
    /// Seen inside another peer's peer-book answer, or announced on a
    /// connection whose certificate identity the transport could not report.
    ///
    /// Third-hand by construction, so it may fill a gap the book has but never
    /// displace a first-hand entry, and `seq` may only advance it by
    /// [`MAX_PEX_SEQ_JUMP`] at a time.
    Relayed,
    /// Carried by a [`crate::net::mesh::wire::MeshMessage::PeerAnnounce`] on
    /// the announcer's *own* TLS-authenticated connection, with
    /// [`PeerRecord::spki`] equal to the certificate that handshake proved.
    ///
    /// That binding is what makes this rank meaningful:
    /// `PeerConnection::authenticated_peer_public_key` (stoffelnet
    /// `quic.rs:147`) is the exact DER `SubjectPublicKeyInfo` the peer proved
    /// possession of, so an `Announced` record is a statement a peer can only
    /// make about *itself*. A frame announcing somebody else's SPKI is refused
    /// by [`crate::net::mesh::MeshRouter`] before it reaches the book, and a
    /// connection that reports no certificate produces [`Self::Relayed`]
    /// instead of this rank.
    Announced,
    /// Configured locally — `--peers`, the roster, or anything this node knew
    /// before it spoke to anyone. Gossip never overrides it.
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
    /// A relayed record at or below the `seq` the book already holds, or a
    /// relayed record offered against an entry a relay may not displace.
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

/// A sender's fixed-window frame count.
#[derive(Debug, Clone, Copy)]
struct Quota {
    window_start: Instant,
    frames: u32,
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
    quotas: HashMap<PartyId, Quota>,
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
            quotas: HashMap::new(),
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
            quotas: HashMap::new(),
        }
    }

    pub fn limits(&self) -> PexLimits {
        self.limits
    }

    /// Whether this book is pinned to a fixed admissible set.
    pub fn is_pinned(&self) -> bool {
        self.admissible.is_some()
    }

    /// Charge one gossip frame carrying `records` records against `sender`.
    ///
    /// Called once per frame, *before* its records are read, so that a refused
    /// frame costs the receiver one map lookup rather than `records` of them.
    pub fn admit(
        &mut self,
        sender: PartyId,
        records: usize,
        now: Instant,
    ) -> Result<(), PexRejection> {
        if records > self.limits.max_records_per_message {
            return Err(PexRejection::TooManyRecords {
                sender,
                count: records,
                max: self.limits.max_records_per_message,
            });
        }

        let window = self.limits.window;
        let max = self.limits.max_messages_per_window;
        let quota = self.quotas.entry(sender).or_insert(Quota {
            window_start: now,
            frames: 0,
        });
        if now.duration_since(quota.window_start) >= window {
            quota.window_start = now;
            quota.frames = 0;
        }
        if quota.frames >= max {
            return Err(PexRejection::RateLimited {
                sender,
                seen: quota.frames,
                max,
                window,
            });
        }
        quota.frames += 1;
        Ok(())
    }

    /// Fold one record into the book.
    ///
    /// `source` decides what `seq` cannot: `seq` is chosen by whoever wrote the
    /// record, so a liar picks `u64::MAX` and wins every comparison forever. The
    /// three rules, in order:
    ///
    /// 1. **Rank first.** A record may only replace an entry held from an
    ///    equally or less trusted source ([`RecordSource`]), so no amount of
    ///    gossip displaces what a peer said about itself or what the operator
    ///    configured.
    /// 2. **A first-party statement always applies.** At equal rank, an
    ///    [`RecordSource::Announced`] or [`RecordSource::Local`] record replaces
    ///    what is held without consulting `seq`, because it arrived on the
    ///    announcer's own authenticated connection (or from this node's own
    ///    configuration) and is therefore current by construction. This is also
    ///    what refreshes the TTL on an unchanged re-announcement, and what lets
    ///    a node whose counter reset across a restart advertise again
    ///    immediately instead of waiting out [`PexLimits::ttl`].
    /// 3. **A relay may fill a gap, not overwrite one.** At equal rank a
    ///    [`RecordSource::Relayed`] record must beat the stored `seq`, and by no
    ///    more than [`MAX_PEX_SEQ_JUMP`], which is what stops one member from
    ///    claiming `u64::MAX` for somebody else's SPKI and pinning it there.
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

    /// Live records, in SPKI order so two nodes answering the same
    /// [`crate::net::mesh::wire::MeshMessage::PeerRequest`] answer the same way.
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
    /// [`PeerBook::snapshot`]. That clamp exists so a gossip answer fits in one
    /// [`crate::net::mesh::wire::MeshMessage::PeerBook`] frame
    /// ([`MAX_PEER_RECORDS_PER_MESSAGE`], 64); applying it here would silently
    /// hand a dialer the same deterministic 64-entry prefix of a larger book
    /// and leave the tail of the mesh permanently unreconnected. A wire bound
    /// is not a local-iteration bound.
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
/// which runs *after* the connectivity barrier, so gossip cannot supply an
/// address the mesh needs in order to form — it is what a *later* join starts
/// from. The requirement on a first join is per pair: for any two parties, at
/// least one of them must hold a hint for the other. Listing all `n - 1` peers
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

    #[test]
    fn a_new_peer_is_learned_and_a_higher_seq_refreshes_it() {
        let now = Instant::now();
        let mut book = PeerBook::default();

        assert_eq!(
            book.observe(record(1, 9000, 1), RecordSource::Relayed, now),
            PexOutcome::Learned
        );
        assert_eq!(
            book.observe(record(1, 9001, 2), RecordSource::Relayed, now),
            PexOutcome::Refreshed
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9001)));
        assert_eq!(book.len(), 1);
    }

    /// `seq` is the announcer's own counter, so a replayed frame must not move
    /// a peer's address backwards.
    #[test]
    fn a_replayed_or_equal_seq_does_not_move_the_address() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        book.observe(record(1, 9001, 5), RecordSource::Relayed, now);

        assert_eq!(
            book.observe(record(1, 9002, 5), RecordSource::Relayed, now),
            PexOutcome::Stale
        );
        assert_eq!(
            book.observe(record(1, 9002, 4), RecordSource::Relayed, now),
            PexOutcome::Stale
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9001)));
    }

    /// Under the default static roster, an invented SPKI is not merely
    /// undialable — it must not consume a book slot at all.
    #[test]
    fn a_pinned_book_refuses_an_spki_outside_the_roster() {
        let now = Instant::now();
        let mut book = PeerBook::pinned_to([key(1), key(2)], PexLimits::default());

        assert!(book.is_pinned());
        assert_eq!(
            book.observe(record(1, 9000, 1), RecordSource::Relayed, now),
            PexOutcome::Learned
        );
        assert_eq!(
            book.observe(record(9, 9009, 1), RecordSource::Relayed, now),
            PexOutcome::NotAdmissible
        );
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn a_record_that_is_never_refreshed_expires() {
        let now = Instant::now();
        let limits = PexLimits {
            ttl: Duration::from_secs(60),
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);
        book.observe(record(1, 9000, 1), RecordSource::Relayed, now);

        let later = now + Duration::from_secs(61);
        assert_eq!(book.address_of(&key(1), later), None);
        assert!(book.snapshot(16, later).is_empty());
        assert_eq!(book.expire(later), 1);
        assert!(book.is_empty());
    }

    #[test]
    fn the_book_stops_growing_at_its_peer_cap() {
        let now = Instant::now();
        let limits = PexLimits {
            max_peers: 2,
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);

        assert_eq!(
            book.observe(record(1, 9001, 1), RecordSource::Relayed, now),
            PexOutcome::Learned
        );
        assert_eq!(
            book.observe(record(2, 9002, 1), RecordSource::Relayed, now),
            PexOutcome::Learned
        );
        assert_eq!(
            book.observe(record(3, 9003, 1), RecordSource::Relayed, now),
            PexOutcome::Full
        );
        // A peer already in a full book can still move.
        assert_eq!(
            book.observe(record(2, 9012, 2), RecordSource::Relayed, now),
            PexOutcome::Refreshed
        );
    }

    #[test]
    fn a_frame_over_the_record_bound_is_refused_whole() {
        let now = Instant::now();
        let limits = PexLimits {
            max_records_per_message: 4,
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);

        assert_eq!(
            book.admit(3, 5, now),
            Err(PexRejection::TooManyRecords {
                sender: 3,
                count: 5,
                max: 4,
            })
        );
        assert_eq!(book.admit(3, 4, now), Ok(()));
    }

    #[test]
    fn a_sender_is_rate_limited_within_a_window_and_forgiven_after_it() {
        let now = Instant::now();
        let limits = PexLimits {
            max_messages_per_window: 2,
            window: Duration::from_secs(10),
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);

        assert_eq!(book.admit(1, 1, now), Ok(()));
        assert_eq!(book.admit(1, 1, now), Ok(()));
        assert_eq!(
            book.admit(1, 1, now),
            Err(PexRejection::RateLimited {
                sender: 1,
                seen: 2,
                max: 2,
                window: Duration::from_secs(10),
            })
        );

        // Another sender has its own budget.
        assert_eq!(book.admit(2, 1, now), Ok(()));
        // And the window rolls.
        assert_eq!(book.admit(1, 1, now + Duration::from_secs(10)), Ok(()));
    }

    /// Two nodes answering the same request must answer the same way, or a
    /// later all-to-all digest comparison would see spurious disagreement.
    #[test]
    fn a_snapshot_is_spki_ordered_and_bounded() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        book.observe(record(3, 9003, 1), RecordSource::Relayed, now);
        book.observe(record(1, 9001, 1), RecordSource::Relayed, now);
        book.observe(record(2, 9002, 1), RecordSource::Relayed, now);

        let snapshot = book.snapshot(2, now);
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].spki, key(1).0);
        assert_eq!(snapshot[1].spki, key(2).0);

        // Never more than one frame's worth, whatever the caller asks for.
        assert!(book.snapshot(usize::MAX, now).len() <= MAX_PEER_RECORDS_PER_MESSAGE);
    }

    #[test]
    fn dial_targets_pair_each_address_with_the_identity_to_pin() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        book.observe(record(1, 9001, 1), RecordSource::Relayed, now);

        assert_eq!(book.dial_targets(now), vec![(key(1), addr(9001))]);
    }

    /// The attack unsigned records make cheap: a roster member gossiping a
    /// wrong address for somebody else, with a `seq` no honest announcement can
    /// beat. It must not displace what the operator configured, nor what the
    /// peer itself announced — otherwise an honest party is unreachable for as
    /// long as the liar keeps talking, which is a partition, not a wasted dial.
    #[test]
    fn a_relayed_record_cannot_displace_a_local_or_announced_address() {
        let now = Instant::now();
        let forged = PeerRecord::new(&key(1), addr(6661), u64::MAX);

        let mut configured = PeerBook::default();
        assert_eq!(
            configured.observe(record(1, 9001, 1), RecordSource::Local, now),
            PexOutcome::Learned
        );
        assert_eq!(
            configured.observe(forged.clone(), RecordSource::Relayed, now),
            PexOutcome::Outranked
        );
        assert_eq!(
            configured.observe(forged.clone(), RecordSource::Announced, now),
            PexOutcome::Outranked
        );
        assert_eq!(configured.address_of(&key(1), now), Some(addr(9001)));

        let mut announced = PeerBook::default();
        announced.observe(record(1, 9001, 1), RecordSource::Announced, now);
        assert_eq!(
            announced.observe(forged, RecordSource::Relayed, now),
            PexOutcome::Outranked
        );
        assert_eq!(announced.address_of(&key(1), now), Some(addr(9001)));
        assert_eq!(announced.source_of(&key(1)), Some(RecordSource::Announced));
    }

    /// The other direction: a peer that genuinely moved must still be able to
    /// correct a relayed record, or provenance would freeze stale addresses in
    /// place.
    #[test]
    fn a_peers_own_announcement_upgrades_a_relayed_record() {
        let now = Instant::now();
        let mut book = PeerBook::default();

        book.observe(record(1, 9001, 9), RecordSource::Relayed, now);
        // Lower `seq`, higher rank: rank decides first.
        assert_eq!(
            book.observe(record(1, 9101, 1), RecordSource::Announced, now),
            PexOutcome::Refreshed
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9101)));
        assert_eq!(book.source_of(&key(1)), Some(RecordSource::Announced));
    }

    /// The `u64::MAX` brick, at the one rank where `seq` still decides: a relay
    /// may nudge a relayed address forward, but it may not jump the counter
    /// somewhere no honest counter will ever reach.
    #[test]
    fn a_relayed_record_cannot_jump_the_counter_out_of_reach() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        book.observe(record(1, 9001, 10), RecordSource::Relayed, now);

        assert_eq!(
            book.observe(
                PeerRecord::new(&key(1), addr(6661), u64::MAX),
                RecordSource::Relayed,
                now
            ),
            PexOutcome::SeqJumpTooLarge
        );
        assert_eq!(
            book.observe(
                record(1, 6661, 10 + MAX_PEX_SEQ_JUMP + 1),
                RecordSource::Relayed,
                now
            ),
            PexOutcome::SeqJumpTooLarge
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9001)));

        // A step inside the bound is an ordinary correction.
        assert_eq!(
            book.observe(
                record(1, 9002, 10 + MAX_PEX_SEQ_JUMP),
                RecordSource::Relayed,
                now
            ),
            PexOutcome::Refreshed
        );
        assert_eq!(book.address_of(&key(1), now), Some(addr(9002)));
    }

    /// A peer that re-announces with an unchanged `seq` — the common case for a
    /// node whose counter reset across a restart — must still keep its entry
    /// alive, or it silently expires out of every book after the TTL.
    #[test]
    fn a_first_party_record_applies_without_beating_the_stored_seq() {
        let now = Instant::now();
        let limits = PexLimits {
            ttl: Duration::from_secs(60),
            ..PexLimits::default()
        };
        let mut book = PeerBook::new(limits);
        book.observe(record(1, 9001, 900), RecordSource::Announced, now);

        // Same counter, later moment: the TTL stamp moves even though `seq`
        // did not.
        let later = now + Duration::from_secs(45);
        assert_eq!(
            book.observe(record(1, 9001, 900), RecordSource::Announced, later),
            PexOutcome::Refreshed
        );
        assert_eq!(
            book.address_of(&key(1), later + Duration::from_secs(30)),
            Some(addr(9001)),
            "the re-announcement must have reset the TTL"
        );

        // Counter reset to 1 after a restart, at a new address.
        assert_eq!(
            book.observe(record(1, 9101, 1), RecordSource::Announced, later),
            PexOutcome::Refreshed
        );
        assert_eq!(book.address_of(&key(1), later), Some(addr(9101)));
    }

    /// `dial_targets` is a local iteration, not a wire frame: clamping it to
    /// one `PeerBook` frame's worth would leave every peer past the 64th
    /// permanently unreconnected in a mesh larger than that.
    #[test]
    fn dial_targets_are_not_clamped_to_one_frames_worth() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        let count = MAX_PEER_RECORDS_PER_MESSAGE * 3;
        for index in 0..count {
            let spki = (index as u32).to_be_bytes().to_vec();
            book.observe(
                PeerRecord {
                    spki,
                    advertise_addr: addr(9000 + index as u16),
                    seq: 1,
                },
                RecordSource::Relayed,
                now,
            );
        }

        assert_eq!(book.len(), count);
        assert_eq!(book.dial_targets(now).len(), count);
        // The wire snapshot is still bounded; only the local view is not.
        assert_eq!(
            book.snapshot(usize::MAX, now).len(),
            MAX_PEER_RECORDS_PER_MESSAGE
        );
    }

    #[test]
    fn seed_hints_drop_self_and_duplicates_but_keep_order() {
        let hints = SeedHints::new(
            [addr(9002), addr(9001), addr(9002), addr(9000)],
            Some(addr(9000)),
        );

        assert_eq!(hints.addrs(), &[addr(9002), addr(9001)]);
        assert_eq!(hints.len(), 2);
        assert!(!hints.is_empty());
    }

    /// `--peers` is a hint list, not a membership list: one live entry is a
    /// complete configuration, and an empty one is a legal (if lonely) state.
    #[test]
    fn any_non_empty_subset_is_a_usable_hint_list() {
        let full = [addr(9001), addr(9002), addr(9003)];
        for subset in [&full[..1], &full[1..2], &full[..2], &full[..]] {
            let hints = SeedHints::new(subset.iter().copied(), Some(addr(9000)));
            assert!(!hints.is_empty());
            assert_eq!(hints.len(), subset.len());
        }
        assert!(SeedHints::new([], None).is_empty());
    }
}
