//! The mesh control plane's in-band frame, and the prefix registry it lives in.
//!
//! `docs/design/bootnode-elimination.md` §5 row 4, §12.D. Mesh control traffic
//! shares one framed stream with everything else a party connection carries, so
//! every control message is tagged with [`MESH_CTRL_PREFIX`] and is decoded
//! *only* after that tag matches.
//!
//! # In-band tagging is forced, not chosen
//!
//! An untagged `bincode` enum cannot answer "is this frame mine?". Bincode
//! writes a bare little-endian `u32` discriminant, so two unrelated enums on
//! one stream produce byte-identical frames for matching variant indices, and
//! trial-decoding in sequence silently routes one enum's frame to the other's
//! handler — which is exactly what used to happen here (design doc §2). A tag
//! makes the question *decidable* instead of a guess about which enum happened
//! to accept the bytes first.
//!
//! # Where these frames are allowed to travel
//!
//! Only inside [`crate::net::mesh::join_mesh`]'s lock-step handshake, on
//! connections that function is the sole reader of, before the execution
//! transport takes its single-reader scanner lease over them.
//!
//! That is not a style preference, it is what the transport permits.
//! [`crate::net::execution_transport::ExecutionConnectionScanner`] closes a
//! connection outright on the first frame that is not a valid `STXE` envelope,
//! so a mesh control frame written after the scanner is reading would terminate
//! the peer link rather than fall through to another reader. There is therefore
//! no mesh control plane after the join, no gossip round, no heartbeat and no
//! unsolicited peer-book answer — a peer book is exchanged once, in the
//! handshake, and the reconnect supervisor repairs the mesh by *dialing*, which
//! puts no control frame on the wire at all.
//!
//! # Blocker B7: mutual disjointness
//!
//! Five other prefixes travel party connections — `OPN1`, `XOP1`, `AXOP`,
//! `AXG2` (`net/open_registry/wire.rs`) and `STXE`
//! ([`crate::net::execution_transport::EXECUTION_ENVELOPE_MAGIC`]) — plus the
//! mesh-ready frame below. A reader dispatches on "does this payload start with
//! my prefix", so if any prefix were a prefix *of another*, one reader would
//! swallow the other's frames. [`ReservedPrefix`] names all seven in one place
//! and `every_reserved_prefix_is_disjoint_from_every_other` asserts the
//! invariant over the real constants rather than over copies of their
//! spellings.

use serde::{Deserialize, Serialize};

use crate::net::execution_transport::EXECUTION_ENVELOPE_MAGIC;
use crate::net::mesh::pex::PeerRecord;
use crate::net::open_registry::{
    AVSS_EXP_WIRE_PREFIX, AVSS_G2_EXP_WIRE_PREFIX, HB_EXP_OPEN_WIRE_PREFIX,
    OPEN_REGISTRY_WIRE_PREFIX,
};
use crate::net::session::ExecutionId;

/// Tag every mesh control frame carries.
///
/// Must stay disjoint from every other entry of [`ReservedPrefix`] (blocker
/// B7). Versioned in its last byte so a future frame layout can travel beside
/// this one instead of replacing it in place.
pub const MESH_CTRL_PREFIX: &[u8; 4] = b"MSH1";

/// The mesh-formed frame's tag.
///
/// Not a [`MeshMessage`]: it is a bare `prefix || namespace` with no body, and
/// it is the first thing a peer writes in the handshake, so a peer pinned to a
/// different roster is refused before a [`MeshMessage::MeshCommit`] is ever
/// decoded.
pub const MESH_READY_PREFIX: &[u8] = b"STOFFEL_MESH_READY_V1";

/// Largest mesh control body accepted off the wire.
///
/// Matches `open_registry::wire::MAX_WIRE_MESSAGE_LEN`: the two travel the same
/// stream, and a control plane that accepted larger frames than the data plane
/// would be the cheaper thing to point a flood at.
pub const MAX_MESH_MESSAGE_LEN: usize = 1_048_576;

/// Largest number of peer records one frame may carry.
///
/// Bounds the work a single peer-book frame can ask of a receiver,
/// independently of the byte cap: without it a 1 MB frame could carry tens of
/// thousands of tiny records, each of which costs a map insert and an
/// admissibility check.
pub const MAX_PEER_RECORDS_PER_MESSAGE: usize = 64;

/// An in-band tag that travels the same framed stream as party traffic.
///
/// Exists so blocker B7's invariant has something to quantify over. An enum
/// rather than a `&[&[u8]]` table so that adding a prefix without adding it here
/// is a compile error at the `ALL` array, not a silently untested addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservedPrefix {
    /// [`MESH_CTRL_PREFIX`].
    MeshControl,
    /// [`MESH_READY_PREFIX`].
    MeshReady,
    /// `STXE` — the execution transport envelope, which carries every MPC and
    /// per-execution control byte once the mesh is formed.
    ExecutionEnvelope,
    /// `OPN1` — open-share and RBC frames.
    OpenRegistry,
    /// `XOP1` — HoneyBadger open-in-exponent.
    HoneyBadgerExpOpen,
    /// `AXOP` — AVSS open-in-exponent.
    AvssExpOpen,
    /// `AXG2` — AVSS G2 open-in-exponent.
    AvssG2ExpOpen,
}

impl ReservedPrefix {
    /// Every prefix that shares the framed stream.
    pub const ALL: [Self; 7] = [
        Self::MeshControl,
        Self::MeshReady,
        Self::ExecutionEnvelope,
        Self::OpenRegistry,
        Self::HoneyBadgerExpOpen,
        Self::AvssExpOpen,
        Self::AvssG2ExpOpen,
    ];

    /// The bytes this tag is spelled as.
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Self::MeshControl => MESH_CTRL_PREFIX,
            Self::MeshReady => MESH_READY_PREFIX,
            Self::ExecutionEnvelope => &EXECUTION_ENVELOPE_MAGIC,
            Self::OpenRegistry => OPEN_REGISTRY_WIRE_PREFIX,
            Self::HoneyBadgerExpOpen => HB_EXP_OPEN_WIRE_PREFIX,
            Self::AvssExpOpen => AVSS_EXP_WIRE_PREFIX,
            Self::AvssG2ExpOpen => AVSS_G2_EXP_WIRE_PREFIX,
        }
    }
}

/// What a node commits to when it also commits to one execution.
///
/// `None` on a standing node: one certificate-pinned mesh carries many
/// concurrent executions, so there is no mesh-wide program or entry point to
/// agree on, and the roster is the whole agreement (§12.D). `Some` in one-shot
/// mode, where the process exists to run exactly one execution of one program —
/// and where the check on whether `n` processes are running the same
/// computation lives. Comparing the program alone would not be one: a party
/// with a different `n`, threshold or entry point runs a differently
/// parameterised protocol that nothing downstream reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCommitment {
    /// The execution this node was started for. A party joined under another
    /// one would pass the join and then wait forever on rounds of an execution
    /// no other party is in.
    pub execution_id: ExecutionId,
    /// Content address of the program this node actually loaded.
    pub program_id: [u8; 32],
    pub entry: String,
}

/// One mesh control frame.
///
/// Neither variant is trusted on its own: a peer-book address is checked by the
/// pinned TLS handshake of the dial that uses it, and a commitment is checked
/// by all-to-all equality against this node's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshMessage {
    /// "Here is where I am, and where I think everyone else is."
    ///
    /// Exchanged once per peer inside the join handshake. Records for
    /// identities outside the roster are dropped by the receiver.
    PeerBook { records: Vec<PeerRecord> },
    /// "This is the mesh — and, in one-shot mode, the execution — I believe I
    /// am joining."
    ///
    /// Disagreement is detected here, before any MPC byte flows (design doc
    /// §3).
    MeshCommit {
        roster_digest: [u8; 32],
        n_parties: u64,
        threshold: u64,
        session: Option<SessionCommitment>,
    },
}

impl MeshMessage {
    /// A short name for this frame, for diagnostics that have to say what
    /// arrived where something else was expected.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PeerBook { .. } => "PeerBook",
            Self::MeshCommit { .. } => "MeshCommit",
        }
    }
}

/// Why a mesh control frame could not be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MeshWireError {
    #[error("mesh control frame body is {len} bytes (max {max})")]
    TooLarge { len: usize, max: usize },
    #[error("mesh control frame carries {count} peer records (max {max})")]
    TooManyRecords { count: usize, max: usize },
    #[error("mesh control frame did not decode: {reason}")]
    Malformed { reason: String },
    #[error("mesh control frame could not be encoded: {reason}")]
    Unencodable { reason: String },
}

impl From<MeshWireError> for String {
    fn from(error: MeshWireError) -> Self {
        error.to_string()
    }
}

/// The pre-session namespace the mesh-ready frame travels under.
///
/// The low 64 bits of the roster digest: the only thing the parties have
/// already agreed on when the frame is written, and a cheap early membership
/// check before the full 32 bytes are compared by
/// [`MeshMessage::MeshCommit`].
pub fn roster_namespace(roster_digest: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&roster_digest[..8]);
    u64::from_le_bytes(bytes)
}

/// The frame a node announces mesh readiness with.
pub fn mesh_ready_frame(namespace: u64) -> Vec<u8> {
    let mut frame = Vec::with_capacity(MESH_READY_PREFIX.len() + std::mem::size_of::<u64>());
    frame.extend_from_slice(MESH_READY_PREFIX);
    frame.extend_from_slice(&namespace.to_le_bytes());
    frame
}

/// The namespace `payload` announces, or `None` if it is not a ready frame.
///
/// `None` is a fall-through, never an error: the payload belongs to another
/// reader on the same framed stream.
pub fn classify_mesh_ready(payload: &[u8]) -> Option<u64> {
    if payload.len() != MESH_READY_PREFIX.len() + std::mem::size_of::<u64>()
        || !payload.starts_with(MESH_READY_PREFIX)
    {
        return None;
    }
    let mut namespace = [0u8; 8];
    namespace.copy_from_slice(&payload[MESH_READY_PREFIX.len()..]);
    Some(u64::from_le_bytes(namespace))
}

/// Tag and serialize one control frame.
pub fn encode(message: &MeshMessage) -> Result<Vec<u8>, MeshWireError> {
    check_record_bound(message)?;

    let body = bincode::serialize(message).map_err(|error| MeshWireError::Unencodable {
        reason: error.to_string(),
    })?;
    if body.len() > MAX_MESH_MESSAGE_LEN {
        return Err(MeshWireError::TooLarge {
            len: body.len(),
            max: MAX_MESH_MESSAGE_LEN,
        });
    }

    let mut out = Vec::with_capacity(MESH_CTRL_PREFIX.len() + body.len());
    out.extend_from_slice(MESH_CTRL_PREFIX);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode `payload` as a control frame, if it is one.
///
/// Three outcomes, and keeping them apart is the point of the tag:
///
/// * `Ok(None)` — not a mesh frame. The caller must go on offering it to
///   whatever else reads this stream.
/// * `Err(_)` — a mesh frame that is malformed or over a bound. The caller must
///   *not* fall through: the frame was addressed to this reader.
/// * `Ok(Some(_))` — a frame to act on.
pub fn try_decode(payload: &[u8]) -> Result<Option<MeshMessage>, MeshWireError> {
    if payload.len() < MESH_CTRL_PREFIX.len()
        || &payload[..MESH_CTRL_PREFIX.len()] != MESH_CTRL_PREFIX.as_slice()
    {
        return Ok(None);
    }

    let body = &payload[MESH_CTRL_PREFIX.len()..];
    if body.len() > MAX_MESH_MESSAGE_LEN {
        return Err(MeshWireError::TooLarge {
            len: body.len(),
            max: MAX_MESH_MESSAGE_LEN,
        });
    }

    let message: MeshMessage =
        bincode::deserialize(body).map_err(|error| MeshWireError::Malformed {
            reason: error.to_string(),
        })?;
    check_record_bound(&message)?;
    Ok(Some(message))
}

/// Enforce [`MAX_PEER_RECORDS_PER_MESSAGE`] on both directions.
///
/// On decode it is the flood bound; on encode it stops this node from emitting
/// a frame its own peers are required to reject.
fn check_record_bound(message: &MeshMessage) -> Result<(), MeshWireError> {
    if let MeshMessage::PeerBook { records } = message {
        if records.len() > MAX_PEER_RECORDS_PER_MESSAGE {
            return Err(MeshWireError::TooManyRecords {
                count: records.len(),
                max: MAX_PEER_RECORDS_PER_MESSAGE,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn record(seq: u64) -> PeerRecord {
        PeerRecord {
            spki: vec![1, 2, 3, 4],
            advertise_addr: "127.0.0.1:9000".parse::<SocketAddr>().expect("parse addr"),
            seq,
        }
    }

    /// Blocker B7. All seven tags share one framed stream and every reader
    /// dispatches on "does this payload start with my prefix", so a prefix
    /// relation between any two of them means one reader silently eats the
    /// other's frames.
    #[test]
    fn every_reserved_prefix_is_disjoint_from_every_other() {
        for left in ReservedPrefix::ALL {
            for right in ReservedPrefix::ALL {
                if left == right {
                    continue;
                }
                assert!(
                    !left.bytes().starts_with(right.bytes()),
                    "{left:?} ({:?}) starts with {right:?} ({:?}); one reader would swallow the other's frames",
                    String::from_utf8_lossy(left.bytes()),
                    String::from_utf8_lossy(right.bytes()),
                );
            }
        }
    }

    /// The table is only an invariant if it is complete; a prefix that is not
    /// listed is not tested.
    #[test]
    fn the_reserved_prefix_table_lists_every_variant_exactly_once() {
        let mut seen = std::collections::HashSet::new();
        for prefix in ReservedPrefix::ALL {
            assert!(seen.insert(prefix), "{prefix:?} listed twice");
            assert!(!prefix.bytes().is_empty(), "{prefix:?} has an empty tag");
        }
        assert_eq!(seen.len(), ReservedPrefix::ALL.len());
    }

    /// The execution transport is the reader a mesh frame must never be
    /// mistaken for: it closes the connection on a frame it cannot decode as
    /// its own envelope, so "mesh frame" and "execution envelope" have to be
    /// distinguishable from the first byte.
    #[test]
    fn a_mesh_frame_is_not_an_execution_envelope() {
        let framed = encode(&MeshMessage::PeerBook {
            records: vec![record(1)],
        })
        .expect("encode mesh frame");

        assert!(!framed.starts_with(&EXECUTION_ENVELOPE_MAGIC));
        assert!(
            crate::net::execution_transport::ExecutionEnvelopeV1::decode(&framed).is_err(),
            "a mesh frame must not decode as an execution envelope"
        );
    }

    #[test]
    fn a_round_trip_preserves_every_variant() {
        let messages = vec![
            MeshMessage::PeerBook {
                records: vec![record(1), record(2)],
            },
            MeshMessage::MeshCommit {
                roster_digest: [3u8; 32],
                n_parties: 5,
                threshold: 1,
                session: None,
            },
            MeshMessage::MeshCommit {
                roster_digest: [3u8; 32],
                n_parties: 5,
                threshold: 1,
                session: Some(SessionCommitment {
                    execution_id: ExecutionId::from_bytes([8u8; 32]),
                    program_id: [4u8; 32],
                    entry: "main".to_string(),
                }),
            },
        ];

        for message in messages {
            let framed = encode(&message).expect("encode mesh frame");
            assert!(framed.starts_with(MESH_CTRL_PREFIX));
            let decoded = try_decode(&framed)
                .expect("decode mesh frame")
                .expect("the frame carries the mesh tag");
            assert_eq!(decoded, message);
        }
    }

    /// A payload that carries another reader's tag is a fall-through, so that a
    /// chain of readers over one stream is correct.
    #[test]
    fn a_foreign_payload_is_not_claimed() {
        assert_eq!(try_decode(b"OPN1whatever"), Ok(None));
        assert_eq!(try_decode(b"STXE"), Ok(None));
        assert_eq!(try_decode(MESH_READY_PREFIX), Ok(None));
        assert_eq!(try_decode(b""), Ok(None));
    }

    /// A frame that carries the mesh tag and then does not decode is an error,
    /// never a fall-through: passing it on would hand another reader bytes
    /// already known to be mesh control traffic.
    #[test]
    fn a_tagged_frame_that_does_not_decode_is_an_error() {
        let mut framed = MESH_CTRL_PREFIX.to_vec();
        framed.extend_from_slice(b"not bincode");

        assert!(matches!(
            try_decode(&framed),
            Err(MeshWireError::Malformed { .. })
        ));
    }

    /// The record cap is enforced on the way out as well as on the way in, so
    /// a node cannot emit a frame its peers are required to reject.
    #[test]
    fn the_record_cap_is_enforced_in_both_directions() {
        let records = (0..=MAX_PEER_RECORDS_PER_MESSAGE as u64)
            .map(record)
            .collect::<Vec<_>>();

        assert!(matches!(
            encode(&MeshMessage::PeerBook { records }),
            Err(MeshWireError::TooManyRecords { .. })
        ));
    }

    #[test]
    fn the_ready_frame_round_trips_its_namespace() {
        let namespace = roster_namespace(&[0xab; 32]);
        let frame = mesh_ready_frame(namespace);

        assert_eq!(classify_mesh_ready(&frame), Some(namespace));
        assert_eq!(classify_mesh_ready(MESH_READY_PREFIX), None);
        assert_eq!(classify_mesh_ready(b"OPN1whatever"), None);
    }
}
