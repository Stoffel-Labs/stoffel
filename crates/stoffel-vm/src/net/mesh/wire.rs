//! The mesh control plane's in-band frame, and the prefix registry it lives in.
//!
//! Stage 4 of `docs/design/bootnode-elimination.md` (§5, row 4). Mesh control
//! traffic shares one framed stream with the MPC data plane, so every control
//! message carries [`MESH_CTRL_PREFIX`] and is decoded *only* after that tag
//! matches.
//!
//! # In-band tagging is forced, not chosen
//!
//! The deleted bootnode read its stream by trial-decoding the same bytes
//! against three untagged `bincode` enums in sequence. Bincode writes a bare
//! little-endian `u32` discriminant, so `DiscoveryMessage` variants 2 and 3 and
//! `ProgramSyncMessage` variants 2 and 3 produced byte-identical frames:
//! `ProgramSyncMessage::ProgramFetchRequest` always decoded as a
//! `DiscoveryMessage` and dispatched to that arm, leaving the
//! `ProgramSyncMessage` arm unreachable for it (design doc §2). A tag is what
//! makes "this frame is not mine" a *decidable* question rather than a guess
//! about which enum happened to accept the bytes first.
//!
//! # Blocker B7: mutual disjointness
//!
//! Four other prefixes already travel this stream — `OPN1`, `XOP1`, `AXOP`,
//! `AXG2` (`net/open_registry/wire.rs`) — plus the three barrier tags
//! ([`crate::net::mesh::barrier`]). A router chain dispatches on "does this
//! payload start with my prefix", so if any prefix were a prefix *of another*,
//! one router would swallow the other's frames. [`ReservedPrefix`] names all
//! ten in one place and `every_reserved_prefix_is_disjoint_from_every_other`
//! asserts the invariant over the real constants rather than over copies of
//! their spellings.
//!
//! The barrier tags therefore live here rather than in `stoffel-run.rs`, which
//! is a binary the library cannot see into: the runner now uses these
//! constants, so the test covers the bytes production actually sends.
//!
//! # Why a barrier is *not* a [`MeshMessage`]
//!
//! Stage 4 modelled the barrier as a control-frame variant. Stage 5 removed it,
//! because a [`MeshMessage`] is by construction consumed by
//! [`crate::net::mesh::MeshRouter`] before it reaches the receive loop's
//! channel — and a barrier's whole job is to be observed by the code waiting on
//! it, which is not the router. The barrier keeps its own top-level prefix per
//! tag, exactly as `STOFFEL_HB_PREPROCESSING_READY_V1` already did, so it falls
//! through every router to the loop that is counting it. One mechanism, not
//! two: see [`crate::net::mesh::barrier::MeshBarrier`].

use serde::{Deserialize, Serialize};

use crate::net::mesh::pex::PeerRecord;
use crate::net::open_registry::{
    AVSS_EXP_WIRE_PREFIX, AVSS_G2_EXP_WIRE_PREFIX, HB_EXP_OPEN_WIRE_PREFIX,
    OPEN_REGISTRY_WIRE_PREFIX,
};
use crate::net::session::SessionExecutionId;

/// Tag every mesh control frame carries.
///
/// Must stay disjoint from every other entry of [`ReservedPrefix`] (blocker
/// B7). Versioned in its last byte so a future frame layout can travel beside
/// this one instead of replacing it in place.
pub const MESH_CTRL_PREFIX: &[u8; 4] = b"MSH1";

/// The mesh-formed barrier tag.
///
/// Announced once a node holds every peer's authenticated key and has settled
/// its connection set — see [`crate::net::mesh::barrier::BarrierTag::MeshReady`].
pub const MESH_READY_PREFIX: &[u8] = b"STOFFEL_MESH_READY_V1";

/// The HoneyBadger preprocessing barrier tag.
///
/// Moved out of `stoffel-run.rs` so the disjointness invariant can be stated
/// over the constant production sends. Spelled exactly as the runner spelled
/// it, so migrating that site onto
/// [`crate::net::mesh::barrier::MeshBarrier`] leaves the bytes on the wire
/// byte-identical.
pub const HB_PREPROCESSING_READY_PREFIX: &[u8] = b"STOFFEL_HB_PREPROCESSING_READY_V1";

/// The output-phase barrier tag.
///
/// See [`crate::net::mesh::barrier::BarrierTag::OutputReady`].
pub const OUTPUT_READY_PREFIX: &[u8] = b"STOFFEL_OUTPUT_READY_V1";

/// The admission-agreement barrier tag.
///
/// See [`crate::net::mesh::barrier::DigestBarrierTag::AdmissionsAgreed`]. Its
/// frames carry a 32-byte digest after the namespace, which no other barrier
/// frame does (`docs/design/bootnode-elimination.md` §9.D.6).
pub const ADMISSIONS_AGREED_PREFIX: &[u8] = b"STOFFEL_ADMISSIONS_AGREED_V1";

/// The masked-input agreement barrier tag.
///
/// See [`crate::net::mesh::barrier::DigestBarrierTag::InputsAgreed`].
pub const INPUTS_AGREED_PREFIX: &[u8] = b"STOFFEL_INPUTS_AGREED_V1";

/// Largest mesh control body accepted off the wire.
///
/// Matches `open_registry::wire::MAX_WIRE_MESSAGE_LEN`: the two enums share a
/// stream, and a control plane that accepted larger frames than the data plane
/// would be the cheaper thing to point a flood at.
pub const MAX_MESH_MESSAGE_LEN: usize = 1_048_576;

/// Largest number of peer records one frame may carry.
///
/// Bounds the work a single gossip frame can ask of a receiver, independently
/// of the byte cap: without it a 1 MB frame could carry tens of thousands of
/// tiny records, each of which costs a map insert and an admissibility check.
pub const MAX_PEER_RECORDS_PER_MESSAGE: usize = 64;

/// An in-band tag that travels the same framed stream as MPC traffic.
///
/// Exists so blocker B7's invariant has something to quantify over. An enum
/// rather than a `&[&[u8]]` table so that adding a prefix without adding it here
/// is a compile error at the `ALL` array, not a silently untested addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservedPrefix {
    /// [`MESH_CTRL_PREFIX`].
    MeshControl,
    /// `OPN1` — open-share and RBC frames.
    OpenRegistry,
    /// `XOP1` — HoneyBadger open-in-exponent.
    HoneyBadgerExpOpen,
    /// `AXOP` — AVSS open-in-exponent.
    AvssExpOpen,
    /// `AXG2` — AVSS G2 open-in-exponent.
    AvssG2ExpOpen,
    /// [`MESH_READY_PREFIX`].
    MeshReadyBarrier,
    /// [`HB_PREPROCESSING_READY_PREFIX`].
    PreprocessingReadyBarrier,
    /// [`OUTPUT_READY_PREFIX`].
    OutputReadyBarrier,
    /// [`ADMISSIONS_AGREED_PREFIX`].
    AdmissionsAgreedBarrier,
    /// [`INPUTS_AGREED_PREFIX`].
    InputsAgreedBarrier,
}

impl ReservedPrefix {
    /// Every prefix that shares the framed stream.
    pub const ALL: [Self; 10] = [
        Self::MeshControl,
        Self::OpenRegistry,
        Self::HoneyBadgerExpOpen,
        Self::AvssExpOpen,
        Self::AvssG2ExpOpen,
        Self::MeshReadyBarrier,
        Self::PreprocessingReadyBarrier,
        Self::OutputReadyBarrier,
        Self::AdmissionsAgreedBarrier,
        Self::InputsAgreedBarrier,
    ];

    /// The bytes this tag is spelled as.
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Self::MeshControl => MESH_CTRL_PREFIX,
            Self::OpenRegistry => OPEN_REGISTRY_WIRE_PREFIX,
            Self::HoneyBadgerExpOpen => HB_EXP_OPEN_WIRE_PREFIX,
            Self::AvssExpOpen => AVSS_EXP_WIRE_PREFIX,
            Self::AvssG2ExpOpen => AVSS_G2_EXP_WIRE_PREFIX,
            Self::MeshReadyBarrier => MESH_READY_PREFIX,
            Self::PreprocessingReadyBarrier => HB_PREPROCESSING_READY_PREFIX,
            Self::OutputReadyBarrier => OUTPUT_READY_PREFIX,
            Self::AdmissionsAgreedBarrier => ADMISSIONS_AGREED_PREFIX,
            Self::InputsAgreedBarrier => INPUTS_AGREED_PREFIX,
        }
    }
}

/// One mesh control frame.
///
/// Every variant is a statement the sender makes about itself, and none of them
/// is trusted on its own: an address is checked by the TLS handshake that
/// follows it, a `JoinProposal` is checked by all-to-all `JoinCommit` equality,
/// and a `ProgramChunk` is checked by its BLAKE3 content address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshMessage {
    /// "I am reachable at this address." Gossiped onward by receivers.
    PeerAnnounce { record: PeerRecord },
    /// "Send me up to `max_records` of what you know."
    PeerRequest { max_records: u32 },
    /// The answer to a [`MeshMessage::PeerRequest`].
    PeerBook { records: Vec<PeerRecord> },
    /// "This is the session I believe I am joining."
    ///
    /// `epoch` is this node's monotone freshness counter (blocker B5); the
    /// agreed `instance_id` is bounded by `max(proposals)`, so a Byzantine
    /// member cannot brick honest stores by proposing `u64::MAX`.
    JoinProposal {
        roster_digest: [u8; 32],
        /// The coordinator execution the sender was started for (design doc
        /// §9.D.5).
        execution_id: SessionExecutionId,
        program_id: [u8; 32],
        entry: String,
        n_parties: u64,
        threshold: u64,
        epoch: u64,
    },
    /// "I commit to exactly this proposal." Disagreement is detected here,
    /// before any MPC byte flows (design doc §3).
    JoinCommit {
        proposal_digest: [u8; 32],
        instance_id: u64,
    },
    /// "Send me chunk `chunk_index` of the program with this content address."
    ProgramRequest {
        program_id: [u8; 32],
        chunk_index: u64,
    },
    /// One chunk of a content-addressed program.
    ProgramChunk {
        program_id: [u8; 32],
        chunk_index: u64,
        chunk_count: u64,
        bytes: Vec<u8>,
    },
    /// Liveness only. Carries no state the receiver acts on.
    Heartbeat { seq: u64, unix_millis: u64 },
}

impl MeshMessage {
    /// A short name for this frame, for diagnostics that have to say what
    /// arrived where something else was expected.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PeerAnnounce { .. } => "PeerAnnounce",
            Self::PeerRequest { .. } => "PeerRequest",
            Self::PeerBook { .. } => "PeerBook",
            Self::JoinProposal { .. } => "JoinProposal",
            Self::JoinCommit { .. } => "JoinCommit",
            Self::ProgramRequest { .. } => "ProgramRequest",
            Self::ProgramChunk { .. } => "ProgramChunk",
            Self::Heartbeat { .. } => "Heartbeat",
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
/// * `Ok(None)` — not a mesh frame. The caller must go on offering it to the
///   next router, which is what makes a chain of `try_handle_wire_message`
///   calls correct.
/// * `Err(_)` — a mesh frame that is malformed or over a bound. The caller must
///   *not* fall through: the frame was addressed to this router, and passing it
///   on would hand the MPC engine bytes that are known to be control traffic.
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

    /// Blocker B7. All six tags share one framed stream and every router
    /// dispatches on "does this payload start with my prefix", so a prefix
    /// relation between any two of them means one router silently eats the
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
                    "{left:?} ({:?}) starts with {right:?} ({:?}); one router would swallow the other's frames",
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

    #[test]
    fn a_round_trip_preserves_every_variant() {
        let messages = vec![
            MeshMessage::PeerAnnounce { record: record(1) },
            MeshMessage::PeerRequest { max_records: 8 },
            MeshMessage::PeerBook {
                records: vec![record(1), record(2)],
            },
            MeshMessage::JoinProposal {
                roster_digest: [3u8; 32],
                execution_id: SessionExecutionId::from_bytes([8u8; 32]),
                program_id: [4u8; 32],
                entry: "main".to_string(),
                n_parties: 5,
                threshold: 1,
                epoch: 42,
            },
            MeshMessage::JoinCommit {
                proposal_digest: [5u8; 32],
                instance_id: 77779,
            },
            MeshMessage::ProgramRequest {
                program_id: [6u8; 32],
                chunk_index: 0,
            },
            MeshMessage::ProgramChunk {
                program_id: [6u8; 32],
                chunk_index: 0,
                chunk_count: 1,
                bytes: vec![9, 9, 9],
            },
            MeshMessage::Heartbeat {
                seq: 3,
                unix_millis: 1_700_000_000_000,
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

    /// A barrier frame is deliberately *not* a mesh control frame: it must fall
    /// through every router to the loop counting it (see the module docs).
    #[test]
    fn a_barrier_frame_is_not_a_mesh_control_frame() {
        for prefix in [
            MESH_READY_PREFIX,
            HB_PREPROCESSING_READY_PREFIX,
            OUTPUT_READY_PREFIX,
        ] {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&77779u64.to_le_bytes());
            assert_eq!(
                try_decode(&payload).expect("a barrier tag is not a mesh-frame error"),
                None,
                "{} must fall through the mesh router",
                String::from_utf8_lossy(prefix)
            );
        }
    }

    /// The reason the tag exists: an untagged payload must be reported as "not
    /// mine" rather than trial-decoded into whichever variant accepts it.
    #[test]
    fn an_untagged_payload_is_not_a_mesh_frame() {
        for prefix in ReservedPrefix::ALL {
            if prefix == ReservedPrefix::MeshControl {
                continue;
            }
            let mut payload = prefix.bytes().to_vec();
            payload.extend_from_slice(&[0u8; 32]);
            assert_eq!(
                try_decode(&payload).expect("a foreign tag is not an error"),
                None,
                "{prefix:?} must not decode as a mesh frame"
            );
        }

        assert_eq!(try_decode(b"").expect("empty is not an error"), None);
        assert_eq!(try_decode(b"MSH").expect("short is not an error"), None);
    }

    /// A tagged frame that does not decode is an error, never `Ok(None)`:
    /// falling through would hand the MPC engine bytes known to be control
    /// traffic.
    #[test]
    fn a_tagged_but_corrupt_frame_is_an_error_not_a_pass_through() {
        let mut payload = MESH_CTRL_PREFIX.to_vec();
        payload.extend_from_slice(&[0xff; 16]);

        let error = try_decode(&payload).expect_err("a tagged frame must not fall through");
        assert!(matches!(error, MeshWireError::Malformed { .. }));
    }

    #[test]
    fn a_peer_book_over_the_record_bound_is_refused_in_both_directions() {
        let records: Vec<PeerRecord> = (0..=MAX_PEER_RECORDS_PER_MESSAGE as u64)
            .map(record)
            .collect();
        let oversized = MeshMessage::PeerBook { records };

        let encode_error = encode(&oversized).expect_err("encoding an over-bound book");
        assert_eq!(
            encode_error,
            MeshWireError::TooManyRecords {
                count: MAX_PEER_RECORDS_PER_MESSAGE + 1,
                max: MAX_PEER_RECORDS_PER_MESSAGE,
            }
        );

        // Built the long way round, because `encode` refuses to produce it.
        let body = bincode::serialize(&oversized).expect("serialize past the encoder");
        let mut framed = MESH_CTRL_PREFIX.to_vec();
        framed.extend_from_slice(&body);
        let decode_error = try_decode(&framed).expect_err("decoding an over-bound book");
        assert!(matches!(decode_error, MeshWireError::TooManyRecords { .. }));
    }

    #[test]
    fn an_over_long_body_is_refused_before_it_is_deserialized() {
        let mut framed = MESH_CTRL_PREFIX.to_vec();
        framed.resize(MESH_CTRL_PREFIX.len() + MAX_MESH_MESSAGE_LEN + 1, 0u8);

        let error = try_decode(&framed).expect_err("an over-long body");
        assert_eq!(
            error,
            MeshWireError::TooLarge {
                len: MAX_MESH_MESSAGE_LEN + 1,
                max: MAX_MESH_MESSAGE_LEN,
            }
        );
    }
}
