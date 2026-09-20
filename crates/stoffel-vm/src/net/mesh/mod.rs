//! The session-join seam, and the roster-pinned mesh behind it.
//!
//! `docs/design/bootnode-elimination.md`. Stage 1 put [`SessionJoin`](crate::net::mesh::SessionJoin) in front
//! of the two production join sites so that the later stages could substitute a
//! bootnode-free join without editing them again; Stage 5 added [`MeshJoin`](crate::net::mesh::MeshJoin)
//! beside the bootnode implementation, and Stage 8 deleted the bootnode, so
//! [`MeshJoin`](crate::net::mesh::MeshJoin) is now the only implementation there is.
//!
//! # What the seam deliberately does not carry
//!
//! [`JoinRequest`](crate::net::mesh::JoinRequest) is what a node asks for, and nothing more. Two omissions are
//! the point:
//!
//! * There is no bootstrap address. That was *construction* state of one
//!   implementation, never something a caller asks for, and a roster-pinned mesh
//!   has no single address to put there — it has seed hints and a roster.
//! * There are no `tls_ids`. Relaying peer transport identities through a third
//!   party is what the whole migration existed to delete (design doc §2);
//!   membership is now the certificate allowlist installed from the roster, so
//!   an address is a hint and only a certificate is an identity.

pub mod barrier;
pub mod dial;
pub mod epoch;
pub mod join;
pub mod pex;
pub mod program;
pub mod roster;
pub mod router;
pub mod wire;

pub use barrier::{
    wait_until_mesh_connected, BarrierTag, BarrierTransport, DigestBarrier, DigestBarrierTag,
    MeshBarrier, MESH_BARRIER_POLL_INTERVAL,
};
pub use dial::{
    dial_address_expecting, dial_peer, dial_peer_expecting, reconnect_sweep, DialOutcome,
    DialPolicy, ExpectedIdentity, NodeInstall, ReconnectPolicy, ReconnectSupervisor,
    ReconnectSweep, ReconnectTarget,
};
pub use epoch::{
    agree_epoch, epoch_store_path, EpochError, EpochStore, EPOCH_STORE_ENV, MAX_EPOCH_JUMP,
};
pub use join::{
    join_mesh, session_digest, MeshJoin, MeshJoinTimeouts, SessionField, SESSION_DIGEST_CONTEXT,
};
pub use pex::{
    PeerBook, PeerRecord, PexLimits, PexOutcome, PexRejection, RecordSource, SeedHints,
    DEFAULT_PEX_MAX_PEERS, MAX_PEX_SEQ_JUMP,
};
pub use program::{
    chunk_count as program_chunk_count, pull_program, ProgramAssembler, ProgramSource,
    PROGRAM_CHUNK_BYTES,
};
pub use roster::{Roster, RosterError};
pub use router::{MeshEvent, MeshRouter, MeshRouterCounters, PeerRequest, SharedMeshRouter};
pub use wire::{
    MeshMessage, MeshWireError, ReservedPrefix, ADMISSIONS_AGREED_PREFIX,
    HB_PREPROCESSING_READY_PREFIX, INPUTS_AGREED_PREFIX, MAX_MESH_MESSAGE_LEN,
    MAX_PEER_RECORDS_PER_MESSAGE, MESH_CTRL_PREFIX, MESH_READY_PREFIX, OUTPUT_READY_PREFIX,
};

use std::net::SocketAddr;
use std::time::Duration;

use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::net::session::SessionExecutionId;

pub type MeshResult<T> = Result<T, MeshError>;

/// Why a [`SessionJoin`] did not produce a session.
///
/// `#[non_exhaustive]`: every variant here is a typed failure of mesh formation
/// or session agreement, and the set is expected to keep growing as the mesh
/// learns to report more precisely. Stage 8 removed `MeshError::Join`, the
/// untyped `{reason}` pass-through that existed only so the bootnode's
/// `Result<_, String>` could reach a caller unchanged, and the close-out of the
/// migration removed `MeshError::MissingTlsId` with `form_mesh`, the last
/// consumer of a relayed `tls_ids` map.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MeshError {
    /// The connectivity barrier expired before this node held every peer's
    /// authenticated public key.
    ///
    /// `expected` is the full party count including self.
    #[error("mesh did not reach {expected} authenticated parties within {waited:?}")]
    MeshIncomplete { expected: usize, waited: Duration },
    /// The pinned roster could not be built, or could not be installed as the
    /// transport's peer-certificate allowlist.
    ///
    /// Rendered without a prefix: [`RosterError`]'s own messages already name
    /// the roster, and the runner prints this behind `Session registration
    /// failed: `.
    #[error("{source}")]
    Roster {
        #[from]
        source: RosterError,
    },
    /// The session announced a different number of parties than the pinned
    /// roster admits.
    ///
    /// The roster is the definition of the session, so this is a disagreement
    /// about membership, not a recoverable count mismatch: a peer that proposes
    /// a different `n` is not in the same session as this node.
    #[error("the session announced {announced} parties but the pinned roster admits {roster}")]
    RosterSize { announced: usize, roster: usize },
    /// This node's own certificate is not one of the roster's nodes.
    ///
    /// `install_expected_server_public_keys` refuses this too
    /// (`quic.rs:1301-1305`); raising it separately lets mesh formation say
    /// *which* of its two roster preconditions failed.
    #[error("this node's own certificate is not in the pinned roster")]
    LocalNotInRoster,
    /// The session announced a threshold the pinned roster does not carry.
    #[error("the session announced threshold {announced} but the pinned roster is t={roster}")]
    RosterThreshold { announced: usize, roster: usize },
    /// The roster's rank for this node is not the rank the transport derived.
    ///
    /// Both are the lexicographic order of DER SPKIs, but the transport ranks
    /// over *connected* peers (`get_sorted_public_keys`, `quic.rs:1856-1872`)
    /// while the roster ranks over the whole membership, so they agree only at
    /// full connectivity. Checked after the barrier, where they must: a
    /// disagreement means this node would address every peer under the wrong
    /// index, and MPC traffic sent under a wrong index is not an error anywhere
    /// downstream — it is a silently wrong protocol run.
    #[error(
        "the pinned roster ranks this node {roster_rank} but the transport ranks it \
         {transport_rank}; the mesh is not the roster"
    )]
    RankMismatch {
        roster_rank: PartyId,
        transport_rank: PartyId,
    },
    /// A mesh join was asked to form a mesh with nothing to dial.
    #[error("a mesh join needs at least one address to dial: pass --peers, or seed the peer book")]
    NoSeeds,
    /// The transport lost a peer between the barrier and the handshake.
    #[error("the transport has no connection to party {party_id} after the mesh barrier passed")]
    PeerConnectionMissing { party_id: PartyId },
    /// The connection the transport hands out for a rank belongs to another
    /// roster member.
    #[error(
        "the connection the transport indexes as party {party_id} presents a certificate the \
         roster ranks {presented:?}"
    )]
    PeerIdentityMismatch {
        party_id: PartyId,
        presented: Option<PartyId>,
    },
    /// Sending to or reading from a peer failed during the join handshake.
    #[error("{operation} with party {party_id} failed: {reason}")]
    PeerExchange {
        party_id: PartyId,
        operation: &'static str,
        reason: String,
    },
    /// A peer sent a frame the handshake's lock-step script does not allow
    /// there.
    #[error("party {party_id} sent {got} where {expected} was expected")]
    UnexpectedFrame {
        party_id: PartyId,
        expected: &'static str,
        got: &'static str,
    },
    /// A peer announced a roster namespace other than this node's.
    ///
    /// The earliest membership disagreement is detectable: the `MeshReady`
    /// barrier frame carries the low 64 bits of the roster digest, so a peer
    /// pinned to a different roster is refused before a `JoinProposal` is
    /// written.
    #[error(
        "party {party_id} announced roster namespace {got:#018x}, not this node's \
         {expected:#018x}"
    )]
    RosterNamespaceMismatch {
        party_id: PartyId,
        expected: u64,
        got: u64,
    },
    /// Two parties proposed different sessions.
    ///
    /// This is the divergence the bootnode never checked: its `handle_register`
    /// compared only `program_id`, so a party registering with a different `n`,
    /// threshold or entry was admitted to a session it did not agree with.
    #[error("party {party_id} proposed a different {field}; this is not one session")]
    SessionDivergence {
        party_id: PartyId,
        field: SessionField,
    },
    /// A peer committed to a different session digest.
    ///
    /// The catch-all behind [`MeshError::SessionDivergence`]: the digest covers
    /// every agreed field including the epoch, so a party that agreed on every
    /// field separately but derived a different session is still caught here,
    /// before any MPC byte flows.
    #[error("party {party_id} committed to session {got} where this node committed {expected}")]
    CommitDivergence {
        party_id: PartyId,
        expected: String,
        got: String,
    },
    /// The join handshake did not finish in time.
    ///
    /// Fatal to the join by construction: the handshake reads a framed stream
    /// in lock-step, and a cancelled read can leave that stream positioned
    /// mid-frame, so there is no safe way to retry on the same connection.
    #[error("the mesh join handshake did not complete within {waited:?}")]
    HandshakeTimeout { waited: Duration },
    /// The monotone epoch could not be read, agreed or committed (blocker B5).
    #[error("{source}")]
    Epoch {
        #[from]
        source: EpochError,
    },
    /// A control frame could not be encoded or decoded.
    #[error("{source}")]
    Wire {
        #[from]
        source: MeshWireError,
    },
    /// Program bytes do not hash to the content address they travel under.
    #[error("{reason}")]
    ProgramMismatch { reason: String },
    /// A chunked program transfer could not be completed.
    #[error("program transfer failed: {reason}")]
    ProgramTransferFailed { reason: String },
    /// A barrier could not be announced to a peer.
    #[error("the {tag:?} barrier could not be announced to party {party_id}: {reason}")]
    BarrierUnannounceable {
        tag: BarrierTag,
        party_id: PartyId,
        reason: String,
    },
    /// A barrier expired before every peer reached it.
    #[error("the {tag:?} barrier reached {reached} of {expected} peers within {waited:?}")]
    BarrierIncomplete {
        tag: BarrierTag,
        reached: usize,
        expected: usize,
        waited: Duration,
    },
    /// A peer agreed to a different client admission set, or to a different
    /// execution summary, than this node was served
    /// (`docs/design/bootnode-elimination.md` §9.D.6).
    ///
    /// The coordinator served the nodes of one mesh different admissions: no
    /// mask share may be released and no input stored.
    #[error(
        "party {party_id} was served different client admissions than this node; \
         the coordinator is equivocating"
    )]
    AdmissionDivergence { party_id: PartyId },
    /// A peer received different masked inputs than this node (§9.D.6).
    #[error(
        "party {party_id} received different masked client inputs than this node; \
         the coordinator is equivocating"
    )]
    InputDivergence { party_id: PartyId },
    /// A digest barrier could not be announced to a peer.
    #[error("the {tag:?} barrier could not be announced to party {party_id}: {reason}")]
    DigestBarrierUnannounceable {
        tag: DigestBarrierTag,
        party_id: PartyId,
        reason: String,
    },
    /// A digest barrier expired before every peer announced its digest.
    #[error("the {tag:?} barrier reached {reached} of {expected} peers within {waited:?}")]
    DigestBarrierIncomplete {
        tag: DigestBarrierTag,
        reached: usize,
        expected: usize,
        waited: Duration,
    },
}

impl From<MeshError> for String {
    fn from(error: MeshError) -> Self {
        error.to_string()
    }
}

/// What a node asks for when it wants to join a session.
///
/// Everything here is this node's own proposal. Disagreement is resolved by
/// all-to-all digest equality, so a peer proposing a different session is named
/// and refused before any MPC byte flows — where the deleted bootnode resolved
/// it first-registrant-wins and never told anyone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// Index this node announces itself under.
    ///
    /// Not the index it will use: the runner discards the announced id and
    /// derives its party index from SPKI sort order (design doc §1).
    pub my_party_id: PartyId,
    /// Address peers should dial to reach this node.
    pub my_listen: SocketAddr,
    /// Content address of the program, from
    /// [`crate::net::program_sync::program_id_from_bytes`].
    pub program_id: [u8; 32],
    pub entry: String,
    pub n_parties: usize,
    pub threshold: usize,
    /// The coordinator execution this node was started for (`--execution-id`).
    ///
    /// Agreed like every other field: a party proposing another execution is
    /// refused with [`MeshError::SessionDivergence`] naming
    /// [`SessionField::ExecutionId`] (design doc §9.D.5).
    pub execution_id: SessionExecutionId,
    /// Bound on the join.
    pub timeout: Duration,
}

/// The session every node in the mesh agreed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSession {
    pub program_id: [u8; 32],
    /// MPC session namespace (`net/mpc/protocol_ids.rs`).
    ///
    /// Must be fresh per run — blocker B5.
    pub instance_id: u64,
    pub entry: String,
    pub parties: Vec<(PartyId, SocketAddr)>,
    pub n_parties: usize,
    pub threshold: usize,
}

/// How a node gets from "I hold a program and a certificate" to "I am in a
/// session with n-1 authenticated peers".
///
/// An implementation owns whatever bootstrap state it needs — a pinned roster,
/// seed hints and an epoch store, for the one that ships — and is handed the
/// caller's [`QuicNetworkManager`] to form the mesh on. It must leave that
/// manager connected to every other party, because the returned [`MeshSession`]
/// is the runner's signal that the transport is ready for MPC traffic.
///
/// The trait outlives the second implementation it was introduced for: it is
/// what keeps the runner's two join sites blind to how a session is formed, so
/// the coordinator-issued roster (design doc §9.D) reaches [`MeshJoin`] as a
/// constructor argument without editing them.
///
/// `Debug` is a supertrait so that a caller holding a `Box<dyn SessionJoin>` can
/// still say *which* join it built.
#[async_trait::async_trait]
pub trait SessionJoin: std::fmt::Debug + Send + Sync {
    async fn join(
        &self,
        net: &mut QuicNetworkManager,
        request: JoinRequest,
    ) -> MeshResult<MeshSession>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The join request is this node's proposal, and it carries no program
    /// bytes: Stage 8 deleted that field with the bootnode's custody path, which
    /// was inert anyway (design doc §2). A mesh member that needs the program
    /// pulls it, verified, from a peer (`net::mesh::program`).
    #[test]
    fn a_join_request_proposes_a_session_and_offers_no_program_bytes() {
        let request = JoinRequest {
            my_party_id: 1,
            my_listen: "127.0.0.1:9001".parse().expect("parse listen address"),
            program_id: [7u8; 32],
            entry: "main".to_string(),
            n_parties: 5,
            threshold: 1,
            execution_id: SessionExecutionId::from_bytes([9u8; 32]),
            timeout: Duration::from_secs(120),
        };

        assert_eq!(request.n_parties, 5);
        assert_eq!(request.threshold, 1);
        assert_eq!(request.execution_id.as_bytes(), &[9u8; 32]);
    }

    /// Every remaining [`MeshError`] names what disagreed and with whom. The
    /// untyped `Join { reason }` pass-through that used to sit in front of the
    /// bootnode's `Result<_, String>` is gone, so an unexplained failure string
    /// can no longer reach a caller through this type.
    #[test]
    fn a_session_divergence_names_the_party_and_the_field() {
        let error = MeshError::SessionDivergence {
            party_id: 3,
            field: SessionField::Threshold,
        };

        let rendered = error.to_string();
        assert!(rendered.contains("party 3"), "{rendered}");
        assert!(rendered.contains("this is not one session"), "{rendered}");
    }
}
