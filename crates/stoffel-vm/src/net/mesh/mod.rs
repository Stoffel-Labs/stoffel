//! The session-join seam, and the roster-pinned mesh behind it.
//!
//! `docs/design/bootnode-elimination.md`. [`SessionJoin`] sits in front of the
//! runner's join sites so that how a mesh is formed is not written into them;
//! [`MeshJoin`] is the only implementation there is.
//!
//! # What the seam deliberately does not carry
//!
//! [`JoinRequest`] is what a node asks for, and nothing more. Two omissions are
//! the point:
//!
//! * There is no bootstrap address. That was *construction* state of one
//!   implementation, never something a caller asks for, and a roster-pinned
//!   mesh has no single address to put there — it has seed hints and a roster.
//! * There are no `tls_ids`. Relaying peer transport identities through a third
//!   party is what the whole migration existed to delete (design doc §2);
//!   membership is now the certificate allowlist installed from the roster, so
//!   an address is a hint and only a certificate is an identity.
//!
//! # The mesh is per roster, and many executions ride one
//!
//! §12.D. A standing node hosts many concurrent instances on one
//! certificate-pinned transport, so it cannot re-join per computation and the
//! mesh it joins commits to the roster alone — `n` and `t` are inside the
//! roster digest, so agreeing the digest agrees them with it. One-shot mode
//! exists to run exactly one execution, so it commits to that execution as
//! well, through [`JoinRequest::session`]. That commitment is where the only
//! check on whether `n` processes are running the *same* computation lives.

pub mod dial;
pub mod join;
pub mod pex;
pub mod wire;

pub use dial::{
    dial_address_expecting, dial_peer_expecting, reconnect_sweep, DialOutcome, DialPolicy,
    ReconnectPolicy, ReconnectSupervisor, ReconnectSweep, ReconnectTarget,
};
pub use join::{
    dial_duties, dials_towards, join_mesh, session_digest, wait_until_mesh_connected, MeshJoin,
    MeshJoinTimeouts, SessionField, MESH_BARRIER_POLL_INTERVAL, SESSION_DIGEST_CONTEXT,
};
pub use pex::{
    PeerBook, PeerDirectory, PeerRecord, PexLimits, PexOutcome, RecordSource, SeedHints,
    DEFAULT_PEX_MAX_PEERS, MAX_PEX_SEQ_JUMP,
};
pub use wire::{
    MeshMessage, MeshWireError, ReservedPrefix, SessionCommitment, MAX_MESH_MESSAGE_LEN,
    MAX_PEER_RECORDS_PER_MESSAGE, MESH_CTRL_PREFIX, MESH_READY_PREFIX,
};

use std::net::SocketAddr;
use std::time::Duration;

use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::net::roster::RosterError;

pub type MeshResult<T> = Result<T, MeshError>;

/// Why a [`SessionJoin`] did not produce a mesh.
///
/// `#[non_exhaustive]`: every variant here is a typed failure of mesh formation
/// or agreement, and the set is expected to keep growing as the mesh learns to
/// report more precisely. There is deliberately no untyped `{reason}`
/// pass-through: an unexplained failure string cannot reach a caller through
/// this type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MeshError {
    /// The connectivity barrier expired before this node held every peer's
    /// authenticated public key.
    ///
    /// `expected` is the full party count including self.
    #[error("mesh did not reach {expected} authenticated parties within {waited:?}")]
    MeshIncomplete { expected: usize, waited: Duration },
    /// The pinned roster could not be installed as the transport's
    /// peer-certificate allowlist.
    ///
    /// Rendered without a prefix: [`RosterError`]'s own messages already name
    /// the roster, and the runner prints this behind `Mesh formation failed: `.
    #[error(transparent)]
    Roster(#[from] RosterError),
    /// The caller asked for a different number of parties than the pinned
    /// roster admits.
    ///
    /// The roster is the definition of the mesh, so this is a disagreement
    /// about membership, not a recoverable count mismatch.
    #[error(
        "this node was configured for {configured} parties but the pinned roster admits {roster}"
    )]
    RosterSize { configured: usize, roster: usize },
    /// The caller asked for a threshold the pinned roster does not carry.
    #[error(
        "this node was configured for threshold {configured} but the pinned roster is t={roster}"
    )]
    RosterThreshold { configured: usize, roster: usize },
    /// This node's own certificate is not one of the roster's nodes.
    ///
    /// `install_expected_server_public_keys` refuses this too
    /// (`quic.rs:1301-1305`); raising it separately lets mesh formation say
    /// *which* of its two roster preconditions failed.
    #[error("this node's own certificate is not in the pinned roster")]
    LocalNotInRoster,
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
    /// The earliest membership disagreement is detectable: the mesh-ready frame
    /// carries the low 64 bits of the roster digest, so a peer pinned to a
    /// different roster is refused before a commitment is decoded.
    #[error(
        "party {party_id} announced roster namespace {got:#018x}, not this node's \
         {expected:#018x}"
    )]
    RosterNamespaceMismatch {
        party_id: PartyId,
        expected: u64,
        got: u64,
    },
    /// Two parties committed to different meshes, or to different executions
    /// on one mesh.
    ///
    /// Every agreed field is compared, not just the program: a party running
    /// with a different `n`, threshold or entry point is running a differently
    /// parameterised protocol, and no layer below reports that — a wrong
    /// threshold is not a decode error, it is a silently wrong reconstruction.
    #[error("party {party_id} committed to a different {field}; this is not one mesh")]
    CommitDivergence {
        party_id: PartyId,
        field: SessionField,
    },
    /// A peer's commitment agreed field by field and still digested
    /// differently.
    ///
    /// The catch-all behind [`MeshError::CommitDivergence`]: the digest covers
    /// every committed field, so a field added to the frame without being added
    /// to the comparison is still caught here, before any MPC byte flows.
    #[error(
        "party {party_id} digested its commitment as {got} where this node digested {expected}"
    )]
    CommitDigestDivergence {
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
    /// A control frame could not be encoded or decoded.
    #[error(transparent)]
    Wire(#[from] MeshWireError),
}

impl From<MeshError> for String {
    fn from(error: MeshError) -> Self {
        error.to_string()
    }
}

/// What a node asks for when it wants to join its roster's mesh.
///
/// Everything here is this node's own proposal, and nothing about it is
/// authoritative: disagreement is resolved by all-to-all equality, so a peer
/// committing to a different mesh is named and refused before any MPC byte
/// flows. No party's view wins by arriving first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// Index this node announces itself under, for log lines only.
    ///
    /// Not the index it will use: the index on the wire is this node's rank in
    /// the roster's lexicographic SPKI order, and the join refuses to proceed
    /// unless the transport derives the same one
    /// ([`MeshError::RankMismatch`]).
    pub my_party_id: PartyId,
    /// Address peers should dial to reach this node.
    pub my_listen: SocketAddr,
    /// Party count this node was configured for. Checked against the roster,
    /// which is the only authority for it.
    pub n_parties: usize,
    /// Threshold this node was configured for. Checked against the roster.
    pub threshold: usize,
    /// The one execution this mesh exists to run, in one-shot mode.
    ///
    /// `None` on a standing node: many concurrent executions ride one mesh, so
    /// there is no mesh-wide program or entry point to agree on (§12.D).
    pub session: Option<SessionCommitment>,
    /// Bound on the join.
    pub timeout: Duration,
}

/// The transport every node of one roster shares.
///
/// Carries no instance id: a `u64` MPC session namespace is per execution and
/// is derived from the execution id
/// ([`crate::net::session::derive_instance_id_for_execution`]), of which many
/// ride one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshTransport {
    /// The roster every member of this mesh committed to, byte for byte.
    pub roster_digest: [u8; 32],
    /// The digest every member committed to, which equals the roster digest's
    /// commitment when [`JoinRequest::session`] is `None` and covers the
    /// execution as well when it is not.
    pub commit_digest: [u8; 32],
    /// Where each party says it listens, by roster rank.
    pub parties: Vec<(PartyId, SocketAddr)>,
    pub n_parties: usize,
    pub threshold: usize,
}

/// How a node gets from "I hold a certificate and a roster" to "I am in a mesh
/// with n-1 authenticated peers".
///
/// An implementation owns whatever bootstrap state it needs — a pinned roster,
/// seed hints and a peer directory, for the one that ships — and is handed the
/// caller's [`QuicNetworkManager`] to form the mesh on. It must leave that
/// manager connected to every other party, because the returned
/// [`MeshTransport`] is the runner's signal that the transport is ready for MPC
/// traffic.
///
/// `Debug` is a supertrait so that a caller holding a `Box<dyn SessionJoin>`
/// can still say *which* join it built.
#[async_trait::async_trait]
pub trait SessionJoin: std::fmt::Debug + Send + Sync {
    async fn join(
        &self,
        net: &mut QuicNetworkManager,
        request: JoinRequest,
    ) -> MeshResult<MeshTransport>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::session::ExecutionId;

    /// The join request is this node's proposal, and it carries no program
    /// bytes. A program reaches a node through its own catalog or path (design
    /// doc §2); what travels is its content address, so parties that loaded
    /// different bytes diverge at the commitment instead of agreeing.
    #[test]
    fn a_join_request_proposes_a_mesh_and_offers_no_program_bytes() {
        let request = JoinRequest {
            my_party_id: 1,
            my_listen: "127.0.0.1:9001".parse().expect("parse listen address"),
            n_parties: 5,
            threshold: 1,
            session: Some(SessionCommitment {
                execution_id: ExecutionId::from_bytes([9u8; 32]),
                program_id: [7u8; 32],
                entry: "main".to_string(),
            }),
            timeout: Duration::from_secs(120),
        };

        assert_eq!(request.n_parties, 5);
        assert_eq!(request.threshold, 1);
        assert_eq!(
            request.session.expect("one-shot session").execution_id,
            ExecutionId::from_bytes([9u8; 32])
        );
    }

    /// A standing node's request commits to no execution, because many ride
    /// the mesh it is joining.
    #[test]
    fn a_standing_join_request_commits_to_no_execution() {
        let request = JoinRequest {
            my_party_id: 0,
            my_listen: "127.0.0.1:9000".parse().expect("parse listen address"),
            n_parties: 5,
            threshold: 1,
            session: None,
            timeout: Duration::from_secs(120),
        };

        assert!(request.session.is_none());
    }

    /// Every remaining [`MeshError`] names what disagreed and with whom.
    #[test]
    fn a_commit_divergence_names_the_party_and_the_field() {
        let error = MeshError::CommitDivergence {
            party_id: 3,
            field: SessionField::Threshold,
        };

        let rendered = error.to_string();
        assert!(rendered.contains("party 3"), "{rendered}");
        assert!(rendered.contains("this is not one mesh"), "{rendered}");
    }
}
