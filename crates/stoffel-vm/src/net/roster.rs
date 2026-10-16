//! The node roster: membership as a set of node SPKIs, served by the coordinator.
//!
//! `docs/design/bootnode-elimination.md` §9.D.4. The coordinator is the only
//! roster authority (§8, §9 rule 1): a node fetches the node roster once at
//! startup over a connection pinned to the coordinator's certificate, builds a
//! [`Roster`] from the served certificates with [`Roster::from_coordinator`],
//! installs it once as the mesh transport's peer-certificate allowlist, and
//! never re-fetches it. There is no join, leave or rotation.
//!
//! Every party does this: a standing node once at startup, and a one-shot party
//! before it binds a socket. The roster is also the party *set*, so a party's
//! index on the wire is its rank in the lexicographic order of the node SPKIs —
//! which is the order the transport independently derives from the same
//! certificates, and [`crate::net::mesh::join_mesh`] refuses to go on unless
//! the two agree. `--party-id` is a label for on-disk state and nothing else.
//!
//! A roster holds **nodes only**, and [`Roster::install_into`] is the only
//! thing that sets the *mesh* transport's party allowlist: it installs the node
//! keys and nothing else, and it refuses to run if the allowlist is already
//! non-empty and different, so nothing may precede it.
//!
//! A client installs the same roster from the other side with
//! [`Roster::install_for_client`], which is the only thing that sets a
//! *client* transport's allowlist and carries the same freeze — it refuses a
//! transport that already has one. Neither function may overwrite an installed
//! set: a roster is the first writer of a transport's allowlist or it is no
//! writer at all. A client is not a roster member, so it binds
//! no listener and its own key enters no allowlist; what the roster gives it is
//! the set of node certificates its dials are authorized against, so the node
//! set a client reaches is the coordinator's and an operator's address list
//! alone cannot add to it. There is no coordinator-less client:
//! `a_client_pinned_to_the_roster_reaches_only_its_nodes` pins what an unpinned
//! one would have accepted.
//!
//! Nothing in this crate writes a mesh allowlist other than
//! [`Roster::install_into`], and in particular no client key enters one. §6
//! blocker B1 is closed by [`NodeListeners`]: a standing node binds two
//! transports, the roster-pinned mesh and a client-facing listener that carries
//! no allowlist at all, and the coordinator's per-execution admission —
//! enforced by
//! [`ExecutionTransportMux`](crate::net::execution_transport::ExecutionTransportMux)
//! against the published client roster — is the whole of client authorization
//! (§9 rule 3). The split is necessary because stoffelnet authorizes a
//! connection's certificate *before* it knows the connection's ALPN role, so a
//! key in a transport's allowlist has node-level standing on that transport
//! whatever role it dials with:
//! `an_allowlisted_non_node_key_is_ranked_as_a_server_peer` pins that cost, and
//! `a_client_the_mesh_refuses_reaches_the_client_facing_listener` pins both
//! halves of the resolution.
//!
//! The listeners are scanned with matching
//! [`ExecutionScannerScope`](crate::net::execution_transport::ExecutionScannerScope)s,
//! so a dial that negotiated the *server* ALPN on the unauthorized listener
//! cannot be attributed to a party.
//!
//! A transport that authorizes nobody decides nothing about who may hold a
//! connection, which is a separate problem with a separate answer one layer up:
//! [`ClientIngressGate`](crate::net::client_ingress::ClientIngressGate) holds
//! the client-facing listener to the coordinator's admissions. It keeps a
//! connection only for a certificate some registered execution's published
//! client roster names, caps what those admissions may occupy, and refuses a
//! connection whose certificate identity the handshake never exposed —
//! stoffelnet can admit one on a listener with no allowlist, and it could never
//! match a published admission. So every client connection a node holds is one
//! the coordinator admitted, without any client key acquiring the node-level
//! standing a transport allowlist would give it.
//!
//! # Three ways this silently breaks, and what stops each one
//!
//! **B2 — the SPKI byte shape.** stoffelnet authorizes against the full DER
//! `SubjectPublicKeyInfo` that [`QuicNetworkManager::public_key_from_certificate_der`]
//! returns, while the coordinator's `ClientIdentity` is the bare BIT STRING
//! inside it — different bytes from the same certificate. The coordinator
//! therefore serves full certificate DERs, and [`Roster::from_coordinator`]
//! derives every key with stoffelnet's own extraction and nothing else;
//! `a_roster_key_is_the_full_spki_not_the_bare_bit_string` pins the difference.
//!
//! **B3 — an empty allowlist disables the check.** stoffelnet's
//! `verify_peer_public_key_allowed` returns `Ok(())` when the set is empty, so a
//! roster that parsed to nothing would produce a mesh with *no* peer
//! authorization rather than a loud failure. [`Roster::from_node_keys`] refuses
//! an empty node set before the transport is touched, and
//! [`Roster::install_into`] re-reads `has_certificate_public_key_allowlist`
//! afterwards so the enabled-ness is observed rather than assumed.
//!
//! **A drifted digest.** `stoffel-vm` does not depend on the coordinator
//! crates, so it implements the §9.B digest itself. [`Roster::from_coordinator`]
//! recomputes it over the served certificates and refuses a roster whose served
//! digest differs ([`RosterError::DigestMismatch`]), so a drifted implementation
//! on either side is a refusal rather than an installed roster nobody checked.
//!
//! # The bounds are the coordinator's
//!
//! [`Roster::from_node_keys`] refuses `t == 0` — with `t = 0` every single node
//! could reconstruct every client mask — and `n < 2t + 1`, exactly as the
//! coordinator's `NodeRoster::new` does, so a drifted or forged served roster is
//! checked no more weakly here than there. The canonical-encoding check of §9.A
//! is not repeated: every certificate reaches [`Roster::from_coordinator`] only
//! after the coordinator crate's `NodeRoster::try_from` ran it.

use std::collections::HashMap;
use std::net::SocketAddr;

use stoffelnet::network_utils::{NodePublicKey, PartyId};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};

/// BLAKE3 derive-key context for [`Roster::digest`].
///
/// The coordinator's node-roster digest (design doc §9.B), byte for byte: `n`
/// and `t` as 8-byte little-endian integers, then every node SPKI in canonical
/// order, each prefixed by its 8-byte little-endian length.
pub const ROSTER_DIGEST_CONTEXT: &str = "stoffel-coordinator-node-roster-v1";

/// Why a roster could not be built, or could not be installed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RosterError {
    /// Blocker B3: an empty allowlist disables peer authorization entirely.
    #[error("the node roster is empty; an empty certificate allowlist disables peer authorization instead of enforcing it")]
    Empty,
    /// Two roster entries are the same certificate, or two distinct
    /// certificates share a compact id.
    ///
    /// Either way `n` would not be the number of distinct admissible nodes, and
    /// `install_expected_server_public_keys` would quietly install fewer keys
    /// than the roster listed.
    #[error("two node roster entries collide at compact party id {compact_id}")]
    DuplicateNode { compact_id: usize },
    /// `t == 0`: every single node could reconstruct every client mask.
    #[error("the node roster has threshold 0; every single node could reconstruct every secret")]
    ZeroThreshold,
    /// `n < 2t + 1`.
    #[error(
        "threshold {threshold} needs at least {} nodes, and the node roster has {n}",
        threshold.saturating_mul(2).saturating_add(1)
    )]
    ThresholdTooLarge { n: usize, threshold: usize },
    /// The coordinator served a digest that is not the §9.B digest of the
    /// certificates it served alongside it.
    #[error(
        "the coordinator's roster digest {} does not match its certificates ({})",
        hex::encode(served),
        hex::encode(computed)
    )]
    DigestMismatch {
        served: [u8; 32],
        computed: [u8; 32],
    },
    /// A served certificate stoffelnet cannot derive an SPKI from.
    #[error("served node certificate {index} is not a certificate the transport can derive a key from: {reason}")]
    ServedCertificateUnderivable { index: usize, reason: String },
    /// stoffelnet refused the roster. Carries its message verbatim.
    #[error("the transport refused the certificate roster: {reason}")]
    InstallRejected { reason: String },
    /// Blocker B3, observed after the fact: the transport reports no allowlist.
    #[error("the certificate allowlist is empty after installing {nodes} nodes; peer authorization would be silently disabled")]
    AllowlistDisabled { nodes: usize },
    /// A client transport already carried a certificate allowlist, so
    /// installing the roster would silently replace whatever was pinned there.
    ///
    /// [`Roster::install_for_client`]'s freeze, mirroring the one
    /// `install_expected_server_public_keys` applies for the mesh: the roster
    /// may be the *first* writer of a transport's allowlist and never the
    /// second.
    #[error(
        "the client transport already has a certificate allowlist; installing the {nodes}-node \
         roster would replace a pin this roster did not set"
    )]
    ClientAllowlistAlreadyInstalled { nodes: usize },
    /// The node's own certificate or key is not something the transport will
    /// take, so neither listener can be brought up under this identity.
    #[error("configure the node certificate: {reason}")]
    LocalCertificateRejected { reason: String },
    /// One of the two listeners could not bind.
    #[error("listen for {listener} on {address}: {reason}")]
    ListenFailed {
        listener: NodeListener,
        address: SocketAddr,
        reason: String,
    },
    /// The client-facing listener came up with a certificate allowlist, which
    /// would refuse every client at the handshake instead of deferring the
    /// decision to per-execution admission.
    #[error(
        "the client-facing listener has a certificate allowlist; client admission is the \
         coordinator's per-execution decision and must not be pre-empted at the transport"
    )]
    ClientListenerIsAllowlisted,
    /// The two listeners were asked to bind the same socket, which would put
    /// one transport's allowlist in front of the other's traffic.
    #[error("the node mesh and the client-facing listener were both given {address}")]
    ListenersShareAnAddress { address: SocketAddr },
}

/// Which of a standing node's two listeners something is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeListener {
    /// The roster-pinned party mesh.
    NodeMesh,
    /// The client-facing listener, which authorizes no certificate.
    ClientFacing,
}

impl std::fmt::Display for NodeListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NodeMesh => "the node mesh",
            Self::ClientFacing => "the client-facing listener",
        })
    }
}

/// The two transports a standing node binds, and the only place either one's
/// certificate allowlist is decided.
///
/// Design doc §9 rule 3, and the close of §6 blocker B1. stoffelnet authorizes
/// a peer certificate before it knows the connection's ALPN role, so a key in a
/// transport's allowlist is a key with *node-level* standing on that transport:
/// it is admitted with the server ALPN, counted by `is_fully_connected` and
/// ranked by `get_sorted_public_keys`, which is the party-index order
/// ([`an_allowlisted_non_node_key_is_ranked_as_a_server_peer`](self#tests)).
/// A node therefore cannot authorize its clients and its peers on one socket,
/// and this type is the split:
///
/// * [`NodeListeners::mesh`] carries the coordinator's roster as its allowlist
///   and nothing else. [`Roster::install_into`] is its only writer, it runs
///   before the socket is bound, and no other code may add a key to it.
/// * [`NodeListeners::clients`] carries **no** allowlist, so every client
///   certificate reaches the handshake and no client key gains node-level
///   standing. The coordinator's per-execution admissions — held by
///   [`crate::net::execution_transport::ExecutionTransportMux`] — are the whole
///   of client authorization, asked twice over: by
///   [`ClientIngressGate`](crate::net::client_ingress::ClientIngressGate) on
///   accept, which keeps a connection only for a certificate some registered
///   execution names, and per frame in `authorize_client_route_if_registered`,
///   which admits it into that one execution and no other.
///
/// The two managers are constructed here rather than cloned from one another:
/// `allowed_peer_public_keys` is an `Arc<DashSet>` shared across `clone()`, so
/// a clone of the mesh manager would carry the mesh allowlist and refuse every
/// client, and a clone taken before the install would share the set the install
/// later fills.
///
/// Scanning them is scoped accordingly:
/// [`ExecutionScannerScope::Parties`](crate::net::execution_transport::ExecutionScannerScope::Parties)
/// for the mesh and
/// [`Clients`](crate::net::execution_transport::ExecutionScannerScope::Clients)
/// for the client-facing listener, so a dial that negotiated the server ALPN on
/// the unauthorized listener cannot be attributed to a party.
#[derive(Debug)]
pub struct NodeListeners {
    mesh: QuicNetworkManager,
    clients: QuicNetworkManager,
}

impl NodeListeners {
    /// Bind both listeners under the node's own certificate.
    ///
    /// The mesh is given `roster` as its allowlist before it binds, and the
    /// client-facing listener is read back afterwards to confirm it has none.
    pub async fn bind(
        roster: &Roster,
        party_id: PartyId,
        certificate_der: Vec<u8>,
        key_der: Vec<u8>,
        mesh_bind: SocketAddr,
        client_bind: SocketAddr,
    ) -> Result<Self, RosterError> {
        if mesh_bind == client_bind {
            return Err(RosterError::ListenersShareAnAddress { address: mesh_bind });
        }

        let mut mesh = QuicNetworkManager::with_node_id(party_id);
        mesh.set_local_certificate_der(certificate_der.clone(), key_der.clone())
            .map_err(|reason| RosterError::LocalCertificateRejected { reason })?;
        // Nothing may precede this: an allowlist that is already non-empty and
        // different freezes the install out, and an empty one would disable
        // peer authorization altogether rather than enforce it.
        roster.install_into(&mut mesh)?;
        mesh.listen(mesh_bind)
            .await
            .map_err(|reason| RosterError::ListenFailed {
                listener: NodeListener::NodeMesh,
                address: mesh_bind,
                reason,
            })?;

        let mut clients = QuicNetworkManager::with_node_id(party_id);
        clients
            .set_local_certificate_der(certificate_der, key_der)
            .map_err(|reason| RosterError::LocalCertificateRejected { reason })?;
        clients
            .listen(client_bind)
            .await
            .map_err(|reason| RosterError::ListenFailed {
                listener: NodeListener::ClientFacing,
                address: client_bind,
                reason,
            })?;
        // Read back rather than assumed, for the same reason `install_into`
        // reads its own allowlist back: this is the statement that client
        // authorization has *not* been pre-empted at the transport.
        if clients.has_certificate_public_key_allowlist() {
            return Err(RosterError::ClientListenerIsAllowlisted);
        }

        Ok(Self { mesh, clients })
    }

    /// The roster-pinned party mesh.
    pub fn mesh(&self) -> &QuicNetworkManager {
        &self.mesh
    }

    /// The roster-pinned party mesh, for mesh formation, which assigns party
    /// ids and therefore needs `&mut`.
    ///
    /// There is deliberately no mutable accessor for anything that would let a
    /// caller write the allowlist: `install_expected_server_public_keys` and
    /// `add_allowed_certificate_public_key` both take `&mut self` on the
    /// manager, so handing out `&mut` here is the one seam that has to stay
    /// narrow — mesh formation is its only caller.
    pub fn mesh_mut(&mut self) -> &mut QuicNetworkManager {
        &mut self.mesh
    }

    /// The client-facing listener, which authorizes no certificate.
    pub fn clients(&self) -> &QuicNetworkManager {
        &self.clients
    }

    /// Take the two managers apart once both listeners are up and the mesh has
    /// formed.
    pub fn into_parts(self) -> (QuicNetworkManager, QuicNetworkManager) {
        (self.mesh, self.clients)
    }
}

/// Who the parties are: the node certificates the coordinator serves, and the
/// `(n, t)` they come with.
///
/// `nodes` are kept in lexicographic order of their DER SPKI bytes, which is
/// both the coordinator's canonical order and the order
/// `QuicNetworkManager::get_sorted_public_keys` puts them in, so
/// [`Roster::index_of`] returns the same index the transport's party assignment
/// will, and node `i` of the served roster is party `i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    nodes: Vec<NodePublicKey>,
    n: usize,
    t: usize,
    digest: [u8; 32],
}

impl Roster {
    /// Build a roster from already-derived SPKIs.
    ///
    /// Sorts, then refuses, in this order: an empty set ([`RosterError::Empty`]),
    /// compact-id collisions ([`RosterError::DuplicateNode`]), `t == 0`
    /// ([`RosterError::ZeroThreshold`]) and `n < 2t + 1`
    /// ([`RosterError::ThresholdTooLarge`]); then computes the §9.B digest from
    /// the key bytes.
    pub fn from_node_keys(keys: Vec<NodePublicKey>, threshold: usize) -> Result<Self, RosterError> {
        let mut nodes = keys;
        nodes.sort_by(|left, right| left.0.cmp(&right.0));

        let n = nodes.len();
        if n == 0 {
            return Err(RosterError::Empty);
        }

        // Reject both "the same certificate twice" and "two certificates whose
        // compact ids collide" in one pass: `derive_id` is what
        // `install_expected_server_public_keys` dedupes on, so either case
        // makes the installed allowlist smaller than `n`.
        let mut by_compact_id: HashMap<usize, &NodePublicKey> = HashMap::with_capacity(n);
        for key in &nodes {
            let compact_id = key.derive_id();
            if by_compact_id.insert(compact_id, key).is_some() {
                return Err(RosterError::DuplicateNode { compact_id });
            }
        }

        if threshold == 0 {
            return Err(RosterError::ZeroThreshold);
        }
        if n < threshold.saturating_mul(2).saturating_add(1) {
            return Err(RosterError::ThresholdTooLarge { n, threshold });
        }

        let digest = node_roster_digest(&nodes, threshold);
        Ok(Self {
            nodes,
            n,
            t: threshold,
            digest,
        })
    }

    /// Build the roster the coordinator served.
    ///
    /// `certificates` are the served node certificate DERs, `threshold` and
    /// `served_digest` the served `t` and digest. Derives every key with
    /// [`QuicNetworkManager::public_key_from_certificate_der`] (blocker B2) —
    /// never the VM's own bare-BIT-STRING extraction — calls
    /// [`Roster::from_node_keys`], and refuses a served digest that differs
    /// from the recomputed one.
    pub fn from_coordinator(
        certificates: &[&[u8]],
        threshold: u64,
        served_digest: [u8; 32],
    ) -> Result<Self, RosterError> {
        let keys = certificates
            .iter()
            .enumerate()
            .map(|(index, certificate)| {
                QuicNetworkManager::public_key_from_certificate_der(certificate)
                    .map_err(|reason| RosterError::ServedCertificateUnderivable { index, reason })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // A threshold beyond `usize` is beyond any roster's `2t + 1` bound.
        let threshold = usize::try_from(threshold).unwrap_or(usize::MAX);
        let roster = Self::from_node_keys(keys, threshold)?;
        if roster.digest != served_digest {
            return Err(RosterError::DigestMismatch {
                served: served_digest,
                computed: roster.digest,
            });
        }
        Ok(roster)
    }

    /// The node certificates' SPKIs, in lexicographic (party-index) order.
    pub fn nodes(&self) -> &[NodePublicKey] {
        &self.nodes
    }

    /// Number of parties.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Corruption threshold.
    pub fn t(&self) -> usize {
        self.t
    }

    /// The coordinator's node-roster digest (design doc §9.B), computed once
    /// when the roster is built.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Rank of `key` among the node certificates, or `None` if it is not one.
    ///
    /// This is the party index the transport will independently derive from the
    /// same certificate, because both orderings are the lexicographic order of
    /// the DER bytes.
    pub fn index_of(&self, key: &NodePublicKey) -> Option<PartyId> {
        self.nodes
            .binary_search_by(|candidate| candidate.0.cmp(&key.0))
            .ok()
    }

    /// The node certificate the roster ranks `rank`, or `None` if `rank` is
    /// outside the roster. The inverse of [`Roster::index_of`], which is what
    /// lets a dial be pinned to the party it is meant for.
    pub fn key_of(&self, rank: PartyId) -> Option<&NodePublicKey> {
        self.nodes.get(rank)
    }

    /// Make this roster the transport's peer-certificate allowlist: the nodes,
    /// and nothing else.
    ///
    /// `install_expected_server_public_keys` requires the local certificate to
    /// already be installed and the local key to be in the roster, and it
    /// refuses to run at all if the allowlist is already non-empty and
    /// different — one more reason no non-node key may enter the allowlist
    /// before it.
    ///
    /// Must run before the manager is shared. It takes `&mut self` on the
    /// transport, and it rejects a roster that omits an already-connected peer,
    /// so it belongs at the very start of mesh formation — before any dial,
    /// before the accept loop is spawned, and before `Arc::new(manager)`.
    pub fn install_into(&self, net: &mut QuicNetworkManager) -> Result<(), RosterError> {
        net.install_expected_server_public_keys(self.nodes.iter().cloned())
            .map_err(|reason| RosterError::InstallRejected { reason })?;
        self.observe_allowlist_enabled(net)
    }

    /// Make this roster a *client's* peer-certificate allowlist: a client may
    /// hold a connection to a node of this roster and to nothing else.
    ///
    /// This is the other half of §9 rule 1 read from the client's side. A
    /// client is told which nodes exist by the coordinator it pinned, and the
    /// certificates it pins them to are the ones that roster served — so the
    /// node set a client dials is the coordinator's, never an operator's
    /// `--servers` list on its own. `connect_as_client` runs
    /// `verify_peer_public_key_allowed` against this set before it opens a
    /// stream, so a certificate the roster does not name is refused at the
    /// handshake rather than trusted because it answered the address.
    ///
    /// [`Roster::install_into`] cannot serve here:
    /// `install_expected_server_public_keys` requires the local key to be one
    /// of the keys it installs, and a client is deliberately not a roster
    /// member. The allowlist is therefore set through stoffelnet's unguarded
    /// `set_allowed_certificate_public_keys`, which *clears* the set before it
    /// writes — so this carries the freeze `install_expected_server_public_keys`
    /// would have carried, and refuses a transport that already has an
    /// allowlist ([`RosterError::ClientAllowlistAlreadyInstalled`]) rather than
    /// replacing a pin it did not set. The roster is the first writer of a
    /// transport's allowlist or it is no writer at all.
    ///
    /// The enabled-ness is then read back for exactly the reason
    /// `install_into` reads it back — blocker B3, an empty set makes
    /// `verify_peer_public_key_allowed` return `Ok(())` for every peer.
    ///
    /// Unlike the mesh install this sets no local certificate and binds no
    /// listener: a client accepts nothing. Run it before the first dial, while
    /// the manager is still owned exclusively.
    pub fn install_for_client(&self, net: &mut QuicNetworkManager) -> Result<(), RosterError> {
        if net.has_certificate_public_key_allowlist() {
            return Err(RosterError::ClientAllowlistAlreadyInstalled {
                nodes: self.nodes.len(),
            });
        }
        net.set_allowed_certificate_public_keys(self.nodes.to_vec());
        self.observe_allowlist_enabled(net)
    }

    /// Blocker B3, read back from the transport rather than inferred: "the
    /// roster installed" and "peer authorization is on" are separate
    /// statements, and only the transport can make the second one.
    fn observe_allowlist_enabled(&self, net: &QuicNetworkManager) -> Result<(), RosterError> {
        if !net.has_certificate_public_key_allowlist() {
            return Err(RosterError::AllowlistDisabled {
                nodes: self.nodes.len(),
            });
        }

        Ok(())
    }
}

/// The §9.B digest over sorted node SPKIs.
fn node_roster_digest(sorted_nodes: &[NodePublicKey], threshold: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ROSTER_DIGEST_CONTEXT);
    hasher.update(&(sorted_nodes.len() as u64).to_le_bytes());
    hasher.update(&(threshold as u64).to_le_bytes());
    for key in sorted_nodes {
        hasher.update(&(key.0.len() as u64).to_le_bytes());
        hasher.update(&key.0);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::path::PathBuf;
    use std::time::Duration;

    use std::sync::Arc;

    use stoffelnet::transports::quic::{NetworkManager, PeerConnection};
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;
    use crate::net::client_ingress::{
        ClientIngressDecision, ClientIngressGate, ClientIngressLimits,
    };
    use crate::net::execution_transport::{
        encode_execution_frame, ExecutionConnectionScanner, ExecutionMessageKind,
        ExecutionScannerScope, ExecutionTransportMux, ExecutionTransportSource,
        EXECUTION_CLIENT_ROUTE_HELLO_V1,
    };
    use crate::net::session::ExecutionId;
    use crate::tests::test_utils::init_crypto_provider;

    /// Budget for one loopback QUIC handshake in the enforcement tests.
    ///
    /// Generous on purpose: it bounds a test that would otherwise hang, and is
    /// never the thing under test.
    const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

    /// The §9.B golden vector: `ids/nodes/cert{0..4}.crt` with `t = 1`.
    ///
    /// The coordinator's `node_roster_golden_vector_matches_the_shipped_node_certificates`
    /// asserts the same order and the same digest over byte-identical
    /// certificates, so the two digest implementations cannot drift apart
    /// unnoticed.
    const GOLDEN_DIGEST: &str = "da7fa2fee0f97aaef9e77aa8534a2be721fbaf3ab26a52b5c2fd560f41a8e00d";

    struct Identity {
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        public_key: NodePublicKey,
    }

    fn generate_identity() -> Identity {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed certificate");
        let cert_der = generated.cert.der().to_vec();
        let key_der = generated.signing_key.serialize_der();
        let public_key = QuicNetworkManager::public_key_from_certificate_der(&cert_der)
            .expect("derive SPKI from generated certificate");
        Identity {
            cert_der,
            key_der,
            public_key,
        }
    }

    fn generate_identities(count: usize) -> Vec<Identity> {
        (0..count).map(|_| generate_identity()).collect()
    }

    fn keys(identities: &[Identity]) -> Vec<NodePublicKey> {
        identities
            .iter()
            .map(|identity| identity.public_key.clone())
            .collect()
    }

    fn reserve_local_addr() -> SocketAddr {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind UDP socket on localhost");
        socket.local_addr().expect("get local socket address")
    }

    /// A manager carrying `identity`'s certificate and listening, which is what
    /// `install_expected_server_public_keys` requires before it will run.
    async fn listening_manager(identity: &Identity) -> QuicNetworkManager {
        listening_manager_at(identity, reserve_local_addr()).await
    }

    async fn listening_manager_at(identity: &Identity, addr: SocketAddr) -> QuicNetworkManager {
        init_crypto_provider();
        let mut net = QuicNetworkManager::new();
        net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
            .expect("install local certificate");
        net.listen(addr).await.expect("listen on loopback");
        net
    }

    /// A manager carrying `identity`'s certificate that only ever dials.
    async fn dialing_manager(identity: &Identity) -> QuicNetworkManager {
        init_crypto_provider();
        let mut net = QuicNetworkManager::new();
        net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
            .expect("install local certificate");
        net
    }

    /// A manager with *no* local certificate. stoffelnet mints an ephemeral
    /// self-signed certificate for it on first use, so it has a transport
    /// identity that no roster can possibly list.
    async fn anonymous_manager() -> QuicNetworkManager {
        init_crypto_provider();
        QuicNetworkManager::new()
    }

    /// Runs one `accept()` on a clone of `net` while `dial` runs, and returns
    /// what the accept path answered.
    ///
    /// `dial` returns the dialing manager, which is held until the accept path
    /// has answered: dropping it first would close the connection before the
    /// acceptor reads its stream.
    async fn accept_while<F>(net: &QuicNetworkManager, dial: F) -> Result<(), String>
    where
        F: std::future::Future<Output = QuicNetworkManager>,
    {
        let mut acceptor = net.clone();
        let accepting =
            tokio::spawn(
                async move { tokio::time::timeout(HANDSHAKE_BUDGET, acceptor.accept()).await },
            );
        let _dialer = dial.await;
        accepting
            .await
            .expect("the accept task is not cancelled")
            .expect("the accept path answers within the budget")
            .map(|_| ())
    }

    /// Dial the client-facing listener as a client while its accept loop runs,
    /// and return the dialer's end of the admitted connection.
    ///
    /// The dialing manager is leaked on purpose: dropping it would close the
    /// connection the test is about to speak on.
    async fn accept_and_dial_as_client(
        listeners: &NodeListeners,
        client_addr: SocketAddr,
        identity: &Identity,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        let mut acceptor = listeners.clients().clone();
        let accepting =
            tokio::spawn(
                async move { tokio::time::timeout(HANDSHAKE_BUDGET, acceptor.accept()).await },
            );
        let mut dialer = dialing_manager(identity).await;
        let connection = dialer.connect_as_client(client_addr).await;
        std::mem::forget(dialer);
        accepting
            .await
            .expect("the accept task is not cancelled")
            .expect("the accept path answers within the budget")?;
        connection
    }

    /// Frame a payload for `execution_id` and write it on `connection`.
    async fn send_frame(
        connection: &Arc<dyn PeerConnection>,
        execution_id: ExecutionId,
        kind: ExecutionMessageKind,
        payload: &[u8],
    ) {
        let frame =
            encode_execution_frame(execution_id, kind, payload).expect("frame the client payload");
        connection
            .send(&frame)
            .await
            .expect("the admitted client leg carries bytes");
    }

    /// Dial the client-facing listener as a client, leaving the accept to
    /// whatever loop the test is running.
    ///
    /// The dialing manager is leaked on purpose: dropping it would close the
    /// connection the test is about to speak on.
    async fn dial_as_client(
        client_addr: SocketAddr,
        identity: &Identity,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        let mut dialer = dialing_manager(identity).await;
        let connection = dialer.connect_as_client(client_addr).await;
        std::mem::forget(dialer);
        connection
    }

    /// Exactly what the standing node's client-facing accept loop does: accept,
    /// ask the gate, and close what it refuses. Each decision is published so a
    /// test can observe the refusal rather than infer it.
    fn spawn_gated_client_accept_loop(
        listeners: &NodeListeners,
        gate: Arc<ClientIngressGate>,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<ClientIngressDecision>,
    ) {
        let mut acceptor = listeners.clients().clone();
        let (decisions, receiver) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                match acceptor.accept().await {
                    Ok(connection) => {
                        let decision = gate.admit(&connection).await;
                        if !decision.is_admitted() {
                            let _ = connection.close().await;
                        }
                        if decisions.send(decision).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        // A refused handshake is routine on this socket; do not
                        // spin on it.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });
        (task, receiver)
    }

    fn shipped_node_certificates() -> Vec<(String, Vec<u8>)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ids/nodes");
        (0..5)
            .map(|index| {
                let name = format!("cert{index}.crt");
                let der = std::fs::read(dir.join(&name))
                    .unwrap_or_else(|error| panic!("read ids/nodes/{name}: {error}"));
                (name, der)
            })
            .collect()
    }

    /// Blocker B2. The two extractions disagree on the *same* certificate, and
    /// stoffelnet authorizes against the longer one. A roster built from the
    /// coordinator's `ClientIdentity` shape — which is what the runner's own
    /// `extract_pubkey_from_cert` returns — would match no peer at all.
    #[test]
    fn a_roster_key_is_the_full_spki_not_the_bare_bit_string() {
        let identity = generate_identity();
        let (_, parsed) =
            X509Certificate::from_der(&identity.cert_der).expect("parse the generated certificate");
        let bare_bit_string = parsed
            .public_key()
            .subject_public_key
            .data
            .as_ref()
            .to_vec();

        assert_ne!(
            identity.public_key.0, bare_bit_string,
            "the roster key must be the SPKI stoffelnet compares against, not its inner BIT STRING"
        );
        assert!(
            identity.public_key.0.len() > bare_bit_string.len(),
            "the SPKI wraps the BIT STRING, so it is strictly longer"
        );
        assert!(
            identity.public_key.0.ends_with(&bare_bit_string),
            "the BIT STRING is the tail of the SPKI it is wrapped in"
        );
    }

    /// The shared golden vector of design doc §9.B.
    #[test]
    fn a_coordinator_roster_matches_the_golden_digest() {
        let certificates = shipped_node_certificates();
        let served: Vec<&[u8]> = certificates.iter().map(|(_, der)| der.as_slice()).collect();
        let mut golden = [0u8; 32];
        hex::decode_to_slice(GOLDEN_DIGEST, &mut golden).expect("the golden digest is hex");

        let roster = Roster::from_coordinator(&served, 1, golden)
            .expect("the shipped certificates are the golden roster");

        assert_eq!(hex::encode(roster.digest()), GOLDEN_DIGEST);
        let order: Vec<&str> = roster
            .nodes()
            .iter()
            .map(|key| {
                certificates
                    .iter()
                    .find(|(_, der)| {
                        QuicNetworkManager::public_key_from_certificate_der(der)
                            .expect("derive a shipped key")
                            == *key
                    })
                    .map(|(name, _)| name.as_str())
                    .expect("every roster key is a shipped certificate")
            })
            .collect();
        assert_eq!(
            order,
            [
                "cert3.crt",
                "cert0.crt",
                "cert1.crt",
                "cert2.crt",
                "cert4.crt"
            ]
        );
        assert!(roster.nodes().iter().all(|key| key.0.len() == 91));
        for (rank, key) in roster.nodes().iter().enumerate() {
            assert_eq!(roster.index_of(key), Some(rank));
            assert_eq!(roster.key_of(rank), Some(key));
        }
    }

    #[test]
    fn a_roster_whose_served_digest_disagrees_is_refused() {
        let identities = generate_identities(3);
        let served: Vec<&[u8]> = identities
            .iter()
            .map(|identity| identity.cert_der.as_slice())
            .collect();
        let computed = Roster::from_node_keys(keys(&identities), 1)
            .expect("build the roster the certificates define")
            .digest();

        let error = Roster::from_coordinator(&served, 1, [0x5a; 32])
            .expect_err("a served digest that is not the certificates' digest must be refused");

        assert_eq!(
            error,
            RosterError::DigestMismatch {
                served: [0x5a; 32],
                computed,
            }
        );
    }

    /// Blocker B3 at the source: nothing may build a roster that would install
    /// an empty allowlist, because an empty allowlist is fail-open.
    #[test]
    fn an_empty_roster_is_refused_before_the_transport_is_touched() {
        assert_eq!(
            Roster::from_node_keys(Vec::new(), 1),
            Err(RosterError::Empty)
        );
        assert_eq!(
            Roster::from_coordinator(&[], 1, [0; 32]),
            Err(RosterError::Empty)
        );
    }

    /// The coordinator's own bounds, checked no more weakly on receipt.
    #[test]
    fn a_served_roster_is_held_to_the_coordinators_bounds() {
        let identities = generate_identities(3);
        assert_eq!(
            Roster::from_node_keys(keys(&identities), 0),
            Err(RosterError::ZeroThreshold)
        );
        assert_eq!(
            Roster::from_node_keys(keys(&identities), 2),
            Err(RosterError::ThresholdTooLarge { n: 3, threshold: 2 })
        );
        assert!(Roster::from_node_keys(keys(&identities), 1).is_ok());
    }

    /// The same certificate twice is not two admissible nodes: `n` would say
    /// three where the installed allowlist holds two.
    #[test]
    fn a_repeated_node_certificate_is_refused() {
        let identities = generate_identities(2);
        let mut duplicated = keys(&identities);
        duplicated.push(identities[0].public_key.clone());
        let compact_id = identities[0].public_key.derive_id();

        assert_eq!(
            Roster::from_node_keys(duplicated, 1),
            Err(RosterError::DuplicateNode { compact_id })
        );
    }

    #[test]
    fn a_served_certificate_the_transport_cannot_read_is_refused() {
        let identity = generate_identity();
        let served: Vec<&[u8]> = vec![identity.cert_der.as_slice(), b"not a certificate"];

        let error = Roster::from_coordinator(&served, 1, [0; 32])
            .expect_err("an unparseable served certificate must be refused");

        assert!(
            matches!(
                error,
                RosterError::ServedCertificateUnderivable { index: 1, .. }
            ),
            "expected the served-certificate refusal to name index 1, got: {error}"
        );
    }

    /// The roster is the allowlist, and the allowlist is observed to be on
    /// afterwards rather than assumed (blocker B3).
    #[tokio::test]
    async fn an_installed_roster_admits_a_member_and_refuses_an_outsider() {
        let identities = generate_identities(3);
        let outsider = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let addr = reserve_local_addr();
        let mut net = listening_manager_at(&identities[0], addr).await;
        assert!(
            !net.has_certificate_public_key_allowlist(),
            "precondition: peer authorization starts disabled"
        );
        roster.install_into(&mut net).expect("install the roster");
        assert!(
            net.has_certificate_public_key_allowlist(),
            "install_into must leave peer authorization enabled"
        );

        accept_while(&net, async {
            let mut member = dialing_manager(&identities[1]).await;
            member
                .connect(addr)
                .await
                .expect("a roster member reaches a roster-pinned node");
            member
        })
        .await
        .expect("a roster member is admitted");

        let refusal = accept_while(&net, async {
            let mut stranger = dialing_manager(&outsider).await;
            let _ = tokio::time::timeout(HANDSHAKE_BUDGET, stranger.connect(addr)).await;
            stranger
        })
        .await
        .expect_err("a certificate outside the roster must not reach the mesh");
        assert!(
            refusal.contains("peer certificate public key is not in allowlist"),
            "expected the certificate-allowlist refusal, got: {refusal}"
        );
    }

    /// Design doc §9 rule 3, as the transport sees it: a client certificate is
    /// refused at the mesh transport in **both** ALPN roles, and so is a manager
    /// that brings no certificate at all — including on a clone taken *before*
    /// the install, the order the runner's party setups take theirs in.
    #[tokio::test]
    async fn an_installed_node_roster_refuses_every_client_certificate() {
        let identities = generate_identities(3);
        let client = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let addr = reserve_local_addr();
        let mut net = listening_manager_at(&identities[0], addr).await;
        // The clone exists first; the roster is installed on the original only.
        let client_facing = net.clone();
        assert!(
            !client_facing.has_certificate_public_key_allowlist(),
            "precondition: the clone starts with no allowlist"
        );
        roster.install_into(&mut net).expect("install the roster");
        assert!(
            client_facing.has_certificate_public_key_allowlist(),
            "the allowlist must be shared with clones, not replaced on install"
        );

        for (role, via_server_alpn) in [("client ALPN", false), ("server ALPN", true)] {
            let refusal = accept_while(&client_facing, async {
                let mut dialer = dialing_manager(&client).await;
                let dial = async {
                    if via_server_alpn {
                        dialer.connect(addr).await.map(|_| ())
                    } else {
                        dialer.connect_as_client(addr).await.map(|_| ())
                    }
                };
                let _ = tokio::time::timeout(HANDSHAKE_BUDGET, dial).await;
                dialer
            })
            .await
            .expect_err("a certificate that is not a node must not reach the mesh");
            assert!(
                refusal.contains("peer certificate public key is not in allowlist"),
                "expected the certificate-allowlist refusal over the {role}, got: {refusal}"
            );
        }

        let refusal = accept_while(&client_facing, async {
            let mut anonymous = anonymous_manager().await;
            let _ = tokio::time::timeout(HANDSHAKE_BUDGET, anonymous.connect_as_client(addr)).await;
            anonymous
        })
        .await
        .expect_err("a manager with no certificate must not reach the mesh");
        assert!(
            refusal.contains("peer certificate public key is not in allowlist"),
            "expected the certificate-allowlist refusal, got: {refusal}"
        );
    }

    /// The client's half of §9 rule 1: a client pinned to the coordinator's
    /// roster reaches a node of that roster, and a certificate the roster does
    /// not name is refused at the handshake rather than trusted for having
    /// answered the address.
    ///
    /// This is the leg that carries a client's masked inputs and its output
    /// routes, so "whatever answers the address" is the whole of the exposure
    /// [`Roster::install_for_client`] closes.
    #[tokio::test]
    async fn a_client_pinned_to_the_roster_reaches_only_its_nodes() {
        let identities = generate_identities(3);
        let impostor = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let node_addr = reserve_local_addr();
        let node = listening_manager_at(&identities[0], node_addr).await;
        let impostor_addr = reserve_local_addr();
        let impostor_node = listening_manager_at(&impostor, impostor_addr).await;

        let client_identity = generate_identity();
        let mut client = dialing_manager(&client_identity).await;
        assert!(
            !client.has_certificate_public_key_allowlist(),
            "precondition: an unpinned client authorizes every server it dials"
        );
        roster
            .install_for_client(&mut client)
            .expect("pin the client to the coordinator's roster");
        assert!(
            client.has_certificate_public_key_allowlist(),
            "install_for_client must leave peer authorization enabled"
        );

        let mut dialer = client.clone();
        accept_while(&node, async move {
            dialer
                .connect_as_client(node_addr)
                .await
                .expect("a roster node answers a client pinned to that roster");
            dialer
        })
        .await
        .expect("the roster node admits the client");

        let mut dialer = client.clone();
        let refusal = {
            let mut acceptor = impostor_node.clone();
            let accepting = tokio::spawn(async move {
                tokio::time::timeout(HANDSHAKE_BUDGET, acceptor.accept()).await
            });
            let refusal =
                tokio::time::timeout(HANDSHAKE_BUDGET, dialer.connect_as_client(impostor_addr))
                    .await
                    .expect("the dial resolves within the budget")
                    .expect_err(
                        "a certificate outside the roster must not carry a client's inputs",
                    );
            accepting.abort();
            refusal
        };
        assert!(
            refusal.contains("peer certificate public key is not in allowlist"),
            "expected the certificate-allowlist refusal, got: {refusal}"
        );
    }

    /// Blocker B3 from the client's side, the inclusion half: *every* node the
    /// coordinator's roster names is reachable by a client pinned to it, not
    /// only the one `a_client_pinned_to_the_roster_reaches_only_its_nodes`
    /// dials. A pin that authorized a proper subset of the roster would be a
    /// liveness hole nothing upstream reports — the client would simply fail to
    /// reach some of the nodes its masked inputs must go to — and
    /// `install_for_client`'s only observable post-condition on the transport is
    /// that an allowlist is *enabled*: [`QuicNetworkManager`] exposes no reader
    /// for the installed key set. So the property is asserted the only way it
    /// can be, against the transport rather than against the [`Roster`] value:
    /// by dialling each roster node over loopback QUIC with the pinned client.
    ///
    /// The exclusion half — a certificate the roster does not name is refused —
    /// is `a_client_pinned_to_the_roster_reaches_only_its_nodes`, and an empty
    /// roster never reaching a transport at all is
    /// `an_empty_roster_is_refused_before_the_transport_is_touched`.
    #[tokio::test]
    async fn a_client_pin_authorizes_every_roster_node() {
        let identities = generate_identities(3);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mut nodes = Vec::with_capacity(identities.len());
        for identity in &identities {
            let addr = reserve_local_addr();
            nodes.push((addr, listening_manager_at(identity, addr).await));
        }

        // No local certificate: a client is not a roster member, so it has no
        // node identity to install and the pin must not require one.
        let mut client = anonymous_manager().await;
        roster
            .install_for_client(&mut client)
            .expect("a client needs no local certificate to pin a roster");
        assert!(
            client.has_certificate_public_key_allowlist(),
            "install_for_client must leave peer authorization enabled"
        );

        // `nodes` follows the identities the roster was built from, not the
        // roster's own SPKI order, so the index names the listener rather than
        // a party rank — which is the point: the pin must cover all of them
        // however they happen to sort.
        for (listener, (addr, node)) in nodes.iter().enumerate() {
            let addr = *addr;
            let mut dialer = client.clone();
            let admitted = accept_while(node, async move {
                dialer.connect_as_client(addr).await.unwrap_or_else(|error| {
                    panic!("roster listener {listener} must answer a client pinned to that roster: {error}")
                });
                dialer
            })
            .await;
            assert!(
                admitted.is_ok(),
                "roster listener {listener} must admit a client pinned to that roster, \
                 but its accept path answered: {admitted:?}"
            );
        }
    }

    /// The freeze `install_for_client` carries in place of the one
    /// `install_expected_server_public_keys` applies to the mesh.
    ///
    /// stoffelnet's `set_allowed_certificate_public_keys` *clears* the set
    /// before it writes, and the set is the same `allowed_peer_public_keys` a
    /// mesh manager's roster lives in. Without a guard a second call — on a
    /// transport whose pin came from somewhere else, a mesh manager included —
    /// would silently replace an installed allowlist. So the roster is the
    /// first writer of a transport's allowlist or it is no writer at all.
    #[tokio::test]
    async fn a_client_pin_refuses_a_transport_that_is_already_pinned() {
        let identities = generate_identities(3);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");
        let others = generate_identities(3);
        let other_roster = Roster::from_node_keys(keys(&others), 1).expect("build another roster");

        let client_identity = generate_identity();
        let mut client = dialing_manager(&client_identity).await;
        roster
            .install_for_client(&mut client)
            .expect("the first pin installs");

        assert_eq!(
            other_roster.install_for_client(&mut client).unwrap_err(),
            RosterError::ClientAllowlistAlreadyInstalled { nodes: 3 },
            "a second roster must not replace the pin the first one installed"
        );
        assert_eq!(
            roster.install_for_client(&mut client).unwrap_err(),
            RosterError::ClientAllowlistAlreadyInstalled { nodes: 3 },
            "not even the same roster may be installed twice: the guard is on \
             the transport's state, not on which keys are being written"
        );

        // The refusals left the installed set alone rather than clearing it:
        // the second roster's nodes are still refused, and the first roster's
        // are still admitted.
        let other_addr = reserve_local_addr();
        let other_node = listening_manager_at(&others[0], other_addr).await;
        let mut dialer = client.clone();
        let refusal = {
            let mut acceptor = other_node.clone();
            let accepting = tokio::spawn(async move {
                tokio::time::timeout(HANDSHAKE_BUDGET, acceptor.accept()).await
            });
            let refusal =
                tokio::time::timeout(HANDSHAKE_BUDGET, dialer.connect_as_client(other_addr))
                    .await
                    .expect("the dial resolves within the budget")
                    .expect_err("the refused install must not have pinned the second roster");
            accepting.abort();
            refusal
        };
        assert!(
            refusal.contains("peer certificate public key is not in allowlist"),
            "expected the certificate-allowlist refusal, got: {refusal}"
        );

        let node_addr = reserve_local_addr();
        let node = listening_manager_at(&identities[0], node_addr).await;
        let mut dialer = client.clone();
        accept_while(&node, async move {
            dialer
                .connect_as_client(node_addr)
                .await
                .expect("the first roster's pin survived the refusals");
            dialer
        })
        .await
        .expect("the roster node admits the client");
    }

    /// The mechanism the runner's party setups rely on, carried to payload
    /// bytes: they serve from clones of the mesh manager, and that keeps working
    /// only because the allowlist is a shared set mutated *in place*. A
    /// handshake alone does not prove the first stream works.
    #[tokio::test]
    async fn a_member_exchanges_bytes_through_a_clone_taken_before_the_install() {
        let identities = generate_identities(3);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let addr = reserve_local_addr();
        let mut net = listening_manager_at(&identities[0], addr).await;
        let mut serving = net.clone();
        roster.install_into(&mut net).expect("install the roster");

        let accepting = tokio::spawn(async move {
            let connection = tokio::time::timeout(HANDSHAKE_BUDGET, serving.accept())
                .await
                .expect("the accept path answers within the budget")
                .expect("a roster member must be admitted with the allowlist on");
            let received = tokio::time::timeout(HANDSHAKE_BUDGET, connection.receive())
                .await
                .expect("the node reads the member's bytes within the budget")
                .expect("the admitted leg carries data, not just a handshake");
            connection
                .send(b"roster-pinned-pong")
                .await
                .expect("the node answers on the admitted connection");
            received
        });

        let mut member = dialing_manager(&identities[1]).await;
        let connection = member
            .connect(addr)
            .await
            .expect("a roster member must reach a roster-pinned node");
        connection
            .send(b"roster-pinned-ping")
            .await
            .expect("the member writes its first stream");
        let answer = tokio::time::timeout(HANDSHAKE_BUDGET, connection.receive())
            .await
            .expect("the member reads the answer within the budget")
            .expect("the leg is usable in both directions");

        let received = accepting.await.expect("the accept task is not cancelled");
        assert_eq!(received, b"roster-pinned-ping");
        assert_eq!(answer, b"roster-pinned-pong");
    }

    /// Why no non-node key may ever be allowlisted beside the roster (design doc
    /// §9 rule 3, and §6 blocker B1): stoffelnet authorizes the certificate
    /// before it looks at the ALPN role, so an extra key that dials with the
    /// *server* ALPN is accepted as a server peer and is ranked by
    /// `get_sorted_public_keys` — the party-index order.
    #[tokio::test]
    async fn an_allowlisted_non_node_key_is_ranked_as_a_server_peer() {
        let identities = generate_identities(3);
        let extra = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let addr = reserve_local_addr();
        let mut net = listening_manager_at(&identities[0], addr).await;
        roster.install_into(&mut net).expect("install the roster");
        // What allowlisting a client certificate beside the nodes would do.
        net.add_allowed_certificate_public_key(extra.public_key.clone());

        accept_while(&net, async {
            let mut dialer = dialing_manager(&extra).await;
            dialer
                .connect(addr)
                .await
                .expect("an allowlisted key dialing with the server ALPN is accepted");
            dialer
        })
        .await
        .expect("the transport admits any allowlisted key as a server peer");

        assert!(
            net.get_sorted_public_keys().contains(&extra.public_key),
            "an allowlisted extra key is ranked among the parties"
        );
    }

    /// Design doc §9 rule 3 and the close of §6 blocker B1, both halves at
    /// once: the node mesh admits the coordinator's roster and refuses every
    /// other certificate, and the client-facing listener the *same* node binds
    /// admits the very certificate the mesh just refused.
    ///
    /// This is the test that fails if a non-node key ever reaches the mesh
    /// allowlist. stoffelnet exposes no way to enumerate an installed
    /// allowlist — only `has_certificate_public_key_allowlist` — so the mesh's
    /// refusal of the client certificate *is* the observation that the key is
    /// not in it, and the refusal is checked in both ALPN roles because
    /// stoffelnet authorizes the certificate before it knows the role.
    #[tokio::test]
    async fn a_client_the_mesh_refuses_reaches_the_client_facing_listener() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let client = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both of a standing node's listeners");

        assert!(
            listeners.mesh().has_certificate_public_key_allowlist(),
            "the mesh must come up with the roster as its peer authorization"
        );
        assert!(
            !listeners.clients().has_certificate_public_key_allowlist(),
            "the client-facing listener must authorize no certificate: an allowlist there \
             pre-empts the coordinator's per-execution admission"
        );

        for (role, via_server_alpn) in [("client ALPN", false), ("server ALPN", true)] {
            let refusal = accept_while(listeners.mesh(), async {
                let mut dialer = dialing_manager(&client).await;
                let dial = async {
                    if via_server_alpn {
                        dialer.connect(mesh_addr).await.map(|_| ())
                    } else {
                        dialer.connect_as_client(mesh_addr).await.map(|_| ())
                    }
                };
                let _ = tokio::time::timeout(HANDSHAKE_BUDGET, dial).await;
                dialer
            })
            .await
            .expect_err("a client certificate must not be in the mesh allowlist");
            assert!(
                refusal.contains("peer certificate public key is not in allowlist"),
                "expected the mesh's certificate-allowlist refusal over the {role}, got: {refusal}"
            );
        }

        accept_while(listeners.clients(), async {
            let mut dialer = dialing_manager(&client).await;
            dialer
                .connect_as_client(client_addr)
                .await
                .expect("the client-facing listener admits a client certificate");
            dialer
        })
        .await
        .expect("the client-facing listener must admit the certificate the mesh refused");

        // The two allowlists are separate sets, not one shared `Arc<DashSet>`:
        // admitting the client on the client-facing listener must not have
        // taught the mesh that key, and the mesh must still admit a node.
        assert!(
            listeners.mesh().has_certificate_public_key_allowlist(),
            "the mesh allowlist must survive client traffic"
        );
        assert!(
            !listeners.clients().has_certificate_public_key_allowlist(),
            "admitting a client must not install an allowlist on the client-facing listener"
        );
        accept_while(listeners.mesh(), async {
            let mut member = dialing_manager(&identities[1]).await;
            member
                .connect(mesh_addr)
                .await
                .expect("a roster member still reaches the mesh");
            member
        })
        .await
        .expect("the mesh still admits its own roster");
    }

    /// The listener with no allowlist must not become a second party ingress.
    ///
    /// stoffelnet refuses an unknown peer-role dial when `use_tls` is on and no
    /// allowlist is configured, and the client-facing manager is never told
    /// about any node, so the refusal is the transport's own. The scanner's
    /// [`ExecutionScannerScope::Clients`] is the second line: a peer-role
    /// connection on this listener could not be attributed to a party even if
    /// one got in.
    #[tokio::test]
    async fn the_client_facing_listener_refuses_a_peer_role_dial() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        let refusal = accept_while(listeners.clients(), async {
            let mut peer = dialing_manager(&identities[1]).await;
            let _ = tokio::time::timeout(HANDSHAKE_BUDGET, peer.connect(client_addr)).await;
            peer
        })
        .await
        .expect_err("the client-facing listener must not accept a peer-role dial");
        assert!(
            refusal.contains("Unauthorized peer ID"),
            "expected the transport's unknown-peer refusal, got: {refusal}"
        );
    }

    /// What a refused client can actually observe, and when.
    ///
    /// `ClientIngressGate` decides after the TLS handshake, so the accept loop
    /// closes the connection rather than failing it: `connect_as_client`
    /// returns `Ok` and nothing about the dial says the route was refused. The
    /// observable consequence arrives later, once the transport has processed
    /// the party's `CONNECTION_CLOSE` — which is why a client that sends the
    /// execution hello once and checks only that send would take a refused
    /// route for an established one.
    ///
    /// This pins the half a client may rely on: a frame sent after the close
    /// has been processed fails. It deliberately does *not* assert that the
    /// first frame succeeds — that is the transport's timing, not a contract —
    /// only that checking a later frame is what makes the refusal visible.
    /// `establish_coordinator_output_client_routes` therefore checks every pass
    /// of the hello, each one `CLIENT_ROUTE_HELLO_RESEND_INTERVAL` apart, and
    /// not just the first.
    #[tokio::test]
    async fn a_refused_client_route_fails_a_later_frame_not_the_dial() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let unadmitted = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        // A mux with no registered execution: nothing names this certificate,
        // so the gate refuses it.
        let mux = ExecutionTransportMux::new(8).expect("build the execution mux");
        let gate = Arc::new(ClientIngressGate::new(
            ClientIngressLimits::standing_node(),
            Arc::new(mux.clone()),
        ));
        let (_accept_loop, mut decisions) =
            spawn_gated_client_accept_loop(&listeners, Arc::clone(&gate));

        // The dial itself succeeds: the client-facing listener carries no
        // allowlist, and the gate has not run yet.
        let connection = dial_as_client(client_addr, &unadmitted)
            .await
            .expect("the client-facing listener completes the handshake before any policy runs");

        let decision = tokio::time::timeout(HANDSHAKE_BUDGET, decisions.recv())
            .await
            .expect("the accept loop decides within the budget")
            .expect("the accept loop is live");
        assert!(
            matches!(
                decision,
                ClientIngressDecision::RefusedCertificateNoExecutionNames { .. }
            ),
            "a certificate no registered execution names must be refused, got: {decision}"
        );

        // Now the half a client may depend on. Keep sending at the interval the
        // runner re-sends its hello at; one of those passes must fail, well
        // inside the handshake budget. A client that only ever checked the
        // frame it sent immediately after the dial could see every one of these
        // errors and throw them away.
        let frame = vec![0u8; 16];
        let deadline = tokio::time::Instant::now() + HANDSHAKE_BUDGET;
        let mut failed_at = None;
        let mut pass = 0usize;
        while tokio::time::Instant::now() < deadline {
            if connection.send(&frame).await.is_err() {
                failed_at = Some(pass);
                break;
            }
            pass += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let failed_at = failed_at.expect(
            "a client whose route the gate refused must eventually see its sends fail; \
             otherwise no number of re-sends could tell a refused route from a live one",
        );
        assert!(
            failed_at > 0,
            "this test exists because the refusal is not visible on the frame that \
             follows the dial; if it now is, the runner's later passes are redundant \
             rather than load-bearing and that reasoning must be revisited"
        );
    }

    /// One socket cannot be both listeners, because the allowlist belongs to
    /// the transport and not to the connection.
    #[tokio::test]
    async fn the_two_listeners_may_not_share_one_address() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");
        let shared = reserve_local_addr();

        let error = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            shared,
            shared,
        )
        .await
        .expect_err("binding both listeners to one address must be refused");

        assert_eq!(
            error,
            RosterError::ListenersShareAnAddress { address: shared }
        );
    }

    /// What now authorizes a client, end to end: the certificate reaches the
    /// client-facing listener because nothing at the transport judges it, and
    /// the per-execution client roster the coordinator published — registered
    /// with the mux — is the whole of the decision. A certificate that
    /// execution does not name gets a handshake and nothing else.
    ///
    /// This is the transport and the mux without the accept policy in between,
    /// which is why the stranger here keeps its connection: a standing node
    /// would have closed it, because `ClientIngressGate` holds the socket to
    /// the coordinator's admissions. The adversary that still reaches *this*
    /// boundary on a standing node is a client the coordinator admitted to some
    /// other execution, and that is
    /// `a_client_admitted_to_one_execution_is_refused_the_route_of_another`.
    #[tokio::test]
    async fn a_client_route_is_authorized_by_the_per_execution_roster_alone() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let admitted = generate_identity();
        let stranger = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        let execution_id = ExecutionId::from_bytes([7; 32]);
        let mux = ExecutionTransportMux::new(8).expect("build the execution mux");
        let mut inbox = mux
            .register_with_client_identities(
                execution_id,
                vec![admitted.public_key.certificate_identity()],
            )
            .expect("register the coordinator's published client roster");
        // Exactly the standing node's pair of scanners, on one mux.
        let _mesh_scanner = ExecutionConnectionScanner::spawn(
            listeners.mesh().clone(),
            mux.clone(),
            ExecutionScannerScope::Parties,
        )
        .expect("start the mesh scanner");
        let _client_scanner = ExecutionConnectionScanner::spawn(
            listeners.clients().clone(),
            mux.clone(),
            ExecutionScannerScope::Clients,
        )
        .expect("start the client-facing scanner");

        // The admitted client: handshake, announce the execution, then speak.
        let admitted_connection = accept_and_dial_as_client(&listeners, client_addr, &admitted)
            .await
            .expect("the admitted client reaches the client-facing listener");
        send_frame(
            &admitted_connection,
            execution_id,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        )
        .await;
        send_frame(
            &admitted_connection,
            execution_id,
            ExecutionMessageKind::Mpc,
            b"masked-input-share",
        )
        .await;

        let hello = tokio::time::timeout(HANDSHAKE_BUDGET, inbox.client.recv())
            .await
            .expect("the hello reaches the execution within the budget")
            .expect("the client inbox is live");
        assert_eq!(hello.payload, EXECUTION_CLIENT_ROUTE_HELLO_V1);
        let share = tokio::time::timeout(HANDSHAKE_BUDGET, inbox.client.recv())
            .await
            .expect("the admitted client's frame reaches the execution")
            .expect("the client inbox is live");
        assert_eq!(share.payload, b"masked-input-share");
        assert!(
            matches!(share.source, ExecutionTransportSource::Client(_)),
            "a frame from the client-facing listener is a client's, never a party's"
        );

        // A certificate the execution does not name: the transport lets it in,
        // and the per-execution roster is what refuses it.
        let stranger_connection = accept_and_dial_as_client(&listeners, client_addr, &stranger)
            .await
            .expect("the transport authorizes no certificate on this listener");
        send_frame(
            &stranger_connection,
            execution_id,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        )
        .await;
        send_frame(
            &stranger_connection,
            execution_id,
            ExecutionMessageKind::Mpc,
            b"not-my-execution",
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), inbox.client.recv())
                .await
                .is_err(),
            "a certificate the published admission does not name must reach no inbox"
        );
    }

    /// Being admitted somewhere is what gets a client onto the socket; it is
    /// not what gets its frames into an execution.
    ///
    /// `ClientIngressGate` asks the weaker question — has the coordinator
    /// admitted this certificate anywhere on this node — because a freshly
    /// accepted connection carries no frame to route yet. This pins that the
    /// stronger question is still asked where it always was: a client the
    /// coordinator admitted to one execution keeps its connection and is
    /// refused the route of an execution that does not name it. On a standing
    /// node this is the only adversary that reaches the per-execution roster at
    /// all, which is why the campaign's route probe is given an admission of
    /// its own before it dials.
    #[tokio::test]
    async fn a_client_admitted_to_one_execution_is_refused_the_route_of_another() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let mine = generate_identity();
        let theirs = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        let mine_execution = ExecutionId::from_bytes([17; 32]);
        let their_execution = ExecutionId::from_bytes([19; 32]);
        let mux = ExecutionTransportMux::new(8).expect("build the execution mux");
        let mut mine_inbox = mux
            .register_with_client_identities(
                mine_execution,
                vec![mine.public_key.certificate_identity()],
            )
            .expect("register the first published client roster");
        let _their_inbox = mux
            .register_with_client_identities(
                their_execution,
                vec![theirs.public_key.certificate_identity()],
            )
            .expect("register the second published client roster");
        let _client_scanner = ExecutionConnectionScanner::spawn(
            listeners.clients().clone(),
            mux.clone(),
            ExecutionScannerScope::Clients,
        )
        .expect("start the client-facing scanner");

        let gate = Arc::new(ClientIngressGate::new(
            ClientIngressLimits::standing_node(),
            Arc::new(mux.clone()),
        ));
        let (_accept_loop, mut decisions) =
            spawn_gated_client_accept_loop(&listeners, Arc::clone(&gate));

        // Admitted to `their_execution`, so the socket is open to it.
        let connection = dial_as_client(client_addr, &theirs)
            .await
            .expect("a coordinator-admitted client reaches the client-facing listener");
        let decision = tokio::time::timeout(HANDSHAKE_BUDGET, decisions.recv())
            .await
            .expect("the accept loop decides within the budget")
            .expect("the accept loop is live");
        assert!(
            matches!(decision, ClientIngressDecision::Admitted { .. }),
            "a certificate a registered execution names is admitted, got: {decision}"
        );

        // And refused the route of the execution that does not name it.
        send_frame(
            &connection,
            mine_execution,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        )
        .await;
        send_frame(
            &connection,
            mine_execution,
            ExecutionMessageKind::Mpc,
            b"not-my-execution",
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), mine_inbox.client.recv())
                .await
                .is_err(),
            "an admission to one execution must authorize no route into another"
        );
        assert_eq!(
            gate.occupancy().await,
            1,
            "the refused route is the mux's decision, not the gate's: the connection stands"
        );
    }

    /// The client-facing listener authorizes no certificate, so its occupancy
    /// is bounded by [`ClientIngressGate`] and by nothing else.
    ///
    /// Before the two-listener split, an unlisted certificate died at the TLS
    /// handshake, so the operator's client catalog bounded what a standing
    /// node's connection table could hold. This asserts the replacement: the
    /// surplus past the cap is refused and closed, while the client the
    /// execution admitted keeps routing.
    ///
    /// Every flooding certificate here is one the execution's published roster
    /// names, so the total cap is the only thing that can refuse it. What
    /// happens to a certificate no execution names — which is what any
    /// self-signed certificate reaching this listener is — is
    /// `a_flood_of_unnamed_certificates_cannot_lock_out_an_admitted_client_over_quic`.
    #[tokio::test]
    async fn the_client_facing_listener_refuses_connections_past_its_cap() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let admitted = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        const CAP: usize = 3;
        let flood: Vec<Identity> = (0..CAP).map(|_| generate_identity()).collect();

        let execution_id = ExecutionId::from_bytes([11; 32]);
        let mux = ExecutionTransportMux::new(8).expect("build the execution mux");
        let mut inbox = mux
            .register_with_client_identities(
                execution_id,
                std::iter::once(admitted.public_key.certificate_identity())
                    .chain(
                        flood
                            .iter()
                            .map(|identity| identity.public_key.certificate_identity()),
                    )
                    .collect(),
            )
            .expect("register the coordinator's published client roster");
        let _client_scanner = ExecutionConnectionScanner::spawn(
            listeners.clients().clone(),
            mux.clone(),
            ExecutionScannerScope::Clients,
        )
        .expect("start the client-facing scanner");

        let gate = Arc::new(ClientIngressGate::new(
            ClientIngressLimits {
                max_connections: std::num::NonZeroUsize::new(CAP).expect("non-zero cap"),
                max_connections_per_certificate: std::num::NonZeroUsize::new(CAP)
                    .expect("non-zero per-certificate cap"),
            },
            Arc::new(mux.clone()),
        ));
        let (_accept_loop, mut decisions) =
            spawn_gated_client_accept_loop(&listeners, Arc::clone(&gate));

        // The admitted client takes its slot first, as a real one would.
        let admitted_connection = dial_as_client(client_addr, &admitted)
            .await
            .expect("the admitted client reaches the client-facing listener");
        let first = tokio::time::timeout(HANDSHAKE_BUDGET, decisions.recv())
            .await
            .expect("the accept loop decides the admitted client within the budget")
            .expect("the accept loop is live");
        assert!(
            first.is_admitted(),
            "the first client is within the cap, got: {first}"
        );

        // Fill the cap, then overrun it.
        let mut refusals = 0usize;
        let mut admissions = 1usize;
        for identity in &flood {
            // A dial past the cap is still accepted by the transport — the gate
            // is what refuses it — so the dial itself must not be asserted on.
            let _ = dial_as_client(client_addr, identity).await;
            let decision = tokio::time::timeout(HANDSHAKE_BUDGET, decisions.recv())
                .await
                .expect("the accept loop decides every dial within the budget")
                .expect("the accept loop is live");
            match decision {
                ClientIngressDecision::Admitted { .. } => admissions += 1,
                ClientIngressDecision::RefusedTotalCapacity { max_connections } => {
                    assert_eq!(max_connections, CAP);
                    refusals += 1;
                }
                other => panic!("unexpected ingress decision: {other}"),
            }
        }
        assert_eq!(
            admissions, CAP,
            "the gate must admit exactly its cap, not more"
        );
        assert_eq!(
            refusals,
            flood.len() + 1 - CAP,
            "every dial past the cap must be refused"
        );
        assert_eq!(
            gate.occupancy().await,
            CAP,
            "a refused connection must occupy no slot"
        );

        // And the admitted client still routes, which is the point of bounding
        // the listener rather than closing it.
        send_frame(
            &admitted_connection,
            execution_id,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        )
        .await;
        send_frame(
            &admitted_connection,
            execution_id,
            ExecutionMessageKind::Mpc,
            b"masked-input-share",
        )
        .await;
        let hello = tokio::time::timeout(HANDSHAKE_BUDGET, inbox.client.recv())
            .await
            .expect("the admitted client's hello survives the flood")
            .expect("the client inbox is live");
        assert_eq!(hello.payload, EXECUTION_CLIENT_ROUTE_HELLO_V1);
        let share = tokio::time::timeout(HANDSHAKE_BUDGET, inbox.client.recv())
            .await
            .expect("the admitted client's frame survives the flood")
            .expect("the client inbox is live");
        assert_eq!(share.payload, b"masked-input-share");
        assert!(matches!(share.source, ExecutionTransportSource::Client(_)));
    }

    /// The admission rule, over real loopback QUIC: a flood of certificates no
    /// execution names holds no part of the listener, and the client the
    /// coordinator admitted connects and routes through it.
    ///
    /// Certificates are free and this listener carries no allowlist, so every
    /// self-signed one reaches the handshake and a bound stated per certificate
    /// bounds nothing a peer cannot defeat by churning them. What stops the
    /// flood is that the coordinator's admissions decide who may hold a
    /// connection at all: the transport accepts each dial, the gate refuses it,
    /// and the surplus is closed rather than held.
    #[tokio::test]
    async fn a_flood_of_unnamed_certificates_cannot_lock_out_an_admitted_client_over_quic() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let admitted = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        let execution_id = ExecutionId::from_bytes([13; 32]);
        let mux = ExecutionTransportMux::new(8).expect("build the execution mux");
        let mut inbox = mux
            .register_with_client_identities(
                execution_id,
                vec![admitted.public_key.certificate_identity()],
            )
            .expect("register the coordinator's published client roster");
        let _client_scanner = ExecutionConnectionScanner::spawn(
            listeners.clients().clone(),
            mux.clone(),
            ExecutionScannerScope::Clients,
        )
        .expect("start the client-facing scanner");

        // A listener wide enough that nothing the flood meets can be a cap:
        // whatever refuses it has to be the admission rule.
        const FLOOD: usize = 4;
        let gate = Arc::new(ClientIngressGate::new(
            ClientIngressLimits {
                max_connections: std::num::NonZeroUsize::new(FLOOD * 4).expect("non-zero cap"),
                max_connections_per_certificate: std::num::NonZeroUsize::new(FLOOD * 4)
                    .expect("non-zero per-certificate cap"),
            },
            Arc::new(mux.clone()),
        ));
        let (_accept_loop, mut decisions) =
            spawn_gated_client_accept_loop(&listeners, Arc::clone(&gate));

        // A fresh certificate per dial, so the per-certificate cap is never
        // what refuses anything: this is the churn the admission rule exists
        // for.
        let mut flood_connections = Vec::new();
        for index in 0..FLOOD {
            let identity = generate_identity();
            // The dial itself is still accepted by the transport — the gate is
            // what refuses it — so only the decision is asserted on.
            if let Ok(connection) = dial_as_client(client_addr, &identity).await {
                flood_connections.push(connection);
            }
            let decision = tokio::time::timeout(HANDSHAKE_BUDGET, decisions.recv())
                .await
                .expect("the accept loop decides every dial within the budget")
                .expect("the accept loop is live");
            assert!(
                matches!(
                    decision,
                    ClientIngressDecision::RefusedCertificateNoExecutionNames { .. }
                ),
                "dial {index} carries a certificate no execution names, got: {decision}"
            );
        }
        assert_eq!(
            gate.occupancy().await,
            0,
            "a certificate the coordinator never admitted must hold no slot"
        );

        // And the whole listener is the admitted client's: it connects, and its
        // frames reach the execution's inbox.
        let admitted_connection = dial_as_client(client_addr, &admitted)
            .await
            .expect("the admitted client reaches the client-facing listener through the flood");
        let decision = tokio::time::timeout(HANDSHAKE_BUDGET, decisions.recv())
            .await
            .expect("the accept loop decides the admitted client within the budget")
            .expect("the accept loop is live");
        assert!(
            matches!(decision, ClientIngressDecision::Admitted { .. }),
            "the client the execution admitted must be admitted, got: {decision}"
        );

        send_frame(
            &admitted_connection,
            execution_id,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        )
        .await;
        send_frame(
            &admitted_connection,
            execution_id,
            ExecutionMessageKind::Mpc,
            b"masked-input-share",
        )
        .await;
        let hello = tokio::time::timeout(HANDSHAKE_BUDGET, inbox.client.recv())
            .await
            .expect("the admitted client's hello survives the flood")
            .expect("the client inbox is live");
        assert_eq!(hello.payload, EXECUTION_CLIENT_ROUTE_HELLO_V1);
        let share = tokio::time::timeout(HANDSHAKE_BUDGET, inbox.client.recv())
            .await
            .expect("the admitted client's frame survives the flood")
            .expect("the client inbox is live");
        assert_eq!(share.payload, b"masked-input-share");
        assert!(matches!(share.source, ExecutionTransportSource::Client(_)));
        assert_eq!(
            flood_connections.len(),
            FLOOD,
            "the transport accepts every dial; refusing them is the gate's job"
        );
        assert_eq!(
            gate.occupancy().await,
            1,
            "only the coordinator-admitted client occupies the listener"
        );
    }

    /// The residual `ClientIngressGate` cannot bound, pinned where it lives.
    ///
    /// stoffelnet records every accepted client's public key in its own
    /// `client_public_keys` map inside `accept()` — before any policy of ours
    /// is consulted — and `cleanup_dead_connections` prunes `client_connections`
    /// and `client_ids` but not that map. So a peer cycling free self-signed
    /// certificates leaves one SPKI behind per handshake for the life of the
    /// process, which is memory the gate's occupancy caps do not bound. §9 of
    /// `docs/design/bootnode-elimination.md` records this as an open residual
    /// that needs an upstream change, and this test is what keeps that record
    /// honest: if it ever fails because stoffelnet now prunes the map, delete
    /// the test and the residual paragraph together.
    #[tokio::test]
    async fn the_transports_client_key_table_outlives_its_connections() {
        init_crypto_provider();
        let identities = generate_identities(3);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");
        let mesh_addr = reserve_local_addr();
        let client_addr = reserve_local_addr();
        let listeners = NodeListeners::bind(
            &roster,
            0,
            identities[0].cert_der.clone(),
            identities[0].key_der.clone(),
            mesh_addr,
            client_addr,
        )
        .await
        .expect("bind both listeners");

        let mut acceptor = listeners.clients().clone();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let _accept_loop = tokio::spawn(async move {
            while let Ok(connection) = acceptor.accept().await {
                if accepted_tx.send(connection).is_err() {
                    break;
                }
            }
        });

        // Two certificates, each used once and then dropped: the churn pattern
        // the per-certificate cap cannot see.
        let mut transport_ids = Vec::new();
        for _ in 0..2 {
            let client = generate_identity();
            let dialed = dial_as_client(client_addr, &client)
                .await
                .expect("the client reaches the client-facing listener");
            let accepted = tokio::time::timeout(HANDSHAKE_BUDGET, accepted_rx.recv())
                .await
                .expect("the listener accepts within the budget")
                .expect("the accept loop is live");
            transport_ids.push(client.public_key.derive_id());
            let _ = accepted.close().await;
            let _ = dialed.close().await;
        }

        // Wait for the transport to agree the connections are gone, then let it
        // prune everything it knows how to prune.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_BUDGET;
        loop {
            listeners.clients().cleanup_dead_connections().await;
            if listeners.clients().get_all_client_connections().is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the transport never released the closed client connections"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        for transport_id in transport_ids {
            assert!(
                listeners
                    .clients()
                    .client_public_key_bytes_by_transport_id(transport_id)
                    .is_some(),
                "stoffelnet still retains the public key of a client connection it has \
                 pruned; if this now fails, the §9 residual is closed and both this test \
                 and that paragraph must go"
            );
        }
    }

    /// Why [`Roster::install_into`] must be the first thing to touch the
    /// allowlist, and one more reason no non-node key may enter it: a key added
    /// before the node install makes the allowlist non-empty, and the node
    /// install then sees a frozen set that does not match its own.
    #[tokio::test]
    async fn adding_a_client_before_the_nodes_freezes_the_node_install_out() {
        let identities = generate_identities(3);
        let client = generate_identity();
        let mut net = listening_manager(&identities[0]).await;

        net.add_allowed_certificate_public_key(client.public_key.clone());
        let error = Roster::from_node_keys(keys(&identities), 1)
            .expect("build roster")
            .install_into(&mut net)
            .expect_err("a non-empty differing allowlist freezes the roster install");

        match error {
            RosterError::InstallRejected { reason } => assert!(
                reason.contains("frozen"),
                "expected the frozen-roster refusal, got: {reason}"
            ),
            other => panic!("expected the transport's own refusal, got: {other}"),
        }
    }

    /// The precondition `install_into` inherits, and the §9.D.1 membership
    /// check at the transport: the local certificate must already be on the
    /// manager, and it must be one of the roster's nodes.
    #[tokio::test]
    async fn a_node_outside_its_own_roster_cannot_install_it() {
        let outsider = generate_identity();
        let roster = Roster::from_node_keys(keys(&generate_identities(3)), 1).expect("build");
        let mut net = listening_manager(&outsider).await;

        assert_eq!(roster.index_of(&outsider.public_key), None);
        let error = roster
            .install_into(&mut net)
            .expect_err("a node absent from the roster must not install it");

        assert!(
            matches!(error, RosterError::InstallRejected { .. }),
            "expected the transport's own refusal, got: {error}"
        );
        assert!(
            !net.has_certificate_public_key_allowlist(),
            "a refused install must not leave a partial allowlist behind"
        );
    }
}
