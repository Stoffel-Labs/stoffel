//! The node roster: membership as a set of SPKIs, served by the coordinator.
//!
//! `docs/design/bootnode-elimination.md` §9.D.4. The coordinator is the only
//! roster authority (§8, §9 rule 1): a node fetches the node roster once at
//! startup over a pinned connection (`CoordinatorLink::connect` in
//! `stoffel-mpc-coordinator-off-chain`), builds a [`Roster`] from the served
//! certificates with [`Roster::from_coordinator`], installs it once, and never
//! re-fetches it. There is no join, leave or rotation, and nodes carry no roster
//! certificate list of their own.
//!
//! A roster holds **nodes only**. Client participation is a per-execution
//! admission the coordinator decides and the application layer enforces (§9
//! rule 3), and client certificates never enter the mesh transport's allowlist:
//! stoffelnet authorizes a certificate before it looks at the connection's ALPN
//! role (`quic.rs:3292` against `:3355`/`:3376`), so a key allowlisted "as a
//! client" that dials with the server ALPN is accepted as a server peer and
//! ranked among the parties (`an_allowlisted_non_node_key_is_ranked_as_a_server_peer`
//! pins that), and the allowlist is frozen once the manager is shared, so it
//! could never admit a client that arrives later anyway.
//!
//! # Three ways this silently breaks, and what stops each one
//!
//! **B2 — the SPKI byte shape.** stoffelnet authorizes against
//! `cert.public_key().raw`, the full DER `SubjectPublicKeyInfo`
//! (`quic.rs:1768`), while the coordinator's `ClientIdentity` is the bare BIT
//! STRING inside it — different bytes from the same certificate. The coordinator
//! therefore serves full certificate DERs, and [`Roster::from_coordinator`]
//! derives every key with stoffelnet's own
//! [`QuicNetworkManager::public_key_from_certificate_der`] and nothing else;
//! `a_roster_key_is_the_full_spki_not_the_bare_bit_string` pins the difference.
//!
//! **B3 — an empty allowlist disables the check.**
//! `verify_peer_public_key_allowed` (`quic.rs:1791-1796`) returns `Ok(())` when
//! the set is empty, so a roster that parsed to nothing would produce a mesh
//! with *no* peer authorization rather than a loud failure.
//! [`Roster::from_node_keys`] refuses an empty node set before the transport is
//! touched, and [`Roster::install_into`] re-reads
//! `has_certificate_public_key_allowlist` afterwards so the enabled-ness is
//! observed rather than assumed.
//!
//! **A drifted digest.** `stoffel-vm` does not depend on the coordinator
//! crates, so it implements the §9.B digest itself. [`Roster::from_coordinator`]
//! recomputes it over the served certificates and refuses a roster whose served
//! digest differs ([`RosterError::DigestMismatch`]), so a drifted implementation
//! on either side is a refusal, never an installed roster whose epoch store and
//! instance ids are keyed by the wrong value. The shared golden vector
//! (`a_coordinator_roster_matches_the_golden_digest`) keeps the two equal.
//!
//! # The bounds are the coordinator's
//!
//! [`Roster::from_node_keys`] refuses `t == 0` — with `t = 0` every single node
//! could reconstruct every client mask — and `n < 2t + 1`, exactly as
//! `NodeRoster::new` does, so a drifted or forged served roster is checked no
//! more weakly here than there. The canonical-encoding check of §9.A is not
//! repeated: every certificate reaches [`Roster::from_coordinator`] only after
//! `NodeRoster::try_from` ran it.

use std::collections::HashMap;

use stoffelnet::network_utils::{NodePublicKey, PartyId};
use stoffelnet::transports::quic::QuicNetworkManager;

/// BLAKE3 derive-key context for [`Roster::digest`].
///
/// The coordinator's node-roster digest (design doc §9.B), byte for byte:
/// `n` and `t` as 8-byte little-endian integers, then every node SPKI in
/// canonical order, each prefixed by its 8-byte little-endian length.
/// Domain-separated from the program id (`stoffel-program-v1`), the session
/// digest (`stoffel-mesh-session-v2`) and the instance id
/// (`stoffel-session-instance-v2`).
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
    /// Either way `n` would not be the number of distinct admissible nodes,
    /// and `install_expected_server_public_keys` would quietly install fewer
    /// keys than the roster listed (`quic.rs:1281-1289`).
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
    /// stoffelnet refused the roster.
    ///
    /// Carries its message verbatim; the ones reachable from here are "local
    /// certificate must be installed before the server certificate roster",
    /// "local certificate is absent from the server certificate roster",
    /// "already connected server peer … is absent from the certificate roster"
    /// and "server certificate roster is already frozen"
    /// (`quic.rs:1294-1321`).
    #[error("the transport refused the certificate roster: {reason}")]
    InstallRejected { reason: String },
    /// Blocker B3, observed after the fact: the transport reports no allowlist.
    #[error("the certificate allowlist is empty after installing {nodes} nodes; peer authorization would be silently disabled")]
    AllowlistDisabled { nodes: usize },
}

/// Who the session is: the node certificates the coordinator serves, and the
/// `(n, t)` they come with.
///
/// `nodes` are kept in lexicographic order of their DER SPKI bytes, which is
/// both the coordinator's canonical order and the order
/// `QuicNetworkManager::get_sorted_public_keys` (`quic.rs:1856-1872`) puts them
/// in, so [`Roster::index_of`] returns the same index the transport's
/// `assign_party_ids` will, and node `i` of the served roster is party `i`.
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
    /// the key bytes. That is §9.B exactly, because §9.B digests SPKIs, not
    /// certificate bytes — so a roster built from keys needs no certificate.
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
    /// [`QuicNetworkManager::public_key_from_certificate_der`] (blocker B2) — a
    /// certificate it cannot derive is
    /// [`RosterError::ServedCertificateUnderivable`] — calls
    /// [`Roster::from_node_keys`], and refuses a served digest that differs from
    /// the recomputed one ([`RosterError::DigestMismatch`]).
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

    /// The coordinator's node-roster digest (design doc §9.B).
    ///
    /// Computed once, when the roster is built. The join compares it across
    /// parties before any MPC byte flows, the epoch store is keyed by it, and
    /// `derive_instance_id` mixes it into the session namespace (§9.D.5).
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
    /// outside the roster.
    ///
    /// The inverse of [`Roster::index_of`], and what lets a dial be *pinned* to
    /// the party it is meant for: a discovery loop knows which ranks it is
    /// missing long before it knows which address belongs to which rank.
    pub fn key_of(&self, rank: PartyId) -> Option<&NodePublicKey> {
        self.nodes.get(rank)
    }

    /// Make this roster the transport's peer-certificate allowlist: the nodes,
    /// and nothing else.
    ///
    /// `install_expected_server_public_keys(nodes)` requires the local
    /// certificate to already be installed and the local key to be in the
    /// roster (`quic.rs:1294-1305`), and it refuses to run at all if the
    /// allowlist is already non-empty and different (`quic.rs:1310-1321`) —
    /// one more reason no non-node key may enter the allowlist before it.
    ///
    /// Must run before the manager is shared. It takes `&mut self` on the
    /// transport, and it rejects a roster that omits an already-connected peer,
    /// so it belongs at the very start of mesh formation — before any dial,
    /// before the accept loop is spawned, and before `Arc::new(mgr)`.
    pub fn install_into(&self, net: &mut QuicNetworkManager) -> Result<(), RosterError> {
        net.install_expected_server_public_keys(self.nodes.iter().cloned())
            .map_err(|reason| RosterError::InstallRejected { reason })?;

        // Blocker B3, read back from the transport rather than inferred: an
        // empty set makes `verify_peer_public_key_allowed` return `Ok(())` for
        // every peer, so "the roster installed" and "peer authorization is on"
        // have to be separate statements.
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

    use stoffelnet::transports::quic::NetworkManager;
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;
    use crate::tests::test_utils::init_crypto_provider;

    /// Budget for one loopback QUIC handshake in the enforcement test.
    ///
    /// Generous on purpose: it bounds a test that would otherwise hang, and is
    /// never the thing under test.
    const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

    /// The §9.B golden vector: `ids/nodes/cert{0..4}.crt` with `t = 1`.
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

    /// [`listening_manager`] on a caller-chosen address, for the tests that
    /// have to dial it.
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
    /// self-signed certificate for it on first use (`ensure_local_certificate`,
    /// `quic.rs:1741-1757`), so it has a transport identity that no roster can
    /// possibly list.
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
    /// coordinator's `ClientIdentity` shape would match no peer at all.
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

    /// The shared golden vector of design doc §9.B: the coordinator's
    /// `node_roster_golden_vector_matches_the_shipped_node_certificates` asserts
    /// the same order and the same digest over the same five certificates, so
    /// the two digest implementations cannot drift apart unnoticed.
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

        assert_eq!(
            Roster::from_coordinator(&served, 1, [7u8; 32])
                .expect_err("a digest that is not the certificates' is refused"),
            RosterError::DigestMismatch {
                served: [7u8; 32],
                computed,
            }
        );
        // The served threshold is part of the digest too.
        assert!(matches!(
            Roster::from_coordinator(&served, 1, computed),
            Ok(ref roster) if roster.digest() == computed
        ));
    }

    /// Retargets `a_file_that_is_not_a_certificate_names_itself`: file I/O moved
    /// to the runner's `--cert`/`--coord-cert` handling, and what reaches the
    /// roster now is served bytes, named by their position.
    #[test]
    fn a_served_certificate_that_is_not_a_certificate_names_its_index() {
        let identities = generate_identities(2);
        let served: Vec<&[u8]> = vec![
            identities[0].cert_der.as_slice(),
            b"this is not DER",
            identities[1].cert_der.as_slice(),
        ];

        let error = Roster::from_coordinator(&served, 1, [0u8; 32])
            .expect_err("a served entry that is not a certificate is fatal");

        assert!(
            matches!(
                error,
                RosterError::ServedCertificateUnderivable { index: 1, .. }
            ),
            "expected an underivable-certificate error naming index 1, got: {error}"
        );
    }

    /// Blocker B3's first half: a roster that parsed to nothing must fail
    /// loudly, not install an allowlist that authorizes everyone.
    #[test]
    fn an_empty_node_roster_is_refused_before_the_transport_is_touched() {
        assert_eq!(
            Roster::from_node_keys(Vec::new(), 1).expect_err("an empty roster cannot be built"),
            RosterError::Empty
        );
    }

    /// `DuplicateNode` is checked before either threshold rule, so a two-entry
    /// roster of one key still fails for the duplicate.
    #[test]
    fn a_repeated_node_certificate_is_refused_rather_than_shrinking_the_mesh() {
        let identity = generate_identity();
        let compact_id = identity.public_key.derive_id();

        assert_eq!(
            Roster::from_node_keys(
                vec![identity.public_key.clone(), identity.public_key.clone()],
                1,
            )
            .expect_err("a duplicate node entry makes n wrong"),
            RosterError::DuplicateNode { compact_id }
        );
    }

    /// Retargets `a_threshold_at_or_above_the_party_count_is_refused`, whose
    /// accepted `n = 2, t = 1` came from the NAT stack design doc §4 deleted.
    #[test]
    fn a_roster_below_two_t_plus_one_or_with_a_zero_threshold_is_refused() {
        assert_eq!(
            Roster::from_node_keys(keys(&generate_identities(2)), 1)
                .expect_err("n = 2 is below 2t + 1 for t = 1"),
            RosterError::ThresholdTooLarge { n: 2, threshold: 1 }
        );
        assert_eq!(
            Roster::from_node_keys(keys(&generate_identities(3)), 2)
                .expect_err("n = 3 is below 2t + 1 for t = 2"),
            RosterError::ThresholdTooLarge { n: 3, threshold: 2 }
        );
        assert_eq!(
            Roster::from_node_keys(keys(&generate_identities(3)), 0)
                .expect_err("t = 0 lets one node reconstruct every secret"),
            RosterError::ZeroThreshold
        );
        Roster::from_node_keys(keys(&generate_identities(3)), 1)
            .expect("n = 3, t = 1 is the smallest roster there is");
        Roster::from_node_keys(keys(&generate_identities(5)), 2)
            .expect("n = 5, t = 2 meets 2t + 1 exactly");
    }

    /// Party indices are derived locally from sorted SPKIs, and the roster must
    /// derive the *same* order the transport does.
    #[test]
    fn index_of_follows_the_lexicographic_spki_order_the_transport_uses() {
        let identities = generate_identities(4);
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let mut expected = keys(&identities);
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(roster.nodes(), expected.as_slice());
        for (rank, key) in expected.iter().enumerate() {
            assert_eq!(roster.index_of(key), Some(rank));
            assert_eq!(roster.key_of(rank), Some(key));
        }
        assert_eq!(roster.index_of(&generate_identity().public_key), None);
    }

    /// Retargets `the_digest_ignores_input_order_but_not_membership_or_parameters`:
    /// the digest identifies the *membership* and its threshold, not the order
    /// the coordinator's operator listed the certificates in. The client
    /// dimension is gone with the client set.
    #[test]
    fn the_digest_ignores_input_order_but_not_membership_or_threshold() {
        let identities = generate_identities(5);

        let forwards = Roster::from_node_keys(keys(&identities), 1).expect("build forward roster");
        let mut reversed = keys(&identities);
        reversed.reverse();
        let backwards = Roster::from_node_keys(reversed, 1).expect("build reversed roster");
        assert_eq!(forwards.digest(), backwards.digest());

        let other_threshold =
            Roster::from_node_keys(keys(&identities), 2).expect("build t=2 roster");
        assert_ne!(forwards.digest(), other_threshold.digest());

        let fewer =
            Roster::from_node_keys(keys(&identities[..4]), 1).expect("build a four-node roster");
        assert_ne!(forwards.digest(), fewer.digest());

        let other_members = Roster::from_node_keys(keys(&generate_identities(5)), 1)
            .expect("build disjoint roster");
        assert_ne!(forwards.digest(), other_members.digest());
    }

    /// Blockers B2 and B3, end to end. The boolean `install_into` reads back
    /// says the allowlist is non-empty; only a handshake says it holds the
    /// right *bytes*. An allowlist built from the bare BIT STRING would satisfy
    /// that boolean and then refuse every roster member — B2's whole failure
    /// mode — and an allowlist that had silently stayed empty would admit the
    /// outsider, which is B3's.
    #[tokio::test]
    async fn an_installed_roster_admits_a_member_and_refuses_an_outsider() {
        let identities = generate_identities(3);
        let outsider = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let addr = reserve_local_addr();
        let mut net = listening_manager_at(&identities[0], addr).await;
        roster.install_into(&mut net).expect("install the roster");

        let refusal = accept_while(&net, async {
            let mut intruder = dialing_manager(&outsider).await;
            let _ = tokio::time::timeout(HANDSHAKE_BUDGET, intruder.connect(addr)).await;
            intruder
        })
        .await
        .expect_err("a certificate outside the roster must not be admitted");
        // The *certificate* refusal (`verify_peer_public_key_allowed`), not the
        // node-list one (`Unauthorized peer ID … not in allowlist`) a
        // certificate-free `use_tls` accept would have produced: only the
        // former proves the installed roster is what did the rejecting.
        assert!(
            refusal.contains("peer certificate public key is not in allowlist"),
            "expected the certificate-allowlist refusal, got: {refusal}"
        );

        accept_while(&net, async {
            let mut member = dialing_manager(&identities[1]).await;
            member
                .connect(addr)
                .await
                .expect("a roster member must reach a roster-pinned node");
            member
        })
        .await
        .expect("a roster member must be admitted by the roster it is listed in");
    }

    /// Design doc §9 rule 3, as the transport sees it, and the retarget of the
    /// five client-set tests the node-only roster removed
    /// (`a_roster_admits_its_clients_alongside_its_nodes`,
    /// `a_roster_pinned_node_admits_its_clients_and_refuses_an_unlisted_one`,
    /// `a_roster_pinned_node_refuses_a_client_that_brings_no_certificate`,
    /// `a_listed_client_still_exchanges_bytes_through_an_allowlisted_node` and
    /// `a_clone_taken_before_the_install_still_enforces_the_roster_for_clients`).
    ///
    /// A certificate that is not a node is refused at the mesh transport in
    /// both ALPN roles, and so is a manager that brings no certificate at all —
    /// including on a clone taken *before* the install, the order in which the
    /// runner's party setups take theirs. Clients reach a node through its RPC
    /// listener, never through the mesh.
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

    /// The mechanism the runner's party setups rely on, carried to payload
    /// bytes: they serve from clones of the mesh manager, and that keeps working
    /// only because `allowed_peer_public_keys` is an `Arc<DashSet>` mutated *in
    /// place* (`quic.rs:1445-1450`). A clone taken before the install must admit
    /// a roster member and carry a round trip of bytes, since
    /// `extract_and_verify_peer_public_key` runs at `quic.rs:3292` and a
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
    /// §9, "Rule 3 is a transport-security requirement"): stoffelnet authorizes
    /// the certificate before it looks at the ALPN role, so an extra key that
    /// dials with the *server* ALPN is accepted as a server peer, lands in
    /// `peer_public_keys` and is ranked by `get_sorted_public_keys` — the
    /// party-index order.
    #[tokio::test]
    async fn an_allowlisted_non_node_key_is_ranked_as_a_server_peer() {
        let identities = generate_identities(3);
        let extra = generate_identity();
        let roster = Roster::from_node_keys(keys(&identities), 1).expect("build roster");

        let addr = reserve_local_addr();
        let mut net = listening_manager_at(&identities[0], addr).await;
        roster.install_into(&mut net).expect("install the roster");
        // What `install_into`'s deleted client loop used to do.
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

    /// Why [`Roster::install_into`] must be the first thing to touch the
    /// allowlist, and one more reason no non-node key may enter it: a key added
    /// before the node install makes the allowlist non-empty, and the node
    /// install then sees a frozen set that does not match its own
    /// (`quic.rs:1310-1321`).
    #[tokio::test]
    async fn adding_a_client_before_the_nodes_freezes_the_node_install_out() {
        let identities = generate_identities(3);
        let client = generate_identity();
        let mut net = listening_manager(&identities[0]).await;

        net.add_allowed_certificate_public_key(client.public_key.clone());
        let reason = net
            .install_expected_server_public_keys(keys(&identities))
            .expect_err("a non-empty differing allowlist freezes the roster install");

        assert!(
            reason.contains("frozen"),
            "expected the frozen-roster refusal, got: {reason}"
        );
    }

    /// The precondition `install_into` inherits: the local certificate must
    /// already be on the manager, and it must be one of the roster's nodes.
    #[tokio::test]
    async fn a_node_outside_its_own_roster_cannot_install_it() {
        let outsider = generate_identity();
        let roster = Roster::from_node_keys(keys(&generate_identities(3)), 1).expect("build");
        let mut net = listening_manager(&outsider).await;

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
