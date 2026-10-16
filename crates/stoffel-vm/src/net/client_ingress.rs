//! Admission control for a node's client-facing listener.
//!
//! `docs/design/bootnode-elimination.md` §9 rule 3 gives a standing node two
//! transports: the roster-pinned mesh, whose certificate allowlist decides who
//! may connect at all, and a client-facing listener that deliberately carries
//! **no** allowlist, because stoffelnet verifies a certificate before it knows
//! the connection's role — a key in a transport allowlist is a key with
//! node-level network standing
//! ([`an_allowlisted_non_node_key_is_ranked_as_a_server_peer`](crate::net::roster)),
//! and nothing may turn a client certificate into that.
//!
//! So the transport authorizes nobody here, and the node does. The coordinator
//! is the sole authority for which clients exist: it publishes, per execution,
//! the client certificates that execution admits, and an execution registers
//! that roster with
//! [`ExecutionTransportMux`](crate::net::execution_transport::ExecutionTransportMux)
//! when it prepares. [`ClientIngressGate`] is what holds the socket to it.
//! Four refusals, in the order [`ClientIngressGate::admit`] asks them:
//!
//! * **No readable certificate identity.** Such a connection can never be
//!   named — [`ExecutionTransportMux`](crate::net::execution_transport::ExecutionTransportMux)
//!   answers `ClientCertificateIdentityUnavailable` for it — and because the
//!   authenticated key is fixed when the connection is accepted and never
//!   becomes readable afterwards, there is nothing to wait for. stoffelnet can
//!   produce one on a listener with no allowlist.
//! * **A certificate no registered execution names.** The coordinator has not
//!   admitted it anywhere on this node, so no frame it could send would ever be
//!   routed and the connection is refused outright rather than held. Every
//!   connection this listener holds therefore belongs to a client the
//!   coordinator admitted, and the two caps below are bounds *within* that.
//! * **The total cap.** What every client connection together may occupy.
//! * **The per-certificate cap.** One admitted certificate legitimately opens
//!   more than one connection (a client dials every party, and a party's output
//!   route is separate from its input route), so this is deliberately not one —
//!   but it is not unbounded either, or one admitted client reaches the total
//!   cap on its own and locks the rest of the deployment out.
//!
//! The admission refusal is what makes those caps bounds on the deployment's
//! own clients rather than on an attacker's appetite. Certificates are free,
//! and on a listener with no allowlist every self-signed one reaches the
//! handshake, so a cap stated per certificate bounds nothing a peer cannot
//! defeat by churning them: before this rule, a peer could hold the whole
//! listener and turn the total cap into a deterministic refusal for every
//! client the coordinator admitted. A certificate the coordinator never named
//! now occupies no slot at all.
//!
//! **What this costs, and why it is the right cost.** A client that dials a
//! party before the node has registered the execution naming it is refused,
//! and has to dial again — the refusal is a closed connection rather than a
//! handshake failure, because the gate runs after the handshake, so a client
//! must treat a dropped connection as retryable
//! (`stoffel-vm-runner`'s `establish_coordinator_output_client_routes` does).
//! Nothing admits such a client early: admission is re-read on every accept,
//! so the retry is admitted the moment the registration lands, and in the
//! ordinary flow there is nothing to retry, because the coordinator publishes
//! an execution to its nodes before the client it admitted associates with it.
//!
//! A refused connection is not retried against: the gate holds no memory of it,
//! because remembering unauthenticated peers is itself unbounded state. The
//! bound it enforces is concurrent occupancy, and [`ClientIngressGate::admit`]
//! prunes connections that have closed before it counts, so a client that
//! leaves releases its slot.
//!
//! What the gate bounds is concurrent occupancy of *this* listener, which is
//! not the whole cost of an unauthenticated handshake. stoffelnet records every
//! accepted client's public key in its own `client_public_keys` map and prunes
//! only `client_connections` and `client_ids` in `cleanup_dead_connections`, so
//! a peer cycling free self-signed certificates leaves one SPKI behind per
//! handshake for the life of the process — including the certificates this gate
//! refuses, because that insert happens inside stoffelnet's `accept()`, strictly
//! before [`ClientIngressGate::admit`] is ever consulted. No policy here can
//! prevent it: bounding it needs stoffelnet to prune that map alongside
//! `client_ids`. §9 of `docs/design/bootnode-elimination.md` records the
//! residual, and
//! `roster.rs::the_transports_client_key_table_outlives_its_connections` pins
//! the upstream behaviour the residual rests on.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Weak};

use stoffelnet::network_utils::{CertificateIdentity, ClientId};
use stoffelnet::transports::quic::PeerConnection;
use tokio::sync::Mutex;

use crate::net::execution_transport::ExecutionTransportMux;

/// How much of a node's client-facing listener one admitted client, and all of
/// them together, may occupy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIngressLimits {
    /// Concurrent accepted client connections across every certificate.
    pub max_connections: NonZeroUsize,
    /// Concurrent accepted client connections sharing one certificate.
    pub max_connections_per_certificate: NonZeroUsize,
}

impl ClientIngressLimits {
    /// The caps a standing node runs with.
    ///
    /// Both bound the deployment's own clients, because a certificate the
    /// coordinator never admitted holds no connection here at all, so both have
    /// to clear real load by a wide margin: a cap a healthy deployment can
    /// reach is an outage, not a bound. One client opens a connection to every
    /// party for each execution it joins, and an output-only client holds a
    /// second route, so one party's socket sees on the order of
    /// `2 * clients * concurrent executions`.
    ///
    /// The per-certificate cap is the one that is easy to set too low. The
    /// standing-concurrency campaign's examples take their client certificate
    /// from the program manifest's client slot, so nearly every single-client
    /// example uses `cert0`, and `all_examples` runs waves of
    /// `STOFFEL_ALL_EXAMPLES_WAVE_SIZE` (16 by default, and raisable)
    /// executions at once: a cap of 16 would be *at* the campaign's own
    /// concurrency. 256 leaves an order of magnitude over that while still
    /// denying any one certificate more than a quarter of the listener.
    pub fn standing_node() -> Self {
        Self {
            max_connections: NonZeroUsize::new(1024).expect("1024 is not zero"),
            max_connections_per_certificate: NonZeroUsize::new(256).expect("256 is not zero"),
        }
    }
}

/// Whether some execution registered on this node names a certificate.
///
/// This is the weaker of the two questions the coordinator's admissions answer,
/// and the only one that can be asked of a connection with no frame on it yet:
/// has the coordinator admitted this certificate *anywhere* on this node. It is
/// what the client-facing listener admits a connection on. Whether a frame may
/// reach a particular execution remains
/// [`ExecutionTransportMux`]'s decision, per execution, per frame, in
/// `authorize_client_route_if_registered`, and it stays there: being admitted
/// to one execution buys nothing in another.
pub trait AdmittedClientDirectory: Send + Sync {
    fn names_client_certificate(&self, identity: CertificateIdentity) -> bool;
}

impl AdmittedClientDirectory for ExecutionTransportMux {
    fn names_client_certificate(&self, identity: CertificateIdentity) -> bool {
        ExecutionTransportMux::names_client_certificate(self, identity)
    }
}

/// What [`ClientIngressGate::admit`] decided, and why.
///
/// Every refusal names the bound it hit so the caller can log a cause rather
/// than a bare rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIngressDecision {
    /// Admitted, with the certificate-derived id and its resulting occupancy.
    ///
    /// Only a certificate a registered execution names is ever admitted, so an
    /// admission is always one the coordinator published.
    Admitted {
        client_id: ClientId,
        connections_for_certificate: usize,
    },
    /// The TLS handshake produced no readable certificate public key, so the
    /// per-execution client roster could never match this connection.
    RefusedUnidentifiedCertificate,
    /// No execution registered on this node names this certificate, so the
    /// coordinator has not admitted it here and this listener holds no
    /// connection for it.
    RefusedCertificateNoExecutionNames { client_id: ClientId },
    /// [`ClientIngressLimits::max_connections`] is already occupied.
    RefusedTotalCapacity { max_connections: usize },
    /// This certificate already holds
    /// [`ClientIngressLimits::max_connections_per_certificate`].
    RefusedCertificateCapacity {
        client_id: ClientId,
        max_connections_per_certificate: usize,
    },
}

impl ClientIngressDecision {
    /// Whether the caller should keep the connection.
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

impl std::fmt::Display for ClientIngressDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admitted {
                client_id,
                connections_for_certificate,
            } => write!(
                f,
                "admitted client {client_id}, named by a registered execution ({connections_for_certificate} connections for this certificate)"
            ),
            Self::RefusedUnidentifiedCertificate => {
                write!(f, "the TLS handshake exposed no client certificate public key, so no per-execution admission can name it")
            }
            Self::RefusedCertificateNoExecutionNames { client_id } => write!(
                f,
                "client {client_id}'s certificate is named by no execution registered on this node, so the coordinator has not admitted it here"
            ),
            Self::RefusedTotalCapacity { max_connections } => write!(
                f,
                "the client-facing listener already holds its {max_connections} permitted connections"
            ),
            Self::RefusedCertificateCapacity {
                client_id,
                max_connections_per_certificate,
            } => write!(
                f,
                "client {client_id} already holds its {max_connections_per_certificate} permitted connections"
            ),
        }
    }
}

/// Holds a node's client-facing listener to the coordinator's admissions, and
/// bounds what those admissions may occupy.
pub struct ClientIngressGate {
    limits: ClientIngressLimits,
    /// Which certificates the executions registered on this node name, which is
    /// the whole of what this listener will hold a connection for.
    admitted_clients: Arc<dyn AdmittedClientDirectory>,
    /// Admitted connections per certificate-derived id, held weakly so the gate
    /// never keeps a connection alive that its owner has dropped.
    admitted: Mutex<HashMap<ClientId, Vec<Weak<dyn PeerConnection>>>>,
}

impl std::fmt::Debug for ClientIngressGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIngressGate")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl ClientIngressGate {
    pub fn new(
        limits: ClientIngressLimits,
        admitted_clients: Arc<dyn AdmittedClientDirectory>,
    ) -> Self {
        Self {
            limits,
            admitted_clients,
            admitted: Mutex::new(HashMap::new()),
        }
    }

    pub fn limits(&self) -> ClientIngressLimits {
        self.limits
    }

    /// Decide whether a freshly accepted client connection may be kept.
    ///
    /// The caller closes anything this refuses. The first question is the
    /// coordinator's — does any registered execution name this certificate —
    /// and a certificate it has not admitted here is refused before any
    /// occupancy is counted, so an unadmitted peer costs the node nothing but
    /// the handshake stoffelnet already completed. The admission is resolved
    /// per accept rather than remembered, so a client refused while its
    /// execution was still preparing is admitted on the dial after the
    /// registration lands.
    ///
    /// A departed client's slot is released without any explicit release call —
    /// there is no release call on purpose, because a caller that forgot one
    /// would leak occupancy permanently. Instead, a bound that is *about* to be
    /// hit triggers a prune and is then re-evaluated, so pruning costs nothing
    /// on the healthy path and the only accepts that pay for it are the ones at
    /// a bound.
    pub async fn admit(&self, connection: &Arc<dyn PeerConnection>) -> ClientIngressDecision {
        let Some(public_key) = connection.authenticated_peer_public_key() else {
            return ClientIngressDecision::RefusedUnidentifiedCertificate;
        };
        let client_id = public_key.derive_id();
        if !self
            .admitted_clients
            .names_client_certificate(public_key.certificate_identity())
        {
            return ClientIngressDecision::RefusedCertificateNoExecutionNames { client_id };
        }

        let mut admitted = self.admitted.lock().await;
        let mut pruned = false;

        let max_connections = self.limits.max_connections.get();
        let mut total: usize = admitted.values().map(Vec::len).sum();
        if total >= max_connections {
            prune_closed(&mut admitted).await;
            pruned = true;
            total = admitted.values().map(Vec::len).sum();
        }
        if total >= max_connections {
            return ClientIngressDecision::RefusedTotalCapacity { max_connections };
        }

        let per_certificate = self.limits.max_connections_per_certificate.get();
        if admitted
            .get(&client_id)
            .is_some_and(|connections| connections.len() >= per_certificate)
            && !pruned
        {
            prune_closed(&mut admitted).await;
        }
        let entry = admitted.entry(client_id).or_default();
        if entry.len() >= per_certificate {
            return ClientIngressDecision::RefusedCertificateCapacity {
                client_id,
                max_connections_per_certificate: per_certificate,
            };
        }
        entry.push(Arc::downgrade(connection));
        ClientIngressDecision::Admitted {
            client_id,
            connections_for_certificate: entry.len(),
        }
    }

    /// Live admitted connections, after pruning. For tests and diagnostics.
    pub async fn occupancy(&self) -> usize {
        let mut admitted = self.admitted.lock().await;
        prune_closed(&mut admitted).await;
        admitted.values().map(Vec::len).sum()
    }
}

/// Drop every entry whose connection has been dropped or closed.
///
/// `is_connected` is the only liveness signal `PeerConnection` offers, and it
/// is async, so this is a sequential walk over at most
/// [`ClientIngressLimits::max_connections`] entries. [`ClientIngressGate::admit`]
/// calls it only when a cap is already reached, so the walk is paid for by the
/// accepts at a bound rather than by every accept.
async fn prune_closed(admitted: &mut HashMap<ClientId, Vec<Weak<dyn PeerConnection>>>) {
    for connections in admitted.values_mut() {
        let mut live = Vec::with_capacity(connections.len());
        for weak in connections.drain(..) {
            let Some(connection) = weak.upgrade() else {
                continue;
            };
            if connection.is_connected().await {
                live.push(weak);
            }
        }
        *connections = live;
    }
    admitted.retain(|_, connections| !connections.is_empty());
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    use stoffelnet::network_utils::{ClientType, NodePublicKey, PartyId};
    use stoffelnet::transports::quic::ConnectionState;

    use super::*;

    /// A client connection with exactly the two properties the gate reads: the
    /// certificate key the handshake authenticated, and whether it is still up.
    ///
    /// Nothing else is exercised, so the remaining trait methods are
    /// deliberately inert rather than approximated.
    struct TestClientConnection {
        public_key: Option<NodePublicKey>,
        connected: AtomicBool,
    }

    impl TestClientConnection {
        fn identified(key: &[u8]) -> Arc<dyn PeerConnection> {
            Arc::new(Self {
                public_key: Some(NodePublicKey(key.to_vec())),
                connected: AtomicBool::new(true),
            })
        }

        fn unidentified() -> Arc<dyn PeerConnection> {
            Arc::new(Self {
                public_key: None,
                connected: AtomicBool::new(true),
            })
        }
    }

    impl PeerConnection for TestClientConnection {
        fn send<'a>(
            &'a self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn receive<'a>(
            &'a self,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
        {
            Box::pin(async { Err("the gate never reads".to_string()) })
        }

        fn remote_address(&self) -> SocketAddr {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))
        }

        fn close<'a>(
            &'a self,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.connected.store(false, Ordering::SeqCst);
                Ok(())
            })
        }

        fn state<'a>(
            &'a self,
        ) -> Pin<Box<dyn std::future::Future<Output = ConnectionState> + Send + 'a>> {
            Box::pin(async move {
                if self.connected.load(Ordering::SeqCst) {
                    ConnectionState::Connected
                } else {
                    ConnectionState::Closed
                }
            })
        }

        fn is_connected<'a>(
            &'a self,
        ) -> Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            Box::pin(async move { self.connected.load(Ordering::SeqCst) })
        }

        fn get_connection_role(&self) -> ClientType {
            ClientType::Client
        }

        fn authenticated_peer_public_key(&self) -> Option<NodePublicKey> {
            self.public_key.clone()
        }

        fn remote_party_id(&self) -> Option<PartyId> {
            None
        }

        fn set_remote_party_id(&self, _party_id: PartyId) {}
    }

    /// The admission directory the gate consults, decided by the test rather
    /// than by a live mux.
    ///
    /// `names_every_certificate` is for the tests whose subject is a cap: with
    /// every certificate admitted by the coordinator, the cap under test is the
    /// only thing that can refuse anything.
    #[derive(Debug, Default)]
    struct TestDirectory {
        names_every_certificate: bool,
        named: std::sync::Mutex<HashSet<CertificateIdentity>>,
    }

    impl TestDirectory {
        fn names_every_certificate() -> Arc<Self> {
            Arc::new(Self {
                names_every_certificate: true,
                named: std::sync::Mutex::new(HashSet::new()),
            })
        }

        fn naming(keys: &[&[u8]]) -> Arc<Self> {
            Arc::new(Self {
                names_every_certificate: false,
                named: std::sync::Mutex::new(
                    keys.iter()
                        .map(|key| NodePublicKey(key.to_vec()).certificate_identity())
                        .collect(),
                ),
            })
        }

        /// What a coordinator-pushed execution registration does to the gate's
        /// view: a certificate nothing named a moment ago is now named.
        fn start_naming(&self, key: &[u8]) {
            self.named
                .lock()
                .expect("the directory lock is not poisoned")
                .insert(NodePublicKey(key.to_vec()).certificate_identity());
        }
    }

    impl AdmittedClientDirectory for TestDirectory {
        fn names_client_certificate(&self, identity: CertificateIdentity) -> bool {
            self.names_every_certificate
                || self
                    .named
                    .lock()
                    .expect("the directory lock is not poisoned")
                    .contains(&identity)
        }
    }

    fn limits(total: usize, per_certificate: usize) -> ClientIngressLimits {
        ClientIngressLimits {
            max_connections: NonZeroUsize::new(total).expect("non-zero total"),
            max_connections_per_certificate: NonZeroUsize::new(per_certificate)
                .expect("non-zero per-certificate"),
        }
    }

    /// A gate whose subject is a cap rather than the admission rule.
    fn capped_gate(total: usize, per_certificate: usize) -> ClientIngressGate {
        ClientIngressGate::new(
            limits(total, per_certificate),
            TestDirectory::names_every_certificate(),
        )
    }

    /// A cap a healthy deployment can reach is an outage, not a bound.
    ///
    /// The number that is easy to get wrong is the per-certificate one: the
    /// standing-concurrency campaign's examples take their client certificate
    /// from the program manifest's client slot, so nearly every single-client
    /// example runs as `cert0`, and `all_examples` submits waves of
    /// `STOFFEL_ALL_EXAMPLES_WAVE_SIZE` executions at once — 16 by default. A
    /// cap of 16 would therefore sit exactly at the campaign's own concurrency.
    /// This fails if anyone narrows the margin without saying so.
    #[test]
    fn the_standing_caps_leave_room_for_real_load() {
        /// `DEFAULT_ALL_EXAMPLES_WAVE_SIZE` in
        /// `docker/standing-concurrency/all_examples.py`.
        const CAMPAIGN_WAVE_SIZE: usize = 16;
        /// An execution's client dials every party once, and an output-only
        /// client holds a second route on the same socket.
        const ROUTES_PER_EXECUTION_PER_CERTIFICATE: usize = 2;

        let limits = ClientIngressLimits::standing_node();
        let campaign_load = CAMPAIGN_WAVE_SIZE * ROUTES_PER_EXECUTION_PER_CERTIFICATE;
        assert!(
            limits.max_connections_per_certificate.get() >= campaign_load * 8,
            "one certificate's cap ({}) must clear the campaign's own concurrency ({campaign_load}) by an order of magnitude",
            limits.max_connections_per_certificate
        );
        assert!(
            limits.max_connections >= limits.max_connections_per_certificate,
            "a per-certificate cap above the total cap would never be reachable"
        );
        assert!(
            limits.max_connections.get() >= limits.max_connections_per_certificate.get() * 4,
            "no single certificate may hold more than a quarter of the listener"
        );
        // The whole listener is the coordinator-admitted clients' now, so the
        // total cap is what has to hold a real wave of them: this is the
        // assertion the reserve's margin used to carry.
        assert!(
            limits.max_connections.get() >= campaign_load * 8,
            "the total cap ({}) must hold a real wave of coordinator-admitted clients ({campaign_load}) by an order of magnitude",
            limits.max_connections
        );
    }

    /// The lockout the per-certificate cap alone cannot prevent: certificates
    /// are free, so a peer churning them defeats any bound stated per
    /// certificate. What stops it is that a certificate no registered execution
    /// names holds no slot at all, so the caps bound the deployment's own
    /// clients and nothing an attacker can manufacture.
    #[tokio::test]
    async fn a_flood_of_unnamed_certificates_cannot_lock_out_an_admitted_client() {
        const ADMITTED: &[u8] = b"coordinator-admitted";
        let gate = ClientIngressGate::new(limits(4, 4), TestDirectory::naming(&[ADMITTED]));

        // A fresh certificate per dial, so the per-certificate cap is never
        // what refuses anything: this is the churn the admission rule exists
        // for, and none of it occupies the listener.
        for index in 0..8u8 {
            let connection = TestClientConnection::identified(&[index]);
            assert_eq!(
                gate.admit(&connection).await,
                ClientIngressDecision::RefusedCertificateNoExecutionNames {
                    client_id: NodePublicKey(vec![index]).derive_id(),
                },
                "a certificate no execution names is refused (connection {index})"
            );
        }
        assert_eq!(
            gate.occupancy().await,
            0,
            "the flood must hold no part of the listener"
        );

        // And the whole listener is still the coordinator's client's, with both
        // of its routes.
        let input_route = TestClientConnection::identified(ADMITTED);
        let output_route = TestClientConnection::identified(ADMITTED);
        assert!(matches!(
            gate.admit(&input_route).await,
            ClientIngressDecision::Admitted {
                connections_for_certificate: 1,
                ..
            }
        ));
        assert!(matches!(
            gate.admit(&output_route).await,
            ClientIngressDecision::Admitted {
                connections_for_certificate: 2,
                ..
            }
        ));
        assert_eq!(gate.occupancy().await, 2);
    }

    /// The admission follows the coordinator rather than a static list: a
    /// certificate refused a moment ago is admitted once an execution naming it
    /// is registered, which is how a client that reaches a party before its
    /// execution does gets in on its retry.
    #[tokio::test]
    async fn naming_a_certificate_is_what_admits_it() {
        const LATE: &[u8] = b"admitted-a-moment-later";
        let directory = TestDirectory::naming(&[]);
        let gate = ClientIngressGate::new(limits(2, 2), Arc::clone(&directory) as Arc<_>);

        let early = TestClientConnection::identified(LATE);
        assert_eq!(
            gate.admit(&early).await,
            ClientIngressDecision::RefusedCertificateNoExecutionNames {
                client_id: NodePublicKey(LATE.to_vec()).derive_id(),
            },
            "nothing names it yet, so the node has heard no admission for it"
        );
        assert_eq!(gate.occupancy().await, 0);

        directory.start_naming(LATE);

        let retry = TestClientConnection::identified(LATE);
        assert!(matches!(
            gate.admit(&retry).await,
            ClientIngressDecision::Admitted { .. }
        ));
        assert_eq!(gate.occupancy().await, 1);
    }

    /// The listener authorizes no certificate, so an unreadable one is not a
    /// connection to wait on: the per-execution roster can never name it.
    #[tokio::test]
    async fn a_connection_without_a_certificate_identity_is_refused() {
        let gate = capped_gate(8, 4);

        assert_eq!(
            gate.admit(&TestClientConnection::unidentified()).await,
            ClientIngressDecision::RefusedUnidentifiedCertificate
        );
        assert_eq!(
            gate.occupancy().await,
            0,
            "a refused connection must occupy nothing"
        );
    }

    /// The bound this type exists for: the surplus is refused, and an already
    /// admitted certificate keeps its slots.
    #[tokio::test]
    async fn the_surplus_beyond_the_total_cap_is_refused() {
        let gate = capped_gate(3, 3);
        let mut held = Vec::new();
        for index in 0..3u8 {
            let connection = TestClientConnection::identified(&[index]);
            assert!(
                gate.admit(&connection).await.is_admitted(),
                "connection {index} is within the cap"
            );
            held.push(connection);
        }

        let surplus = TestClientConnection::identified(&[9]);
        assert_eq!(
            gate.admit(&surplus).await,
            ClientIngressDecision::RefusedTotalCapacity { max_connections: 3 }
        );
        assert_eq!(gate.occupancy().await, 3);
    }

    /// One certificate may hold several routes, but not the whole listener.
    #[tokio::test]
    async fn one_certificate_cannot_occupy_more_than_its_share() {
        let gate = capped_gate(16, 2);
        let first = TestClientConnection::identified(b"same");
        let second = TestClientConnection::identified(b"same");
        let third = TestClientConnection::identified(b"same");

        assert!(matches!(
            gate.admit(&first).await,
            ClientIngressDecision::Admitted {
                connections_for_certificate: 1,
                ..
            }
        ));
        assert!(matches!(
            gate.admit(&second).await,
            ClientIngressDecision::Admitted {
                connections_for_certificate: 2,
                ..
            }
        ));
        let client_id = NodePublicKey(b"same".to_vec()).derive_id();
        assert_eq!(
            gate.admit(&third).await,
            ClientIngressDecision::RefusedCertificateCapacity {
                client_id,
                max_connections_per_certificate: 2,
            }
        );

        // A different certificate is unaffected: the per-certificate cap is not
        // a way for one peer to lock the listener.
        let other = TestClientConnection::identified(b"other");
        assert!(gate.admit(&other).await.is_admitted());
    }

    /// A client that leaves releases its slot, with no release call to forget.
    #[tokio::test]
    async fn a_closed_connection_releases_its_slot() {
        let gate = capped_gate(2, 2);
        let first = TestClientConnection::identified(b"a");
        let second = TestClientConnection::identified(b"b");
        assert!(gate.admit(&first).await.is_admitted());
        assert!(gate.admit(&second).await.is_admitted());
        assert_eq!(
            gate.admit(&TestClientConnection::identified(b"c")).await,
            ClientIngressDecision::RefusedTotalCapacity { max_connections: 2 }
        );

        first.close().await.expect("the test connection closes");

        let replacement = TestClientConnection::identified(b"c");
        assert!(
            gate.admit(&replacement).await.is_admitted(),
            "the closed connection's slot must be reusable"
        );
        assert_eq!(gate.occupancy().await, 2);
    }

    /// Dropping the owner's `Arc` must release the slot too: the gate holds
    /// weak references precisely so a dropped connection cannot pin occupancy.
    #[tokio::test]
    async fn a_dropped_connection_releases_its_slot() {
        let gate = capped_gate(1, 1);
        {
            let only = TestClientConnection::identified(b"a");
            assert!(gate.admit(&only).await.is_admitted());
            assert_eq!(gate.occupancy().await, 1);
            // While it is held, the slot really is taken — otherwise the
            // release below would prove nothing.
            assert_eq!(
                gate.admit(&TestClientConnection::identified(b"b")).await,
                ClientIngressDecision::RefusedTotalCapacity { max_connections: 1 }
            );
        }

        assert_eq!(gate.occupancy().await, 0);
        assert!(gate
            .admit(&TestClientConnection::identified(b"b"))
            .await
            .is_admitted());
    }
}
