//! Characterization harness for the roster-pinned mesh join.
//!
//! See `docs/design/bootnode-elimination.md`. This module began life in Stage 0
//! as cover for the *bootnode* join — invariants that any replacement had to
//! reproduce, pinned before the thing being replaced was touched. Stage 5 ran
//! the same invariant set against [`MeshJoin`], and Stage 8 deleted the
//! bootnode, so what is left is the invariant set and the one join that has to
//! satisfy it. Nothing was weakened in the process: every assertion below was
//! written against the old path first and still holds.
//!
//! It stands up n real `QuicNetworkManager` endpoints with per-node `rcgen`
//! certificates, drives them through the production [`SessionJoin`] seam, and
//! records what every node believes about the session. The invariants:
//!
//! 1. **Full connectivity** — every node ends up holding every other node's
//!    authenticated SPKI, and every peer connection carries an assigned party
//!    index.
//! 2. **Party indices follow SPKI sort order** — the index a node computes
//!    locally is its rank in the lexicographic order of DER SubjectPublicKeyInfo
//!    bytes, *not* the id it asked to be known by. Each party deliberately
//!    proposes the wrong index, so a join that echoed the proposal back would
//!    fail here.
//! 3. **An agreed session tuple** — program id, entry, `n`, `t` and the party
//!    address list are identical at every node, and the addresses are filed
//!    under the rank every node derives from the certificates.
//! 4. **A fresh `instance_id`** — two joins over *the same certificate roster*,
//!    program, entry **and epoch stores** must not produce the same
//!    `instance_id` (blocker B5: the MPC session namespace must not become a
//!    constant). Three things hold that assertion up. The roster is fixed by
//!    generating the certificates once and passing them to both runs; a harness
//!    that minted fresh certificates per run would pass even for a derivation
//!    like `H(roster_digest || program_id || entry)`, which is exactly the
//!    constant B5 warns about in a deployment where `ids/` never changes. The
//!    program and entry are constants for the same reason. And both runs share
//!    **one** set of per-party [`EpochStores`], so the persisted counter is the
//!    only thing that can differ — which is what makes it the source of
//!    freshness rather than an implementation detail.
//! 5. **One session view** — every node computes the *same* sorted SPKI list,
//!    so every node derives the same index for every other node.
//!
//! What is *not* configured anywhere in this module is as much of the point as
//! what is: no bootstrap process, no `STOFFEL_AUTH_TOKEN`, no relayed
//! `tls_ids`, no announced party list, and no roster a node carries of its own.
//! The only inputs are the coordinator's node roster (membership), a list of
//! addresses (hints), and a per-node epoch store (freshness).
//!
//! **Every roster here is the coordinator's.** The coordinator is the only
//! roster authority (design doc §8, §9 rule 1), so the harness obtains each
//! roster the way `stoffel-run` does (§9.D.1 steps 2-5): it serves the node
//! certificates from an in-process coordinator, every node fetches the roster
//! once over a link pinned to that coordinator's certificate and authenticated
//! with its own, and builds its [`Roster`] with [`Roster::from_coordinator`] —
//! the step that recomputes the digest and refuses a served one that differs.
//! See [`coordinator_rosters`].
//!
//! **Cost and failure mode.** Every run here serialises behind [`RUN_LOCK`],
//! so its time does not overlap with the rest of the suite. Three cases are
//! deliberately slow and are meant to be: a staggered start that waits 3s for
//! its last party, a second that waits 1.5s, and a topology case that lets a
//! discovery budget expire to prove a seed list cannot cover the mesh. The
//! waits *are* the test — each one is a timing shape — so shortening them
//! deletes the coverage rather than the cost. The harness imposes its own
//! [`RUN_TIMEOUT`] over the whole set of joins and **aborts every party task**
//! when it fires, so the worst case is a bounded, attributable failure per join
//! rather than an indefinite hang. Abort is cooperative: a task inside a QUIC
//! syscall stops at its next await point.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use stoffelnet::network_utils::{NodePublicKey, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;

use crate::net::mesh::epoch::EpochStore;
use crate::net::mesh::join::{MeshJoin, MeshJoinTimeouts};
use crate::net::mesh::pex::SeedHints;
use crate::net::mesh::roster::Roster;
use crate::net::mesh::{JoinRequest, MeshSession, SessionJoin};
use crate::net::program_sync::{program_id_from_bytes, verify_program_id};
use crate::net::session::SessionExecutionId;
use crate::tests::test_utils::init_crypto_provider;

/// Program bytes every harness run agrees on. Deliberately constant across runs
/// so that invariant (4) — `instance_id` freshness — is actually load-bearing.
const HARNESS_PROGRAM_BYTES: &[u8] = b"stoffel-mesh-join-harness-program-v1";

/// Entry point name the session agrees on.
const HARNESS_ENTRY: &str = "main";

/// The coordinator execution every harness party is started for.
///
/// Constant across runs like the program, so that `instance_id` freshness still
/// rests on the epoch alone (invariant 4).
const HARNESS_EXECUTION: SessionExecutionId = SessionExecutionId::from_bytes([0x5e; 32]);

/// Bound a single node's [`SessionJoin::join`] is asked for.
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the whole harness run (every node binding and joining).
///
/// This, not [`JOIN_TIMEOUT`], is the harness's real deadline: a join's own
/// phase budgets ([`MeshJoinTimeouts`]) are per-phase, so their sum can outlive
/// the caller's timeout.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// Attempts a bind gets before an ephemeral-port lottery is called fatal.
const BIND_ATTEMPTS: usize = 16;

static RUN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Serialize harness runs against each other.
///
/// Each run stands up n QUIC endpoints and a full mesh; overlapping runs would
/// multiply the port pressure without testing anything extra.
async fn acquire_run_slot() -> MutexGuard<'static, ()> {
    RUN_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// A node's stable transport identity.
///
/// Deliberately carries **no listen address**: a node's address is whatever
/// port it actually wins when it binds (see [`listen_on_free_local_port`]), and
/// is exchanged with peers afterwards. Identity is the certificate, which is
/// what the roster pins and what every party index is derived from.
#[derive(Clone)]
pub(crate) struct NodeIdentity {
    /// Index the node *proposes* for itself (`--party-id`).
    ///
    /// Not the index it gets: the mesh derives every index from SPKI order and
    /// ignores the proposal. Kept as the harness's own stable handle on a node.
    pub(crate) announced_party_id: PartyId,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) key_der: Vec<u8>,
    /// Full DER SubjectPublicKeyInfo, as stoffelnet derives it.
    ///
    /// Blocker B2: this must come from
    /// [`QuicNetworkManager::public_key_from_certificate_der`], never from the
    /// runner's `extract_pubkey_from_cert`, which returns the bare BIT STRING.
    pub(crate) public_key: NodePublicKey,
}

/// What a single node believes about the session once the join returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionView {
    pub(crate) announced_party_id: PartyId,
    /// Index derived locally from the sorted SPKI list.
    pub(crate) local_party_id: PartyId,
    /// Address this node actually bound and announced.
    pub(crate) listen: SocketAddr,
    pub(crate) program_id: [u8; 32],
    pub(crate) instance_id: u64,
    pub(crate) entry: String,
    pub(crate) n_parties: usize,
    pub(crate) threshold: usize,
    /// Announced party list, sorted so it compares structurally across nodes.
    pub(crate) session_parties: Vec<(PartyId, SocketAddr)>,
    /// Lexicographically sorted SPKI list this node computed.
    pub(crate) sorted_public_keys: Vec<NodePublicKey>,
    /// Party indices assigned to this node's peer connections.
    pub(crate) peer_party_ids: BTreeSet<PartyId>,
    pub(crate) fully_connected: bool,
}

/// The result of one full harness run.
pub(crate) struct JoinOutcome {
    pub(crate) identities: Vec<NodeIdentity>,
    /// Indexed by [`NodeIdentity::announced_party_id`].
    pub(crate) views: Vec<SessionView>,
    pub(crate) program_bytes: Vec<u8>,
    /// Every node's network manager, kept alive until the outcome is dropped.
    ///
    /// Dropping a manager closes its QUIC endpoint, which tears its peers'
    /// in-flight `accept()` down with `closed by peer: 0`. A node whose own
    /// join returned is therefore *not* free to go away while slower peers are
    /// still forming the mesh — in production these managers live for the whole
    /// run. Holding them here reproduces that lifetime.
    _managers: Vec<QuicNetworkManager>,
}

impl JoinOutcome {
    pub(crate) fn instance_id(&self) -> u64 {
        self.views
            .first()
            .expect("harness run produced at least one session view")
            .instance_id
    }

    /// The roster this run formed, as the sorted SPKI list every node agreed on.
    pub(crate) fn roster(&self) -> &[NodePublicKey] {
        &self
            .views
            .first()
            .expect("harness run produced at least one session view")
            .sorted_public_keys
    }

    /// Everything a cross-run assertion needs in order to be diagnosable.
    ///
    /// An `instance_id` is `blake3(domain || program_id || epoch)` truncated to
    /// 64 bits, so two runs agreeing on one cannot be an RNG collision — it
    /// means the agreed epoch did not move, which is blocker B5 firing.
    /// Printing each run's party list and bound addresses is what says whether
    /// the two runs were the same membership at all.
    pub(crate) fn summary(&self) -> String {
        let mut out = format!("instance_id={}", self.instance_id());
        for view in &self.views {
            out.push_str(&format!(
                "\n  party {} (local index {}) bound {}, sees parties {:?}",
                view.announced_party_id, view.local_party_id, view.listen, view.session_parties
            ));
        }
        out
    }
}

/// Ask the OS for a loopback UDP port that is free *right now*.
///
/// The probe socket is released before the caller binds for real, so the
/// address is **advisory only**: any other test in this binary, or any other
/// process, can take the port in the window between this call and the real
/// bind. Every caller must therefore be prepared to lose that race and ask
/// again — see [`listen_on_free_local_port`]. A
/// reserve-then-bind helper *without* retry is a TOCTOU bug that fires often
/// enough to matter (observed ~1 in 70 runs under process-level concurrency,
/// as `Failed to create server endpoint: Address already in use`).
fn free_local_addr() -> SocketAddr {
    let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind probe UDP socket on localhost");
    probe.local_addr().expect("read probe socket address")
}

/// True when nothing in this process (or on the host) holds `addr`.
///
/// Used to observe that an endpoint has actually taken its socket instead of
/// sleeping and assuming so.
fn local_udp_port_is_free(addr: SocketAddr) -> bool {
    UdpSocket::bind(addr).is_ok()
}

/// Bind `net` to a free loopback port, retrying when the port is lost.
///
/// Returns the address actually bound, which is what the node then offers its
/// peers as a seed hint — an address carries no identity, so it can be
/// discovered after `listen` rather than reserved before it.
async fn listen_on_free_local_port(net: &mut QuicNetworkManager) -> Result<SocketAddr, String> {
    let mut last_error = String::from("no attempt was made");
    for attempt in 1..=BIND_ATTEMPTS {
        let addr = free_local_addr();
        match net.listen(addr).await {
            Ok(()) => return Ok(addr),
            Err(reason) => {
                last_error = format!("listen on {addr}: {reason}");
                if attempt < BIND_ATTEMPTS {
                    tokio::task::yield_now().await;
                }
            }
        }
    }
    Err(format!(
        "no loopback port could be bound in {BIND_ATTEMPTS} attempts (last: {last_error})"
    ))
}

/// Generate `n` self-signed node identities with distinct SPKIs.
pub(crate) fn generate_identities(n: usize) -> Vec<NodeIdentity> {
    (0..n)
        .map(|announced_party_id| {
            let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate self-signed node certificate");
            let cert_der = generated.cert.der().to_vec();
            let key_der = generated.signing_key.serialize_der();
            let public_key = QuicNetworkManager::public_key_from_certificate_der(&cert_der)
                .expect("extract DER SubjectPublicKeyInfo from node certificate");
            NodeIdentity {
                announced_party_id,
                cert_der,
                key_der,
                public_key,
            }
        })
        .collect()
}

/// Serve `identities` as an in-process coordinator's node roster, and return
/// the [`Roster`] each node builds from what it fetched, in identity order.
///
/// Design doc §9.D.1 steps 2-5, as `stoffel-run` runs them: the coordinator
/// holds a `NodeRoster` of the node certificates and `t`; each node opens one
/// `CoordinatorLink` pinned to the coordinator's certificate and authenticated
/// with its own, which fetches and verifies the roster exactly once; the node
/// checks it is a member, and [`Roster::from_coordinator`] derives every SPKI,
/// recomputes the §9.B digest and refuses a served one that differs. The
/// coordinator is shut down once every node has fetched: nothing re-fetches a
/// roster for the life of a node.
pub(crate) async fn coordinator_rosters(
    identities: &[NodeIdentity],
    threshold: usize,
) -> Vec<Roster> {
    use stoffel_mpc_coordinator_off_chain::{
        CoordinatorLink, CoordinatorRPCServerSharedBase, OffChainCoordinatorConnection,
        OffChainCoordinatorServer,
    };
    use stoffel_mpc_coordinator_shared::rpc::RpcServerLimits;
    use stoffel_mpc_coordinator_shared::{
        self_signed_certs, NodeCertificateDer, NodeRoster, SpkiDer,
    };

    const COORDINATOR_HOST: &str = "127.0.0.1";

    init_crypto_provider();
    let coordinator = self_signed_certs::server_cert();
    let coordinator_der = coordinator.cert.der().to_vec();
    let coordinator_spki = SpkiDer::from_certificate_der(&coordinator_der)
        .expect("the harness coordinator certificate is pinnable");
    let node_roster = NodeRoster::new(
        threshold as u64,
        identities
            .iter()
            .map(|identity| NodeCertificateDer::from_der(identity.cert_der.clone()))
            .collect(),
    )
    .expect("the harness identities form a roster the coordinator accepts");
    let port = std::net::TcpListener::bind((COORDINATOR_HOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("reserve a loopback port for the harness coordinator")
        .port();
    let server = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
        CoordinatorRPCServerSharedBase::new(node_roster, coordinator_spki.clone()),
        COORDINATOR_HOST,
        port,
        coordinator_der,
        coordinator.signing_key.serialize_der(),
        RpcServerLimits::default(),
    )
    .await
    .expect("start the harness coordinator");

    let mut rosters = Vec::with_capacity(identities.len());
    for identity in identities {
        let link = CoordinatorLink::connect(
            COORDINATOR_HOST,
            port,
            &coordinator_spki,
            None,
            identity.cert_der.clone(),
            identity.key_der.clone(),
        )
        .await
        .expect("a node fetches the roster from its pinned coordinator");
        let served = link.node_roster();
        assert!(
            served.position_of(link.own_spki()).is_some(),
            "party {} must be a member of the roster it was served",
            identity.announced_party_id
        );
        let certificates: Vec<&[u8]> = served
            .node_certificates()
            .iter()
            .map(|certificate| certificate.as_bytes())
            .collect();
        rosters.push(
            Roster::from_coordinator(&certificates, served.t(), *served.digest().as_bytes())
                .expect("the served roster verifies on the node"),
        );
    }
    server.shutdown().await;
    rosters
}

/// The one roster every node of `identities` was served, for a fixture that
/// needs it once.
pub(crate) async fn coordinator_roster(identities: &[NodeIdentity], threshold: usize) -> Roster {
    let rosters = coordinator_rosters(identities, threshold).await;
    let first = rosters[0].clone();
    assert!(
        rosters.iter().all(|roster| *roster == first),
        "one coordinator serves one roster to every node"
    );
    first
}

/// Snapshot what `net` believes after the join returned `info`.
fn observe(
    net: &QuicNetworkManager,
    identity: &NodeIdentity,
    listen: SocketAddr,
    info: MeshSession,
) -> SessionView {
    let local_party_id = net
        .compute_local_party_id()
        .expect("local party id is derivable once the local certificate is installed");

    let peer_party_ids = net
        .get_all_server_connections()
        .into_iter()
        .filter_map(|(_, conn)| conn.remote_party_id())
        .filter(|assigned| *assigned != local_party_id)
        .collect::<BTreeSet<_>>();

    let mut session_parties = info.parties.clone();
    session_parties.sort();

    SessionView {
        announced_party_id: identity.announced_party_id,
        local_party_id,
        listen,
        program_id: info.program_id,
        instance_id: info.instance_id,
        entry: info.entry,
        n_parties: info.n_parties,
        threshold: info.threshold,
        session_parties,
        sorted_public_keys: net.get_sorted_public_keys(),
        peer_party_ids,
        fully_connected: net.is_fully_connected(info.n_parties),
    }
}

/// Budgets a harness mesh join runs on.
///
/// Much tighter than production's: every party is in this process on loopback,
/// so a dial that has not answered in a second is not going to.
fn harness_mesh_timeouts() -> MeshJoinTimeouts {
    MeshJoinTimeouts {
        discovery: Duration::from_secs(20),
        dial: Duration::from_secs(2),
        discovery_round: Duration::from_millis(50),
        barrier: Duration::from_secs(10),
        settle: Duration::from_millis(200),
        accept_poll: Duration::from_millis(100),
        handshake: Duration::from_secs(15),
    }
}

/// A directory tree holding one epoch store per party, deleted on drop.
///
/// One store *per node*, never shared, exactly as the compose wiring puts it —
/// a shared store would let one party's commit satisfy another's monotonicity
/// check and the freshness assertion would stop testing anything.
pub(crate) struct EpochStores {
    root: std::path::PathBuf,
    stores: Vec<std::sync::Arc<EpochStore>>,
}

impl EpochStores {
    pub(crate) fn open(n: usize) -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoffel-mesh-harness-epochs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after the unix epoch")
                .as_nanos()
        ));
        let stores = (0..n)
            .map(|party| {
                std::sync::Arc::new(
                    EpochStore::open(root.join(format!("party-{party}")))
                        .expect("open a per-party epoch store"),
                )
            })
            .collect();
        Self { root, stores }
    }

    fn get(&self, party: usize) -> std::sync::Arc<EpochStore> {
        self.stores[party].clone()
    }
}

impl Drop for EpochStores {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Run one complete **bootnode-free** join over a caller-supplied roster.
///
/// Stage 5. The shape differs from [`run_join_with_identities`] in one way, and
/// it is the difference the whole migration is about: there is no bootstrap
/// process, so nobody relays a directory of addresses, so every node has to
/// bind *before* anybody can be told where to dial. The harness therefore
/// listens all n endpoints first, collects what they actually bound, and hands
/// each node the other n-1 addresses as `--peers` seeds — which is exactly the
/// shape a compose file has, where the addresses are static and known before
/// anything starts.
///
/// `epochs` is a parameter rather than a local so that two runs can share one
/// set of per-party stores. That is what makes the freshness assertion
/// load-bearing: a run that opened fresh stores would start from epoch 0 every
/// time and could never observe a reused `instance_id` (blocker B5).
pub(crate) async fn run_mesh_join_with_identities(
    identities: &[NodeIdentity],
    threshold: usize,
    epochs: &EpochStores,
) -> JoinOutcome {
    run_mesh_join_on_plan(
        identities,
        threshold,
        epochs,
        &MeshRunPlan::new(identities.len()),
    )
    .await
}

/// How a mesh run differs from "everybody starts at once, knowing everybody".
///
/// Two knobs, both of which exist because the default shape hides things.
/// Starting every party together means no dial ever fails, so discovery's
/// re-dial path is never taken; seeding every party with every address means
/// the seed list is never the thing under test.
#[derive(Debug, Clone)]
pub(crate) struct MeshRunPlan {
    /// How long party `i` waits before it calls `join`.
    ///
    /// Its endpoint is bound with everyone else's — the addresses have to exist
    /// before they can be handed out as `--peers` — but until its join starts,
    /// nothing calls `accept()` on it, so a dial aimed there stalls and then
    /// fails exactly as it does against a compose service whose container is
    /// not up yet.
    schedule: Vec<Duration>,
    /// Which parties (by index into the bound address list) party `i` is seeded
    /// with. `None` means everybody, which is what every shipped stack does.
    seeds: Option<Vec<Vec<usize>>>,
    timeouts: MeshJoinTimeouts,
}

impl MeshRunPlan {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            schedule: vec![Duration::ZERO; n],
            seeds: None,
            timeouts: harness_mesh_timeouts(),
        }
    }

    pub(crate) fn starting_at(mut self, schedule: Vec<Duration>) -> Self {
        self.schedule = schedule;
        self
    }

    pub(crate) fn seeded_with(mut self, seeds: Vec<Vec<usize>>) -> Self {
        self.seeds = Some(seeds);
        self
    }

    pub(crate) fn with_timeouts(mut self, timeouts: MeshJoinTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
}

/// [`run_mesh_join_with_identities`], run on a caller-supplied [`MeshRunPlan`].
///
/// Returns the per-party results rather than panicking, so a test can assert
/// that a topology *fails* as well as that one succeeds.
pub(crate) async fn try_mesh_join_on_plan(
    identities: &[NodeIdentity],
    threshold: usize,
    epochs: &EpochStores,
    plan: &MeshRunPlan,
) -> Result<JoinOutcome, Vec<String>> {
    let n = identities.len();
    let schedule = &plan.schedule;
    let timeouts = plan.timeouts;
    assert_eq!(
        schedule.len(),
        n,
        "the start schedule must name every party exactly once"
    );
    if let Some(seeds) = &plan.seeds {
        assert_eq!(
            seeds.len(),
            n,
            "the seed plan must name every party exactly once"
        );
    }
    assert!(
        n >= 3,
        "a coordinator roster has n >= 2t + 1 >= 3 parties (design doc §9.D.4)"
    );
    init_crypto_provider();
    let _slot = acquire_run_slot().await;

    let program_bytes = HARNESS_PROGRAM_BYTES.to_vec();
    let program_id = program_id_from_bytes(&program_bytes);
    let rosters = coordinator_rosters(identities, threshold).await;

    // Bind everything first: an address only exists once its endpoint does, and
    // with no bootstrap there is nobody to learn it from afterwards.
    let mut bound: Vec<(QuicNetworkManager, SocketAddr)> = Vec::with_capacity(n);
    for identity in identities {
        let mut net = QuicNetworkManager::with_node_id(identity.announced_party_id);
        net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
            .expect("install local certificate");
        let listen = listen_on_free_local_port(&mut net)
            .await
            .expect("bind a loopback port for a mesh party");
        bound.push((net, listen));
    }
    let addrs: Vec<SocketAddr> = bound.iter().map(|(_, addr)| *addr).collect();

    let mut handles: Vec<JoinHandle<Result<(SessionView, QuicNetworkManager), String>>> =
        Vec::with_capacity(n);
    for (index, (((identity, roster), (mut net, listen)), start_after)) in identities
        .iter()
        .zip(rosters)
        .zip(bound)
        .zip(schedule.iter().copied())
        .enumerate()
    {
        let identity = identity.clone();
        let hints: Vec<SocketAddr> = match &plan.seeds {
            None => addrs.clone(),
            Some(seeds) => seeds[index].iter().map(|peer| addrs[*peer]).collect(),
        };
        let join = MeshJoin::new(
            roster,
            SeedHints::new(hints, Some(listen)),
            epochs.get(identity.announced_party_id),
        )
        .with_timeouts(timeouts);

        handles.push(tokio::spawn(async move {
            if !start_after.is_zero() {
                tokio::time::sleep(start_after).await;
            }
            let info = join
                .join(
                    &mut net,
                    JoinRequest {
                        // Deliberately *wrong* for every party but one: the
                        // mesh must derive its own index from the certificates
                        // and ignore what the request claims.
                        my_party_id: identity.announced_party_id,
                        my_listen: listen,
                        program_id,
                        entry: HARNESS_ENTRY.to_string(),
                        n_parties: n,
                        threshold,
                        execution_id: HARNESS_EXECUTION,
                        timeout: JOIN_TIMEOUT,
                    },
                )
                .await
                .map_err(|reason| {
                    format!(
                        "party {} failed to join the mesh: {reason}",
                        identity.announced_party_id
                    )
                })?;

            let view = observe(&net, &identity, listen, info);
            Ok::<(SessionView, QuicNetworkManager), String>((view, net))
        }));
    }

    let collected =
        tokio::time::timeout(RUN_TIMEOUT, futures::future::join_all(handles.iter_mut())).await;
    let collected = match collected {
        Ok(collected) => collected,
        Err(_) => {
            for handle in &handles {
                handle.abort();
            }
            for handle in handles {
                let _ = handle.await;
            }
            panic!("mesh join for {n} parties did not complete within {RUN_TIMEOUT:?}");
        }
    };

    let mut joined: Vec<(SessionView, QuicNetworkManager)> = Vec::with_capacity(n);
    let mut refused: Vec<String> = Vec::new();
    for task in collected {
        match task.expect("harness mesh join task did not panic") {
            Ok(party) => joined.push(party),
            Err(reason) => refused.push(reason),
        }
    }
    if !refused.is_empty() {
        return Err(refused);
    }
    joined.sort_by_key(|(view, _)| view.announced_party_id);
    let (views, managers) = joined.into_iter().unzip();

    Ok(JoinOutcome {
        identities: identities.to_vec(),
        views,
        program_bytes,
        _managers: managers,
    })
}

/// [`try_mesh_join_on_plan`], panicking with every party's reason on failure.
pub(crate) async fn run_mesh_join_on_plan(
    identities: &[NodeIdentity],
    threshold: usize,
    epochs: &EpochStores,
    plan: &MeshRunPlan,
) -> JoinOutcome {
    try_mesh_join_on_plan(identities, threshold, epochs, plan)
        .await
        .unwrap_or_else(|reasons| panic!("{}", reasons.join("\n")))
}

/// Assert every invariant a join must satisfy.
pub(crate) fn assert_join_invariants(outcome: &JoinOutcome) {
    let n = outcome.identities.len();
    assert_eq!(
        outcome.views.len(),
        n,
        "every identity must produce exactly one session view"
    );

    let reference = &outcome.views[0];

    // (3) Agreed session tuple.
    for view in &outcome.views {
        assert_eq!(
            view.program_id, reference.program_id,
            "party {} disagrees on the program id",
            view.announced_party_id
        );
        assert_eq!(
            view.instance_id, reference.instance_id,
            "party {} disagrees on the instance id",
            view.announced_party_id
        );
        assert_eq!(
            view.entry, reference.entry,
            "party {} disagrees on the entry point",
            view.announced_party_id
        );
        assert_eq!(
            view.n_parties, n,
            "party {} disagrees on the party count",
            view.announced_party_id
        );
        assert_eq!(
            view.threshold, reference.threshold,
            "party {} disagrees on the threshold",
            view.announced_party_id
        );
        assert_eq!(
            view.session_parties, reference.session_parties,
            "party {} disagrees on the announced party list",
            view.announced_party_id
        );
        assert_eq!(
            view.session_parties.len(),
            n,
            "party {} sees {} announced parties, expected {n}",
            view.announced_party_id,
            view.session_parties.len()
        );
    }
    assert_eq!(
        reference.entry, HARNESS_ENTRY,
        "the agreed entry must be the one the parties proposed"
    );

    // Every node's own bound address must be the one the session announced for
    // it — the address is discovered at bind time, so this is what ties the
    // agreed directory back to reality. It is filed under the rank every node
    // derives from the certificates, never under an index a party asserted
    // about itself. The deleted bootnode did the opposite: it relayed each
    // party's own claim about its index, so a party could be listed under any
    // index it liked.
    for view in &outcome.views {
        let index = view.local_party_id;
        assert!(
            reference.session_parties.contains(&(index, view.listen)),
            "party {} (index {index}) bound {} but the session announces {:?}",
            view.announced_party_id,
            view.listen,
            reference.session_parties
        );
    }

    // The agreed session must be bound to the program the parties actually hold.
    verify_program_id(&reference.program_id, &outcome.program_bytes)
        .expect("agreed program id must be the content address of the harness program bytes");

    // (4), locally: the namespace must at least not be a fixed constant. The
    // cross-run half of this invariant lives in
    // `a_mesh_join_produces_a_fresh_instance_id_per_run`.
    assert_ne!(
        reference.instance_id, 0,
        "instance_id must not be the zero namespace"
    );

    // (5) One session view: everybody sorted the same SPKI list.
    let mut expected_order: Vec<NodePublicKey> = outcome
        .identities
        .iter()
        .map(|identity| identity.public_key.clone())
        .collect();
    expected_order.sort();
    assert_eq!(
        expected_order.len(),
        expected_order.iter().collect::<BTreeSet<_>>().len(),
        "harness generated colliding node SPKIs"
    );
    for view in &outcome.views {
        assert_eq!(
            view.sorted_public_keys, expected_order,
            "party {} computed a different sorted SPKI list",
            view.announced_party_id
        );
    }

    // (2) Party indices follow SPKI sort order, not registration order.
    for identity in &outcome.identities {
        let expected_index = expected_order
            .iter()
            .position(|key| key == &identity.public_key)
            .expect("every identity appears in the sorted SPKI list");
        let view = &outcome.views[identity.announced_party_id];
        assert_eq!(
            view.local_party_id, expected_index,
            "party registered as {} must derive index {expected_index} from SPKI order",
            identity.announced_party_id
        );
    }

    // (1) Full connectivity.
    let all_indices: BTreeSet<PartyId> = (0..n).collect();
    for view in &outcome.views {
        assert!(
            view.fully_connected,
            "party {} did not reach a fully connected mesh",
            view.announced_party_id
        );
        let expected_peers: BTreeSet<PartyId> = all_indices
            .iter()
            .copied()
            .filter(|index| *index != view.local_party_id)
            .collect();
        assert_eq!(
            view.peer_party_ids, expected_peers,
            "party {} (index {}) has peer indices {:?}, expected {:?}",
            view.announced_party_id, view.local_party_id, view.peer_party_ids, expected_peers
        );
    }
}

/// Regression cover for the bind race this harness used to lose.
///
/// A port handed out by [`free_local_addr`] is advisory: it can be gone by the
/// time the QUIC endpoint binds it. This pins both halves of that contract —
/// that losing the port is a hard `listen` error (so a reserve-then-bind
/// harness really would panic), and that [`listen_on_free_local_port`] recovers
/// from it. It also pins the assumption [`local_udp_port_is_free`] leans on —
/// that a bound port is observably unavailable to a second binder — for **both**
/// kinds of binder: a plain `UdpSocket` and a live QUIC endpoint. The QUIC half
/// is the one that matters: were quinn ever to bind with `SO_REUSEPORT`, that
/// probe would answer "free" forever and no endpoint could ever be observed
/// coming up.
#[tokio::test]
async fn listen_recovers_when_the_advisory_port_is_lost() {
    init_crypto_provider();
    let identity = generate_identities(1).remove(0);
    let mut net = QuicNetworkManager::with_node_id(identity.announced_party_id);
    net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
        .expect("install local certificate");

    let lost = free_local_addr();
    let squatter = UdpSocket::bind(lost).expect("take the advisory address first");
    assert!(
        !local_udp_port_is_free(lost),
        "a bound UDP port must be observably unavailable, or the readiness probe \
         is meaningless"
    );
    assert!(
        net.listen(lost).await.is_err(),
        "binding a taken port must fail loudly, or the retry has nothing to recover from"
    );

    let bound = listen_on_free_local_port(&mut net)
        .await
        .expect("a retrying listen finds a free port even after losing one");
    assert_ne!(bound, lost, "the retry must not reuse the lost port");
    assert!(
        !local_udp_port_is_free(bound),
        "a live QUIC endpoint must make its port unbindable, or the readiness \
         probe can never observe an endpoint coming up"
    );
    drop(squatter);
}

/// The base case, end to end: a join with **no bootstrap process at all**
/// satisfies every invariant.
///
/// Note what is *not* configured — this is the whole migration stated as a
/// fixture: no bootstrap process, no `STOFFEL_AUTH_TOKEN`, no relayed
/// `tls_ids`, no announced party list. The only inputs are the certificates
/// (membership), a list of addresses (hints), and a per-node epoch store
/// (freshness).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mesh_join_forms_a_session_without_a_bootnode() {
    let identities = generate_identities(3);
    let epochs = EpochStores::open(identities.len());

    let outcome = run_mesh_join_with_identities(&identities, 1, &epochs).await;

    assert_join_invariants(&outcome);
}

/// Blocker B5 on the mesh path: two runs over one roster, one program, one
/// entry and **one set of epoch stores** must not reuse the MPC session
/// namespace.
///
/// The stores are shared between the two runs on purpose. Roster, program and
/// entry are constant here exactly as they are constant in every shipped
/// deployment — `ids/` never changes and the program is baked into the image —
/// so a derivation keyed on those alone would produce the same `instance_id`
/// twice and this assertion would catch it. The persisted epoch is the only
/// thing that differs between the two runs, which is what makes it the source
/// of freshness rather than an implementation detail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mesh_join_produces_a_fresh_instance_id_per_run() {
    let identities = generate_identities(3);
    let epochs = EpochStores::open(identities.len());

    let first = run_mesh_join_with_identities(&identities, 1, &epochs).await;
    assert_join_invariants(&first);
    let second = run_mesh_join_with_identities(&identities, 1, &epochs).await;
    assert_join_invariants(&second);

    assert_eq!(
        first.roster(),
        second.roster(),
        "the two runs must form the same roster, or the freshness check is vacuous"
    );
    assert_eq!(
        first.views[0].program_id, second.views[0].program_id,
        "the two runs must agree on the program, or the freshness check is vacuous"
    );
    assert_eq!(
        first.views[0].entry, second.views[0].entry,
        "the two runs must agree on the entry, or the freshness check is vacuous"
    );
    assert_eq!(
        (first.views[0].n_parties, first.views[0].threshold),
        (second.views[0].n_parties, second.views[0].threshold),
        "the two runs must agree on (n, t), or the freshness check is vacuous"
    );

    assert_ne!(
        first.instance_id(),
        second.instance_id(),
        "two mesh joins over an identical roster, program and entry reused the MPC session \
         namespace (see blocker B5)\nfirst  {}\nsecond {}",
        first.summary(),
        second.summary()
    );
}

/// Budgets for a run where parties deliberately do **not** start together.
///
/// The only difference from [`harness_mesh_timeouts`] is a short `dial`: a
/// party that has not started yet never answers, so the probe has to give up
/// before the stagger elapses or no dial ever fails and the whole scenario
/// evaporates. Production sees both shapes — a container that is not up yet
/// refuses or drops the dial immediately, a process that bound but has not
/// reached its accept loop stalls it — and this is the first.
fn staggered_mesh_timeouts() -> MeshJoinTimeouts {
    MeshJoinTimeouts {
        dial: Duration::from_millis(400),
        ..harness_mesh_timeouts()
    }
}

/// A mesh still forms when its parties start seconds apart.
///
/// Every other mesh case in this file binds *and* starts all n parties
/// together, so no dial ever fails, every address is identified on the first
/// round, and discovery's re-dial path is never taken at all. This one puts
/// discovery in the state that path exists for: two parties come up
/// immediately and two come up later, so the early parties' probes at the late
/// addresses fail, those addresses stay unidentified, and the late parties —
/// once they start — arrive at the early ones **inbound**. An early party is
/// then holding a live connection to a peer whose address it never managed to
/// identify, while still missing somebody else, which is exactly when discovery
/// re-dials.
///
/// Four parties rather than three, because that state needs a party to still be
/// missing someone *after* a late peer has connected to it.
///
/// This asserts that the join survives the shape; it is not a reproduction of
/// the unpinned-re-dial hazard, whose destructive window is a race the loopback
/// scheduler almost always wins. That hazard is pinned deterministically by
/// [`an_unpinned_redial_kills_a_live_connection_and_a_pinned_probe_does_not`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mesh_join_survives_parties_that_start_seconds_apart() {
    let identities = generate_identities(4);
    let epochs = EpochStores::open(identities.len());
    let schedule = vec![
        Duration::ZERO,
        Duration::ZERO,
        Duration::from_millis(1500),
        Duration::from_millis(3000),
    ];

    let outcome = run_mesh_join_on_plan(
        &identities,
        1,
        &epochs,
        &MeshRunPlan::new(identities.len())
            .starting_at(schedule)
            .with_timeouts(staggered_mesh_timeouts()),
    )
    .await;

    assert_join_invariants(&outcome);
}

/// Which parties party `index` is the tournament dialer for, as indices into
/// `identities`.
///
/// `crate::net::mesh::join::dials_towards` decides a pair on
/// `NodePublicKey::derive_id`, a BLAKE3 digest, so this order is not the
/// identity order, not the roster's lexicographic SPKI rank, and not anything
/// a fixture can hardcode. A seed plan that wants to be *exactly* the
/// tournament — in either direction — has to compute it.
fn dial_duties_of(identities: &[NodeIdentity], index: usize) -> Vec<usize> {
    let mine = identities[index].public_key.derive_id();
    (0..identities.len())
        .filter(|peer| *peer != index)
        .filter(|peer| {
            let theirs = identities[*peer].public_key.derive_id();
            match mine.cmp(&theirs) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                // The same tie-break `dials_towards` uses, on the SPKI bytes.
                std::cmp::Ordering::Equal => {
                    identities[index].public_key.0 > identities[*peer].public_key.0
                }
            }
        })
        .collect()
}

/// What `--peers` actually has to cover, stated as a test: every pair, **in the
/// dialer's direction**, and nothing more.
///
/// This replaces a three-party *ring* — each party seeded with one address,
/// A→B→C→A — which encoded the weaker, undirected claim that for any two
/// parties at least one of them must hold a hint for the other. That claim was
/// true only while the non-dialing side was allowed to dial after a delay, and
/// that allowance is what created a duplicate connection and tore down live
/// join handshakes (see `crate::net::mesh::join`'s module docs). A pair is now
/// dialed from one end only, always, so the coverage requirement is directional
/// and the ring is no longer sufficient in general: whether a given ring forms
/// depends on how BLAKE3 happened to order three certificates.
///
/// What is *still* true, and is what this pins, is that the full `n - 1` list
/// is not required. Half the edges are: party `i` is seeded with exactly the
/// parties it wins the tournament against, which is `n(n-1)/2` hints across the
/// mesh rather than `n(n-1)`, and the remaining edges all arrive inbound.
///
/// It also puts every party in the shape the re-dial hazard lives in: each one
/// spends its hints immediately and is then missing somebody with no unspent
/// address left, holding peers that arrived inbound. Whether a discovery loop
/// re-dials a held peer is decided by `missing_ranks`, and this test is *not*
/// the cover for that — end-to-end on loopback the churn a wrong missing set
/// causes is usually outrun by the join. The deterministic cover is
/// [`the_missing_set_is_read_from_certificates_not_from_rank_lookups`], with
/// [`a_correctly_aimed_pinned_redial_is_just_as_destructive`] for what a wrong
/// answer costs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seeding_only_the_dialing_half_of_every_pair_still_forms_the_mesh() {
    let identities = generate_identities(4);
    let epochs = EpochStores::open(identities.len());
    let seeds: Vec<Vec<usize>> = (0..identities.len())
        .map(|index| dial_duties_of(&identities, index))
        .collect();

    let total: usize = seeds.iter().map(Vec::len).sum();
    let n = identities.len();
    assert_eq!(
        total,
        n * (n - 1) / 2,
        "a tournament seeds exactly one end of every pair: {seeds:?}"
    );

    let outcome = run_mesh_join_on_plan(
        &identities,
        1,
        &epochs,
        &MeshRunPlan::new(n).seeded_with(seeds),
    )
    .await;

    assert_join_invariants(&outcome);
}

/// The same hints, pointed the wrong way, form nothing at all.
///
/// Every pair is covered — exactly one of the two holds an address for the
/// other — so under the old undirected rule this mesh formed. Under the
/// tournament the side holding each hint is precisely the side that must not
/// dial, so no dial in the system is ever issued and discovery runs its budget
/// out. This is the cost of the rule, made deterministic rather than left to
/// how BLAKE3 orders a fixture, and it is why the operator-facing guidance is
/// "pass every party the full n-1 list": the direction is not readable off a
/// config file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seed_list_that_covers_every_pair_the_wrong_way_forms_nothing() {
    let identities = generate_identities(3);
    let epochs = EpochStores::open(identities.len());
    // The complement of the tournament: party i is seeded with exactly the
    // parties that are responsible for dialing *it*.
    let seeds: Vec<Vec<usize>> = (0..identities.len())
        .map(|index| {
            let duties = dial_duties_of(&identities, index);
            (0..identities.len())
                .filter(|peer| *peer != index && !duties.contains(peer))
                .collect()
        })
        .collect();

    let plan = MeshRunPlan::new(identities.len())
        .seeded_with(seeds)
        .with_timeouts(MeshJoinTimeouts {
            // Short, because the point is the direction, not the budget.
            discovery: Duration::from_secs(2),
            ..harness_mesh_timeouts()
        });

    let refused = match try_mesh_join_on_plan(&identities, 1, &epochs, &plan).await {
        Err(reasons) => reasons,
        Ok(outcome) => panic!(
            "hints held only by the non-dialing end must not form a mesh, but the join \
             succeeded:\n{}",
            outcome.summary()
        ),
    };

    assert!(
        refused
            .iter()
            .any(|reason| reason.contains("authenticated parties within")),
        "the failure must name incomplete connectivity, not something else: {refused:?}"
    );
}

/// The shape a compose healthcheck actually produces: one party up, the rest
/// gated behind it and starting together, much later.
///
/// `docker-compose.avss.yml` makes party1..4 wait on party0's healthcheck, so
/// party0 spends ten-plus seconds with *every* peer missing before any of them
/// exist. That is the state a timed "dial out of turn after all" escape hatch
/// fires in, and firing it there is worst case rather than edge case: the four
/// peers appear at the same moment party0 gives up waiting for them, so
/// party0's out-of-turn dials and their in-turn dials cross. This pins that the
/// shape forms a mesh with no such hatch — party0 simply keeps dialing its own
/// half and accepting the rest — and it is the regression cover for
/// re-introducing one.
///
/// The gate is deliberately longer than a dial timeout by a wide margin, so
/// party0 has exhausted and re-planned several discovery rounds against dead
/// addresses before anybody answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mesh_forms_when_every_peer_is_gated_behind_one_partys_healthcheck() {
    let identities = generate_identities(5);
    let epochs = EpochStores::open(identities.len());
    let gate = Duration::from_millis(4000);
    let schedule = vec![Duration::ZERO, gate, gate, gate, gate];

    let outcome = run_mesh_join_on_plan(
        &identities,
        1,
        &epochs,
        &MeshRunPlan::new(identities.len())
            .starting_at(schedule)
            .with_timeouts(staggered_mesh_timeouts()),
    )
    .await;

    assert_join_invariants(&outcome);
}

/// The other half of the same claim: a seed list that leaves a **pair**
/// uncovered cannot form the mesh, and peer exchange does not rescue it.
///
/// Both non-seed parties are told about the same third party and nothing about
/// each other, so no dial in the system ever crosses that edge. The peer book
/// each of them would need is exchanged inside the join handshake, which runs
/// after the connectivity barrier — so it does not exist yet, and cannot.
///
/// This is why the `--peers` documentation says "list every other party" and
/// why `build_session_join` warns on a short list, rather than promising that
/// gossip fills the gaps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seed_list_that_leaves_a_pair_uncovered_cannot_form_the_mesh() {
    let identities = generate_identities(3);
    let epochs = EpochStores::open(identities.len());

    // Parties 1 and 2 both know only party 0. The edge 1<->2 has no hint on
    // either side.
    let plan = MeshRunPlan::new(3)
        .seeded_with(vec![vec![], vec![0], vec![0]])
        .with_timeouts(MeshJoinTimeouts {
            // Short, because the point is the missing edge, not the budget.
            discovery: Duration::from_secs(2),
            ..harness_mesh_timeouts()
        });

    let refused = match try_mesh_join_on_plan(&identities, 1, &epochs, &plan).await {
        Err(reasons) => reasons,
        Ok(outcome) => panic!(
            "an uncovered pair must not form a full mesh, but the join succeeded:\n{}",
            outcome.summary()
        ),
    };

    assert!(
        refused
            .iter()
            .any(|reason| reason.contains("authenticated parties within")),
        "the failure must name incomplete connectivity, not something else: {refused:?}"
    );
}

/// Two roster-pinned managers on loopback, arranged so that the **destructive**
/// direction of stoffelnet's simultaneous-connect tie-breaker is the one under
/// test.
///
/// The dialer is the identity with the higher derived id, which is the case
/// where a duplicate connect replaces the existing entry
/// (`quic.rs:2266-2288`) and the peer's accept path closes the connection it
/// was holding (`:3411-3441`). With the roles reversed stoffelnet discards the
/// new connection and hands back the existing one, and nothing is disturbed
/// either way — so the direction is chosen, not hoped for.
///
/// The bystander exists only to be a third roster rank that a deliberately
/// mis-aimed pin can name.
struct ProbeFixture {
    dialer_net: QuicNetworkManager,
    /// Held because dropping the manager would close the target's endpoint.
    _target_net: QuicNetworkManager,
    target: NodeIdentity,
    bystander: NodeIdentity,
    target_addr: SocketAddr,
    accepted: tokio::sync::mpsc::UnboundedReceiver<Arc<dyn PeerConnection>>,
    accepting: JoinHandle<()>,
}

impl ProbeFixture {
    /// A probe budget: everything here is loopback and already listening.
    const PROBE: Duration = Duration::from_secs(5);

    async fn setup() -> Self {
        init_crypto_provider();

        let identities = generate_identities(3);
        let roster = coordinator_roster(&identities, 1).await;

        let mut by_id = identities.clone();
        by_id.sort_by_key(|identity| identity.public_key.derive_id());
        let bystander = by_id[0].clone();
        let target = by_id[1].clone();
        let dialer = by_id[2].clone();
        assert!(
            dialer.public_key.derive_id() > target.public_key.derive_id(),
            "the dialer must be the tie-breaker winner or the hazard does not arise"
        );

        let mut dialer_net = QuicNetworkManager::new();
        dialer_net
            .set_local_certificate_der(dialer.cert_der.clone(), dialer.key_der.clone())
            .expect("install the dialer certificate");
        roster
            .install_into(&mut dialer_net)
            .expect("pin the roster on the dialer");
        listen_on_free_local_port(&mut dialer_net)
            .await
            .expect("bind the dialer");

        let mut target_net = QuicNetworkManager::new();
        target_net
            .set_local_certificate_der(target.cert_der.clone(), target.key_der.clone())
            .expect("install the target certificate");
        roster
            .install_into(&mut target_net)
            .expect("pin the roster on the target");
        let target_addr = listen_on_free_local_port(&mut target_net)
            .await
            .expect("bind the target");

        // The target's accept loop, handing each accepted connection back so
        // the test holds the *same* `Arc` a join handshake would be reading
        // from.
        let (accepted_tx, accepted) = tokio::sync::mpsc::unbounded_channel();
        let mut acceptor = target_net.clone();
        let accepting = tokio::spawn(async move {
            loop {
                match acceptor.accept().await {
                    Ok(conn) => {
                        if accepted_tx.send(conn).is_err() {
                            return;
                        }
                    }
                    Err(reason) => eprintln!("[probe-target] accept refused: {reason}"),
                }
            }
        });

        Self {
            dialer_net,
            _target_net: target_net,
            target,
            bystander,
            target_addr,
            accepted,
            accepting,
        }
    }

    /// Dial the target pinned to `expected`, and return the dialer's end.
    async fn dial_pinned(
        &mut self,
        expected: &NodePublicKey,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        crate::net::mesh::dial::dial_address_expecting(
            &mut self.dialer_net,
            self.target_addr,
            expected,
            Self::PROBE,
        )
        .await
        .map_err(|error| error.to_string())
    }

    /// The next connection the target's accept loop handed out.
    async fn accept_next(&mut self) -> Arc<dyn PeerConnection> {
        tokio::time::timeout(Self::PROBE, self.accepted.recv())
            .await
            .expect("the target accepted within the probe budget")
            .expect("the accept loop is still running")
    }

    /// Assert a frame still crosses from the dialer's end to the target's.
    async fn assert_round_trips(
        outgoing: &Arc<dyn PeerConnection>,
        held: &Arc<dyn PeerConnection>,
        payload: &[u8],
        context: &str,
    ) {
        outgoing
            .send(payload)
            .await
            .unwrap_or_else(|error| panic!("{context}: send failed: {error}"));
        let received = tokio::time::timeout(Self::PROBE, held.receive())
            .await
            .unwrap_or_else(|_| panic!("{context}: the target read nothing in time"))
            .unwrap_or_else(|error| panic!("{context}: the target read failed: {error}"));
        assert_eq!(received, payload.to_vec(), "{context}");
    }

    /// Whether `held` is observed going down within the probe budget.
    async fn observed_dying(held: &Arc<dyn PeerConnection>) -> bool {
        let deadline = tokio::time::Instant::now() + Self::PROBE;
        while tokio::time::Instant::now() < deadline {
            if !held.is_connected().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    async fn shutdown(self) {
        self.accepting.abort();
        let _ = self.accepting.await;
    }
}

/// Why every discovery probe is pinned: an **unpinned** re-dial of an address
/// whose peer is already connected destroys that peer's live connection, and a
/// pinned probe aimed at *somebody else* at the same address does not.
///
/// This is why `discover_peers` dials roster ranks through
/// [`dial_address_expecting`](crate::net::mesh::dial::dial_address_expecting)
/// rather than dialing bare addresses. A discovery loop that filters candidates
/// by "did I dial this myself" keeps re-dialing an address whose first dial
/// failed — a party that had not bound yet — long after that party has come up
/// and connected inbound. Under stoffelnet's simultaneous-connect
/// deduplication the re-dial is not a harmless no-op:
///
/// * the dialer's connect path replaces its existing entry when its own derived
///   id is the higher one (`quic.rs:2266-2288`), and
/// * the *peer's* accept path then closes the connection it was holding
///   (`quic.rs:3411-3441`).
///
/// If that peer has already left the connectivity barrier, the connection that
/// dies is the one carrying its join handshake, and the failure surfaces as a
/// read error on a connection that was healthy a moment earlier.
///
/// A **mis-aimed** pinned probe cannot do it:
/// `connect_as_server_with_expected_public_key` compares the presented SPKI and
/// closes the fresh connection *before* it opens the persistent stream
/// (`quic.rs:2203-2219`, ahead of `:2221`), so the far end's `accept()` fails at
/// `accept_bi` before reaching its own deduplication branch.
///
/// What this does **not** establish — and its companion
/// [`a_correctly_aimed_pinned_redial_is_just_as_destructive`] establishes the
/// opposite of — is that pinning makes a re-dial safe in general. A probe aimed
/// at the peer that is actually there passes the comparison and falls straight
/// through to the tie-breaker. Only never issuing that probe protects the
/// connection, which is what [`missing_ranks`](crate::net::mesh::join::missing_ranks)
/// is for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unpinned_redial_kills_a_live_connection_and_a_pinned_probe_does_not() {
    let _slot = acquire_run_slot().await;
    let mut probe = ProbeFixture::setup().await;

    let target_key = probe.target.public_key.clone();
    let bystander_key = probe.bystander.public_key.clone();

    let outgoing = probe
        .dial_pinned(&target_key)
        .await
        .expect("the pinned dial to the target must succeed");
    let held = probe.accept_next().await;
    ProbeFixture::assert_round_trips(
        &outgoing,
        &held,
        b"before",
        "the connection must be live before anything is re-dialed",
    )
    .await;

    // A pinned probe aimed at the bystander's certificate, at the target's
    // address. It must be refused, and it must leave the live connection alone.
    assert!(
        probe.dial_pinned(&bystander_key).await.is_err(),
        "a probe pinned to the bystander must not be satisfied by the target"
    );
    ProbeFixture::assert_round_trips(
        &outgoing,
        &held,
        b"after-pinned",
        "a mis-aimed pinned probe must not disturb a connection the target is holding",
    )
    .await;

    // The same address, dialed the way a candidate-address loop would dial it.
    // This is the hazard, and it is not subtle: the target's accept path closes
    // the connection it was holding.
    let _duplicate = NetworkManager::connect(&mut probe.dialer_net, probe.target_addr)
        .await
        .expect("the unpinned re-dial connects");
    // The target's accept path is what closes the old connection, so wait until
    // it has actually handed the duplicate out. (Its `remote_address` equals the
    // first one's: quinn dials both from the same client endpoint socket, which
    // is precisely why an address is not an identity.)
    let _replaced = probe.accept_next().await;

    assert!(
        ProbeFixture::observed_dying(&held).await,
        "an unpinned re-dial of an already-connected peer must be observed killing the \
         connection that peer is holding — if this stops being true, the pinning in \
         `discover_peers` is no longer load-bearing and this test is the place to say so"
    );

    probe.shutdown().await;
}

/// The half the test above cannot state: a **correctly aimed** pinned re-dial of
/// a peer this node already holds is exactly as destructive as an unpinned one.
///
/// The pin is compared at `quic.rs:2203-2219` and, when it *matches*, the connect
/// path continues to `open_bi` (`:2221`) and then to the simultaneous-connect
/// tie-breaker (`:2266`) like any other dial. The target's accept loop reaches
/// its own deduplication branch (`:3411-3441`) and, being the lower derived id,
/// closes the connection it was holding.
///
/// So pinning protects against dialing the *wrong party*. Nothing at the
/// transport protects against dialing the *right party twice* — that has to be
/// prevented by never issuing the dial, which is the entire job of
/// [`missing_ranks`](crate::net::mesh::join::missing_ranks) and why it is
/// computed from authenticated certificates rather than from
/// `get_connection_by_party_id`. `the_missing_set_is_read_from_certificates_not_from_rank_lookups`
/// is the direct cover; this test is why that cover matters.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_correctly_aimed_pinned_redial_is_just_as_destructive() {
    let _slot = acquire_run_slot().await;
    let mut probe = ProbeFixture::setup().await;

    let target_key = probe.target.public_key.clone();

    let outgoing = probe
        .dial_pinned(&target_key)
        .await
        .expect("the pinned dial to the target must succeed");
    let held = probe.accept_next().await;
    ProbeFixture::assert_round_trips(
        &outgoing,
        &held,
        b"before",
        "the connection must be live before anything is re-dialed",
    )
    .await;

    // The dial a discovery loop issues when it wrongly believes it is missing a
    // rank it already holds: same address, same certificate, correctly pinned.
    let _duplicate = probe
        .dial_pinned(&target_key)
        .await
        .expect("a correctly aimed pinned re-dial is admitted, which is the problem");
    let _replaced = probe.accept_next().await;

    assert!(
        ProbeFixture::observed_dying(&held).await,
        "a correctly aimed pinned re-dial must be observed killing the connection the peer \
         was holding — if this ever stops being true, the exactness requirement on \
         `missing_ranks` has weakened and the reasoning in its doc comment needs revisiting"
    );

    probe.shutdown().await;
}

/// The missing set is read from the certificate each connection authenticated,
/// never from a rank lookup — because a rank lookup is wrong for the whole
/// window discovery runs in.
///
/// This is the deterministic cover for the defect the two tests above make
/// destructive. `get_connection_by_party_id` resolves its argument through
/// `get_sorted_public_keys()` (`quic.rs:1856-1879`), which sorts the local key
/// plus the peers whose certificates have been *seen so far*. `Roster::install_into`
/// populates `allowed_peer_public_keys` and never `peer_public_keys`
/// (`quic.rs:1273-1322`), so during discovery that list is a strict subset of
/// the roster and its indices are compressed.
///
/// The fixture is the smallest shape that exhibits it: a three-node roster, a
/// node at rank 0 holding a live pinned connection to rank 2, and rank 1 still
/// absent. Rank 2's key is the *second* of the two keys this node knows, so the
/// lookup at index 1 hands back rank 2's connection and the lookup at index 2
/// hands back nothing. A rank-indexed missing set therefore reports both 1 and
/// 2 missing, and discovery re-dials a peer it is already holding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_missing_set_is_read_from_certificates_not_from_rank_lookups() {
    use crate::net::mesh::dial::dial_address_expecting;
    use crate::net::mesh::join::missing_ranks;

    /// Loopback, already listening.
    const PROBE: Duration = Duration::from_secs(5);

    init_crypto_provider();
    let _slot = acquire_run_slot().await;

    let identities = generate_identities(3);
    let roster = coordinator_roster(&identities, 1).await;

    // Address the parties by roster rank, which is SPKI sort order.
    let mut by_rank = identities.clone();
    by_rank.sort_by(|left, right| left.public_key.0.cmp(&right.public_key.0));
    let local = by_rank[0].clone();
    let high = by_rank[2].clone();

    let mut local_net = QuicNetworkManager::new();
    local_net
        .set_local_certificate_der(local.cert_der.clone(), local.key_der.clone())
        .expect("install the local certificate");
    roster
        .install_into(&mut local_net)
        .expect("pin the roster locally");
    listen_on_free_local_port(&mut local_net)
        .await
        .expect("bind the local node");

    let mut high_net = QuicNetworkManager::new();
    high_net
        .set_local_certificate_der(high.cert_der.clone(), high.key_der.clone())
        .expect("install the rank-2 certificate");
    roster
        .install_into(&mut high_net)
        .expect("pin the roster on rank 2");
    let high_addr = listen_on_free_local_port(&mut high_net)
        .await
        .expect("bind rank 2");

    let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    let mut acceptor = high_net.clone();
    let accepting = tokio::spawn(async move {
        loop {
            match acceptor.accept().await {
                Ok(conn) => {
                    if accepted_tx.send(conn).is_err() {
                        return;
                    }
                }
                Err(reason) => eprintln!("[rank-2] accept refused: {reason}"),
            }
        }
    });

    let outgoing = dial_address_expecting(&mut local_net, high_addr, &high.public_key, PROBE)
        .await
        .expect("the pinned dial to rank 2 must succeed");
    let held = tokio::time::timeout(PROBE, accepted.recv())
        .await
        .expect("rank 2 accepted the dial")
        .expect("the accept loop is still running");
    assert!(
        outgoing.is_connected().await && held.is_connected().await,
        "the rank-2 connection must be live before the missing set is read"
    );

    // The skew, stated rather than assumed: this node knows two of the three
    // roster keys, so the transport's index 1 is the roster's rank 2 and its
    // index 2 does not exist.
    let at_index_one = local_net
        .get_connection_by_party_id(1)
        .and_then(|conn| conn.authenticated_peer_public_key())
        .and_then(|key| roster.index_of(&key));
    assert_eq!(
        at_index_one,
        Some(2),
        "the transport's index 1 is expected to resolve to roster rank 2 under partial \
         connectivity; if this ever stops being true, `missing_ranks` is safe by accident \
         and the reasoning in its doc comment is stale"
    );
    assert!(
        local_net.get_connection_by_party_id(2).is_none(),
        "the transport has no index 2 while only two keys are known"
    );

    assert_eq!(
        missing_ranks(&local_net, &roster, 0, 3).await,
        vec![1],
        "only the party that has not connected may be reported missing; reporting rank 2 \
         missing is what makes discovery re-dial a peer it already holds, and \
         `a_correctly_aimed_pinned_redial_is_just_as_destructive` is what that costs"
    );

    accepting.abort();
    let _ = accepting.await;
}

/// What the divergent party of [`refuse_a_divergent_party`] proposes
/// differently from the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Divergence {
    /// Another entry point, over the same roster, program, execution, n and t.
    Entry,
    /// Another coordinator execution, over the same roster, program, entry, n
    /// and t (design doc §9.D.5).
    Execution,
}

impl Divergence {
    fn field(self) -> crate::net::mesh::SessionField {
        match self {
            Self::Entry => crate::net::mesh::SessionField::Entry,
            Self::Execution => crate::net::mesh::SessionField::ExecutionId,
        }
    }
}

/// Three parties join over one coordinator roster; the third proposes a session
/// that differs from the other two in `divergence` alone. Every party must fail,
/// and the divergence must be named.
///
/// Driven through the real [`MeshJoin`] rather than over a unit fixture,
/// because the property is about the handshake actually aborting the join, not
/// about a comparison returning `false`. Three parties rather than two because
/// a coordinator roster has `n >= 2t + 1 >= 3` (design doc §9.D.4); the third is
/// the divergent one.
async fn refuse_a_divergent_party(divergence: Divergence) {
    use crate::net::mesh::{MeshError, SessionField};

    init_crypto_provider();
    let _slot = acquire_run_slot().await;
    let identities = generate_identities(3);
    let epochs = EpochStores::open(identities.len());
    let rosters = coordinator_rosters(&identities, 1).await;

    let mut bound: Vec<(QuicNetworkManager, SocketAddr)> = Vec::new();
    for identity in &identities {
        let mut net = QuicNetworkManager::with_node_id(identity.announced_party_id);
        net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
            .expect("install local certificate");
        let listen = listen_on_free_local_port(&mut net)
            .await
            .expect("bind a loopback port");
        bound.push((net, listen));
    }
    let addrs: Vec<SocketAddr> = bound.iter().map(|(_, addr)| *addr).collect();
    let program_id = program_id_from_bytes(HARNESS_PROGRAM_BYTES);
    let divergent = identities.len() - 1;

    let mut handles = Vec::new();
    for (index, ((identity, roster), (mut net, listen))) in
        identities.iter().zip(rosters).zip(bound).enumerate()
    {
        let join = MeshJoin::new(
            roster,
            SeedHints::new(addrs.clone(), Some(listen)),
            epochs.get(identity.announced_party_id),
        )
        .with_timeouts(harness_mesh_timeouts());
        // One party proposes a different session in exactly one field. Every
        // other field — the roster, the program, n, t — is identical, so this is
        // precisely the case the bootnode admitted.
        let diverges = index == divergent;
        let entry = match (divergence, diverges) {
            (Divergence::Entry, true) => "other",
            _ => HARNESS_ENTRY,
        }
        .to_string();
        let execution_id = match (divergence, diverges) {
            (Divergence::Execution, true) => SessionExecutionId::from_bytes([0xe1; 32]),
            _ => HARNESS_EXECUTION,
        };
        handles.push(tokio::spawn(async move {
            join.join(
                &mut net,
                JoinRequest {
                    my_party_id: index,
                    my_listen: listen,
                    program_id,
                    entry,
                    n_parties: 3,
                    threshold: 1,
                    execution_id,
                    timeout: JOIN_TIMEOUT,
                },
            )
            .await
        }));
    }

    let results = tokio::time::timeout(RUN_TIMEOUT, futures::future::join_all(handles))
        .await
        .expect("a divergent join must fail fast, not hang");

    // Every party must fail, and the divergence must be *named* — but which
    // party names it is a race, not a property. The peers detect the divergence
    // while reading each other's `JoinProposal`; whichever detects it first
    // returns from `join_mesh`, its `QuicNetworkManager` drops, and its
    // connections close. A peer still mid-read at that moment sees a closed
    // connection instead, and reports `PeerExchange { operation: "reading a
    // handshake frame" }`. That is the divergence being refused too — by the
    // peer that aborted first — and it is reproducible under CPU contention, so
    // asserting that *every* party names the field is an over-specification the
    // implementation cannot honour.
    //
    // The same race reaches one step further back. The parties that finish
    // discovery first start the handshake without waiting for the last, and
    // when one of them has read the divergent proposal it names the divergence
    // and drops while the last party is still in its settle interval. Two
    // outcomes follow, both reproduced in isolation (roughly one run in five):
    //
    // - The late party is honest and never reaches the handshake: it sees the
    //   aborted peer vanish ("mesh lost N peer(s) while settling"), keeps
    //   dialing an address nobody listens on any more — or that another test
    //   has since bound, which the dial pin refuses as a certificate mismatch —
    //   and reports `MeshIncomplete` when discovery gives up. It is only ever an
    //   honest party: nobody can abort before reading the divergent party's
    //   proposal, which that party sends only after its own discovery and
    //   barrier have passed.
    // - A party that did reach the handshake, the divergent one included, waits
    //   on the frames of that late party, which is stuck in discovery, and
    //   reports `HandshakeTimeout`.
    //
    // Both are the divergence being refused by the peer that aborted, exactly
    // like the `PeerExchange` above: the join ends without a session.
    //
    // What is asserted instead is the whole property and nothing weaker: nobody
    // joins, at least one party names the divergence and names the field, and
    // no party fails for an unrelated reason.
    let errors: Vec<MeshError> = results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result
                .expect("the join task did not panic")
                .expect_err(&format!(
                    "party {index} joined a session the parties disagree on ({divergence:?})"
                ))
        })
        .collect();

    let field: SessionField = divergence.field();
    assert!(
        errors.iter().any(|error| matches!(
            error,
            MeshError::SessionDivergence { field: named, .. } if *named == field
        )),
        "no party named the {field} divergence; got {errors:?}"
    );
    for (index, error) in errors.iter().enumerate() {
        let named_it = matches!(
            error,
            MeshError::SessionDivergence { field: named, .. } if *named == field
        );
        let closed_on = matches!(error, MeshError::PeerExchange { .. });
        let abandoned_in_discovery =
            index != divergent && matches!(error, MeshError::MeshIncomplete { .. });
        let waited_on_an_abandoned_peer = matches!(error, MeshError::HandshakeTimeout { .. });
        assert!(
            named_it || closed_on || abandoned_in_discovery || waited_on_an_abandoned_peer,
            "party {index} failed for a reason other than the divergence or its \
             consequences (an aborting peer closing on it, an honest party abandoned in \
             discovery, a handshake waiting on that party), got {error}"
        );
    }
}

/// The divergence the deleted bootnode never checked (its `handle_register`
/// compares `program_id` alone): a party proposing a different entry point is
/// refused, and named, before any MPC byte flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_party_proposing_a_different_session_is_refused_by_name() {
    refuse_a_divergent_party(Divergence::Entry).await;
}

/// A party started for another coordinator execution would pass a join that
/// did not compare executions, and then wait forever on rounds of an execution
/// no other party is in. The join names it instead (design doc §9.D.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_party_started_for_another_execution_is_refused_by_name() {
    refuse_a_divergent_party(Divergence::Execution).await;
}

/// The program the session agreed on is the program the parties hold.
///
/// A mesh member that lacks the program pulls it from a peer and verifies it
/// against the content address the session committed to
/// (`net::mesh::program`). That verification is the same domain-separated hash
/// the session digest binds, which is what makes "the agreed session" and "the
/// program that will run" one statement rather than two.
///
/// The deleted bootnode got this wrong in the one place it mattered: it
/// validated an upload with a bare `blake3::hash` against this
/// domain-separated id, so the two could never agree and every honest upload
/// was silently dropped — the defect `docs/design/bootnode-elimination.md` §2
/// rests its "the custody path is dead code" claim on, and the reason Stage 8's
/// deletion of it is a no-op rather than a removal of function.
#[test]
fn the_agreed_program_id_is_the_content_address_of_the_program_bytes() {
    let program_id = program_id_from_bytes(HARNESS_PROGRAM_BYTES);

    verify_program_id(&program_id, HARNESS_PROGRAM_BYTES)
        .expect("the harness program verifies against its own content address");
    verify_program_id(&program_id, b"a different program")
        .expect_err("a different program must not verify against this content address");
    assert_ne!(
        program_id,
        *blake3::hash(HARNESS_PROGRAM_BYTES).as_bytes(),
        "the program id is domain-separated; a bare blake3 hash is a different name \
         for the same bytes"
    );
}

/// Blocker B5, the Byzantine half: a member proposing a wildly advanced epoch
/// is **refused**, not obeyed.
///
/// The bound is what stops one member from permanently bricking every honest
/// store: an epoch is agreed as `max(proposals)`, so an unbounded rule would
/// let a single party drag every peer's persisted counter to near `u64::MAX`,
/// after which every honest `commit` fails the monotonicity check forever and
/// the deployment needs an out-of-band reset.
///
/// Driven through the real [`MeshJoin`] rather than over [`agree_epoch`]
/// directly — `epoch::tests::an_unbounded_proposal_is_refused_rather_than_
/// bricking_the_store` already pins the function. What this adds is that the
/// refusal actually reaches the join: the proposal travels as a real
/// `JoinProposal` field over a real connection, the honest party aborts, and —
/// the part that matters — **its store is left where it was**, because
/// `join_mesh` commits the epoch only after the whole handshake succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_party_proposing_a_wildly_advanced_epoch_is_refused() {
    use crate::net::mesh::{EpochError, MeshError, MAX_EPOCH_JUMP};

    init_crypto_provider();
    let _slot = acquire_run_slot().await;
    // Three identities, the third Byzantine: a coordinator roster has
    // `n >= 2t + 1 >= 3` (design doc §9.D.4).
    let identities = generate_identities(3);
    let epochs = EpochStores::open(identities.len());
    let rosters = coordinator_rosters(&identities, 1).await;
    let roster_digest = rosters[0].digest();

    // The last party is the Byzantine member: its own store is fast-forwarded
    // far past the bound, so the epoch it proposes (`last + 1`) is one no honest
    // peer can accept. This is the shape a hostile proposal actually takes — a
    // party cannot propose an arbitrary number without its own store agreeing,
    // so the attack is exactly "arrive with an absurd counter".
    let byzantine = identities.len() - 1;
    let honest: Vec<usize> = (0..byzantine).collect();
    let advanced = MAX_EPOCH_JUMP * 64 + 7;
    epochs
        .get(byzantine)
        .bump_to(&roster_digest, advanced)
        .expect("fast-forward the byzantine party's own store");
    for party in &honest {
        assert_eq!(
            epochs
                .get(*party)
                .last(&roster_digest)
                .expect("read an honest party's epoch before the join"),
            0,
            "the honest stores must start fresh, or the bricking assertion below is vacuous"
        );
    }

    let mut bound: Vec<(QuicNetworkManager, SocketAddr)> = Vec::new();
    for identity in &identities {
        let mut net = QuicNetworkManager::with_node_id(identity.announced_party_id);
        net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
            .expect("install local certificate");
        let listen = listen_on_free_local_port(&mut net)
            .await
            .expect("bind a loopback port");
        bound.push((net, listen));
    }
    let addrs: Vec<SocketAddr> = bound.iter().map(|(_, addr)| *addr).collect();
    let program_id = program_id_from_bytes(HARNESS_PROGRAM_BYTES);

    let mut handles = Vec::new();
    for (index, (roster, (mut net, listen))) in rosters.into_iter().zip(bound).enumerate() {
        let join = MeshJoin::new(
            roster,
            SeedHints::new(addrs.clone(), Some(listen)),
            epochs.get(index),
        )
        .with_timeouts(harness_mesh_timeouts());
        handles.push(tokio::spawn(async move {
            join.join(
                &mut net,
                JoinRequest {
                    my_party_id: index,
                    my_listen: listen,
                    program_id,
                    entry: HARNESS_ENTRY.to_string(),
                    n_parties: 3,
                    threshold: 1,
                    execution_id: HARNESS_EXECUTION,
                    timeout: JOIN_TIMEOUT,
                },
            )
            .await
        }));
    }

    let results = tokio::time::timeout(RUN_TIMEOUT, futures::future::join_all(handles))
        .await
        .expect("an unbounded epoch proposal must fail fast, not hang");
    let outcomes: Vec<Result<MeshSession, MeshError>> = results
        .into_iter()
        .map(|task| task.expect("the join task did not panic"))
        .collect();

    // Nobody forms a session: the honest parties refuse, and the byzantine one
    // never collects the commitments it needs.
    for (index, outcome) in outcomes.iter().enumerate() {
        assert!(
            outcome.is_err(),
            "party {index} joined a session over an out-of-bound epoch: {outcome:?}"
        );
    }

    // The refusal is named, and it names the bound it enforced. Asserted over
    // the set rather than at a fixed index for the same reason
    // `a_party_proposing_a_different_session_is_refused_by_name` does: the
    // party that aborts first closes its connections, and a peer still
    // mid-read then reports the closure rather than the cause. Here the honest
    // parties are the ones that abort (the byzantine one's own `agree_epoch`
    // succeeds against its own advanced store), so this is the robust form of
    // the same assertion, not a weaker one.
    assert!(
        outcomes.iter().any(|outcome| matches!(
            outcome,
            Err(MeshError::Epoch {
                source: EpochError::JumpTooLarge { agreed, max, .. },
            }) if *agreed == advanced + 1 && *max == MAX_EPOCH_JUMP
        )),
        "no party refused the advanced epoch by name; got {outcomes:?}"
    );

    // The point of the bound: the honest stores are untouched, so the next join
    // with honest peers still works. An unbounded `max(proposals)` would have
    // left them at `advanced + 1` and every future commit would be non-monotone.
    for party in &honest {
        assert_eq!(
            epochs
                .get(*party)
                .last(&roster_digest)
                .expect("read an honest party's epoch after the failed join"),
            0,
            "a refused join must not ratchet honest party {party}'s store (blocker B5)"
        );
    }
}
