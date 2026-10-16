//! A standing MPC node learns its executions from the coordinator.
//!
//! The coordinator is the trusted party. It mints every execution identity and
//! publishes it down to the roster over the mutually authenticated link each
//! node already opened to fetch the roster: a node never invents an identity
//! and never pushes one up. The link's certificate is the authorization
//! boundary — only the key the coordinator pinned can admit an execution on
//! this node, and only a node the coordinator's roster lists can subscribe.
//!
//! What the coordinator publishes is a key, never certificate material. A
//! published client is named by the `subject_public_key` the coordinator itself
//! reasons about, and this node resolves it against the certificate catalog it
//! froze at startup; a published identity the catalog does not hold refuses the
//! whole admission. Nothing in a notice is trusted as a certificate.
//!
//! Every party independently recomputes [`AdmittedExecution::config_digest`]
//! from the published notice plus its own catalogs, and the parties compare it
//! before any correlated preprocessing moves, so a coordinator that equivocated
//! between parties fails closed rather than making them consume different
//! material.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use stoffel_mpc_coordinator_off_chain::{
    CoordinatorIncarnation, CoordinatorLink, ExecutionNotice, PublishedExecution, Subscription,
};
use stoffel_mpc_coordinator_shared::admission::{AbortReason, AdmissionPolicy, ExecutionOutcome};
use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::{
    program_id_from_bytes, ExecutionSpecV1, MpcBackendKind, MpcCurveConfig, NodeEvent,
    NodeEventKind, NodeExecutionContext, NodeSupervisor, PreparedNodeExecution,
};
use stoffel_vm::storage::RetiredExecutionIndex;
use stoffel_vm_types::compiled_binary::{
    ClientIoManifest, CompiledBinary, PreprocessingDemand,
    PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
};
use stoffelnet::network_utils::{CertificateIdentity, NodePublicKey};
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

/// Upper bound for one catalog artifact read at startup.
///
/// A client certificate is a few kilobytes; one MiB leaves ample room for a
/// legitimate one while preventing a corrupted catalog directory from forcing
/// an unbounded allocation before validation.
const MAX_CATALOG_FILE_BYTES: usize = 1024 * 1024;
/// Upper bound on the text of one reported execution failure.
const MAX_NODE_EVENT_TEXT_BYTES: usize = 16 * 1024;
/// First delay before re-subscribing after the execution stream ends.
const RESUBSCRIBE_MIN_BACKOFF: Duration = Duration::from_millis(250);
/// Ceiling on the re-subscribe delay.
///
/// The stream ending is routine — a saturated connection queue ends it — and
/// the node keeps every running instance while it is away, because the mesh is
/// a separate transport the coordinator is not on. So the retry is patient
/// rather than aggressive, and it never gives up: a standing node with no
/// coordinator and no executions is idle, not failed.
const RESUBSCRIBE_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// One admitted client of a published execution.
///
/// `manifest_slot` is the program's own client slot
/// ([`ClientIoManifest`]'s `ClientIoSchema::client_slot`): it fixes the input
/// range and output rights that client holds. The position of this entry in
/// [`AdmittedExecution::clients`] is the separate execution-local ordinal the
/// MPC backend numbers its clients by, and the two need not coincide — a
/// registration may list its clients in any order so long as their slots are
/// each of the program's slots exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedClient {
    pub manifest_slot: usize,
}

/// One execution the coordinator published to this node, resolved against the
/// catalogs this node froze at startup.
#[derive(Debug, Clone)]
pub struct AdmittedExecution {
    pub execution_id: ExecutionId,
    pub program_id: [u8; 32],
    pub entry: String,
    pub clients: Vec<AdmittedClient>,
    /// Public-key identities used by the coordinator's mutual-TLS authorization.
    /// Vector position is the execution-local client ordinal.
    pub expected_client_public_keys: Vec<Vec<u8>>,
    /// Certificate-exact identities used to authorize execution transport routes.
    /// Vector position is the same execution-local client ordinal.
    pub expected_client_certificate_identities: Vec<CertificateIdentity>,
    /// What every party compares before consuming correlated preprocessing.
    pub config_digest: [u8; 32],
}

/// One immutable, content-addressed program loaded when the standing node starts.
#[derive(Debug)]
pub struct StandingProgram {
    pub program_id: [u8; 32],
    pub bytes: Arc<[u8]>,
    pub backend: MpcBackendKind,
    pub curve: MpcCurveConfig,
    pub client_io_manifest: ClientIoManifest,
    entries: HashSet<String>,
}

impl StandingProgram {
    fn contains_entry(&self, entry: &str) -> bool {
        self.entries.contains(entry)
    }
}

/// Programs frozen at startup and shared by admission, preprocessing, and execution.
#[derive(Debug)]
pub struct StandingProgramCatalog(BTreeMap<[u8; 32], Arc<StandingProgram>>);

impl StandingProgramCatalog {
    pub fn load(directory: &Path) -> Result<Self, ExecutionStreamError> {
        Self::load_with_policy(directory, false)
    }

    /// Load a frozen standing catalog while admitting artifacts whose compiler
    /// manifest contains a conservative dynamic preprocessing floor.
    ///
    /// This is intentionally separate from [`Self::load`] for bounded example
    /// and test campaigns. Normal standing deployments remain fail-closed.
    pub fn load_with_dynamic_preprocessing(directory: &Path) -> Result<Self, ExecutionStreamError> {
        Self::load_with_policy(directory, true)
    }

    fn load_with_policy(
        directory: &Path,
        allow_dynamic_preprocessing: bool,
    ) -> Result<Self, ExecutionStreamError> {
        fs::create_dir_all(directory).map_err(|source| io_error(directory, source))?;
        // An entry this node cannot read is a refusal, never a skip. The
        // catalog is frozen from one directory read, and a node has no second
        // source to notice a missing artifact against: dropping an unreadable
        // entry here would leave it serving a silently short catalog, warming
        // reservoirs for some of the programs it was deployed with and
        // ignoring the others. A standing node that cannot enumerate its own
        // program directory must say so and exit instead.
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
            let path = entry.map_err(|source| io_error(directory, source))?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "stflb")
            {
                paths.push(path);
            }
        }
        paths.sort();

        let mut programs = BTreeMap::new();
        for path in paths {
            let bytes = fs::read(&path).map_err(|source| io_error(&path, source))?;
            let program_id = program_id_from_bytes(&bytes);
            let expected_name = format!("{}.stflb", hex::encode(program_id));
            if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
                return Err(ExecutionStreamError::Catalog(format!(
                    "standing artifact {} is not stored under its content address {expected_name}",
                    path.display()
                )));
            }
            let (client_io_manifest, backend, curve, entries) =
                inspect_standing_program_with_policy(&bytes, allow_dynamic_preprocessing)?;
            programs.insert(
                program_id,
                Arc::new(StandingProgram {
                    program_id,
                    bytes: Arc::from(bytes),
                    backend,
                    curve,
                    client_io_manifest,
                    entries,
                }),
            );
        }
        Ok(Self(programs))
    }

    pub fn get(&self, program_id: &[u8; 32]) -> Option<Arc<StandingProgram>> {
        self.0.get(program_id).cloned()
    }

    /// How many artifacts this catalog froze.
    ///
    /// A standing node says this at startup: the catalog is the whole set of
    /// programs it can ever serve, and the number is the one thing an operator
    /// can check against what they installed.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn programs(&self) -> impl Iterator<Item = Arc<StandingProgram>> + '_ {
        self.0.values().cloned()
    }
}

/// One client certificate frozen alongside the program catalog at startup.
#[derive(Debug, Clone)]
struct StandingClientIdentity {
    /// The file the certificate was read from, for diagnostics only.
    source: String,
    coordinator_public_key: Vec<u8>,
    certificate_identity: CertificateIdentity,
}

/// Client certificates frozen at startup, keyed by the `subject_public_key` the
/// coordinator publishes.
///
/// The coordinator names which of this node's own certificates an execution
/// admits, and nothing more: the certificate-exact identity that authorizes a
/// transport route always comes from the local file, never from the wire.
#[derive(Debug)]
pub struct StandingClientCatalog(BTreeMap<Vec<u8>, StandingClientIdentity>);

impl StandingClientCatalog {
    pub fn load(directory: &Path) -> Result<Self, ExecutionStreamError> {
        fs::create_dir_all(directory).map_err(|source| io_error(directory, source))?;
        let mut identities: BTreeMap<Vec<u8>, StandingClientIdentity> = BTreeMap::new();
        for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
            let entry = entry.map_err(|source| io_error(directory, source))?;
            let path = entry.path();
            if !entry
                .file_type()
                .map_err(|source| io_error(&path, source))?
                .is_file()
            {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let cert_der = fs::read(&path).map_err(|source| io_error(&path, source))?;
            if cert_der.len() > MAX_CATALOG_FILE_BYTES {
                return Err(ExecutionStreamError::Catalog(format!(
                    "client certificate {} exceeds {MAX_CATALOG_FILE_BYTES} bytes",
                    path.display()
                )));
            }
            let (remainder, parsed) = X509Certificate::from_der(&cert_der).map_err(|error| {
                ExecutionStreamError::Catalog(format!(
                    "parse expected client certificate {}: {error}",
                    path.display()
                ))
            })?;
            if !remainder.is_empty() {
                return Err(ExecutionStreamError::Catalog(format!(
                    "expected client certificate {} has trailing bytes",
                    path.display()
                )));
            }
            let coordinator_public_key = parsed
                .public_key()
                .subject_public_key
                .data
                .as_ref()
                .to_vec();
            // The certificate-exact identity a transport route is authorized
            // against. It is derived here and kept; the raw transport key
            // itself is deliberately not retained, because nothing may turn a
            // client certificate into transport-level standing (design doc
            // section 9 rule 3).
            let certificate_identity =
                NodePublicKey(parsed.public_key().raw.to_vec()).certificate_identity();
            // Two files holding one key would make the published identity
            // ambiguous, and an ambiguous lookup is exactly what must never
            // silently resolve to whichever file sorted first.
            if let Some(existing) = identities.get(&coordinator_public_key) {
                return Err(ExecutionStreamError::Catalog(format!(
                    "client certificates {} and {} hold the same public key",
                    existing.source, name
                )));
            }
            identities.insert(
                coordinator_public_key.clone(),
                StandingClientIdentity {
                    source: name.to_owned(),
                    coordinator_public_key,
                    certificate_identity,
                },
            );
        }
        Ok(Self(identities))
    }

    fn get(&self, coordinator_public_key: &[u8]) -> Option<StandingClientIdentity> {
        self.0.get(coordinator_public_key).cloned()
    }
}

#[async_trait::async_trait]
pub trait StandingExecutionHandler: Send + Sync + 'static {
    async fn prepare(
        self: Arc<Self>,
        admission: AdmittedExecution,
        context: NodeExecutionContext,
    ) -> Result<Box<dyn PreparedNodeExecution>, String>;
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionStreamError {
    #[error("standing catalog IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid standing catalog: {0}")]
    Catalog(String),
    #[error("the coordinator published an execution this node refuses: {0}")]
    Admission(String),
    #[error("the durable admitted-execution index failed: {0}")]
    AdmittedIndex(String),
    #[error("the coordinator is no longer the one this node joined: {0}")]
    CoordinatorIdentity(String),
}

fn io_error(path: &Path, source: std::io::Error) -> ExecutionStreamError {
    ExecutionStreamError::Io {
        path: path.to_owned(),
        source,
    }
}

/// What applying one notice did, so the node can say so in its log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoticeOutcome {
    /// An instance was started for this execution.
    Admitted { execution_id: ExecutionId },
    /// A `Prepare` this node is already running, so it was left alone.
    AlreadyRunning { execution_id: ExecutionId },
    /// A `Prepare` for an identity this node has admitted before. An execution
    /// identity is single use, so the republication is skipped rather than
    /// re-run.
    AlreadyAdmitted { execution_id: ExecutionId },
    /// A running instance was torn down because the coordinator aborted its
    /// execution. `reason` is the coordinator's own reason, so the node's log
    /// says why its work stopped rather than only that it did.
    Cancelled {
        execution_id: ExecutionId,
        reason: AbortReason,
    },
    /// An abort for an execution this node is not running. The coordinator
    /// publishes every cancellation to the whole roster, including nodes that
    /// never saw the `Prepare`, so this is ordinary.
    NotRunning { execution_id: ExecutionId },
    /// The coordinator has forgotten an execution that ended by *finishing*,
    /// which it publishes as a cancellation like any other removal. Nothing is
    /// torn down: the execution reached its retirement quorum, so this notice
    /// is caused by the parties' own completions rather than being an order to
    /// stop, and an instance still running here owns its own ending.
    ///
    /// `still_running` is normally false — this node acknowledged its own
    /// retirement during cleanup, which is what the quorum counts. It is true
    /// for an instance that had not acknowledged yet when the quorum was
    /// reached without it, and that instance keeps running to its own terminal
    /// event.
    Retired {
        execution_id: ExecutionId,
        still_running: bool,
    },
    /// The opening snapshot ended, and every live instance it did not name
    /// was judged against what this node already knows.
    ///
    /// `stopped` are the instances this incarnation of the coordinator
    /// admitted and its snapshot did not name with nothing to explain the
    /// omission: that is the dropped `Cancel` this reconciliation exists to
    /// recover. `kept` are instances another incarnation admitted, which this
    /// snapshot says nothing about. `retired` are instances whose execution
    /// this same incarnation has already published as *finished*: that
    /// retirement is why the snapshot omits them, so — exactly as on the
    /// `Cancel` path — the instance is left to its own ending.
    SnapshotReconciled {
        stopped: Vec<ExecutionId>,
        kept: Vec<ExecutionId>,
        retired: Vec<ExecutionId>,
    },
    /// The notice named an execution this node will not run.
    Refused {
        execution_id: ExecutionId,
        error: String,
    },
}

/// Why a fresh coordinator link could not be opened.
#[derive(Debug, Clone)]
pub enum LinkFailure {
    /// The coordinator could not be reached, or refused this attempt for a
    /// reason a later attempt may not hit. The node keeps trying.
    Unreachable(String),
    /// The coordinator answered, but it is not the coordinator this node
    /// joined: it served a different node roster, or one that fails
    /// verification. A node may not follow a changed roster, so this ends the
    /// stream instead of being retried.
    NotTheSameCoordinator(String),
}

/// Opens a fresh mutually authenticated link to the coordinator this node was
/// deployed for, with the roster digest it pinned at startup.
///
/// A standing node's *subscription* is long-lived; the connection underneath it
/// is not. A coordinator restart, a connection the coordinator reclaims, or any
/// transport failure ends it, and the JSON-RPC client cannot be revived once
/// its background task has stopped — every later call on it fails with the same
/// "connection was closed" forever. So the stream reopens the link rather than
/// retrying a dead one, and each reopen re-verifies the pinned roster digest,
/// which is what keeps "reconnect" from becoming "accept whatever answers now".
#[async_trait::async_trait]
pub trait CoordinatorLinkSource: Send + Sync + 'static {
    /// Opens one link, or says why it could not be opened.
    async fn open(&self) -> Result<CoordinatorLink, LinkFailure>;
}

/// Drives one standing node's executions from the coordinator's stream.
///
/// A node subscribes once and is told about every execution it must run. The
/// stream opens with one `Prepare` per execution the coordinator still wants
/// this node to run, then `SnapshotComplete`, then every later notice. An
/// omission from the snapshot that nothing else explains is an order to stop,
/// so reaching `SnapshotComplete` stops every instance that run of the
/// coordinator admitted, did not name, and whose identity this node does not
/// already know to be retired — which is what recovers a `Cancel` that was
/// dropped when a saturated connection ended an earlier stream.
///
/// Both qualifications are load-bearing, and each is a way a snapshot omits an
/// execution without ordering anything. The coordinator's executions do not
/// outlive its process, so a restarted one's snapshot names nothing and
/// reconciling the whole live set against it would abort every execution in
/// flight on the roster. And a retired execution is absent from every snapshot
/// after it, so a node that read that absence as an order would tear down an
/// instance that is ending well — which it learns either from the removal the
/// coordinator publishes or, with no notice at all, from the retirement
/// acknowledgement it sent itself during cleanup. [`InstanceLedger`] holds
/// both.
///
/// Admission is serial and returns immediately, so it cannot stop independent
/// executions from running concurrently: each admitted execution runs on its
/// own Tokio task under [`NodeSupervisor`].
pub struct CoordinatorExecutionStream {
    party_id: usize,
    programs: Arc<StandingProgramCatalog>,
    clients: Arc<StandingClientCatalog>,
    supervisor: Arc<NodeSupervisor>,
    events: tokio::sync::mpsc::UnboundedReceiver<NodeEvent>,
    handler: Arc<dyn StandingExecutionHandler>,
    admitted: Arc<RetiredExecutionIndex>,
    /// What this node knows about each instance it is running, beyond the
    /// supervisor's own liveness.
    instances: Arc<InstanceLedger>,
}

/// What this node knows about each instance it is running, beyond the
/// supervisor's own liveness: which run of the coordinator named it, and
/// whether its identity has already been retired.
///
/// Both halves are what keeps
/// [`CoordinatorExecutionStream::reconcile_snapshot`] from stopping work on an
/// omission that means something else. The coordinator keeps its executions in
/// memory only, so a restarted one's first snapshot names nothing and a node
/// that took that as the complete statement of its work would stop every
/// execution in flight across the whole deployment; and a retired execution is
/// absent from every later snapshot of the same run, so a node that had
/// forgotten the retirement would tear down an instance that is already ending
/// well.
///
/// It is shared rather than owned by the stream because a retirement reaches
/// this node two ways, and only one of them is a notice. The coordinator
/// publishes a removal as `Cancel { outcome: Finished }`, and this node sends
/// a retirement acknowledgement of its own from inside execution cleanup —
/// which makes every later snapshot *of this node* omit the execution at once,
/// with no notice behind it, because the coordinator's per-node snapshot
/// predicate is "not acknowledged by this node" and the acknowledgement is
/// counted the moment it arrives. So the execution path records its own
/// acknowledgement here, before it sends it, and both omissions are explained
/// by the same mechanism.
///
/// In memory because it is only ever about instances this process is running:
/// a node that restarts has none.
#[derive(Debug, Default)]
pub struct InstanceLedger {
    instances: Mutex<HashMap<ExecutionId, InstanceRecord>>,
}

/// What this node has last learned about an execution it is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstanceStanding {
    /// The coordinator still serves the execution, as far as this node knows,
    /// so it still expects to name it in every snapshot it takes.
    Served,
    /// The execution's identity is retired while this node's instance has not
    /// ended yet — either because the coordinator published the removal, or
    /// because this node acknowledged its own retirement during cleanup. The
    /// identity is retired; the work is not. Every snapshot this node is
    /// served from now on omits the execution, and none of those omissions is
    /// an order to stop.
    Retired,
}

/// What this node remembers about one instance it is running, so that it can
/// tell what a snapshot omitting that instance means.
#[derive(Debug, Clone, Copy)]
struct InstanceRecord {
    /// The run of the coordinator that most recently named this instance.
    incarnation: CoordinatorIncarnation,
    standing: InstanceStanding,
}

impl InstanceRecord {
    /// A newly named instance: the coordinator that named it serves it.
    fn served(incarnation: CoordinatorIncarnation) -> Self {
        Self {
            incarnation,
            standing: InstanceStanding::Served,
        }
    }
}

/// How one snapshot's omissions were judged against what this node knows.
#[derive(Debug, Default)]
struct SnapshotVerdict {
    /// Omitted by a snapshot that speaks for the work, with nothing this node
    /// knows to explain the omission: the dropped `Cancel` to recover.
    unexplained: Vec<ExecutionId>,
    /// Omitted by a snapshot that does not speak for the work at all.
    kept: Vec<ExecutionId>,
    /// Omitted because the execution's identity is already retired.
    retired: Vec<ExecutionId>,
}

impl InstanceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `incarnation` has named `execution_id`, keeping only the
    /// entries whose instance is still one of `live`.
    ///
    /// Pruning here is what keeps a standing node whose subscription stays
    /// healthy for weeks from accumulating one entry per execution it has ever
    /// been told about.
    fn named(
        &self,
        execution_id: ExecutionId,
        incarnation: CoordinatorIncarnation,
        live: &HashSet<ExecutionId>,
    ) {
        let mut instances = self.lock();
        // `execution_id` is being admitted, so its instance does not exist yet.
        instances.retain(|id, _| live.contains(id) || *id == execution_id);
        // Being named again records the run that named it and nothing else: a
        // retirement is a fact about the execution, not about one
        // subscription, so a later `Prepare` for the same identity cannot
        // un-retire it.
        instances
            .entry(execution_id)
            .and_modify(|record| record.incarnation = incarnation)
            .or_insert_with(|| InstanceRecord::served(incarnation));
    }

    /// Record that this node knows `execution_id`'s identity is retired, so
    /// that a snapshot omitting it is not read as an order to stop.
    ///
    /// Both retirements go through here: the one the coordinator publishes,
    /// which [`CoordinatorExecutionStream::retire`] records on the notice
    /// path, and the one this node sends itself, which reaches it only through
    /// [`Self::acknowledge_retirement`]. It is private so that the second
    /// cannot be written in the wrong order: the ledger write and the
    /// acknowledgement are one step, not two statements a call site has to
    /// keep in order.
    ///
    /// An instance with no entry needs none: it has no incarnation to match,
    /// so reconciliation keeps it under the same fail-safe default.
    fn retire(&self, execution_id: ExecutionId) {
        if let Some(record) = self.lock().get_mut(&execution_id) {
            record.standing = InstanceStanding::Retired;
        }
    }

    /// Record `execution_id`'s retirement here, and only then let
    /// `acknowledge` tell the coordinator about it. The order is the whole
    /// point of the method.
    ///
    /// The coordinator's per-node snapshot predicate is "not acknowledged by
    /// this node", counted the moment the acknowledgement lands, and for every
    /// party but the one whose acknowledgement completes the quorum nothing at
    /// all is published behind it. Meanwhile [`NodeSupervisor`] holds the
    /// instance live until cleanup returns. So from the acknowledgement until
    /// the end of cleanup there is a window in which every snapshot this node
    /// is served omits an execution it is still running, with no notice to
    /// explain the omission — and a resubscription landing inside that window
    /// would read it as a dropped abort, cancel an execution whose work has
    /// already finished, and report a successful run as cancelled.
    ///
    /// Writing the record first closes the window rather than narrowing it:
    /// the explanation exists before the omission can, and the ledger's mutex
    /// carries that ordering to whichever task reconciles the snapshot. The
    /// acknowledgement is taken as a closure rather than a future so that the
    /// order holds however the caller builds it.
    pub async fn acknowledge_retirement<A, F, T>(
        &self,
        execution_id: ExecutionId,
        acknowledge: A,
    ) -> T
    where
        A: FnOnce() -> F,
        F: Future<Output = T>,
    {
        self.retire(execution_id);
        acknowledge().await
    }

    /// Judge every instance in `live` that a snapshot of `incarnation` did not
    /// name, and forget the entries whose instance has ended.
    ///
    /// Deciding under one lock is what makes the node's own acknowledgement
    /// safe: it is recorded before the coordinator can omit the execution, so
    /// a snapshot that omits it is reconciled strictly afterwards.
    fn judge(
        &self,
        named: &HashSet<ExecutionId>,
        incarnation: CoordinatorIncarnation,
        live: &[ExecutionId],
    ) -> SnapshotVerdict {
        let mut instances = self.lock();
        // An instance that has finished says nothing about a later snapshot.
        let live_set = live.iter().copied().collect::<HashSet<_>>();
        instances.retain(|execution_id, _| live_set.contains(execution_id));
        let mut verdict = SnapshotVerdict::default();
        for execution_id in live.iter().copied() {
            if named.contains(&execution_id) {
                continue;
            }
            match instances.get(&execution_id) {
                Some(record) if record.incarnation == incarnation => match record.standing {
                    InstanceStanding::Served => verdict.unexplained.push(execution_id),
                    InstanceStanding::Retired => verdict.retired.push(execution_id),
                },
                // No entry, or one from another run of the coordinator: this
                // snapshot does not speak for the work.
                _ => verdict.kept.push(execution_id),
            }
        }
        verdict
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ExecutionId, InstanceRecord>> {
        self.instances
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl CoordinatorExecutionStream {
    #[allow(clippy::too_many_arguments)]
    pub fn new<H>(
        party_id: usize,
        programs: Arc<StandingProgramCatalog>,
        clients: Arc<StandingClientCatalog>,
        supervisor: Arc<NodeSupervisor>,
        events: tokio::sync::mpsc::UnboundedReceiver<NodeEvent>,
        handler: Arc<H>,
        admitted: Arc<RetiredExecutionIndex>,
        instances: Arc<InstanceLedger>,
    ) -> Self
    where
        H: StandingExecutionHandler,
    {
        Self {
            party_id,
            programs,
            clients,
            supervisor,
            events,
            handler,
            admitted,
            instances,
        }
    }

    /// Serve executions until `cancellation` fires.
    ///
    /// Returns only on cancellation or on a refusal this node cannot continue
    /// past. The stream ending is not such a refusal: the node re-subscribes
    /// with bounded backoff and takes a fresh snapshot, keeping every running
    /// instance in the meantime. With no executions at all it idles here, which
    /// is a standing node's normal state.
    pub async fn run(
        &mut self,
        mut link: Arc<CoordinatorLink>,
        links: Arc<dyn CoordinatorLinkSource>,
        cancellation: CancellationToken,
    ) -> Result<(), ExecutionStreamError> {
        let mut backoff = RESUBSCRIBE_MIN_BACKOFF;
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            let subscription = tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                subscription = link.subscribe_executions() => subscription,
            };
            let mut reopen = false;
            match subscription {
                Ok(subscription) => {
                    eprintln!(
                        "[party {}] subscribed to the coordinator's execution stream",
                        self.party_id
                    );
                    backoff = RESUBSCRIBE_MIN_BACKOFF;
                    self.serve_subscription(subscription, &cancellation).await?;
                }
                Err(error) => {
                    // The link this node holds may simply have no connection
                    // left under it, which no number of retries on the same
                    // client can fix, so the next attempt is made on a link
                    // opened from scratch.
                    eprintln!(
                        "[party {}] cannot subscribe to the coordinator's execution stream: \
                         {error}; reopening the link in {backoff:?}",
                        self.party_id
                    );
                    reopen = true;
                }
            }
            if cancellation.is_cancelled() {
                return Ok(());
            }
            // The instances this node is already running keep going while it
            // has no subscription, so their lifecycle keeps being reported:
            // waiting for the coordinator must not make a running execution's
            // completion invisible.
            let waiting = tokio::time::sleep(backoff);
            tokio::pin!(waiting);
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = &mut waiting => break,
                    event = self.events.recv() => match event {
                        None => return Ok(()),
                        Some(event) => self.report_event(&event),
                    },
                }
            }
            if reopen {
                match links.open().await {
                    Ok(fresh) => {
                        eprintln!(
                            "[party {}] reopened the link to the coordinator",
                            self.party_id
                        );
                        link = Arc::new(fresh);
                    }
                    Err(LinkFailure::Unreachable(reason)) => {
                        eprintln!(
                            "[party {}] cannot reopen the link to the coordinator: {reason}",
                            self.party_id
                        );
                    }
                    Err(LinkFailure::NotTheSameCoordinator(reason)) => {
                        return Err(ExecutionStreamError::CoordinatorIdentity(reason));
                    }
                }
            }
            backoff = (backoff * 2).min(RESUBSCRIBE_MAX_BACKOFF);
        }
    }

    /// Consume one subscription until it ends.
    async fn serve_subscription(
        &mut self,
        mut subscription: Subscription<ExecutionNotice>,
        cancellation: &CancellationToken,
    ) -> Result<(), ExecutionStreamError> {
        let mut snapshot = SnapshotCursor::default();
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                event = self.events.recv() => match event {
                    // The supervisor's sender lives as long as the supervisor,
                    // so `None` means the node is shutting down.
                    None => return Ok(()),
                    Some(event) => self.report_event(&event),
                },
                notice = subscription.next() => match notice {
                    None => {
                        eprintln!(
                            "[party {}] the coordinator's execution stream ended; \
                             re-subscribing takes a fresh snapshot",
                            self.party_id
                        );
                        return Ok(());
                    }
                    Some(Err(error)) => {
                        eprintln!(
                            "[party {}] the coordinator published a notice this node cannot \
                             decode: {error}; re-subscribing",
                            self.party_id
                        );
                        return Ok(());
                    }
                    Some(Ok(notice)) => {
                        let outcome = self.apply(notice, &mut snapshot);
                        self.report_outcome(&outcome);
                    }
                },
            }
        }
    }

    /// Apply one notice, advancing the subscription's snapshot cursor.
    pub fn apply(&self, notice: ExecutionNotice, snapshot: &mut SnapshotCursor) -> NoticeOutcome {
        match notice {
            ExecutionNotice::Prepare(published) => {
                let execution_id =
                    ExecutionId::from_bytes(*published.registration.execution_id.as_bytes());
                snapshot.observe_prepare(execution_id);
                // A `Prepare` on the live stream is this incarnation of the
                // coordinator naming the execution. One inside the opening
                // snapshot is named by an incarnation this node does not learn
                // until `SnapshotComplete` closes it, which is where the whole
                // snapshot is recorded at once.
                if let Some(incarnation) = snapshot.live_incarnation() {
                    self.record_incarnation(execution_id, incarnation);
                }
                self.admit(published)
            }
            // A `Cancel` is the coordinator saying it no longer serves the
            // execution, and `outcome` says whether that is an order to stop.
            // An abort is; a removal published because the execution finished
            // is not, and tearing an instance down for one would make a node's
            // own completion race the notice that completion caused.
            ExecutionNotice::Cancel {
                execution_id,
                outcome,
            } => {
                let execution_id = ExecutionId::from_bytes(*execution_id.as_bytes());
                match outcome {
                    ExecutionOutcome::Finished => self.retire(execution_id),
                    ExecutionOutcome::Aborted(reason) => self.stop(execution_id, reason),
                }
            }
            ExecutionNotice::SnapshotComplete { incarnation } => {
                match snapshot.complete(incarnation) {
                    None => NoticeOutcome::SnapshotReconciled {
                        stopped: Vec::new(),
                        kept: Vec::new(),
                        retired: Vec::new(),
                    },
                    Some(named) => {
                        for execution_id in &named {
                            self.record_incarnation(*execution_id, incarnation);
                        }
                        self.reconcile_snapshot(&named, incarnation)
                    }
                }
            }
        }
    }

    /// Record which run of the coordinator most recently named `execution_id`.
    fn record_incarnation(&self, execution_id: ExecutionId, incarnation: CoordinatorIncarnation) {
        let live = self
            .supervisor
            .live_executions()
            .into_iter()
            .collect::<HashSet<_>>();
        self.instances.named(execution_id, incarnation, &live);
    }

    /// Admit one published execution, idempotently per identity.
    fn admit(&self, published: PublishedExecution) -> NoticeOutcome {
        let execution_id = ExecutionId::from_bytes(*published.registration.execution_id.as_bytes());
        if self.supervisor.is_live(execution_id) {
            return NoticeOutcome::AlreadyRunning { execution_id };
        }
        let admission = match self.resolve(&published) {
            Ok(admission) => admission,
            Err(error) => {
                return NoticeOutcome::Refused {
                    execution_id,
                    error: error.to_string(),
                }
            }
        };
        // An execution identity is single use, and the claim is taken before
        // the instance starts: a node that crashed mid-execution must not
        // re-admit an identity whose correlated material its peers already
        // consumed.
        match self.admitted.claim(execution_id) {
            Ok(true) => {}
            Ok(false) => return NoticeOutcome::AlreadyAdmitted { execution_id },
            Err(error) => {
                return NoticeOutcome::Refused {
                    execution_id,
                    error: ExecutionStreamError::AdmittedIndex(error.to_string()).to_string(),
                }
            }
        }
        let spec = ExecutionSpecV1::new(execution_id, admission.program_id);
        let handler = Arc::clone(&self.handler);
        match self
            .supervisor
            .prepare(spec, move |context| handler.prepare(admission, context))
        {
            Ok(_) => NoticeOutcome::Admitted { execution_id },
            Err(error) => NoticeOutcome::Refused {
                execution_id,
                error: error.to_string(),
            },
        }
    }

    /// Stop one aborted execution, tolerating one this node is not running.
    fn stop(&self, execution_id: ExecutionId, reason: AbortReason) -> NoticeOutcome {
        match self.supervisor.cancel(execution_id) {
            Ok(_) => NoticeOutcome::Cancelled {
                execution_id,
                reason,
            },
            Err(_) => NoticeOutcome::NotRunning { execution_id },
        }
    }

    /// Note that the coordinator has forgotten a *finished* execution, without
    /// touching the instance.
    fn retire(&self, execution_id: ExecutionId) -> NoticeOutcome {
        let still_running = self.supervisor.is_live(execution_id);
        if still_running {
            // The coordinator has stopped serving this execution, so every
            // snapshot it takes from now on omits it — including the one a
            // routine reconnect takes while this instance is still running.
            // Recording that the omission is this retirement is what keeps
            // [`Self::reconcile_snapshot`] from tearing down work that is
            // ending well. An instance with no record at all needs none: it
            // has no incarnation to match, so reconciliation keeps it.
            self.instances.retire(execution_id);
        }
        NoticeOutcome::Retired {
            execution_id,
            still_running,
        }
    }

    /// Judge every live instance the opening snapshot of `incarnation` did not
    /// name, stopping the ones whose omission can mean nothing else.
    ///
    /// This is what makes a dropped `Cancel` recoverable: within one run of the
    /// coordinator the snapshot is its complete statement of what it still
    /// wants this node to run, so an unexplained omission is an order to stop.
    ///
    /// Two omissions are explained, and neither stops anything, because a
    /// snapshot is authoritative about the set the coordinator serves this node
    /// and not about why an execution left it.
    ///
    /// The first is **another run of the coordinator**. It holds its
    /// executions in memory, so a restarted one has forgotten every identity
    /// it minted and its first snapshot names nothing — and the instances a
    /// node is running under the previous incarnation are work that
    /// coordinator never aborted and cannot speak for. They keep running, and
    /// are reported as kept; a new coordinator that does want one stopped
    /// names it in a `Cancel`, which needs no incarnation to act on.
    ///
    /// The second is **a retirement this node already knows about**, which
    /// reaches it two ways. The coordinator drops a *finished* execution from
    /// the set it serves at all — at unanimous retirement, when an
    /// output-retention window expires, or when capacity pressure evicts it at
    /// the `n - t` quorum, which can be reached without a lagging party — and
    /// publishes that removal as `Cancel { outcome: Finished }`, which
    /// [`Self::retire`] records without touching the instance. And this node
    /// acknowledges its own retirement from inside execution cleanup, which
    /// the coordinator's per-node snapshot predicate counts immediately while
    /// the supervisor holds the instance live until cleanup returns; that
    /// acknowledgement goes through [`InstanceLedger::acknowledge_retirement`],
    /// which records it before it is sent. Either way every later snapshot omits the execution, and the
    /// connection under a subscription ends routinely, so without this a
    /// reconnect would tear down an instance that is finishing well and report
    /// the run of whichever party finished last as cancelled. A retired
    /// identity is not an order to stop, here as on the `Cancel` path.
    pub fn reconcile_snapshot(
        &self,
        named: &HashSet<ExecutionId>,
        incarnation: CoordinatorIncarnation,
    ) -> NoticeOutcome {
        let live = self.supervisor.live_executions();
        let SnapshotVerdict {
            unexplained,
            mut kept,
            mut retired,
        } = self.instances.judge(named, incarnation, &live);
        let mut stopped = Vec::new();
        for execution_id in unexplained {
            if self.supervisor.cancel(execution_id).is_ok() {
                stopped.push(execution_id);
            }
        }
        stopped.sort_unstable();
        kept.sort_unstable();
        retired.sort_unstable();
        NoticeOutcome::SnapshotReconciled {
            stopped,
            kept,
            retired,
        }
    }

    /// Resolve a published execution against the catalogs frozen at startup.
    pub fn resolve(
        &self,
        published: &PublishedExecution,
    ) -> Result<AdmittedExecution, ExecutionStreamError> {
        resolve_published_execution(&self.programs, &self.clients, published)
    }

    fn report_outcome(&self, outcome: &NoticeOutcome) {
        let party = self.party_id;
        match outcome {
            NoticeOutcome::Admitted { execution_id } => {
                eprintln!("[party {party}] admitted execution {execution_id}")
            }
            NoticeOutcome::AlreadyRunning { execution_id } => {
                eprintln!("[party {party}] execution {execution_id} is already running")
            }
            NoticeOutcome::AlreadyAdmitted { execution_id } => eprintln!(
                "[party {party}] execution {execution_id} was already admitted by this node; \
                 an execution identity is single use"
            ),
            NoticeOutcome::Cancelled {
                execution_id,
                reason,
            } => {
                eprintln!("[party {party}] cancelled execution {execution_id}: {reason}")
            }
            NoticeOutcome::NotRunning { execution_id } => {
                eprintln!("[party {party}] execution {execution_id} is not running here")
            }
            NoticeOutcome::Retired {
                execution_id,
                still_running: false,
            } => eprintln!(
                "[party {party}] execution {execution_id} finished and the coordinator \
                 has forgotten it"
            ),
            NoticeOutcome::Retired {
                execution_id,
                still_running: true,
            } => eprintln!(
                "[party {party}] execution {execution_id} is still running here, and the \
                 coordinator has forgotten it as finished; this instance owns its own ending"
            ),
            NoticeOutcome::SnapshotReconciled {
                stopped,
                kept,
                retired,
            } => {
                if stopped.is_empty() {
                    eprintln!("[party {party}] execution snapshot complete");
                } else {
                    eprintln!(
                        "[party {party}] execution snapshot complete; stopped {} because \
                         the coordinator no longer names them",
                        join_execution_ids(stopped)
                    );
                }
                if !kept.is_empty() {
                    eprintln!(
                        "[party {party}] still running {}: another run of the coordinator \
                         admitted them, and this snapshot does not speak for it",
                        join_execution_ids(kept)
                    );
                }
                if !retired.is_empty() {
                    eprintln!(
                        "[party {party}] still running {}: this coordinator has already \
                         forgotten them as finished, so its snapshot omitting them is that \
                         retirement and not an order to stop",
                        join_execution_ids(retired)
                    );
                }
            }
            NoticeOutcome::Refused {
                execution_id,
                error,
            } => eprintln!(
                "[party {party}] refusing execution {execution_id}: {}",
                bounded_event_text(error.clone())
            ),
        }
    }

    fn report_event(&self, event: &NodeEvent) {
        let party = self.party_id;
        let execution_id = event.execution_id;
        match &event.kind {
            NodeEventKind::Preparing => {
                eprintln!("[party {party}] execution {execution_id} preparing")
            }
            NodeEventKind::Ready => eprintln!("[party {party}] execution {execution_id} ready"),
            NodeEventKind::CancelAccepted => {
                eprintln!("[party {party}] execution {execution_id} cancellation accepted")
            }
            // The yield counters are part of the line because they are the only
            // evidence that an execution shared its process cooperatively, and
            // a concurrency campaign has to be able to read them.
            NodeEventKind::Completed { metrics } => eprintln!(
                "[party {party}] execution {execution_id} completed: \
                 instruction_budget_yields={} online_effect_yields={}",
                metrics.instruction_budget_yields, metrics.online_effect_yields
            ),
            NodeEventKind::Cancelled => {
                eprintln!("[party {party}] execution {execution_id} cancelled")
            }
            NodeEventKind::Failed { error } => eprintln!(
                "[party {party}] execution {execution_id} failed: {}",
                bounded_event_text(error.clone())
            ),
        }
    }
}

/// One subscription's view of its opening snapshot.
///
/// `SnapshotComplete` arrives exactly once per subscription, before any later
/// notice, so everything named before it is the snapshot and everything after
/// is live.
#[derive(Debug, Default)]
pub struct SnapshotCursor {
    named: HashSet<ExecutionId>,
    /// `Some` once `SnapshotComplete` has closed the snapshot, carrying the run
    /// of the coordinator this subscription is talking to.
    incarnation: Option<CoordinatorIncarnation>,
}

impl SnapshotCursor {
    fn observe_prepare(&mut self, execution_id: ExecutionId) {
        if self.incarnation.is_none() {
            self.named.insert(execution_id);
        }
    }

    /// Close the snapshot, yielding the executions it named.
    ///
    /// `None` once the snapshot has already closed. A snapshot closes once per
    /// subscription, so a second `SnapshotComplete` names nothing — and
    /// reconciling against nothing would stop every instance this incarnation
    /// started, including the ones the live stream started after the snapshot.
    fn complete(&mut self, incarnation: CoordinatorIncarnation) -> Option<HashSet<ExecutionId>> {
        if self.incarnation.is_some() {
            return None;
        }
        self.incarnation = Some(incarnation);
        Some(std::mem::take(&mut self.named))
    }

    /// The run of the coordinator whose live stream this cursor is on, once the
    /// opening snapshot has closed.
    fn live_incarnation(&self) -> Option<CoordinatorIncarnation> {
        self.incarnation
    }

    pub fn is_complete(&self) -> bool {
        self.incarnation.is_some()
    }
}

/// The identities of `executions`, in one comma-separated line.
fn join_execution_ids(executions: &[ExecutionId]) -> String {
    executions
        .iter()
        .map(ExecutionId::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve one published execution into the admission this node will run.
///
/// Every refusal here is a refusal of the whole execution: a program the
/// catalog does not hold, an entry the program does not define, a client slot
/// table the program's manifest does not match, or a published client identity
/// this node holds no certificate for.
pub fn resolve_published_execution(
    programs: &StandingProgramCatalog,
    clients: &StandingClientCatalog,
    published: &PublishedExecution,
) -> Result<AdmittedExecution, ExecutionStreamError> {
    let registration = &published.registration;
    let execution_id = ExecutionId::from_bytes(*registration.execution_id.as_bytes());
    if execution_id.is_zero() {
        return Err(ExecutionStreamError::Admission(
            "execution identity must be nonzero".to_owned(),
        ));
    }
    let request = &registration.request;
    let program_id = request.program_hash;
    let program = programs.get(&program_id).ok_or_else(|| {
        ExecutionStreamError::Admission(format!(
            "program {} is not in the standing startup catalog",
            hex::encode(program_id)
        ))
    })?;
    if !program.contains_entry(&request.entry) {
        return Err(ExecutionStreamError::Admission(format!(
            "admitted entry function {:?} is absent from compiled program {}",
            request.entry,
            hex::encode(program_id)
        )));
    }
    let AdmissionPolicy::PreRegistered {
        clients: published_clients,
    } = &request.admission
    else {
        return Err(ExecutionStreamError::Admission(
            "a standing node runs only pre-registered admissions: an open policy would let any \
             certificate holder bind a slot of a program this node holds"
                .to_owned(),
        ));
    };

    let mut admitted_clients = Vec::with_capacity(published_clients.len());
    for client in published_clients {
        let manifest_slot = usize::try_from(client.client_slot.0).map_err(|_| {
            ExecutionStreamError::Admission(format!(
                "published client slot {} exceeds this node's usize range",
                client.client_slot.0
            ))
        })?;
        admitted_clients.push(AdmittedClient { manifest_slot });
    }
    validate_client_io_admission(&admitted_clients, &program.client_io_manifest)?;

    let mut expected_client_public_keys = Vec::with_capacity(published_clients.len());
    let mut expected_client_certificate_identities = Vec::with_capacity(published_clients.len());
    let mut unique_client_identities = HashSet::with_capacity(published_clients.len());
    for client in published_clients {
        // The published identity is only a key to look a local certificate up
        // by. Reconstructing certificate material from it would have to guess
        // the issuer's algorithm identifier and encoding, and comparing
        // anything weaker than the certificate identity would downgrade
        // transport route authorization from certificate-exact to key-only.
        let identity = clients.get(&client.identity).ok_or_else(|| {
            ExecutionStreamError::Admission(format!(
                "the coordinator admitted client {} for slot {}, and this node holds no \
                 certificate with that public key",
                hex::encode(&client.identity),
                client.client_slot.0
            ))
        })?;
        if !unique_client_identities.insert(identity.certificate_identity) {
            return Err(ExecutionStreamError::Admission(format!(
                "the admission names certificate {} twice",
                identity.source
            )));
        }
        expected_client_public_keys.push(identity.coordinator_public_key);
        expected_client_certificate_identities.push(identity.certificate_identity);
    }

    let config_digest = admission_config_digest(
        execution_id,
        program_id,
        &request.entry,
        published.registration_nonce.as_bytes(),
        &admitted_clients,
        &expected_client_public_keys,
        &expected_client_certificate_identities,
    );

    Ok(AdmittedExecution {
        execution_id,
        program_id,
        entry: request.entry.clone(),
        clients: admitted_clients,
        expected_client_public_keys,
        expected_client_certificate_identities,
        config_digest,
    })
}

/// The commitment every party recomputes independently from the notice it was
/// published plus its own catalogs.
///
/// The parties compare it before any correlated preprocessing moves, so a
/// coordinator that published a different admission to a different party fails
/// closed there. The registration nonce is in the preimage so that two
/// registrations of one identity are distinguishable, and the client ordinal is
/// in it so that a permuted client list is a different admission.
#[allow(clippy::too_many_arguments)]
fn admission_config_digest(
    execution_id: ExecutionId,
    program_id: [u8; 32],
    entry: &str,
    registration_nonce: &[u8; 32],
    clients: &[AdmittedClient],
    public_keys: &[Vec<u8>],
    certificate_identities: &[CertificateIdentity],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stoffel-coordinator-admission-v1");
    hasher.update(execution_id.as_bytes());
    hasher.update(&program_id);
    hasher.update(registration_nonce);
    hasher.update(&(entry.len() as u64).to_le_bytes());
    hasher.update(entry.as_bytes());
    hasher.update(&(clients.len() as u64).to_le_bytes());
    for client in clients {
        hasher.update(&(client.manifest_slot as u64).to_le_bytes());
    }
    hasher.update(&(public_keys.len() as u64).to_le_bytes());
    for key in public_keys {
        hasher.update(&(key.len() as u64).to_le_bytes());
        hasher.update(key);
    }
    for identity in certificate_identities {
        hasher.update(identity.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
fn inspect_standing_program(
    bytes: &[u8],
) -> Result<
    (
        ClientIoManifest,
        MpcBackendKind,
        MpcCurveConfig,
        HashSet<String>,
    ),
    ExecutionStreamError,
> {
    inspect_standing_program_with_policy(bytes, false)
}

fn inspect_standing_program_with_policy(
    bytes: &[u8],
    allow_dynamic_preprocessing: bool,
) -> Result<
    (
        ClientIoManifest,
        MpcBackendKind,
        MpcCurveConfig,
        HashSet<String>,
    ),
    ExecutionStreamError,
> {
    let mut reader = BufReader::new(bytes);
    let mut entries = HashSet::new();
    let (functions, version, manifest) =
        CompiledBinary::try_for_each_vm_function_from_reader(&mut reader, |function| {
            entries.insert(function.name().to_owned());
            Ok(())
        })
        .map_err(|error| ExecutionStreamError::Catalog(format!("invalid program: {error:?}")))?;
    if functions == 0 {
        return Err(ExecutionStreamError::Catalog(
            "compiled program contains no functions".to_owned(),
        ));
    }
    validate_standing_preprocessing_manifest(
        version,
        &manifest.preprocessing_demand,
        allow_dynamic_preprocessing,
    )
    .map_err(ExecutionStreamError::Catalog)?;
    let backend = MpcBackendKind::from(manifest.mpc_backend);
    let curve = MpcCurveConfig::from(manifest.mpc_curve);
    curve
        .validate_for_backend(backend)
        .map_err(|error| ExecutionStreamError::Catalog(error.to_string()))?;
    Ok((manifest, backend, curve, entries))
}

fn validate_standing_preprocessing_manifest(
    artifact_version: u16,
    demand: &PreprocessingDemand,
    allow_dynamic_preprocessing: bool,
) -> Result<(), String> {
    if artifact_version < PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION {
        return Err(format!(
            "standing execution requires artifact format version {PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION} or newer; version {artifact_version} has no complete preprocessing manifest"
        ));
    }
    if demand.dynamic && !allow_dynamic_preprocessing {
        return Err(
            "standing execution requires statically bounded preprocessing demand".to_owned(),
        );
    }
    Ok(())
}

/// Require the admitted client-to-slot mapping to cover the compiled client
/// manifest exactly. Input-bearing slots and their per-client counts are
/// deliberately not repeated in the admission: execution setup derives them
/// from this same content-addressed manifest.
fn validate_client_io_admission(
    clients: &[AdmittedClient],
    manifest: &ClientIoManifest,
) -> Result<(), ExecutionStreamError> {
    if clients.len() > usize::from(u8::MAX) + 1 {
        return Err(ExecutionStreamError::Admission(format!(
            "{} clients exceed the one-byte MPC client index domain",
            clients.len()
        )));
    }
    let mut roster_slots = HashSet::with_capacity(clients.len());
    for client in clients {
        if !roster_slots.insert(client.manifest_slot) {
            return Err(ExecutionStreamError::Admission(format!(
                "admitted clients contain duplicate manifest slot {}",
                client.manifest_slot
            )));
        }
    }

    let mut manifest_slots = HashSet::with_capacity(manifest.clients.len());
    for schema in &manifest.clients {
        let slot = usize::try_from(schema.client_slot).map_err(|_| {
            ExecutionStreamError::Admission(format!(
                "program client slot {} exceeds this node's usize range",
                schema.client_slot
            ))
        })?;
        if !manifest_slots.insert(slot) {
            return Err(ExecutionStreamError::Catalog(format!(
                "program client IO manifest contains duplicate client slot {slot}"
            )));
        }
    }

    if roster_slots != manifest_slots {
        let mut admitted = roster_slots.into_iter().collect::<Vec<_>>();
        let mut compiled = manifest_slots.into_iter().collect::<Vec<_>>();
        admitted.sort_unstable();
        compiled.sort_unstable();
        return Err(ExecutionStreamError::Admission(format!(
            "admitted client slots {admitted:?} do not match program manifest slots {compiled:?}"
        )));
    }
    manifest.clients.iter().try_fold(0usize, |total, schema| {
        total.checked_add(schema.inputs.len()).ok_or_else(|| {
            ExecutionStreamError::Catalog(
                "program client input total exceeds this node's usize range".to_owned(),
            )
        })
    })?;
    Ok(())
}

/// Bound one reported error so a failing execution cannot emit unbounded text.
fn bounded_event_text(mut value: String) -> String {
    if value.len() <= MAX_NODE_EVENT_TEXT_BYTES {
        return value;
    }
    let original_len = value.len();
    let digest = blake3::hash(value.as_bytes()).to_hex();
    let suffix = format!("...[truncated bytes={original_len} blake3={digest}]");
    let mut keep = MAX_NODE_EVENT_TEXT_BYTES.saturating_sub(suffix.len());
    while keep > 0 && !value.is_char_boundary(keep) {
        keep -= 1;
    }
    value.truncate(keep);
    value.push_str(&suffix);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_mpc_coordinator_off_chain::{ExecutionRegistration, ExecutionRequest};
    use stoffel_mpc_coordinator_shared::admission::{
        AbortReason, ClientIndex, ClientSlotSpec, ClientSlotTable, ExecutionOutcome,
        PreRegisteredClient, RegistrationNonce,
    };
    use stoffel_mpc_coordinator_shared::ExecutionId as CoordinatorExecutionId;
    use stoffel_vm::core_vm::VmCooperativeExecutionMetrics;
    use stoffel_vm_types::compiled_binary::ClientIoSchema;

    fn client(manifest_slot: usize) -> AdmittedClient {
        AdmittedClient { manifest_slot }
    }

    fn manifest(slots: &[u64]) -> ClientIoManifest {
        ClientIoManifest {
            clients: slots
                .iter()
                .map(|slot| ClientIoSchema {
                    client_slot: *slot,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                })
                .collect(),
            ..ClientIoManifest::default()
        }
    }

    fn published(
        execution_id: [u8; 32],
        program_hash: [u8; 32],
        entry: &str,
        clients: Vec<(Vec<u8>, u32)>,
    ) -> PublishedExecution {
        PublishedExecution {
            registration: ExecutionRegistration {
                execution_id: CoordinatorExecutionId::from_bytes(execution_id),
                request: ExecutionRequest {
                    program_hash,
                    entry: entry.to_owned(),
                    client_slots: ClientSlotTable::new(
                        clients
                            .iter()
                            .map(|_| ClientSlotSpec {
                                input_count: 1,
                                output_count: 1,
                            })
                            .collect(),
                    ),
                    admission: AdmissionPolicy::PreRegistered {
                        clients: clients
                            .into_iter()
                            .map(|(identity, client_slot)| PreRegisteredClient {
                                identity,
                                client_slot: ClientIndex(client_slot),
                            })
                            .collect(),
                    },
                    deadlines: None,
                },
            },
            registration_nonce: RegistrationNonce::from_bytes([3; 32]),
        }
    }

    #[test]
    fn admitted_client_bindings_cover_the_manifest_exactly() {
        validate_client_io_admission(&[client(1), client(0)], &manifest(&[0, 1])).unwrap();

        let duplicate_slot = [client(0), client(0)];
        assert!(validate_client_io_admission(&duplicate_slot, &manifest(&[0, 1])).is_err());

        let missing_slot = [client(0)];
        assert!(validate_client_io_admission(&missing_slot, &manifest(&[0, 1])).is_err());

        let too_many = (0..257).map(client).collect::<Vec<_>>();
        assert!(validate_client_io_admission(&too_many, &ClientIoManifest::default()).is_err());
    }

    #[test]
    fn standing_preprocessing_requires_a_current_bounded_manifest() {
        let fixed = PreprocessingDemand::default();
        let old_version = validate_standing_preprocessing_manifest(
            PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION - 1,
            &fixed,
            false,
        )
        .unwrap_err();
        assert!(old_version.contains("no complete preprocessing manifest"));

        let dynamic = PreprocessingDemand {
            dynamic: true,
            ..PreprocessingDemand::default()
        };
        let unbounded = validate_standing_preprocessing_manifest(
            PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
            &dynamic,
            false,
        )
        .unwrap_err();
        assert!(unbounded.contains("statically bounded"));

        validate_standing_preprocessing_manifest(
            PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
            &dynamic,
            true,
        )
        .expect("explicit example/test policy admits a dynamic demand floor");
    }

    #[test]
    fn checked_in_client_mul_is_standing_safe() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../stoffel-vm/src/tests/binaries/client_mul.stflb");
        let bytes = std::fs::read(&fixture).expect("read client_mul fixture");
        let (manifest, backend, curve, entries) =
            inspect_standing_program(&bytes).expect("client_mul must be standing-safe");

        assert_eq!(backend, MpcBackendKind::HoneyBadger);
        assert_eq!(curve, MpcCurveConfig::Bls12_381);
        assert!(entries.contains("main"));
        assert_eq!(manifest.clients.len(), 2);
        assert_eq!(manifest.preprocessing_demand.triples, 1);
        assert!(!manifest.preprocessing_demand.dynamic);
    }

    /// The fixture catalog every resolution test below shares: the checked-in
    /// two-client program, stored under its content address, and two client
    /// certificates taken from the repository's own test identities.
    struct Fixture {
        _directory: tempfile::TempDir,
        programs: Arc<StandingProgramCatalog>,
        clients: Arc<StandingClientCatalog>,
        program_id: [u8; 32],
        client_keys: Vec<Vec<u8>>,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temporary directory");
        let programs_dir = directory.path().join("programs");
        let clients_dir = directory.path().join("clients");
        fs::create_dir_all(&programs_dir).expect("program directory");
        fs::create_dir_all(&clients_dir).expect("client directory");

        let fixture_program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../stoffel-vm/src/tests/binaries/client_mul.stflb");
        let bytes = std::fs::read(&fixture_program).expect("read client_mul fixture");
        let program_id = program_id_from_bytes(&bytes);
        fs::write(
            programs_dir.join(format!("{}.stflb", hex::encode(program_id))),
            &bytes,
        )
        .expect("store program under its content address");

        // Two distinct self-signed certificates, so the catalog holds two
        // distinct published identities to resolve.
        let mut client_keys = Vec::new();
        for index in 0..2 {
            let certified = rcgen::generate_simple_self_signed([format!("client{index}")])
                .expect("generate client certificate");
            let der = certified.cert.der().to_vec();
            fs::write(clients_dir.join(format!("client{index}.crt")), &der)
                .expect("write client certificate");
            let (_, parsed) = X509Certificate::from_der(&der).expect("parse certificate");
            client_keys.push(
                parsed
                    .public_key()
                    .subject_public_key
                    .data
                    .as_ref()
                    .to_vec(),
            );
        }

        let programs =
            Arc::new(StandingProgramCatalog::load(&programs_dir).expect("load program catalog"));
        let clients =
            Arc::new(StandingClientCatalog::load(&clients_dir).expect("load client catalog"));
        Fixture {
            _directory: directory,
            programs,
            clients,
            program_id,
            client_keys,
        }
    }

    #[test]
    fn a_published_execution_resolves_against_the_local_catalogs() {
        let fixture = fixture();
        let notice = published(
            [5; 32],
            fixture.program_id,
            "main",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        let admitted =
            resolve_published_execution(&fixture.programs, &fixture.clients, &notice).unwrap();

        assert_eq!(admitted.execution_id, ExecutionId::from([5; 32]));
        assert_eq!(admitted.program_id, fixture.program_id);
        assert_eq!(admitted.entry, "main");
        assert_eq!(
            admitted.clients,
            vec![client(0), client(1)],
            "the published ordinal order is preserved"
        );
        assert_eq!(admitted.expected_client_public_keys.len(), 2);
        assert_eq!(admitted.expected_client_certificate_identities.len(), 2);
        assert_ne!(admitted.config_digest, [0; 32]);
    }

    #[test]
    fn the_execution_local_ordinal_is_independent_of_the_program_slot() {
        let fixture = fixture();
        // The coordinator lists the client that owns slot 1 first. Both slots
        // are still covered exactly once, so the admission stands and the
        // ordinal order is the published order, not the slot order.
        let permuted = published(
            [6; 32],
            fixture.program_id,
            "main",
            vec![
                (fixture.client_keys[1].clone(), 1),
                (fixture.client_keys[0].clone(), 0),
            ],
        );
        let admitted =
            resolve_published_execution(&fixture.programs, &fixture.clients, &permuted).unwrap();
        assert_eq!(admitted.clients, vec![client(1), client(0)]);

        let identity_order = published(
            [6; 32],
            fixture.program_id,
            "main",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        let in_order =
            resolve_published_execution(&fixture.programs, &fixture.clients, &identity_order)
                .unwrap();
        assert_ne!(
            admitted.config_digest, in_order.config_digest,
            "a permuted client list is a different admission and must not share a digest"
        );
    }

    #[test]
    fn a_published_client_this_node_holds_no_certificate_for_refuses_the_execution() {
        let fixture = fixture();
        let unknown = published(
            [7; 32],
            fixture.program_id,
            "main",
            vec![(fixture.client_keys[0].clone(), 0), (vec![0xab; 65], 1)],
        );
        let error = resolve_published_execution(&fixture.programs, &fixture.clients, &unknown)
            .expect_err("an unresolvable client identity refuses the whole admission");
        assert!(
            error.to_string().contains("holds no certificate"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_published_program_or_entry_the_catalog_does_not_hold_is_refused() {
        let fixture = fixture();
        let unknown_program = published(
            [8; 32],
            [0x11; 32],
            "main",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        assert!(
            resolve_published_execution(&fixture.programs, &fixture.clients, &unknown_program)
                .expect_err("an unknown program is refused")
                .to_string()
                .contains("not in the standing startup catalog")
        );

        let unknown_entry = published(
            [9; 32],
            fixture.program_id,
            "no_such_entry",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        assert!(
            resolve_published_execution(&fixture.programs, &fixture.clients, &unknown_entry)
                .expect_err("an absent entry function is refused")
                .to_string()
                .contains("is absent from compiled program")
        );
    }

    #[test]
    fn an_open_admission_policy_is_refused_by_a_standing_node() {
        let fixture = fixture();
        let mut notice = published(
            [10; 32],
            fixture.program_id,
            "main",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        notice.registration.request.admission = AdmissionPolicy::Open;
        let error = resolve_published_execution(&fixture.programs, &fixture.clients, &notice)
            .expect_err("an open policy is refused");
        assert!(
            error.to_string().contains("pre-registered"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_zero_execution_identity_is_refused() {
        let fixture = fixture();
        let notice = published(
            [0; 32],
            fixture.program_id,
            "main",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        let error = resolve_published_execution(&fixture.programs, &fixture.clients, &notice)
            .expect_err("the reserved zero identity is refused");
        assert!(
            error.to_string().contains("nonzero"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_config_digest_moves_whenever_any_committed_field_does() {
        let fixture = fixture();
        let base = published(
            [11; 32],
            fixture.program_id,
            "main",
            vec![
                (fixture.client_keys[0].clone(), 0),
                (fixture.client_keys[1].clone(), 1),
            ],
        );
        let baseline = resolve_published_execution(&fixture.programs, &fixture.clients, &base)
            .unwrap()
            .config_digest;

        let mut other_id = base.clone();
        other_id.registration.execution_id = CoordinatorExecutionId::from_bytes([12; 32]);
        assert_ne!(
            baseline,
            resolve_published_execution(&fixture.programs, &fixture.clients, &other_id)
                .unwrap()
                .config_digest
        );

        let mut other_nonce = base.clone();
        other_nonce.registration_nonce = RegistrationNonce::from_bytes([4; 32]);
        assert_ne!(
            baseline,
            resolve_published_execution(&fixture.programs, &fixture.clients, &other_nonce)
                .unwrap()
                .config_digest,
            "a re-registration of one identity must not share its predecessor's digest"
        );
    }

    #[test]
    fn two_client_certificates_with_one_key_refuse_the_catalog() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let certified = rcgen::generate_simple_self_signed(["client".to_owned()])
            .expect("generate client certificate");
        let der = certified.cert.der().to_vec();
        fs::write(directory.path().join("a.crt"), &der).expect("write a");
        fs::write(directory.path().join("b.crt"), &der).expect("write b");
        let error = StandingClientCatalog::load(directory.path()).expect_err(
            "an ambiguous published identity must not resolve to whichever file sorted first",
        );
        assert!(
            error.to_string().contains("same public key"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_snapshot_cursor_separates_the_snapshot_from_the_live_stream() {
        let incarnation = CoordinatorIncarnation::from_bytes([7; 16]);
        let mut cursor = SnapshotCursor::default();
        cursor.observe_prepare(ExecutionId::from([1; 32]));
        cursor.observe_prepare(ExecutionId::from([2; 32]));
        assert!(!cursor.is_complete());
        assert!(
            cursor.live_incarnation().is_none(),
            "inside the snapshot the subscription has not yet named its coordinator run"
        );

        let named = cursor
            .complete(incarnation)
            .expect("the first SnapshotComplete closes the snapshot");
        assert!(cursor.is_complete());
        assert_eq!(cursor.live_incarnation(), Some(incarnation));
        assert_eq!(named.len(), 2);
        assert!(named.contains(&ExecutionId::from([1; 32])));

        // A `Prepare` after the snapshot is live traffic and never re-enters it.
        cursor.observe_prepare(ExecutionId::from([3; 32]));
        assert!(
            cursor.complete(incarnation).is_none(),
            "a snapshot closes once, so a second SnapshotComplete reconciles nothing"
        );
    }

    /// A handler whose instances either finish at once or run until cancelled,
    /// so a test can observe what the stream does to something genuinely live.
    struct TestHandler {
        finish_immediately: bool,
    }

    struct TestInstance {
        cancellation: CancellationToken,
        finish_immediately: bool,
    }

    #[async_trait::async_trait]
    impl PreparedNodeExecution for TestInstance {
        async fn execute(&mut self) -> Result<VmCooperativeExecutionMetrics, String> {
            if !self.finish_immediately {
                self.cancellation.cancelled().await;
            }
            Ok(VmCooperativeExecutionMetrics::default())
        }
    }

    #[async_trait::async_trait]
    impl StandingExecutionHandler for TestHandler {
        async fn prepare(
            self: Arc<Self>,
            _admission: AdmittedExecution,
            context: NodeExecutionContext,
        ) -> Result<Box<dyn PreparedNodeExecution>, String> {
            Ok(Box::new(TestInstance {
                cancellation: context.cancellation,
                finish_immediately: self.finish_immediately,
            }))
        }
    }

    /// One stream wired to a real supervisor and a real durable index, so the
    /// notice-handling tests exercise the same objects the node runs.
    struct StreamFixture {
        fixture: Fixture,
        _directory: tempfile::TempDir,
        stream: CoordinatorExecutionStream,
        supervisor: Arc<NodeSupervisor>,
        /// The same ledger the stream holds, so a test can record a
        /// retirement the way the execution path does — from cleanup, rather
        /// than from a notice.
        instances: Arc<InstanceLedger>,
    }

    fn stream_fixture(finish_immediately: bool) -> StreamFixture {
        let fixture = fixture();
        let directory = tempfile::tempdir().expect("temporary directory");
        let admitted = Arc::new(
            RetiredExecutionIndex::open(directory.path().join("admitted"))
                .expect("open admitted-execution index"),
        );
        let (supervisor, events) = NodeSupervisor::new();
        let instances = Arc::new(InstanceLedger::new());
        let stream = CoordinatorExecutionStream::new(
            0,
            Arc::clone(&fixture.programs),
            Arc::clone(&fixture.clients),
            Arc::clone(&supervisor),
            events,
            Arc::new(TestHandler { finish_immediately }),
            admitted,
            Arc::clone(&instances),
        );
        StreamFixture {
            fixture,
            _directory: directory,
            stream,
            supervisor,
            instances,
        }
    }

    impl StreamFixture {
        /// A `Prepare` this node's catalogs resolve.
        fn prepare_notice(&self, execution_id: [u8; 32]) -> ExecutionNotice {
            ExecutionNotice::Prepare(published(
                execution_id,
                self.fixture.program_id,
                "main",
                vec![
                    (self.fixture.client_keys[0].clone(), 0),
                    (self.fixture.client_keys[1].clone(), 1),
                ],
            ))
        }

        /// The notice that closes a snapshot of `incarnation`.
        fn snapshot_complete(incarnation: [u8; 16]) -> ExecutionNotice {
            ExecutionNotice::SnapshotComplete {
                incarnation: CoordinatorIncarnation::from_bytes(incarnation),
            }
        }

        /// Let the supervisor's tasks run until `execution_id` is no longer
        /// live, so a test can observe a replay of a finished identity.
        async fn settle(&self, execution_id: ExecutionId) {
            for _ in 0..10_000 {
                if !self.supervisor.is_live(execution_id) {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("execution {execution_id} never left the supervisor");
        }
    }

    #[tokio::test]
    async fn a_published_prepare_starts_one_instance_and_a_replay_does_not() {
        let harness = stream_fixture(true);
        let mut snapshot = SnapshotCursor::default();
        let execution_id = ExecutionId::from([0x21; 32]);

        let first = harness
            .stream
            .apply(harness.prepare_notice([0x21; 32]), &mut snapshot);
        assert_eq!(first, NoticeOutcome::Admitted { execution_id });
        assert!(harness.supervisor.is_live(execution_id));

        // While it is still running, the same `Prepare` is left alone rather
        // than refused: a re-subscription republishes the whole snapshot.
        assert_eq!(
            harness
                .stream
                .apply(harness.prepare_notice([0x21; 32]), &mut snapshot),
            NoticeOutcome::AlreadyRunning { execution_id }
        );

        harness.settle(execution_id).await;

        // Once it has finished, the identity is spent. The durable claim is
        // what refuses it, so a crashed node cannot re-run material its peers
        // already consumed.
        assert_eq!(
            harness
                .stream
                .apply(harness.prepare_notice([0x21; 32]), &mut snapshot),
            NoticeOutcome::AlreadyAdmitted { execution_id }
        );
        assert!(!harness.supervisor.is_live(execution_id));
    }

    #[tokio::test]
    async fn a_published_execution_this_node_refuses_starts_nothing() {
        let harness = stream_fixture(true);
        let mut snapshot = SnapshotCursor::default();
        let unknown_program = ExecutionNotice::Prepare(published(
            [0x22; 32],
            [0x99; 32],
            "main",
            vec![
                (harness.fixture.client_keys[0].clone(), 0),
                (harness.fixture.client_keys[1].clone(), 1),
            ],
        ));

        let outcome = harness.stream.apply(unknown_program, &mut snapshot);
        let NoticeOutcome::Refused {
            execution_id,
            error,
        } = outcome
        else {
            panic!("a program this node does not hold must be refused, got {outcome:?}");
        };
        assert_eq!(execution_id, ExecutionId::from([0x22; 32]));
        assert!(
            error.contains("not in the standing startup catalog"),
            "unexpected error: {error}"
        );
        assert!(harness.supervisor.live_executions().is_empty());
    }

    #[tokio::test]
    async fn a_cancel_tears_down_a_live_instance_and_an_unknown_one_is_ordinary() {
        let harness = stream_fixture(false);
        let mut snapshot = SnapshotCursor::default();
        let execution_id = ExecutionId::from([0x23; 32]);
        harness
            .stream
            .apply(harness.prepare_notice([0x23; 32]), &mut snapshot);
        assert!(harness.supervisor.is_live(execution_id));

        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x23; 32]),
                    outcome: ExecutionOutcome::Aborted(AbortReason::OperatorRequest),
                },
                &mut snapshot,
            ),
            NoticeOutcome::Cancelled {
                execution_id,
                reason: AbortReason::OperatorRequest,
            }
        );
        harness.settle(execution_id).await;

        // The coordinator publishes every cancellation to the whole roster,
        // including nodes that never saw the `Prepare`, so this is not an error.
        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x24; 32]),
                    outcome: ExecutionOutcome::Aborted(AbortReason::OperatorRequest),
                },
                &mut snapshot,
            ),
            NoticeOutcome::NotRunning {
                execution_id: ExecutionId::from([0x24; 32])
            }
        );
    }

    #[tokio::test]
    async fn completing_the_snapshot_stops_exactly_the_instances_it_omitted() {
        let harness = stream_fixture(false);

        // Two instances this node is already running, as if from an earlier
        // subscription to the same run of the coordinator that ended before
        // their `Cancel` arrived.
        let mut earlier = SnapshotCursor::default();
        harness
            .stream
            .apply(harness.prepare_notice([0x31; 32]), &mut earlier);
        harness
            .stream
            .apply(harness.prepare_notice([0x32; 32]), &mut earlier);
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([1; 16]), &mut earlier);
        assert_eq!(harness.supervisor.live_executions().len(), 2);

        // A fresh subscription whose snapshot names only the first of them.
        let mut snapshot = SnapshotCursor::default();
        assert_eq!(
            harness
                .stream
                .apply(harness.prepare_notice([0x31; 32]), &mut snapshot),
            NoticeOutcome::AlreadyRunning {
                execution_id: ExecutionId::from([0x31; 32])
            }
        );
        let outcome = harness
            .stream
            .apply(StreamFixture::snapshot_complete([1; 16]), &mut snapshot);
        assert_eq!(
            outcome,
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![ExecutionId::from([0x32; 32])],
                kept: Vec::new(),
                retired: Vec::new(),
            },
            "omission from the snapshot is an order to stop, which is what \
             recovers a Cancel a dropped stream never delivered"
        );

        harness.settle(ExecutionId::from([0x32; 32])).await;
        assert!(
            harness.supervisor.is_live(ExecutionId::from([0x31; 32])),
            "an instance the snapshot named must keep running"
        );
    }

    #[tokio::test]
    async fn a_prepare_after_the_snapshot_survives_the_reconciliation() {
        let harness = stream_fixture(false);
        let mut snapshot = SnapshotCursor::default();
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([1; 16]), &mut snapshot);

        // Live traffic, after the snapshot closed. A second `SnapshotComplete`
        // must not retroactively stop it.
        harness
            .stream
            .apply(harness.prepare_notice([0x41; 32]), &mut snapshot);
        assert_eq!(
            harness
                .stream
                .apply(StreamFixture::snapshot_complete([1; 16]), &mut snapshot),
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![],
                kept: vec![],
                retired: vec![],
            }
        );
        assert!(harness.supervisor.is_live(ExecutionId::from([0x41; 32])));
    }

    #[tokio::test]
    async fn a_restarted_coordinator_stops_nothing_it_never_admitted() {
        let harness = stream_fixture(false);

        // Two instances admitted by one run of the coordinator.
        let mut first = SnapshotCursor::default();
        harness
            .stream
            .apply(harness.prepare_notice([0x51; 32]), &mut first);
        harness
            .stream
            .apply(harness.prepare_notice([0x52; 32]), &mut first);
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([1; 16]), &mut first);
        assert_eq!(harness.supervisor.live_executions().len(), 2);

        // The coordinator is restarted. Its executions were in memory, so its
        // snapshot names nothing — and it is not a statement about work it
        // never admitted.
        let mut restarted = SnapshotCursor::default();
        assert_eq!(
            harness
                .stream
                .apply(StreamFixture::snapshot_complete([2; 16]), &mut restarted),
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![],
                kept: vec![ExecutionId::from([0x51; 32]), ExecutionId::from([0x52; 32]),],
                retired: vec![],
            },
            "a restarted coordinator's empty snapshot must not abort the roster's work"
        );
        assert_eq!(harness.supervisor.live_executions().len(), 2);

        // And it must stay that way. The link under a subscription ends
        // routinely, so the node resubscribes to the *same* restarted
        // coordinator and reconciles again; an incarnation recorded only
        // per subscription would stop both instances on this second snapshot.
        let mut again = SnapshotCursor::default();
        assert_eq!(
            harness
                .stream
                .apply(StreamFixture::snapshot_complete([2; 16]), &mut again),
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![],
                kept: vec![ExecutionId::from([0x51; 32]), ExecutionId::from([0x52; 32]),],
                retired: vec![],
            }
        );
        assert_eq!(harness.supervisor.live_executions().len(), 2);

        // What the restarted coordinator does admit, it can still reconcile:
        // one execution of its own, dropped from its next snapshot, stops.
        harness
            .stream
            .apply(harness.prepare_notice([0x53; 32]), &mut again);
        assert!(harness.supervisor.is_live(ExecutionId::from([0x53; 32])));
        let mut later = SnapshotCursor::default();
        assert_eq!(
            harness
                .stream
                .apply(StreamFixture::snapshot_complete([2; 16]), &mut later),
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![ExecutionId::from([0x53; 32])],
                kept: vec![ExecutionId::from([0x51; 32]), ExecutionId::from([0x52; 32]),],
                retired: vec![],
            }
        );
        harness.settle(ExecutionId::from([0x53; 32])).await;
    }

    #[tokio::test]
    async fn a_cancel_from_a_restarted_coordinator_still_stops_an_older_instance() {
        let harness = stream_fixture(false);
        let execution_id = ExecutionId::from([0x61; 32]);
        let mut first = SnapshotCursor::default();
        harness
            .stream
            .apply(harness.prepare_notice([0x61; 32]), &mut first);
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([1; 16]), &mut first);
        assert!(harness.supervisor.is_live(execution_id));

        // Scoping reconciliation by incarnation does not make an older
        // instance unstoppable: a `Cancel` names the identity, so it needs no
        // incarnation to act on.
        let mut restarted = SnapshotCursor::default();
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([2; 16]), &mut restarted);
        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x61; 32]),
                    outcome: ExecutionOutcome::Aborted(AbortReason::OperatorRequest),
                },
                &mut restarted,
            ),
            NoticeOutcome::Cancelled {
                execution_id,
                reason: AbortReason::OperatorRequest,
            }
        );
        harness.settle(execution_id).await;
    }

    /// The coordinator publishes the removal of a *finished* execution as a
    /// cancellation too. That notice is caused by the parties' own retirement
    /// acknowledgements, so it is not an order to stop: the instance keeps its
    /// own ending, and a node that tore it down would report the successful run
    /// of whichever party finished last as cancelled.
    #[tokio::test]
    async fn a_finished_cancel_retires_the_identity_without_stopping_the_instance() {
        let harness = stream_fixture(false);
        let mut snapshot = SnapshotCursor::default();
        let execution_id = ExecutionId::from([0x71; 32]);
        harness
            .stream
            .apply(harness.prepare_notice([0x71; 32]), &mut snapshot);
        assert!(harness.supervisor.is_live(execution_id));

        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x71; 32]),
                    outcome: ExecutionOutcome::Finished,
                },
                &mut snapshot,
            ),
            NoticeOutcome::Retired {
                execution_id,
                still_running: true,
            }
        );
        // Untouched: no cancellation was requested, so the instance is still
        // live and reaches its own terminal event. This instance runs until it
        // is cancelled, so its still being live is evidence that the notice
        // cancelled nothing.
        assert!(harness.supervisor.is_live(execution_id));

        // The same notice for an execution this node has already finished, or
        // never ran, is ordinary.
        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x72; 32]),
                    outcome: ExecutionOutcome::Finished,
                },
                &mut snapshot,
            ),
            NoticeOutcome::Retired {
                execution_id: ExecutionId::from([0x72; 32]),
                still_running: false,
            }
        );

        harness.supervisor.shutdown();
        harness.settle(execution_id).await;
    }

    /// The direction the rule must not give up: an execution the coordinator
    /// really has stopped serving without ever saying it finished is still
    /// torn down by the omission, even while a retired instance of the same
    /// run is kept beside it. This is the dropped-`Cancel` recovery, and
    /// remembering retirements must not weaken it.
    #[tokio::test]
    async fn a_snapshot_omitting_an_execution_no_retirement_explains_still_stops_it() {
        let harness = stream_fixture(false);
        let retired = ExecutionId::from([0x81; 32]);
        let aborted = ExecutionId::from([0x82; 32]);

        let mut first = SnapshotCursor::default();
        harness
            .stream
            .apply(harness.prepare_notice([0x81; 32]), &mut first);
        harness
            .stream
            .apply(harness.prepare_notice([0x82; 32]), &mut first);
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([7; 16]), &mut first);
        assert_eq!(harness.supervisor.live_executions().len(), 2);

        // Only one of the two is retired. The other's `Cancel` is the one the
        // saturated connection dropped, so nothing here says it ended well.
        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x81; 32]),
                    outcome: ExecutionOutcome::Finished,
                },
                &mut first,
            ),
            NoticeOutcome::Retired {
                execution_id: retired,
                still_running: true,
            }
        );

        // The same coordinator, a fresh subscription, and a snapshot that
        // names neither of them.
        let mut reconnected = SnapshotCursor::default();
        assert_eq!(
            harness
                .stream
                .apply(StreamFixture::snapshot_complete([7; 16]), &mut reconnected),
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![aborted],
                kept: vec![],
                retired: vec![retired],
            },
            "an omission no retirement explains is still an order to stop"
        );
        harness.settle(aborted).await;
        assert!(
            harness.supervisor.is_live(retired),
            "the retired instance must still be running"
        );

        harness.supervisor.shutdown();
        harness.settle(retired).await;
    }

    /// The direction a snapshot must not decide. The coordinator forgets a
    /// *finished* execution — at unanimity, at retention expiry, or because
    /// capacity pressure evicted it at the `n - t` quorum reached without this
    /// party — and every snapshot it takes afterwards omits it. The connection
    /// under a subscription ends routinely, so the omission reaches this node
    /// on an ordinary reconnection to the *same* coordinator, and it must not
    /// be what kills an instance that is finishing well: a retirement is a
    /// fact about the execution rather than about one subscription, and the
    /// supervisor would report whatever the interrupted work produced first as
    /// cancelled.
    #[tokio::test]
    async fn a_retired_instance_survives_every_later_snapshot_of_the_same_coordinator() {
        let harness = stream_fixture(false);
        let execution_id = ExecutionId::from([0x91; 32]);
        let mut first = SnapshotCursor::default();
        harness
            .stream
            .apply(harness.prepare_notice([0x91; 32]), &mut first);
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([9; 16]), &mut first);
        harness.stream.apply(
            ExecutionNotice::Cancel {
                execution_id: CoordinatorExecutionId::from_bytes([0x91; 32]),
                outcome: ExecutionOutcome::Finished,
            },
            &mut first,
        );

        for _ in 0..3 {
            let mut reconnected = SnapshotCursor::default();
            assert_eq!(
                harness
                    .stream
                    .apply(StreamFixture::snapshot_complete([9; 16]), &mut reconnected),
                NoticeOutcome::SnapshotReconciled {
                    stopped: vec![],
                    kept: vec![],
                    retired: vec![execution_id],
                }
            );
            assert!(harness.supervisor.is_live(execution_id));
        }

        // An abort by name still reaches it: a retired identity is not an
        // unstoppable one, it is only one the snapshot cannot speak against.
        assert_eq!(
            harness.stream.apply(
                ExecutionNotice::Cancel {
                    execution_id: CoordinatorExecutionId::from_bytes([0x91; 32]),
                    outcome: ExecutionOutcome::Aborted(AbortReason::OperatorRequest),
                },
                &mut first,
            ),
            NoticeOutcome::Cancelled {
                execution_id,
                reason: AbortReason::OperatorRequest,
            }
        );
        harness.settle(execution_id).await;
    }

    /// The omission no notice ever explains: the node's own retirement
    /// acknowledgement.
    ///
    /// The coordinator's per-node snapshot predicate is "not acknowledged by
    /// this node", and the acknowledgement is counted the moment it arrives —
    /// long before the quorum completes and anything is published — while this
    /// node sends it from inside execution cleanup, which the supervisor runs
    /// with the instance still live. A resubscription inside that window gets
    /// a snapshot omitting an execution whose work has already finished, and
    /// cancelling it there is what makes a successful run report `Cancelled`.
    ///
    /// So cleanup goes through [`InstanceLedger::acknowledge_retirement`],
    /// which records the retirement before the acknowledgement it wraps can be
    /// sent. This drives that method with the resubscription *as* the
    /// acknowledgement, which is the window the ordering exists for: the
    /// assertion below is reached only while the coordinator would be learning
    /// of the retirement, so it fails if the record is written afterwards and
    /// fails if it is not written at all.
    #[tokio::test]
    async fn an_instance_this_node_has_acknowledged_survives_the_snapshot_that_omission_causes() {
        let harness = stream_fixture(false);
        let acknowledged = ExecutionId::from([0xa1; 32]);
        let aborted = ExecutionId::from([0xa2; 32]);

        let mut first = SnapshotCursor::default();
        harness
            .stream
            .apply(harness.prepare_notice([0xa1; 32]), &mut first);
        harness
            .stream
            .apply(harness.prepare_notice([0xa2; 32]), &mut first);
        harness
            .stream
            .apply(StreamFixture::snapshot_complete([0xb; 16]), &mut first);
        assert_eq!(harness.supervisor.live_executions().len(), 2);

        // The cleanup step itself, with the reconnection standing in for the
        // acknowledgement: the coordinator's next snapshot of the same run
        // omits the acknowledged execution — no notice is involved, because
        // for every party but the one that completes the quorum nothing is
        // published here — and omits the other one because its `Cancel` was
        // dropped.
        let verdict = harness
            .instances
            .acknowledge_retirement(acknowledged, || async {
                let mut reconnected = SnapshotCursor::default();
                harness.stream.apply(
                    StreamFixture::snapshot_complete([0xb; 16]),
                    &mut reconnected,
                )
            })
            .await;
        assert_eq!(
            verdict,
            NoticeOutcome::SnapshotReconciled {
                stopped: vec![aborted],
                kept: vec![],
                retired: vec![acknowledged],
            },
            "this node's own acknowledgement explains the omission it caused, \
             and explains no other"
        );
        harness.settle(aborted).await;
        assert!(
            harness.supervisor.is_live(acknowledged),
            "an instance in cleanup must reach its own terminal event"
        );

        harness.supervisor.shutdown();
        harness.settle(acknowledged).await;
    }
}
