use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use stoffel_mpc_coordinator_off_chain::node_rpc::NodeRPCServer as OffChainNodeRPCServer;
use stoffel_mpc_coordinator_off_chain::{
    CoordinatorLink, ExecutionSummary, OffChainCoordinatorClient,
};
use stoffel_mpc_coordinator_shared::{
    AssociationRequest, ClientAdmissionSet, ClientIndex, Coordinator, CoordinatorError,
    ExecutionId, NodeRPCError, NodeRoster, OutputRights, PinError, RosterDigest, Round,
    SignedInvitation, SpkiDer,
};
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::curve::{field_from_i64, field_to_i64, SupportedMpcField};
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
use stoffel_vm::net::mesh::{
    epoch_store_path, BarrierTag, DigestBarrier, DigestBarrierTag, EpochStore, JoinRequest,
    MeshBarrier, MeshError, MeshJoin, MeshRouter, PexLimits, Roster, RosterError, SeedHints,
    SessionJoin,
};
use stoffel_vm::net::mpc_engine::{DurableIdentityDigest, MpcEngine, MpcSessionTopology};
use stoffel_vm::net::program_id_from_bytes;
use stoffel_vm::net::SessionExecutionId;
use stoffel_vm::net::{
    honeybadger_node_opts_with_truncation, honeybadger_protocol_timeout, spawn_receive_loops_split,
};
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm::storage::preproc::LmdbPreprocStore;
use stoffel_vm::storage::RedbLocalStorage;
use stoffel_vm_runner::admissions::{
    admission_agreement_digest, check_execution_summary, inputs_agreement_digest,
    inputs_by_admission, outputs_by_admission, reservations_matching_admissions,
    submissions_matching_admissions, MaskedInputMismatch, OutputRightsViolation,
    ReservationMismatch, SummaryExpectations, SummaryMismatch,
};
use stoffel_vm_runner::coordinator_client::{
    CoordinatorClientConfig, CoordinatorClientError, CoordinatorEndpoint,
};
use stoffel_vm_types::compiled_binary::{
    BinaryError, ClientIoManifest, CompiledBinary, MpcCurve, MPC_BACKEND_MANIFEST_FORMAT_VERSION,
    MPC_CURVE_MANIFEST_FORMAT_VERSION,
};
use stoffel_vm_types::core_types::{ShareType, TableRef, Value};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
use stoffelnet::network_utils::ClientId;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
type HbCoordinatorShare<F> = RobustShare<F>;

fn manifest_client_input_types(
    manifest: &ClientIoManifest,
) -> std::collections::BTreeMap<usize, Vec<ShareType>> {
    manifest
        .clients
        .iter()
        .filter_map(|schema| {
            usize::try_from(schema.client_slot)
                .ok()
                .map(|slot| (slot, schema.inputs.clone()))
        })
        .collect()
}

/// Planned preprocessing material counts for one program run.
struct PlannedPreprocessing {
    n_triples: usize,
    n_random: usize,
    n_prandbit: usize,
    n_prandint: usize,
}

fn read_trimmed_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn current_process_rss_bytes() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let value = line.strip_prefix("VmRSS:")?;
                let kb = value.split_whitespace().next()?.parse::<u64>().ok()?;
                Some(kb.saturating_mul(1024))
            })
        })
}

fn current_cgroup_memory_bytes() -> Option<u64> {
    read_trimmed_u64("/sys/fs/cgroup/memory.current")
        .or_else(|| read_trimmed_u64("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
}

/// Round a demand up to a coarse band for privacy: the observable preprocessing
/// volume reveals only which band the program's demand falls in, not its exact
/// operation count. We band to **eighths of an octave** (the next multiple of
/// 1/8 of the demand's power-of-two floor) rather than to the next full power of
/// two. Full-octave banding can nearly *double* the demand, which both wastes
/// preprocessing and — critically — can push a program that comfortably fits the
/// MPC backend's per-session generation capacity over that ceiling (e.g. a
/// 166k-triple program banded to 262k exceeds HoneyBadger's ~196k triple limit,
/// failing with a spurious `LimitError`). Eighth-octave banding over-provisions
/// by at most ~12.5% while still hiding the exact count to within a size band.
fn band_pow2(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    // Largest power of two <= n (the octave floor).
    let floor_pow2 = if n.is_power_of_two() {
        n
    } else {
        n.next_power_of_two() >> 1
    };
    // Round up to the next multiple of an eighth of that octave.
    let granularity = (floor_pow2 >> 3).max(1);
    n.div_ceil(granularity).saturating_mul(granularity)
}

/// Turn the compiler's static preprocessing-demand estimate into concrete
/// material counts to generate up front. Each count is rounded up to a power of
/// two for privacy (see `band_pow2`); `dynamic` programs (data-dependent loops,
/// recursion, runtime-sized batches) get an extra octave of headroom because the
/// static estimate may undercount them. The triple count absorbs the dependency
/// that prandbit generation itself consumes a triple per bit. The random count
/// only covers program-visible random material; HoneyBadger generates the
/// random shares needed to build triples inside `run_preprocessing`.
/// `STOFFEL_PREPROCESSING_TRIPLES` / `STOFFEL_PREPROCESSING_PRANDBITS` override
/// the estimate for unusually loop-heavy programs.
fn plan_preprocessing(
    demand: &stoffel_vm_types::compiled_binary::PreprocessingDemand,
    threshold: usize,
    n_client_random: usize,
) -> PlannedPreprocessing {
    let env_u64 = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
    };

    // Dynamic programs may undercount, so give them an extra octave before banding.
    let with_headroom = |n: u64| -> u64 {
        if demand.dynamic {
            n.saturating_mul(2)
        } else {
            n
        }
    };

    let prandbits = env_u64("STOFFEL_PREPROCESSING_PRANDBITS")
        .map(band_pow2)
        .unwrap_or_else(|| band_pow2(with_headroom(demand.prandbits)));
    let prandints = band_pow2(with_headroom(demand.prandints));
    let direct_randoms = band_pow2(with_headroom(demand.randoms));

    let direct_triples = env_u64("STOFFEL_PREPROCESSING_TRIPLES")
        .map(band_pow2)
        .unwrap_or_else(|| band_pow2(with_headroom(demand.triples)));

    // prandbit generation consumes one triple + one random per bit.
    let mut triple_target = direct_triples.saturating_add(prandbits);
    if triple_target > 0 {
        // Floor to the protocol's minimum triple batch so tiny programs still run.
        triple_target = triple_target.max(2 * threshold as u64 + 1);
    }
    let n_triples = band_pow2(triple_target);
    // HoneyBadger adds and consumes two random shares per triple internally.
    // `n_random` is the pool left for direct program use and prandbit generation
    // after triples have been built; adding `2 * n_triples` here makes the
    // backend generate an extra full random pool.
    let n_random = band_pow2(
        2u64.saturating_add(direct_randoms)
            .saturating_add(prandbits)
            .saturating_add(n_client_random as u64),
    );

    PlannedPreprocessing {
        n_triples: n_triples as usize,
        n_random: n_random as usize,
        n_prandbit: prandbits as usize,
        n_prandint: prandints as usize,
    }
}

type HbOffChainCoordinator<F> = OffChainCoordinatorClient<F, HbCoordinatorShare<F>>;
type AvssCoordinatorShare<F, G> = FeldmanShamirShare<F, G>;
type AvssOffChainCoordinator<F, G> = OffChainCoordinatorClient<F, AvssCoordinatorShare<F, G>>;
/// The reserved all-zero `ExecutionId`. Coordinator `0.2.0` rejects it on every
/// path that takes one, which is exactly why it is what a coordinator-less run
/// carries: reaching a coordinator RPC without an execution fails loudly.
const UNUSED_EXECUTION_ID: ExecutionId = ExecutionId::from_bytes([0u8; 32]);

/// Which program invocation this run belongs to.
///
/// Coordinator `0.2.0` keys every RPC on an `ExecutionId`: rounds, reserved mask
/// indices, masked inputs and output shares all live under one. `0.1.0`'s single
/// implicit session — torn down by `reset_coord` — has no successor, so a
/// coordinator-bearing run must name the invocation it joins, and a run with no
/// coordinator has nothing to name.
///
/// The coordinator-less answer is [`UNUSED_EXECUTION_ID`] rather than an
/// `Option` the callers would each have to unwrap: every read of the result sits
/// inside a branch that already matched on `--off-chain-coord`, and the reserved
/// all-zero value means a future bug that does reach a coordinator RPC without
/// one is rejected there instead of silently joining somebody else's execution.
fn resolve_coord_execution_id(
    has_coordinator: bool,
    execution_id: Option<ExecutionId>,
) -> Result<ExecutionId, String> {
    match (has_coordinator, execution_id) {
        (true, Some(id)) => Ok(id),
        (true, None) => Err(
            "--off-chain-coord requires --execution-id <64 hex characters>. Every party \
             and client of one invocation must pass the same value, and a later \
             invocation must pass a different one."
                .to_owned(),
        ),
        (false, Some(_)) => Err(
            "--execution-id is only meaningful with --off-chain-coord; a mesh session's \
             namespace comes from its agreed instance_id, not from the coordinator."
                .to_owned(),
        ),
        (false, None) => Ok(UNUSED_EXECUTION_ID),
    }
}

/// The coordinator certificate this process pins (`--coord-cert`).
///
/// Coordinator `0.3.0` has no connection without a pin
/// (`docs/design/bootnode-elimination.md` §9.A): a connection that accepted any
/// server would let whoever answers at the coordinator's address serve rounds,
/// admissions and — once nodes take their roster from it — membership. The
/// path is kept beside the derived key so every refusal can name the file.
#[derive(Clone, Debug)]
struct CoordinatorPin {
    path: String,
    spki: SpkiDer,
}

/// Why a `--coord-cert` value cannot be pinned.
#[derive(Debug)]
enum CoordinatorPinError {
    Unreadable {
        path: String,
        reason: std::io::Error,
    },
    Unusable {
        path: String,
        reason: PinError,
    },
}

impl std::fmt::Display for CoordinatorPinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, reason } => {
                write!(f, "cannot read --coord-cert {path}: {reason}")
            }
            Self::Unusable { path, reason } => write!(
                f,
                "--coord-cert {path} is not a usable DER X.509 certificate: {reason}"
            ),
        }
    }
}

impl CoordinatorPin {
    fn load(path: &str) -> Result<Self, CoordinatorPinError> {
        let der = fs::read(path).map_err(|reason| CoordinatorPinError::Unreadable {
            path: path.to_owned(),
            reason,
        })?;
        let spki = SpkiDer::from_certificate_der(&der).map_err(|reason| {
            CoordinatorPinError::Unusable {
                path: path.to_owned(),
                reason,
            }
        })?;
        Ok(Self {
            path: path.to_owned(),
            spki,
        })
    }
}

/// `--coord-cert` is required exactly where `--off-chain-coord` is given.
fn resolve_coordinator_pin(
    has_coordinator: bool,
    coord_cert_path: Option<&str>,
) -> Result<Option<CoordinatorPin>, String> {
    match (has_coordinator, coord_cert_path) {
        (true, Some(path)) => CoordinatorPin::load(path)
            .map(Some)
            .map_err(|error| error.to_string()),
        (true, None) => Err(
            "--off-chain-coord requires --coord-cert <path>. The coordinator is the roster \
             authority, and a connection that does not pin its certificate accepts any server."
                .to_owned(),
        ),
        (false, Some(_)) => Err(
            "--coord-cert is only meaningful with --off-chain-coord; it pins the coordinator's \
             certificate."
                .to_owned(),
        ),
        (false, None) => Ok(None),
    }
}

/// `--expect-roster-digest`, `--expect-n-parties` and `--expect-threshold`
/// (`docs/design/bootnode-elimination.md` §9.D.2).
///
/// Defense in depth, not a second roster authority: none of them carries a
/// certificate, so they can only refuse what the coordinator served, never
/// supply membership. The digest is what lets an operator who knows the intended
/// node set detect a coordinator that serves this process a different one; the
/// two counts keep a caller's configured `parties` and `threshold` meaningful.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RosterExpectations {
    digest: Option<RosterDigest>,
    n_parties: Option<u64>,
    threshold: Option<u64>,
}

/// Which roster size a `--expect-*` flag names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RosterSizeFlag {
    NParties,
    Threshold,
}

impl RosterSizeFlag {
    fn flag(self) -> &'static str {
        match self {
            Self::NParties => "--expect-n-parties",
            Self::Threshold => "--expect-threshold",
        }
    }
}

impl std::fmt::Display for RosterSizeFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.flag())
    }
}

/// The coordinator served a roster of another size than `--expect-n-parties` or
/// `--expect-threshold` names (exit 2, §9.D.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "the coordinator serves a roster of n = {n}, t = {t}, not the expected {flag} {expected}; \
     refusing to install it."
)]
struct UnexpectedRosterSize {
    n: u64,
    t: u64,
    flag: RosterSizeFlag,
    expected: u64,
}

impl RosterExpectations {
    /// The first `--expect-*` flag this process was given, for the refusal
    /// without a coordinator.
    fn first_flag(&self) -> Option<&'static str> {
        if self.digest.is_some() {
            Some("--expect-roster-digest")
        } else if self.n_parties.is_some() {
            Some(RosterSizeFlag::NParties.flag())
        } else if self.threshold.is_some() {
            Some(RosterSizeFlag::Threshold.flag())
        } else {
            None
        }
    }

    /// §9.D.1 step 3, outside `CoordinatorLink::connect`: the served `n` and `t`
    /// against `--expect-n-parties` and `--expect-threshold`. The digest is
    /// compared inside `connect`.
    fn check_size(&self, roster: &NodeRoster) -> Result<(), UnexpectedRosterSize> {
        let (n, t) = (roster.n(), roster.t());
        for (flag, expected, served) in [
            (RosterSizeFlag::NParties, self.n_parties, n),
            (RosterSizeFlag::Threshold, self.threshold, t),
        ] {
            if let Some(expected) = expected {
                if expected != served {
                    return Err(UnexpectedRosterSize {
                        n,
                        t,
                        flag,
                        expected,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Parses `--expect-n-parties` / `--expect-threshold`.
fn parse_expected_roster_size(flag: RosterSizeFlag, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|reason| format!("{flag} must be a non-negative integer: {reason}"))
}

/// Parses `--expect-roster-digest`.
fn parse_expected_roster_digest(value: &str) -> Result<RosterDigest, String> {
    RosterDigest::from_str(value.trim()).map_err(|error| format!("--expect-roster-digest: {error}"))
}

/// Exits for a coordinator connection that failed, naming a pin mismatch as the
/// wrong server it is rather than as a missing one (§9.D.3): 13 for a transport
/// failure, a pin mismatch or a served roster that fails verification, 2 for a
/// served roster that is not the `--expect-roster-digest` one.
fn exit_coordinator_connect_failure(
    coord_addr: &(String, u16),
    pin: &CoordinatorPin,
    error: CoordinatorError,
) -> ! {
    match error {
        CoordinatorError::ServerPinMismatch { .. } => eprintln!(
            "Error: the coordinator at {}:{} presented a key that --coord-cert {} does not pin. \
             Refusing to fetch a roster from it.",
            coord_addr.0, coord_addr.1, pin.path
        ),
        CoordinatorError::Roster(error) => eprintln!(
            "Error: the coordinator at {}:{} served a node roster that fails verification: {error}",
            coord_addr.0, coord_addr.1
        ),
        CoordinatorError::UnexpectedRosterDigest { served, expected } => {
            eprintln!(
                "Error: the coordinator serves roster digest {served}, not the \
                 --expect-roster-digest {expected}; refusing to install it."
            );
            exit(2);
        }
        other => eprintln!(
            "Error: failed to connect to the off-chain coordinator at {}:{}: {other}",
            coord_addr.0, coord_addr.1
        ),
    }
    exit(13);
}

/// This node's own transport identity: `--cert` (with the path, so every
/// refusal can name the file) and `--key`.
struct NodeIdentity<'a> {
    cert_path: &'a str,
    cert_der: &'a [u8],
    key_der: &'a [u8],
}

/// Design doc §9.D.1 steps 2-5: open the pinned coordinator link, which fetches
/// and verifies the node roster exactly once; check the served size against
/// `--expect-*`; check this node is a member; and build the VM [`Roster`] from
/// the served certificates, which recomputes the §9.B digest and refuses a
/// served one that differs. Nothing re-fetches the roster for the life of the
/// process: the returned link becomes the round driver (§9.D.1 step 10).
///
/// Runs before any socket is bound, so every refusal names the coordinator's
/// roster rather than surfacing as a transport error inside the join. Exits
/// with the §9.D.3 message and code on every refusal.
async fn fetch_node_roster(
    coord_addr: &(String, u16),
    pin: &CoordinatorPin,
    expectations: RosterExpectations,
    identity: NodeIdentity<'_>,
) -> (CoordinatorLink, Roster) {
    let own_spki = SpkiDer::from_certificate_der(identity.cert_der).unwrap_or_else(|reason| {
        eprintln!(
            "Error: --cert {} is not a usable DER X.509 certificate: {reason}",
            identity.cert_path
        );
        exit(2);
    });
    let link = CoordinatorLink::connect(
        &coord_addr.0,
        coord_addr.1,
        &pin.spki,
        expectations.digest,
        identity.cert_der.to_vec(),
        identity.key_der.to_vec(),
    )
    .await
    .unwrap_or_else(|error| exit_coordinator_connect_failure(coord_addr, pin, error));
    let served = link.node_roster();

    if let Err(unexpected) = expectations.check_size(served) {
        eprintln!("Error: {unexpected}");
        exit(2);
    }
    if served.position_of(&own_spki).is_none() {
        eprintln!(
            "Error: this node's certificate (--cert {}) is not one of the {} nodes in the \
             coordinator's roster (digest {}). A node cannot join a session it is not a \
             member of.",
            identity.cert_path,
            served.n(),
            hex::encode(&served.digest().as_bytes()[..8])
        );
        exit(2);
    }

    let certificates: Vec<&[u8]> = served
        .node_certificates()
        .iter()
        .map(|certificate| certificate.as_bytes())
        .collect();
    let roster =
        match Roster::from_coordinator(&certificates, served.t(), *served.digest().as_bytes()) {
            Ok(roster) => roster,
            Err(error @ RosterError::DigestMismatch { .. }) => {
                eprintln!("Error: {error}; refusing to install it.");
                exit(2);
            }
            Err(error) => {
                eprintln!(
                    "Error: the coordinator at {}:{} served a node roster that fails \
                     verification: {error}",
                    coord_addr.0, coord_addr.1
                );
                exit(13);
            }
        };
    eprintln!(
        "[roster] the coordinator at {}:{} serves {} nodes (n={}, t={}, digest={}); fetched once",
        coord_addr.0,
        coord_addr.1,
        roster.nodes().len(),
        roster.n(),
        roster.t(),
        hex::encode(roster.digest())
    );
    (link, roster)
}

/// Both agreement barriers of one coordinated execution
/// (`docs/design/bootnode-elimination.md` §9.D.6).
///
/// Created as soon as the join has agreed the `instance_id`, before any receive loop is
/// spawned, so a peer's announcement that arrives before this node computed its own digest
/// is stored rather than handed to the MPC engine.
#[derive(Clone, Debug)]
struct DigestBarriers {
    admissions: Arc<DigestBarrier>,
    inputs: Arc<DigestBarrier>,
}

impl DigestBarriers {
    fn new(instance_id: u64, n: usize, my_id: usize) -> Self {
        Self {
            admissions: Arc::new(DigestBarrier::new(
                DigestBarrierTag::AdmissionsAgreed,
                instance_id,
                n,
                my_id,
            )),
            inputs: Arc::new(DigestBarrier::new(
                DigestBarrierTag::InputsAgreed,
                instance_id,
                n,
                my_id,
            )),
        }
    }

    /// Receive-loop half: `true` when `payload` is either barrier's frame, which the loop
    /// must drop.
    fn record(&self, sender: usize, payload: &[u8]) -> bool {
        self.admissions.record(sender, payload) || self.inputs.record(sender, payload)
    }
}

/// How long a node waits for every peer to announce an agreement digest. Every node reaches
/// each barrier at the same protocol point, a coordinator broadcast apart.
fn agreement_barrier_timeout() -> Duration {
    session_registration_timeout()
}

/// Why a coordinated party stopped (§9.D.7). Exit 4 for an execution or output-rights error,
/// 13 for everything else (§9.D.3).
#[derive(Debug, thiserror::Error)]
enum CoordinatedRunError {
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
    #[error(transparent)]
    Summary(#[from] SummaryMismatch),
    #[error("{0}; refusing to release mask shares.")]
    Reservation(#[from] ReservationMismatch),
    #[error(transparent)]
    MaskedInput(#[from] MaskedInputMismatch),
    #[error("{}", agreement_message(*execution_id, source))]
    Agreement {
        execution_id: ExecutionId,
        source: MeshError,
    },
    #[error("the node RPC listener refused the admitted reservations: {0}")]
    NodeRpc(NodeRPCError),
    #[error("execution {execution_id} registers {mask_count} client inputs, more than this node can index")]
    MaskCountUnindexable {
        execution_id: ExecutionId,
        mask_count: u64,
    },
    #[error(
        "execution {execution_id} registers {mask_count} client inputs, and coordinated client \
         inputs on HoneyBadger are implemented only for BLS12-381, not {curve}"
    )]
    UnsupportedInputCurve {
        execution_id: ExecutionId,
        mask_count: u64,
        curve: &'static str,
    },
    #[error("{0}")]
    Setup(String),
    #[error("Execution error in '{entry}': {reason}")]
    Execution { entry: String, reason: String },
    #[error("Execution error in '{entry}': {violation}")]
    OutputRights {
        entry: String,
        violation: OutputRightsViolation,
    },
}

fn agreement_message(execution_id: ExecutionId, error: &MeshError) -> String {
    match error {
        MeshError::AdmissionDivergence { party_id } => format!(
            "party {party_id} agreed different client admissions for execution {execution_id}; \
             refusing to release mask shares."
        ),
        MeshError::InputDivergence { party_id } => format!(
            "party {party_id} received different masked inputs for execution {execution_id}; \
             refusing to use any of them."
        ),
        other => format!("execution {execution_id}: {other}"),
    }
}

impl CoordinatedRunError {
    fn agreement(execution_id: ExecutionId) -> impl FnOnce(MeshError) -> Self {
        move |source| Self::Agreement {
            execution_id,
            source,
        }
    }

    fn exit_code(&self) -> i32 {
        match self {
            Self::Execution { .. } | Self::OutputRights { .. } => 4,
            _ => 13,
        }
    }

    /// Prints the §9.D.3 message and exits with its code.
    fn exit(self) -> ! {
        let code = self.exit_code();
        if code == 4 {
            eprintln!("{self}");
        } else {
            eprintln!("Error: {self}");
        }
        exit(code);
    }
}

/// §9.D.7 step 1: reads the execution summary and checks it against what this node loaded,
/// before any preprocessing.
async fn checked_execution_summary<F, S>(
    coord: &OffChainCoordinatorClient<F, S>,
    expectations: &SummaryExpectations<'_>,
) -> Result<ExecutionSummary, CoordinatedRunError>
where
    F: ark_ff::FftField,
    S: stoffel_mpc_coordinator_shared::ShareBound<F>,
{
    let summary = coord.get_execution_summary().await?;
    check_execution_summary::<F, S>(&summary, expectations)?;
    Ok(summary)
}

/// The number of client input masks `summary` registers, as an index this node can use.
fn mask_count_of(summary: &ExecutionSummary) -> Result<usize, CoordinatedRunError> {
    let mask_count = summary.client_slots.n_inputs();
    usize::try_from(mask_count).map_err(|_| CoordinatedRunError::MaskCountUnindexable {
        execution_id: summary.execution_id,
        mask_count,
    })
}

/// §9.D.7 step 6: the frozen admission set, agreed with every other node of the mesh.
async fn agree_client_admissions<F, S>(
    coord: &mut OffChainCoordinatorClient<F, S>,
    summary: &ExecutionSummary,
    barriers: &DigestBarriers,
    net: &QuicNetworkManager,
) -> Result<ClientAdmissionSet, CoordinatedRunError>
where
    F: ark_ff::FftField,
    S: stoffel_mpc_coordinator_shared::ShareBound<F>,
{
    let set = coord.get_client_admissions().await?;
    barriers
        .admissions
        .wait(
            net,
            admission_agreement_digest(summary, &set),
            agreement_barrier_timeout(),
        )
        .await
        .map_err(CoordinatedRunError::agreement(summary.execution_id))?;
    Ok(set)
}

/// §9.D.7 steps 2–10 for a registration with inputs: provisions `mask_shares` at indices
/// `0..mask_count`, reserves, freezes and agrees the admissions, releases exactly the
/// reservations they imply, and returns the agreed set with each slot's unmasked inputs keyed
/// on its agreed `ClientIndex` — once every node agreed the masked inputs.
async fn collect_admitted_client_inputs<F, S>(
    coord: &mut OffChainCoordinatorClient<F, S>,
    node_rpc: &OffChainNodeRPCServer,
    summary: &ExecutionSummary,
    barriers: &DigestBarriers,
    net: &QuicNetworkManager,
    mask_shares: Vec<S>,
) -> Result<
    (
        ClientAdmissionSet,
        std::collections::BTreeMap<ClientIndex, Vec<S>>,
    ),
    CoordinatedRunError,
>
where
    F: ark_ff::FftField,
    S: stoffel_mpc_coordinator_shared::ShareBound<F>,
{
    let execution_id = summary.execution_id;
    let mask_count = mask_shares.len() as u64;
    let indexed: Vec<(u64, &S)> = mask_shares
        .iter()
        .enumerate()
        .map(|(index, share)| (index as u64, share))
        .collect();
    node_rpc
        .add_mask_shares_for_execution(execution_id, &indexed)
        .await
        .map_err(CoordinatedRunError::NodeRpc)?;

    eprintln!("coordinator -> InputMaskReservation");
    coord.reserve_input_masks().await?;
    coord.wait_for_round(Round::InputMaskReservation).await?;
    // The complete reservation map. Nothing is registered until the admissions are frozen and
    // agreed.
    let reserved = coord.wait_for_indices(mask_count).await?;

    eprintln!("coordinator -> InputCollection");
    coord.collect_inputs().await?;
    coord.wait_for_round(Round::InputCollection).await?;
    let set = agree_client_admissions(coord, summary, barriers, net).await?;
    let reservations = reservations_matching_admissions(&set, &reserved)?;
    node_rpc
        .register_admitted_reservations_for_execution(execution_id, reservations)
        .await
        .map_err(CoordinatedRunError::NodeRpc)?;

    eprintln!("waiting for masked client inputs");
    let submissions = coord.wait_for_masked_input_submissions(mask_count).await?;
    submissions_matching_admissions(summary, &set, &submissions)?;
    barriers
        .inputs
        .wait(
            net,
            inputs_agreement_digest(execution_id, &submissions),
            agreement_barrier_timeout(),
        )
        .await
        .map_err(CoordinatedRunError::agreement(execution_id))?;
    let unmasked =
        OffChainCoordinatorClient::<F, S>::unmask_submissions(&submissions, &mask_shares)?;
    let inputs = inputs_by_admission(&set, unmasked);
    eprintln!("masked client inputs agreed and unmasked");
    Ok((set, inputs))
}

/// §9.D.7 steps 12–13: delivers the program's captured client outputs by agreed slot, and
/// takes the execution to `ProgramFinished` whether or not it has outputs, then retires it.
async fn finish_coordinated_execution<F, S>(
    coord: &OffChainCoordinatorClient<F, S>,
    summary: &ExecutionSummary,
    set: &ClientAdmissionSet,
    captured: Vec<(usize, Vec<S>)>,
    entry: &str,
) -> Result<(), CoordinatedRunError>
where
    F: ark_ff::FftField,
    S: stoffel_mpc_coordinator_shared::ShareBound<F>,
{
    let outputs = outputs_by_admission(set, captured).map_err(|violation| {
        CoordinatedRunError::OutputRights {
            entry: entry.to_owned(),
            violation,
        }
    })?;
    // Without output slots the coordinator allows `MPCExecution` -> `ProgramFinished`
    // directly; with any, `OutputDistribution` cannot be skipped even if nothing was sent.
    if summary.client_slots.has_output_slots() {
        coord.send_output().await?;
        coord.wait_for_round(Round::OutputDistribution).await?;
        for (client, shares) in outputs {
            // A client's identity is also the HPKE key its outputs are sealed to (§9.0).
            coord
                .send_output_shares(client.clone(), client, shares)
                .await?;
        }
    }
    coord.finalize().await?;
    coord.wait_for_round(Round::ProgramFinished).await?;
    if let Err(error) = coord.retire_execution().await {
        eprintln!(
            "Warning: failed to retire execution {}: {error}",
            summary.execution_id
        );
    }
    Ok(())
}

/// The VM client roster of a coordinated execution: every registered slot, by `ClientIndex`.
fn coordinated_client_roster(summary: &ExecutionSummary) -> Vec<ClientId> {
    (0..summary.client_slots.capacity() as usize).collect()
}

/// What `stoffel-run --client` was asked to do (`docs/design/bootnode-elimination.md` §9.E.2).
///
/// It names no node and no other client: the nodes come from the coordinator's roster, and
/// this client's slot, input range and output rights from its admission.
struct ClientRunArgs {
    backend: MpcBackendKind,
    curve_config: MpcCurveConfig,
    /// `--inputs`; absent for a client of an output-only slot.
    inputs: Option<String>,
    output_format: CoordinatorOutputFormat,
    coord_addr: (String, u16),
    coordinator_pin: CoordinatorPin,
    roster_expectations: RosterExpectations,
    /// `--expect-program-hash`.
    expected_program_hash: Option<[u8; 32]>,
    /// `--client-slot` and `--invitation`.
    request: AssociationRequest,
    /// `--servers`: node RPC addresses, pinned by the roster.
    server_addrs: Vec<SocketAddr>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    execution_id: ExecutionId,
}

/// How a client prints the outputs it reconstructed.
#[derive(Clone, Copy, Debug)]
enum ClientOutputStyle {
    /// HoneyBadger: `outputs: [..]`, each a signed integer or fixed-point value.
    Values(CoordinatorOutputFormat),
    /// AVSS: `Client output: field[n] 0x..`, the concatenated field elements.
    FieldHex(MpcCurveConfig),
}

/// §9.E.1 for one client, over share type `S`: the pinned coordinator and roster (step 1,
/// with `--expect-n-parties` / `--expect-threshold`), then
/// [`CoordinatorClientConfig::run`]. Exits with the §9.D.3 / §9.E.1 message and code on every
/// refusal.
async fn run_coordinator_client_for<F, S>(args: ClientRunArgs, style: ClientOutputStyle)
where
    F: SupportedMpcField,
    S: stoffel_mpc_coordinator_shared::ShareBound<F, ValueType = F>,
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    let inputs = args
        .inputs
        .as_deref()
        .map(parse_inputs_as_field::<F>)
        .unwrap_or_default();
    let config = CoordinatorClientConfig {
        coordinator: CoordinatorEndpoint {
            host: args.coord_addr.0.clone(),
            port: args.coord_addr.1,
            pin: args.coordinator_pin.spki.clone(),
        },
        execution_id: args.execution_id,
        backend: args.backend,
        cert_der: args.cert_der,
        key_der: args.key_der,
        node_rpc_addresses: args
            .server_addrs
            .iter()
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .collect(),
        request: args.request,
        expected_roster_digest: args.roster_expectations.digest,
        expected_program_hash: args.expected_program_hash,
        expected_output_count: None,
    };

    let link = match config.connect().await {
        Ok(link) => link,
        Err(CoordinatorClientError::Connect(error)) => {
            exit_coordinator_connect_failure(&args.coord_addr, &args.coordinator_pin, error)
        }
        Err(other) => exit_coordinator_client_failure(other),
    };
    if let Err(unexpected) = args.roster_expectations.check_size(link.node_roster()) {
        eprintln!("Error: {unexpected}");
        exit(2);
    }

    let run = config
        .run::<F, S>(link, inputs)
        .await
        .unwrap_or_else(|error| exit_coordinator_client_failure(error));
    if let OutputRights::Receive { .. } = run.admission.output_rights {
        match style {
            ClientOutputStyle::Values(format) => {
                println!(
                    "outputs: {}",
                    format_coordinator_outputs(&run.outputs, format)
                )
            }
            ClientOutputStyle::FieldHex(curve_config) => println!(
                "Client output: field[{}] 0x{}",
                run.outputs.len(),
                field_outputs_to_hex(&run.outputs, curve_config)
            ),
        }
    }
}

/// Prints a client refusal and exits with its code (§9.E.1).
fn exit_coordinator_client_failure(error: CoordinatorClientError) -> ! {
    eprintln!("Error: {error}");
    exit(error.exit_code());
}

/// Picks the share type of `--mpc-backend` / `--mpc-curve` and runs the client.
async fn run_coordinator_client(args: ClientRunArgs) {
    let args_output_format = args.output_format;
    let curve_config = args.curve_config;
    macro_rules! hb {
        ($field:ty) => {
            run_coordinator_client_for::<$field, HbCoordinatorShare<$field>>(
                args,
                ClientOutputStyle::Values(args_output_format),
            )
            .await
        };
    }
    macro_rules! avss {
        ($field:ty, $group:ty) => {
            run_coordinator_client_for::<$field, AvssCoordinatorShare<$field, $group>>(
                args,
                ClientOutputStyle::FieldHex(curve_config),
            )
            .await
        };
    }
    match (args.backend, curve_config) {
        (MpcBackendKind::HoneyBadger, MpcCurveConfig::Bls12_381) => hb!(ark_bls12_381::Fr),
        (MpcBackendKind::HoneyBadger, MpcCurveConfig::Bn254) => hb!(ark_bn254::Fr),
        (MpcBackendKind::HoneyBadger, MpcCurveConfig::Curve25519) => hb!(ark_curve25519::Fr),
        (MpcBackendKind::HoneyBadger, MpcCurveConfig::Ed25519) => hb!(ark_ed25519::Fr),
        (MpcBackendKind::HoneyBadger, MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1) => {
            eprintln!(
                "Error: curve {} is not supported by honeybadger backend",
                curve_config.name()
            );
            exit(2);
        }
        (MpcBackendKind::Avss, MpcCurveConfig::Bls12_381) => {
            avss!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
        }
        (MpcBackendKind::Avss, MpcCurveConfig::Bn254) => {
            avss!(ark_bn254::Fr, ark_bn254::G1Projective)
        }
        (MpcBackendKind::Avss, MpcCurveConfig::Curve25519) => {
            avss!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
        }
        (MpcBackendKind::Avss, MpcCurveConfig::Ed25519) => {
            avss!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
        }
        (MpcBackendKind::Avss, MpcCurveConfig::Secp256k1) => {
            avss!(ark_secp256k1::Fr, ark_secp256k1::Projective)
        }
        (MpcBackendKind::Avss, MpcCurveConfig::Secp256r1) => {
            avss!(ark_secp256r1::Fr, ark_secp256r1::Projective)
        }
    }
}

/// Parses `--expect-program-hash`: the coordinator's `program_hash_of` of the program, as 64
/// hexadecimal characters.
fn parse_expected_program_hash(value: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    if value.len() != 64 {
        return Err(format!(
            "--expect-program-hash: expected 64 hexadecimal characters, got {}",
            value.len()
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|error| format!("--expect-program-hash: not hexadecimal: {error}"))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Reads `--invitation`: a `SignedInvitation` as JSON, as `issue-invitation --out` writes it.
fn read_invitation(path: &str) -> Result<SignedInvitation, String> {
    let bytes =
        fs::read(path).map_err(|reason| format!("cannot read --invitation {path}: {reason}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|reason| format!("--invitation {path} is not a signed invitation: {reason}"))
}

// `NodeRPCServer` lost its `<F, S>` parameters in coordinator `0.2.0`: mask shares
// are stored as bytes and the server never reconstructs them, so one listener type
// serves both backends. The share type now appears only where a share is actually
// serialized (`add_mask_shares_for_execution`), which is why there is no
// `HbOffChainNodeRpcServer`/`AvssOffChainNodeRpcServer` alias any more.

// The preprocessing barrier's tag now lives in `stoffel_vm::net::mesh::wire`
// beside the other in-band prefixes, and the send/collect pattern that used it
// lives in `stoffel_vm::net::mesh::MeshBarrier`. Blocker B7's disjointness
// invariant is therefore stated over the constants this binary actually sends.

fn session_registration_timeout() -> Duration {
    let seconds = env::var("STOFFEL_SESSION_REGISTRATION_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(120);
    Duration::from_secs(seconds)
}

/// Build the [`SessionJoin`] this process uses to form its MPC session.
///
/// Stage 1 of `docs/design/bootnode-elimination.md` put this one constructor in
/// front of both production join sites so that the later stages could choose the
/// join here instead of editing the call sites again. Stage 5 added [`MeshJoin`]
/// beside the bootnode; Stage 8 deleted the bootnode, so the choice collapses to
/// one. Membership is the coordinator's node roster (§9.D), fetched once before
/// this is called and handed in as a [`Roster`], never an `Option`: `--peers`
/// without `--off-chain-coord` is refused before anything is bound.
///
/// The mesh's two remaining preconditions are refused here rather than deep
/// inside the join, because both are configuration mistakes with one-line fixes:
/// somebody has to be dialed (`--peers`), and `instance_id` freshness has to be
/// persisted somewhere (the epoch store, blocker B5).
fn build_session_join(
    roster: Roster,
    seeds: &SeedHints,
    epochs: Option<Arc<EpochStore>>,
    router: Arc<MeshRouter>,
) -> Result<Box<dyn SessionJoin>, String> {
    if seeds.is_empty() {
        return Err(
            "no --peers: a party forms its session by dialing the other members of \
                    the roster, so it needs at least one address to start from"
                .to_string(),
        );
    }
    let epochs = epochs.ok_or_else(|| {
        "a mesh join needs an epoch store for instance_id freshness; pass --epoch-store or \
         set STOFFEL_EPOCH_STORE"
            .to_string()
    })?;
    eprintln!(
        "[mesh] joining: {} node roster, {} seed hint(s)",
        roster.n(),
        seeds.len()
    );
    // A first join forms out of dials alone. The peer book is exchanged
    // *inside* the join handshake — after the mesh is already complete — so
    // it cannot supply an address the mesh needs in order to form; it is
    // what lets a *later* join in the same process start from less.
    //
    // The requirement is per pair *and directional*: a pair is dialed from
    // one end only (`net::mesh::join::dials_towards`), so it is the member
    // with the higher transport-derived id that has to hold the hint.
    // Derived ids are BLAKE3 digests of the certificates, so which end that
    // is cannot be read off a config file — which is exactly why the
    // guidance is the blunt one. Listing all n-1 peers everywhere satisfies
    // the requirement whatever the order turns out to be, and is what every
    // shipped stack does. Fewer is not refused, because the node cannot
    // tell here whether its own hints happen to be the covering half, but
    // it is said out loud: the alternative is discovering it as a
    // 90-second timeout.
    let needed = roster.n().saturating_sub(1);
    if seeds.len() < needed {
        eprintln!(
            "[mesh] warning: {} seed hint(s) for a {}-node roster. A pair of parties is \
             dialed from one end only, and which end is decided by a digest of their \
             certificates, so a short list may leave an edge that neither side dials. \
             Pass all {needed} peer addresses unless you have worked the direction out.",
            seeds.len(),
            roster.n(),
        );
    }
    Ok(Box::new(
        MeshJoin::new(roster, seeds.clone(), epochs).with_router(router),
    ))
}

fn durable_identity_from_cert(cert_der: &[u8]) -> DurableIdentityDigest {
    DurableIdentityDigest::from_cert_der(cert_der).unwrap_or_else(|error| {
        eprintln!("Error: failed to derive durable identity from certificate: {error}");
        exit(2);
    })
}

fn required_storage_identity(
    cert_der: &Option<Vec<u8>>,
    key_der: &Option<Vec<u8>>,
    storage_enabled: bool,
) -> Option<DurableIdentityDigest> {
    if !storage_enabled {
        return None;
    }
    let cert = cert_der.as_ref().unwrap_or_else(|| {
        eprintln!("Error: --cert is required when persistent VM/preprocessing storage is enabled");
        exit(2);
    });
    let _key = key_der.as_ref().unwrap_or_else(|| {
        eprintln!("Error: --key is required when persistent VM/preprocessing storage is enabled");
        exit(2);
    });
    Some(durable_identity_from_cert(cert))
}
#[derive(Debug, Clone, Copy)]
enum CoordinatorOutputFormat {
    FieldInteger,
    FixedPoint { fractional_bits: usize },
}
fn render_fixed_point_i64(scaled: i64, fractional_bits: usize) -> Option<String> {
    let scale = 1_i128.checked_shl(u32::try_from(fractional_bits).ok()?)?;
    if scale == 0 {
        return None;
    }

    let scaled = i128::from(scaled);
    let negative = scaled < 0;
    let magnitude = scaled.abs();
    let whole = magnitude / scale;
    let mut remainder = magnitude % scale;

    if remainder == 0 {
        return Some(if negative {
            format!("-{whole}")
        } else {
            whole.to_string()
        });
    }

    let mut fractional = String::new();
    while remainder != 0 {
        remainder *= 10;
        let digit = remainder / scale;
        fractional.push(char::from(b'0' + u8::try_from(digit).ok()?));
        remainder %= scale;
    }

    Some(if negative {
        format!("-{whole}.{fractional}")
    } else {
        format!("{whole}.{fractional}")
    })
}
fn format_coordinator_outputs<F>(outputs: &[F], output_format: CoordinatorOutputFormat) -> String
where
    F: PrimeField + Copy + PartialEq + std::fmt::Debug,
{
    let rendered = outputs
        .iter()
        .copied()
        .map(|output| match (field_to_i64(output), output_format) {
            (Ok(signed), CoordinatorOutputFormat::FieldInteger)
                if field_from_i64::<F>(signed) == output =>
            {
                signed.to_string()
            }
            (Ok(signed), CoordinatorOutputFormat::FixedPoint { fractional_bits })
                if field_from_i64::<F>(signed) == output =>
            {
                render_fixed_point_i64(signed, fractional_bits)
                    .unwrap_or_else(|| format!("{output:?}"))
            }
            _ => format!("{output:?}"),
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!("[{}]", rendered)
}
fn curve_config_from_manifest(curve: MpcCurve) -> MpcCurveConfig {
    match curve {
        MpcCurve::Bls12_381 => MpcCurveConfig::Bls12_381,
        MpcCurve::Bn254 => MpcCurveConfig::Bn254,
        MpcCurve::Curve25519 => MpcCurveConfig::Curve25519,
        MpcCurve::Ed25519 => MpcCurveConfig::Ed25519,
        MpcCurve::Secp256k1 => MpcCurveConfig::Secp256k1,
        MpcCurve::Secp256r1 => MpcCurveConfig::Secp256r1,
    }
}
fn configure_hb_preproc_store<F, G>(
    engine: &Arc<HoneyBadgerMpcEngine<F, G>>,
    program_hash: [u8; 32],
    persistent_identity: DurableIdentityDigest,
    preproc_store_path: Option<&str>,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let Some(path) = preproc_store_path else {
        return Ok(());
    };

    let store = Arc::new(LmdbPreprocStore::open(path)?);
    engine
        .preproc_persistence_ops()?
        .set_preproc_store(store, program_hash)?;
    engine.set_preproc_store_identity(persistent_identity);
    Ok(())
}
/// Network adapter for MPC servers that remaps sequential client indices
/// (0, 1, ...) back to transport client IDs for send_to_client().
/// The MPC protocol uses small indices (because session_id only has 8 bits),
/// and the network layer exposes clients in canonical sorted transport order.
struct ServerClientAdapter {
    inner: QuicNetworkManager,
    /// Maps sequential index to transport client ID.
    client_id_map: Vec<ClientId>,
}
#[async_trait::async_trait]
impl Network for ServerClientAdapter {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send(recipient, message).await
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.broadcast(message).await
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Remap sequential index to the canonical transport client ID.
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.send_to_client(transport_id, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.is_client_connected(transport_id)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count()
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

fn is_flag_present(raw_args: &[String], flag: &str) -> bool {
    raw_args
        .iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

/// The client slot layout's one source, named by every flag that used to size it.
const SLOT_LAYOUT_HINT: &str =
    "The client slot layout is the coordinator's execution registration.";

/// `n` and `t` have exactly one source.
const ROSTER_SIZE_HINT: &str = "n and t come from the coordinator's node roster. To refuse a \
     roster of another size, pass --expect-n-parties and --expect-threshold.";

/// Flags this binary refuses by name, each with its hint
/// (`docs/design/bootnode-elimination.md` §9.D.3). No hint names a flag of this
/// table, so an operator is never sent from one refusal to the next.
const REMOVED_FLAGS: &[(&str, &str)] = &[
    (
        "--roster",
        "Membership is the coordinator's node roster, fetched once at startup. Pass \
         --off-chain-coord, --coord-cert and --execution-id instead.",
    ),
    (
        "--expected-clients",
        "Client certificates no longer enter a node's transport allowlist. Clients \
         associate with an execution through the coordinator, and nodes read the admissions \
         from it.",
    ),
    (
        "--wait-for-clients",
        "Clients no longer connect to the node mesh. They associate through the coordinator \
         and fetch their masks from the nodes' --rpc-bind listeners.",
    ),
    ("--client-roster", SLOT_LAYOUT_HINT),
    ("--client-input-slots", SLOT_LAYOUT_HINT),
    ("--client-input-count", SLOT_LAYOUT_HINT),
    ("--client-input-total", SLOT_LAYOUT_HINT),
    ("--n-parties", ROSTER_SIZE_HINT),
    ("--threshold", ROSTER_SIZE_HINT),
    (
        "--timestamp",
        "No coordinator takes a timestamp; an execution's deadlines are part of its \
         registration. Remove the flag.",
    ),
    (
        "--client-id",
        "A client's slot is requested with --client-slot <index> and granted by the \
         coordinator's admission.",
    ),
    (
        "--client-index",
        "The coordinator assigns each client's input range when it associates. Pass \
         --client-slot <index> to ask for a specific slot.",
    ),
    (
        "--outputs",
        "A client's output count comes from its admission.",
    ),
    ("--expected-client-count", SLOT_LAYOUT_HINT),
    (
        "--bootnode",
        "The bootnode is gone. Every node passes --off-chain-coord <host:port>, --coord-cert \
         <path>, --execution-id <64-hex>, --peers <addrs> and --epoch-store <dir>, and runs no \
         bootstrap process.",
    ),
    (
        "--bootstrap",
        "There is no bootstrap process to register with. Pass --peers <addrs> (seed hints); \
         membership is the coordinator's node roster (--off-chain-coord, --coord-cert).",
    ),
    (
        "--coord-driver",
        "Coordinator transitions are quorum-gated: every party proposes every round and none \
         is designated. Drop the flag.",
    ),
];

fn fail_removed_flag(raw_args: &[String], old_flag: &str, replacement_hint: &str) {
    if is_flag_present(raw_args, old_flag) {
        eprintln!("Error: `{}` was removed. {}", old_flag, replacement_hint);
        exit(2);
    }
}

fn print_vm_result(vm: &mut VirtualMachine, result: Value) {
    let result = if matches!(result, Value::Share(_, _)) && vm.mpc_runtime_info().is_some() {
        eprintln!("Program returned a secret share, revealing...");
        match vm.open_share_value(&result) {
            Ok(revealed) => revealed,
            Err(e) => {
                eprintln!("Failed to reveal returned share: {}", e);
                result
            }
        }
    } else {
        result
    };

    match &result {
        Value::Array(arr_ref) => {
            if let Some(bytes) = vm
                .read_byte_array(&Value::from(*arr_ref))
                .ok()
                .filter(|bytes| !bytes.is_empty())
            {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                println!("Program returned: byte[{}] 0x{}", bytes.len(), hex);
            } else {
                println!("Program returned: {}", format_vm_value(vm, &result, 4));
            }
        }
        _ => println!("Program returned: {}", format_vm_value(vm, &result, 4)),
    }
}

fn format_vm_value(vm: &mut VirtualMachine, value: &Value, max_depth: usize) -> String {
    let mut active_tables = HashSet::new();
    format_vm_value_inner(vm, value, max_depth, &mut active_tables)
}

fn format_vm_value_inner(
    vm: &mut VirtualMachine,
    value: &Value,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    match value {
        Value::I64(i) => i.to_string(),
        Value::I32(i) => i.to_string(),
        Value::I16(i) => i.to_string(),
        Value::I8(i) => i.to_string(),
        Value::U64(i) => i.to_string(),
        Value::U32(i) => i.to_string(),
        Value::U16(i) => i.to_string(),
        Value::U8(i) => i.to_string(),
        Value::Float(fp) => fp.0.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => format!("\"{}\"", s),
        Value::Unit => "()".to_string(),
        Value::Closure(c) => format!("Function({})", c.function_id()),
        Value::Foreign(foreign_ref) => format!("Foreign({})", foreign_ref.id()),
        Value::Share(share_type, _) => format!("Share({:?})", share_type),
        Value::Array(array_ref) => {
            let table_ref = TableRef::from(*array_ref);
            if !active_tables.insert(table_ref) {
                return format!("Array({}) <cycle>", array_ref.id());
            }
            let formatted = format_vm_array(vm, *array_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
        Value::Object(object_ref) => {
            let table_ref = TableRef::from(*object_ref);
            if !active_tables.insert(table_ref) {
                return format!("Object({}) <cycle>", object_ref.id());
            }
            let formatted = format_vm_object(vm, *object_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
    }
}

fn format_vm_array(
    vm: &mut VirtualMachine,
    array_ref: stoffel_vm_types::core_types::ArrayRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    let len = match vm.read_array_len(array_ref) {
        Ok(len) => len,
        Err(error) => return format!("Array({}) <error: {}>", array_ref.id(), error),
    };
    if max_depth == 0 {
        return format!("[...{} elements]", len);
    }

    let display_count = len.min(64);
    let mut parts = Vec::with_capacity(display_count);
    for index in 0..display_count {
        let key = Value::I64(index as i64);
        let value = match vm.read_table_field(TableRef::from(array_ref), &key) {
            Ok(Some(value)) => value,
            Ok(None) => Value::Unit,
            Err(error) => {
                parts.push(format!("<error: {}>", error));
                continue;
            }
        };
        parts.push(format_vm_value_inner(
            vm,
            &value,
            max_depth - 1,
            active_tables,
        ));
    }

    if len > display_count {
        format!("[{}, ...({} more)]", parts.join(", "), len - display_count)
    } else {
        format!("[{}]", parts.join(", "))
    }
}

fn format_vm_object(
    vm: &mut VirtualMachine,
    object_ref: stoffel_vm_types::core_types::ObjectRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    let entries = match vm.read_object_entries(object_ref, 64) {
        Ok(entries) => entries,
        Err(error) => return format!("Object({}) <error: {}>", object_ref.id(), error),
    };
    if max_depth == 0 {
        return format!("{{...{} fields}}", entries.len());
    }

    let mut parts = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key = format_vm_value_inner(vm, &key, max_depth - 1, active_tables);
        let value = format_vm_value_inner(vm, &value, max_depth - 1, active_tables);
        parts.push(format!("{}: {}", key, value));
    }
    format!("{{{}}}", parts.join(", "))
}
fn parse_inputs_as_field<F: PrimeField>(inputs_str: &str) -> Vec<F> {
    // An output-only client has no inputs.
    if inputs_str.trim().is_empty() {
        return Vec::new();
    }
    inputs_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            if let Some(hex_value) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let mut hex_value = hex_value.to_owned();
                if hex_value.len() % 2 == 1 {
                    hex_value.insert(0, '0');
                }
                let bytes = hex::decode(&hex_value).unwrap_or_else(|error| {
                    eprintln!("Invalid hex input value '{}': {}", s, error);
                    exit(2);
                });
                return F::from_be_bytes_mod_order(&bytes);
            }

            let val: i64 = s.parse().unwrap_or_else(|_| {
                eprintln!("Invalid input value: {}", s);
                exit(2);
            });
            stoffel_vm::net::field_from_i64::<F>(val)
        })
        .collect()
}
fn field_outputs_to_hex<F: PrimeField>(outputs: &[F], curve_config: MpcCurveConfig) -> String {
    let mut bytes = Vec::new();
    for output in outputs {
        if matches!(
            curve_config,
            MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1
        ) {
            bytes.extend_from_slice(&fixed_width_be_bytes(
                &output.into_bigint().to_bytes_be(),
                32,
            ));
        } else {
            ark_serialize::CanonicalSerialize::serialize_compressed(output, &mut bytes)
                .expect("field serialization to Vec cannot fail");
        }
    }
    hex::encode(bytes)
}
fn fixed_width_be_bytes(bytes: &[u8], width: usize) -> Vec<u8> {
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|idx| &bytes[idx..])
        .unwrap_or(&[]);
    if significant.len() >= width {
        significant[significant.len() - width..].to_vec()
    } else {
        let mut out = vec![0u8; width - significant.len()];
        out.extend_from_slice(significant);
        out
    }
}

const CLIENT_SET_SYNC_PREFIX: &[u8; 4] = b"CSS1";
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientSetSyncMessage {
    sender_party_id: usize,
    client_ids: Vec<ClientId>,
}
fn normalize_client_ids(mut ids: Vec<ClientId>) -> Vec<ClientId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn encode_client_set_sync(msg: &ClientSetSyncMessage) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(msg)
        .map_err(|e| format!("Failed to serialize client-set sync payload: {}", e))?;
    let mut out = Vec::with_capacity(CLIENT_SET_SYNC_PREFIX.len() + payload.len());
    out.extend_from_slice(CLIENT_SET_SYNC_PREFIX);
    out.extend_from_slice(&payload);
    Ok(out)
}
fn decode_client_set_sync(bytes: &[u8]) -> Result<ClientSetSyncMessage, String> {
    if bytes.len() < CLIENT_SET_SYNC_PREFIX.len()
        || &bytes[..CLIENT_SET_SYNC_PREFIX.len()] != CLIENT_SET_SYNC_PREFIX
    {
        return Err("Unexpected message prefix while waiting for client-set sync".to_string());
    }

    bincode::deserialize(&bytes[CLIENT_SET_SYNC_PREFIX.len()..])
        .map_err(|e| format!("Failed to deserialize client-set sync payload: {}", e))
}
async fn sync_client_set_across_parties(
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n_parties: usize,
    local_client_ids: &[ClientId],
) -> Result<(), String> {
    if n_parties <= 1 {
        return Ok(());
    }

    let normalized_local = normalize_client_ids(local_client_ids.to_vec());
    let sync_payload = encode_client_set_sync(&ClientSetSyncMessage {
        sender_party_id: my_id,
        client_ids: normalized_local.clone(),
    })?;

    eprintln!(
        "[party {}] Broadcasting client-set sync payload: {:?}",
        my_id, normalized_local
    );

    for peer_id in 0..n_parties {
        if peer_id == my_id {
            continue;
        }
        net.send(peer_id, &sync_payload)
            .await
            .map_err(|e| format!("Failed to send client-set sync to party {}: {}", peer_id, e))?;
    }

    let mut confirmed_parties: HashSet<usize> = HashSet::new();
    let expected_confirmations = n_parties - 1;
    let receive_deadline = std::time::Instant::now() + Duration::from_secs(20);

    // CANCELLATION SAFETY (the InvalidData flake): `connection.receive()` reads
    // a length-prefixed frame across MULTIPLE awaits. Wrapping it in
    // `tokio::time::timeout` (the old polling loop here) can cancel it BETWEEN
    // the length read and the payload read; the next receive on that stream
    // then parses payload bytes as a length header, permanently desyncing the
    // frame stream — and these SAME party connections carry all subsequent MPC
    // traffic, which then fails to deserialize
    // (`MulError(ArkSerialization(InvalidData))`) and strands the mesh until
    // the party timeout. Instead, spawn one NEVER-CANCELLED one-shot reader per
    // peer (the same dedicated-reader idiom as `spawn_receive_loops`) that
    // forwards its single sync frame through a channel; the deadline applies
    // to the channel receive, which IS cancellation-safe.
    let (sync_tx, mut sync_rx) = mpsc::unbounded_channel::<(usize, Result<Vec<u8>, String>)>();
    let mut spawned_readers: HashSet<usize> = HashSet::new();

    while confirmed_parties.len() < expected_confirmations {
        if std::time::Instant::now() >= receive_deadline {
            return Err(format!(
                "Timed out waiting for client-set sync confirmations ({}/{})",
                confirmed_parties.len(),
                expected_confirmations
            ));
        }

        // Pick up (possibly late-arriving) peer connections.
        for (derived_id, connection) in net.get_all_server_connections() {
            let sender_id = connection.remote_party_id().unwrap_or(derived_id);
            if sender_id >= n_parties || sender_id == my_id || !spawned_readers.insert(sender_id) {
                continue;
            }
            let tx = sync_tx.clone();
            tokio::spawn(async move {
                let result = connection.receive().await;
                let _ = tx.send((sender_id, result));
            });
        }

        // Wait for the next sync frame; short tick so new connections are
        // still scanned. Cancelling a CHANNEL receive loses nothing.
        match tokio::time::timeout(Duration::from_millis(100), sync_rx.recv()).await {
            Ok(Some((sender_id, Ok(data)))) => {
                let sync = decode_client_set_sync(&data).map_err(|e| {
                    format!(
                        "Failed to decode client-set sync from party {}: {}",
                        sender_id, e
                    )
                })?;

                if sync.sender_party_id != sender_id {
                    return Err(format!(
                        "Client-set sync sender mismatch: transport sender={} payload sender={}",
                        sender_id, sync.sender_party_id
                    ));
                }

                let normalized_remote = normalize_client_ids(sync.client_ids);
                if normalized_remote != normalized_local {
                    return Err(format!(
                        "Client-set mismatch with party {}: local={:?}, remote={:?}",
                        sender_id, normalized_local, normalized_remote
                    ));
                }

                confirmed_parties.insert(sender_id);
                eprintln!(
                    "[party {}] Client-set sync confirmed with party {}",
                    my_id, sender_id
                );
            }
            Ok(Some((sender_id, Err(e)))) => {
                return Err(format!(
                    "Failed to receive client-set sync from party {}: {}",
                    sender_id, e
                ));
            }
            Ok(None) => {
                return Err("Client-set sync channel closed unexpectedly".to_string());
            }
            Err(_) => {}
        }
    }

    eprintln!(
        "[party {}] Client-set sync complete with {} peers",
        my_id, expected_confirmations
    );
    Ok(())
}
struct HbPartySetup<'a> {
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    persistent_identity: DurableIdentityDigest,
    n: usize,
    t: usize,
    instance_id: u64,
    expected_client_count: Option<usize>,
    /// Client input masks a coordinated execution registers (§9.D.7 step 1): preprocessing
    /// is sized for them on top of the program's own demand.
    coordinator_mask_count: usize,
    client_input_count: usize,
    client_input_types: &'a std::collections::BTreeMap<usize, Vec<ShareType>>,
    preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand,
    program_hash: [u8; 32],
    preproc_store_path: Option<&'a str>,
    /// Blocker B6: the receive loops must consume mesh control frames, or they
    /// reach the HoneyBadger node as protocol messages. Built once in `main`
    /// from the coordinator's node roster, so the peer book is pinned to the
    /// session rather than open to any SPKI an authenticated peer cares to
    /// invent.
    mesh_router: Arc<MeshRouter>,
    /// The agreement barriers of a coordinated execution (§9.D.6), offered every frame
    /// beside the preprocessing barrier.
    digest_barriers: Option<DigestBarriers>,
}
async fn setup_hb_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    setup: HbPartySetup<'_>,
) -> Result<Arc<HoneyBadgerMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let HbPartySetup {
        net,
        my_id,
        persistent_identity,
        n,
        t,
        instance_id,
        expected_client_count,
        coordinator_mask_count,
        client_input_count,
        client_input_types,
        preprocessing_demand,
        program_hash,
        preproc_store_path,
        mesh_router,
        digest_barriers,
    } = setup;

    // ---- Phase 1: Wait for clients ----
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--wait-for-clients count must be greater than 0".to_string());
        }
        if client_input_count == 0 {
            return Err("--client-input-count must be greater than 0".to_string());
        }

        eprintln!(
            "[party {}] Waiting for {} clients...",
            my_id, expected_count
        );

        let mut accept_net = (*net).clone();
        let accept_party_id = my_id;
        tokio::spawn(async move {
            loop {
                match accept_net.accept().await {
                    Ok(_) => {
                        eprintln!("[party {}] Accepted client connection", accept_party_id);
                    }
                    Err(e) => {
                        eprintln!("[party {}] Accept error: {}", accept_party_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let connect_timeout = Duration::from_secs(600);
        let check_interval = Duration::from_millis(250);
        let start = std::time::Instant::now();

        loop {
            let mut connected_clients = net.clients();
            connected_clients.sort_unstable();
            connected_clients.dedup();

            eprintln!(
                "[party {}] {} of {} expected clients connected: {:?}",
                my_id,
                connected_clients.len(),
                expected_count,
                connected_clients
            );

            if connected_clients.len() > expected_count {
                return Err(format!(
                    "Expected exactly {} clients, but {} are connected: {:?}",
                    expected_count,
                    connected_clients.len(),
                    connected_clients
                ));
            }

            if connected_clients.len() == expected_count {
                input_ids = connected_clients;
                break;
            }

            if start.elapsed() > connect_timeout {
                return Err(format!(
                    "Timeout waiting for {} clients; connected so far: {:?}",
                    expected_count,
                    net.clients()
                ));
            }

            tokio::time::sleep(check_interval).await;
        }

        eprintln!(
            "[party {}] Using canonical client input IDs: {:?}",
            my_id, input_ids
        );

        sync_client_set_across_parties(net.clone(), my_id, n, &input_ids).await?;
    }

    // ---- Phase 2: Setup MPC node and preprocess ----
    //
    // CRITICAL: We use exactly TWO clones of the MPC node to avoid the
    // double-processing bug where init_ransha() is called multiple times:
    //   - Clone 1 (`processing_node`): handles incoming messages via process()
    //   - Clone 2 (inside `engine`): initiates preprocessing via run_preprocessing()
    // Both share the same Arc<Mutex> stores, but only ONE processes each message.
    // Plan the preprocessing material from the compiler's static demand
    // estimate, rounding each count up to a power of 2 so the generated volume
    // reveals only the program's size octave (privacy), not its exact operation
    // counts. The plan folds in the dependency that prandbit generation consumes
    // a triple + random per bit, and a baseline so light programs still run.
    let n_client_random = input_ids
        .len()
        .saturating_mul(client_input_count)
        .saturating_add(coordinator_mask_count);
    let plan = plan_preprocessing(&preprocessing_demand, t, n_client_random);
    let n_triples = plan.n_triples;
    let n_random = plan.n_random;
    let n_prandbit = plan.n_prandbit;
    let n_prandint = plan.n_prandint;
    let protocol_timeout = honeybadger_protocol_timeout();
    eprintln!(
        "[party {}] Creating MPC node opts (n_triples={}, n_random={}, n_prandbit={}, n_prandint={}, dynamic={}, timeout={}s)",
        my_id,
        n_triples,
        n_random,
        n_prandbit,
        n_prandint,
        preprocessing_demand.dynamic,
        protocol_timeout.as_secs()
    );
    let mpc_opts = honeybadger_node_opts_with_truncation(
        n,
        t,
        n_triples,
        n_random,
        n_prandbit,
        n_prandint,
        instance_id,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to create MPC node options: {}", e);
        std::process::exit(2);
    });

    // Use sequential indices (0..n_clients) as client IDs for the MPC protocol
    // because the session_id only has 8 bits for the client_id field.
    let mpc_input_ids: Vec<ClientId> = (0..input_ids.len()).collect();
    let mpc_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
        F,
        RobustShare<F>,
        QuicNetworkManager,
    >>::setup(my_id, mpc_opts, mpc_input_ids)
    .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;
    eprintln!("[party {}] MPC node setup complete", my_id);

    // Clone 1: the processing node — MOVED into the processing loop task.
    // This is the ONLY clone that calls process() on incoming messages.
    let mut processing_node = mpc_node.clone();

    // Clone 2: the engine node — used for preprocessing initiation only.
    // Created via from_existing_node which wraps it in Arc<Mutex>.
    let open_message_router = Arc::new(stoffel_vm::net::OpenMessageRouter::new());
    let topology = MpcSessionTopology::try_new(instance_id, my_id, n, t)
        .map_err(|error| format!("Invalid HoneyBadger MPC topology: {error}"))?;
    let engine = HoneyBadgerMpcEngine::<F, G>::from_existing_node_with_router_and_topology(
        open_message_router.clone(),
        topology,
        persistent_identity,
        net.clone(),
        mpc_node, // moved, not cloned
    );

    configure_hb_preproc_store(
        &engine,
        program_hash,
        persistent_identity,
        preproc_store_path,
    )?;
    if let Some(path) = preproc_store_path {
        eprintln!("[party {}] Using preprocessing store at {}", my_id, path);
    }
    engine.set_client_output_id_map(input_ids.clone()).await;
    vm.set_mpc_engine(engine.clone());

    eprintln!(
        "[party {}] Spawning receive loops (split channels)...",
        my_id
    );
    let (mut server_rx, mut client_rx) =
        spawn_receive_loops_split(net.clone(), my_id, n, open_message_router, mesh_router).await;

    // Map canonical client transport IDs to MPC protocol indices.
    let client_id_to_index: std::collections::HashMap<ClientId, usize> = input_ids
        .iter()
        .enumerate()
        .map(|(idx, &tid)| (tid, idx))
        .collect();

    // Single processing loop using tokio::select! for both server and client messages.
    // Only this task calls process() — no other task touches the processing_node.
    let processing_net = net.clone();
    let process_party_id = my_id;
    // The all-to-all rendezvous every party has to reach before any party moves
    // on, generalized out of this file into `stoffel_vm::net::mesh::barrier`.
    // The frames are byte-identical to the ones this loop used to build and
    // match by hand (`prefix || instance_id.to_le_bytes()`), which is what
    // makes the migration a no-op on the wire.
    let preprocessing_barrier = Arc::new(MeshBarrier::new(
        BarrierTag::PreprocessingReady,
        instance_id,
        n,
        my_id,
    ));
    let recording_barrier = preprocessing_barrier.clone();
    tokio::spawn(async move {
        let mut msg_count = 0u64;
        let trace_messages = std::env::var("STOFFEL_RUN_TRACE_MESSAGES")
            .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
        loop {
            tokio::select! {
                Some((sender_id, raw_msg)) = server_rx.recv() => {
                    // Consumed here, never handed on: a barrier frame is not a
                    // protocol message, and its tag is disjoint from every
                    // other prefix on this stream (blocker B7).
                    if recording_barrier.record(sender_id, &raw_msg) {
                        continue;
                    }
                    if digest_barriers
                        .as_ref()
                        .is_some_and(|barriers| barriers.record(sender_id, &raw_msg))
                    {
                        continue;
                    }

                    msg_count += 1;
                    if trace_messages && (msg_count <= 5 || msg_count.is_multiple_of(1000)) {
                        eprintln!(
                            "[party {}] Processing message #{} from sender {} ({} bytes)",
                            process_party_id, msg_count, sender_id, raw_msg.len()
                        );
                    }
                    if let Err(e) = processing_node
                        .process(sender_id, raw_msg, processing_net.clone())
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process message from {}: {:?}",
                            process_party_id, sender_id, e
                        );
                    }
                }
                Some((client_id, raw_msg)) = client_rx.recv() => {
                    // Remap transport client ID → sequential index
                    let mpc_sender_id = client_id_to_index
                        .get(&client_id)
                        .copied()
                        .unwrap_or(client_id);
                    if let Err(e) = processing_node
                        .process(mpc_sender_id, raw_msg, processing_net.clone())
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process client message from {} (idx {}): {:?}",
                            process_party_id, client_id, mpc_sender_id, e
                        );
                    }
                }
                else => break,
            }
        }
    });

    // Brief delay to let receive loops discover connections
    tokio::time::sleep(Duration::from_secs(2)).await;

    eprintln!("[party {}] Starting MPC preprocessing...", my_id);
    let preprocessing_started_at = std::time::Instant::now();
    engine
        .preprocess()
        .await
        .map_err(|e| format!("MPC preprocessing failed: {}", e))?;
    eprintln!(
        "[party {}] MPC preprocessing complete! elapsed_ms={}",
        my_id,
        preprocessing_started_at.elapsed().as_millis()
    );
    match current_cgroup_memory_bytes() {
        Some(bytes) => eprintln!(
            "[party {}] POST_PREPROCESSING_CGROUP_MEM_BYTES: {}",
            my_id, bytes
        ),
        None => eprintln!(
            "[party {}] POST_PREPROCESSING_CGROUP_MEM_BYTES: unavailable",
            my_id
        ),
    }
    match current_process_rss_bytes() {
        Some(bytes) => eprintln!("[party {}] POST_PREPROCESSING_RSS_BYTES: {}", my_id, bytes),
        None => eprintln!(
            "[party {}] POST_PREPROCESSING_RSS_BYTES: unavailable",
            my_id
        ),
    }

    if n > 1 {
        eprintln!(
            "[party {}] Waiting for all parties to finish MPC preprocessing...",
            my_id
        );
        preprocessing_barrier
            .wait(net.as_ref(), honeybadger_protocol_timeout())
            .await
            .map_err(|error| error.to_string())?;
        eprintln!(
            "[party {}] All parties completed MPC preprocessing; continuing",
            my_id
        );
    }

    if !input_ids.is_empty() {
        let client_index_map: Vec<(usize, ClientId)> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (idx, tid))
            .collect();

        // Create a server-side network adapter that remaps sequential client
        // indices to transport client IDs for send_to_client().
        let server_adapter = Arc::new(ServerClientAdapter {
            inner: (*net).clone(),
            client_id_map: client_index_map.iter().map(|(_, tid)| *tid).collect(),
        });

        // Access the engine's node for InputServer init
        eprintln!(
            "[party {}] Initializing InputServer for {} clients...",
            my_id,
            client_index_map.len()
        );
        {
            let mut node = engine.node_handle().lock().await;
            for &(idx, _tid) in &client_index_map {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(client_input_count)
                    .map_err(|e| format!("Not enough random shares for client {}: {:?}", idx, e))?;

                eprintln!(
                    "[party {}] Sending random shares to client index {} (server_id={})",
                    my_id, idx, node.id
                );
                node.preprocess
                    .input
                    .init(
                        idx,
                        local_shares,
                        client_input_count,
                        server_adapter.clone(),
                    )
                    .await
                    .map_err(|e| {
                        format!("Failed to init InputServer for client {}: {:?}", idx, e)
                    })?;
                eprintln!(
                    "[party {}] InputServer initialized for client index {}",
                    my_id, idx
                );
            }
        }

        // Signal readiness to clients
        eprintln!(
            "[party {}] Sending INST to {} clients...",
            my_id,
            client_index_map.len()
        );
        for &(idx, tid) in &client_index_map {
            let mut inst_msg = Vec::with_capacity(13);
            inst_msg.extend_from_slice(b"INST");
            inst_msg.extend_from_slice(&instance_id.to_le_bytes());
            inst_msg.push(idx as u8);
            if let Err(e) = net.send_to_client(tid, &inst_msg).await {
                eprintln!(
                    "[party {}] Failed to send INST to client {}: {:?}",
                    my_id, tid, e
                );
            }
        }

        eprintln!(
            "[party {}] Waiting for all client inputs (timeout=600s)...",
            my_id
        );
        let client_inputs = {
            let mut node = engine.node_handle().lock().await;
            node.preprocess
                .input
                .wait_for_all_inputs(Duration::from_secs(600))
                .await
                .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?
        };

        for (idx, shares) in client_inputs {
            let transport_cid = client_index_map
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, tid)| *tid)
                .unwrap_or(idx);
            if let Some(share_types) = client_input_types.get(&idx) {
                vm.try_store_client_input_with_types(idx, shares, share_types)?;
            } else {
                vm.try_store_client_input(idx, shares)?;
            }
            eprintln!(
                "[party {}] Stored inputs for client index {} (client {})",
                my_id, idx, transport_cid
            );
        }
    }

    Ok(engine)
}
struct AvssPartySetup<'a> {
    my_id: usize,
    local_identity: DurableIdentityDigest,
    n: usize,
    t: usize,
    instance_id: u64,
    expected_client_count: Option<usize>,
    client_input_count: usize,
    client_input_types: &'a std::collections::BTreeMap<usize, Vec<ShareType>>,
    /// Client input masks a coordinated execution registers (§9.D.7 step 1): the random-share
    /// pool is generated this much larger, so provisioning them leaves the program's own
    /// randomness in place.
    coordinator_mask_count: usize,
    /// The agreement barriers of a coordinated execution (§9.D.6), offered every frame right
    /// after the mesh router so an agreement frame never reaches the AVSS engine.
    digest_barriers: Option<DigestBarriers>,
    /// Blocker B6, seventh site. This is the production AVSS *party* path: it
    /// spawns its own per-peer receive loops below rather than going through
    /// `AvssQuicServer::spawn_message_loops`, so without a router here a
    /// `MSH1`-tagged frame reaches the AVSS engine as a protocol message.
    mesh_router: Arc<MeshRouter>,
}
async fn setup_avss_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    setup: AvssPartySetup<'_>,
) -> Result<Arc<stoffel_vm::net::avss_engine::AvssMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let AvssPartySetup {
        my_id,
        local_identity,
        n,
        t,
        instance_id,
        expected_client_count,
        client_input_count,
        client_input_types,
        coordinator_mask_count,
        digest_barriers,
        mesh_router,
    } = setup;

    // ---- Phase 1: Wait for clients ----
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--wait-for-clients count must be greater than 0".to_string());
        }
        if client_input_count == 0 {
            return Err("--client-input-count must be greater than 0".to_string());
        }

        eprintln!(
            "[party {}] Waiting for {} clients (AVSS)...",
            my_id, expected_count
        );

        let mut accept_net = (*net).clone();
        let accept_party_id = my_id;
        tokio::spawn(async move {
            loop {
                match accept_net.accept().await {
                    Ok(_) => {
                        eprintln!("[party {}] Accepted client connection", accept_party_id);
                    }
                    Err(e) => {
                        eprintln!("[party {}] Accept error: {}", accept_party_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let connect_timeout = Duration::from_secs(600);
        let check_interval = Duration::from_millis(250);
        let start = std::time::Instant::now();

        loop {
            let mut connected_clients = net.clients();
            connected_clients.sort_unstable();
            connected_clients.dedup();

            eprintln!(
                "[party {}] {} of {} expected clients connected: {:?}",
                my_id,
                connected_clients.len(),
                expected_count,
                connected_clients
            );

            if connected_clients.len() > expected_count {
                return Err(format!(
                    "Expected exactly {} clients, but {} are connected: {:?}",
                    expected_count,
                    connected_clients.len(),
                    connected_clients
                ));
            }

            if connected_clients.len() == expected_count {
                input_ids = connected_clients;
                break;
            }

            if start.elapsed() > connect_timeout {
                return Err(format!(
                    "Timeout waiting for {} clients; connected so far: {:?}",
                    expected_count,
                    net.clients()
                ));
            }

            tokio::time::sleep(check_interval).await;
        }

        eprintln!(
            "[party {}] Using canonical client input IDs: {:?}",
            my_id, input_ids
        );

        sync_client_set_across_parties(net.clone(), my_id, n, &input_ids).await?;
    }

    // ---- Phase 2: ECDH key exchange over existing network ----
    let mpc_input_ids: Vec<ClientId> = (0..input_ids.len()).collect();

    // Generate ECDH key pair for AVSS payload confidentiality
    use ark_std::rand::SeedableRng as _;
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let sk_i = F::rand(&mut rng);
    let pk_i: G = G::generator() * sk_i;

    // Serialize our public key into an envelope: [party_id: u32][pk_bytes]
    let mut pk_bytes = Vec::new();
    pk_i.serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("Failed to serialize ECDH public key: {:?}", e))?;
    let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
    envelope.extend_from_slice(&(my_id as u32).to_le_bytes());
    envelope.extend_from_slice(&pk_bytes);

    eprintln!(
        "[party {}] Exchanging ECDH public keys over existing network...",
        my_id
    );

    // Broadcast our PK to all peers via existing connections
    let connections = net.get_all_server_connections();
    for (peer_id, conn) in &connections {
        let authenticated_peer_id = conn.remote_party_id().unwrap_or(*peer_id);
        if authenticated_peer_id == my_id {
            continue;
        }
        if let Err(e) = conn.send(&envelope).await {
            eprintln!(
                "[party {}] Failed to send PK to peer {}: {}",
                my_id, authenticated_peer_id, e
            );
        }
    }

    // Collect PKs from all peers
    let mut pk_map: Vec<G> = vec![G::default(); n];
    pk_map[my_id] = pk_i;
    let mut received = 1usize;
    let mut seen = std::collections::HashSet::new();
    seen.insert(my_id);

    let (pk_tx, mut pk_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(n);

    for (peer_id, conn) in &connections {
        let authenticated_peer_id = conn.remote_party_id().unwrap_or(*peer_id);
        if authenticated_peer_id == my_id {
            continue;
        }
        let tx = pk_tx.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            match conn.receive().await {
                Ok(data) => {
                    let _ = tx.send((authenticated_peer_id, data)).await;
                }
                Err(e) => {
                    eprintln!(
                        "[AVSS] Failed to receive PK from peer {}: {}",
                        authenticated_peer_id, e
                    );
                }
            }
        });
    }
    drop(pk_tx);

    let pk_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while received < n {
        let remaining = pk_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, pk_rx.recv()).await {
            Ok(Some((peer_id, data))) => {
                if data.len() < 4 {
                    continue;
                }
                let claimed_id = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                // Verify the payload's claimed sender_id against the transport-authenticated
                // peer_id to prevent a malicious party from registering its key under a
                // different party's identity.
                if claimed_id != peer_id {
                    eprintln!(
                        "[party {}] AVSS PK exchange: transport sender {} claims to be party {} — ignoring",
                        my_id, peer_id, claimed_id
                    );
                    continue;
                }
                let sender_id = claimed_id;
                if sender_id >= n || !seen.insert(sender_id) {
                    continue;
                }
                match G::deserialize_compressed(&data[4..]) {
                    Ok(pk) => {
                        pk_map[sender_id] = pk;
                        received += 1;
                        eprintln!(
                            "[party {}] Received PK from party {} ({}/{})",
                            my_id, sender_id, received, n
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[party {}] Failed to deserialize PK from party {}: {:?}",
                            my_id, sender_id, e
                        );
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                return Err(format!(
                    "Timeout during PK exchange: received {}/{} keys",
                    received, n
                ));
            }
        }
    }

    if received < n {
        return Err(format!(
            "PK exchange incomplete: received {}/{} keys",
            received, n
        ));
    }
    eprintln!("[party {}] PK exchange complete ({} keys)", my_id, n);

    let pk_map = Arc::new(pk_map);

    // ---- Phase 3: Create engine directly with existing network ----
    use stoffel_vm::net::avss_engine::{AvssEngineConfig, AvssMpcEngine};
    let session = stoffel_vm::net::MpcSessionConfig::try_new(instance_id, my_id, n, t, net.clone())
        .map_err(|error| format!("Invalid AVSS MPC topology: {error}"))?
        .with_local_identity(local_identity)
        .with_input_ids(mpc_input_ids);
    let engine = AvssMpcEngine::<F, G>::from_config(
        AvssEngineConfig::new(session, sk_i, pk_map)
            .with_additional_random_shares(coordinator_mask_count),
    )
    .await
    .map_err(|e| format!("Failed to create AVSS engine: {}", e))?;
    engine.set_client_output_id_map(input_ids.clone()).await;

    engine
        .start_async()
        .await
        .map_err(|e| format!("Failed to start AVSS engine: {}", e))?;
    vm.set_mpc_engine(engine.clone());

    // ---- Phase 4: Spawn message loops on existing connections ----
    // Server message loops
    let (msg_tx, _server_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(65536);
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(4096);

    // Every server connection is read, the loopback one included: the engine
    // broadcasts to every party, itself too, and a party that never drains its
    // own loopback stream never sees its own protocol messages, so its
    // preprocessing waits forever. The HoneyBadger loops
    // (`spawn_receive_loops_split`) read it the same way.
    let mut spawned_senders = std::collections::HashSet::new();
    for (peer_id, conn) in &connections {
        let peer_id = *peer_id;
        let authenticated_sender_id = conn.remote_party_id().unwrap_or(peer_id);
        if authenticated_sender_id >= n || !spawned_senders.insert(authenticated_sender_id) {
            continue;
        }
        let engine = engine.clone();
        let open_message_router = engine.open_message_router();
        let tx = msg_tx.clone();
        let conn = conn.clone();
        let net_clone = net.clone();
        let mesh_router = mesh_router.clone();
        let digest_barriers = digest_barriers.clone();
        tokio::spawn(async move {
            // Blocker B6, seventh site: this loop is the production AVSS party
            // path and does not go through `AvssQuicServer`, so the mesh router
            // has to be offered every payload here too. It is first in the
            // chain, and `Err` continues rather than falling through — a
            // refused mesh frame is still a mesh frame and must never reach
            // `process_wrapped_message_with_network`.
            let peer_key = conn.authenticated_peer_public_key();
            while let Ok(data) = conn.receive().await {
                match mesh_router.try_handle_wire_message_from(
                    authenticated_sender_id,
                    peer_key.as_ref(),
                    &data,
                ) {
                    Ok(true) => continue,
                    Err(e) => {
                        eprintln!(
                            "[AVSS] Party refused a mesh control frame from {}: {}",
                            authenticated_sender_id, e
                        );
                        continue;
                    }
                    Ok(false) => {}
                }
                if digest_barriers
                    .as_ref()
                    .is_some_and(|barriers| barriers.record(authenticated_sender_id, &data))
                {
                    continue;
                }
                if let Ok(true) =
                    open_message_router.try_handle_wire_message(authenticated_sender_id, &data)
                {
                    continue;
                }
                if let Ok(true) = open_message_router
                    .try_handle_avss_open_exp_wire_message(authenticated_sender_id, &data)
                {
                    continue;
                }
                if let Ok(true) = open_message_router
                    .try_handle_avss_g2_exp_wire_message(authenticated_sender_id, &data)
                {
                    continue;
                }
                if let Err(e) = engine
                    .process_wrapped_message_with_network(
                        authenticated_sender_id,
                        &data,
                        net_clone.clone(),
                    )
                    .await
                {
                    let _ = tx.send((authenticated_sender_id, data)).await;
                    if !e.contains("deserialize") && !e.contains("process failed") {
                        eprintln!(
                            "[AVSS] Party failed to process message from {}: {}",
                            authenticated_sender_id, e
                        );
                    }
                }
            }
        });
    }

    // Client connection monitor
    let client_net = net.clone();
    tokio::spawn(async move {
        let mut spawned = std::collections::HashSet::new();
        loop {
            for (cid, conn) in client_net.get_all_client_connections() {
                if !spawned.insert(cid) {
                    continue;
                }
                let txx = client_tx.clone();
                tokio::spawn(async move {
                    while let Ok(data) = conn.receive().await {
                        if txx.send((cid, data)).await.is_err() {
                            break;
                        }
                    }
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Route client messages through the AVSS node's process()
    if !input_ids.is_empty() {
        let client_id_to_index: std::collections::HashMap<ClientId, usize> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (tid, idx))
            .collect();

        let processing_engine = engine.clone();
        let processing_net = net.clone();
        tokio::spawn(async move {
            while let Some((client_id, raw_msg)) = client_rx.recv().await {
                let mpc_sender_id = client_id_to_index
                    .get(&client_id)
                    .copied()
                    .unwrap_or(client_id);
                if let Err(e) = processing_engine
                    .process_wrapped_message_with_network(
                        mpc_sender_id,
                        &raw_msg,
                        processing_net.clone(),
                    )
                    .await
                {
                    eprintln!(
                        "[party {}] Failed to process client message from {} (idx {}): {:?}",
                        processing_engine.party().id(),
                        client_id,
                        mpc_sender_id,
                        e
                    );
                }
            }
        });
    }

    // ---- Phase 5: Preprocessing ----
    tokio::time::sleep(Duration::from_secs(2)).await;
    eprintln!("[party {}] Starting AVSS preprocessing...", my_id);
    engine.preprocess().await?;
    eprintln!("[party {}] AVSS preprocessing complete!", my_id);

    // ---- Phase 6: Client input initialization ----
    if !input_ids.is_empty() {
        let client_index_map: Vec<(usize, ClientId)> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (idx, tid))
            .collect();

        let server_adapter = Arc::new(ServerClientAdapter {
            inner: (*net).clone(),
            client_id_map: client_index_map.iter().map(|(_, tid)| *tid).collect(),
        });

        eprintln!(
            "[party {}] Initializing AVSS InputServer for {} clients...",
            my_id,
            client_index_map.len()
        );
        {
            let mut node = engine.node_handle().lock().await;
            for &(idx, _tid) in &client_index_map {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_v_random_shares(client_input_count)
                    .map_err(|e| format!("Not enough random shares for client {}: {:?}", idx, e))?;

                node.input_server
                    .init(
                        idx,
                        local_shares,
                        client_input_count,
                        server_adapter.clone(),
                    )
                    .await
                    .map_err(|e| {
                        format!("Failed to init InputServer for client {}: {:?}", idx, e)
                    })?;
                eprintln!(
                    "[party {}] InputServer initialized for client index {}",
                    my_id, idx
                );
            }
        }

        // Signal readiness to clients
        eprintln!(
            "[party {}] Sending INST to {} clients...",
            my_id,
            client_index_map.len()
        );
        for &(idx, tid) in &client_index_map {
            let mut inst_msg = Vec::with_capacity(13);
            inst_msg.extend_from_slice(b"INST");
            inst_msg.extend_from_slice(&instance_id.to_le_bytes());
            inst_msg.push(idx as u8);
            if let Err(e) = net.send_to_client(tid, &inst_msg).await {
                eprintln!(
                    "[party {}] Failed to send INST to client {}: {:?}",
                    my_id, tid, e
                );
            }
        }

        // Wait for all client inputs
        eprintln!(
            "[party {}] Waiting for all client inputs (timeout=600s)...",
            my_id
        );
        let client_inputs = {
            let mut node = engine.node_handle().lock().await;
            node.input_server
                .wait_for_all_inputs(Duration::from_secs(600))
                .await
                .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?
        };

        for (idx, shares) in client_inputs {
            let transport_cid = client_index_map
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, tid)| *tid)
                .unwrap_or(idx);
            if let Some(share_types) = client_input_types.get(&idx) {
                vm.try_store_client_input_feldman_with_types(idx, shares, share_types)?;
            } else {
                vm.try_store_client_input_feldman(idx, shares)?;
            }
            eprintln!(
                "[party {}] Stored inputs for client index {} (client {})",
                my_id, idx, transport_cid
            );
        }
    }

    Ok(engine)
}
/// Everything a coordinated AVSS party needs, gathered once after the join.
struct CoordinatedAvssParty<'a> {
    vm: &'a mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    /// The pinned link that fetched the node roster (§9.D.1 step 10).
    link: CoordinatorLink,
    rpc_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    execution_id: ExecutionId,
    agreed_entry: &'a str,
    program_hash: [u8; 32],
    manifest: &'a ClientIoManifest,
    mesh_router: Arc<MeshRouter>,
    digest_barriers: DigestBarriers,
}

async fn run_avss_coordinated_party_for_curve<F, G>(
    party: CoordinatedAvssParty<'_>,
) -> Result<(), CoordinatedRunError>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let CoordinatedAvssParty {
        vm,
        net,
        my_id,
        n,
        t,
        instance_id,
        link,
        rpc_addr,
        cert_der,
        key_der,
        execution_id,
        agreed_entry,
        program_hash,
        manifest,
        mesh_router,
        digest_barriers,
    } = party;

    // §9.D.1 step 10: the link that fetched the roster drives the rounds. No
    // second connection and no second roster fetch.
    let mut coord: AvssOffChainCoordinator<F, G> =
        AvssOffChainCoordinator::<F, G>::from_link(link, execution_id);

    // §9.D.7 step 1: before any preprocessing, and before the pool is sized.
    let summary = checked_execution_summary::<F, AvssCoordinatorShare<F, G>>(
        &coord,
        &SummaryExpectations {
            execution_id,
            program_hash,
            backend: MpcBackendKind::Avss,
            n,
            t,
            manifest,
        },
    )
    .await?;
    let mask_count = mask_count_of(&summary)?;

    // The node RPC listener is per-execution: every client request carries the execution it
    // belongs to, and an unregistered one is rejected.
    let node_rpc = OffChainNodeRPCServer::start_for_execution(
        &rpc_addr.0,
        rpc_addr.1,
        execution_id,
        cert_der.clone(),
        key_der.clone(),
    )
    .await
    .map_err(|error| {
        CoordinatedRunError::Setup(format!("Failed to start AVSS node RPC server: {error}"))
    })?;

    // Every party proposes every transition; the coordinator applies a round once a quorum
    // of the roster has proposed it.
    coord.start_preprocessing().await?;

    let client_input_types = manifest_client_input_types(manifest);
    let engine = setup_avss_party_for_curve::<F, G>(
        vm,
        net.clone(),
        AvssPartySetup {
            my_id,
            local_identity: durable_identity_from_cert(&cert_der),
            n,
            t,
            instance_id,
            expected_client_count: None,
            client_input_count: 1,
            client_input_types: &client_input_types,
            coordinator_mask_count: mask_count,
            digest_barriers: Some(digest_barriers.clone()),
            mesh_router,
        },
    )
    .await
    .map_err(CoordinatedRunError::Setup)?;
    engine.enable_client_output_capture().await;

    let mut admissions = None;
    if mask_count == 0 {
        eprintln!(
            "[party {}] execution {execution_id} registers no client inputs; skipping input collection",
            my_id
        );
    } else {
        // One mask per registered input, at indices `0..mask_count`.
        let mask_shares = {
            let node = engine.node_handle().lock().await;
            let shares = node
                .preprocessing_material
                .lock()
                .await
                .take_v_random_shares(mask_count)
                .map_err(|error| {
                    CoordinatedRunError::Setup(format!(
                        "Not enough AVSS random shares for {mask_count} input masks: {error:?}"
                    ))
                })?;
            shares
        };
        let (set, inputs) = collect_admitted_client_inputs(
            &mut coord,
            &node_rpc,
            &summary,
            &digest_barriers,
            net.as_ref(),
            mask_shares,
        )
        .await?;
        for (client_index, shares) in inputs {
            let slot = client_index.0 as usize;
            let stored = match client_input_types.get(&slot) {
                Some(share_types) => {
                    vm.try_store_client_input_feldman_with_types(slot, shares, share_types)
                }
                None => vm.try_store_client_input_feldman(slot, shares),
            };
            stored.map_err(|error| {
                CoordinatedRunError::Setup(format!(
                    "Failed to store AVSS input shares for client slot {slot}: {error}"
                ))
            })?;
        }
        admissions = Some(set);
    }

    coord.start_mpc().await?;
    coord.wait_for_round(Round::MPCExecution).await?;
    // An execution without inputs freezes its admissions when `MPCExecution` begins.
    let set = match admissions {
        Some(set) => set,
        None => {
            agree_client_admissions(&mut coord, &summary, &digest_barriers, net.as_ref()).await?
        }
    };
    vm.set_client_roster(coordinated_client_roster(&summary));

    eprintln!("Starting VM execution of '{}'...", agreed_entry);
    let result = vm
        .execute(agreed_entry)
        .map_err(|error| CoordinatedRunError::Execution {
            entry: agreed_entry.to_owned(),
            reason: error.to_string(),
        })?;

    let captured = engine
        .drain_client_output_records()
        .await
        .into_iter()
        .map(|record| (record.client_id, record.shares))
        .collect();
    finish_coordinated_execution(&coord, &summary, &set, captured, agreed_entry).await?;

    print_vm_result(vm, result);
    Ok(())
}

async fn run_avss_coordinated_party(
    curve_config: MpcCurveConfig,
    party: CoordinatedAvssParty<'_>,
) -> Result<(), CoordinatedRunError> {
    match curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_avss_coordinated_party_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
                party,
            )
            .await
        }
        MpcCurveConfig::Bn254 => {
            run_avss_coordinated_party_for_curve::<ark_bn254::Fr, ark_bn254::G1Projective>(party)
                .await
        }
        MpcCurveConfig::Curve25519 => {
            run_avss_coordinated_party_for_curve::<
                ark_curve25519::Fr,
                ark_curve25519::EdwardsProjective,
            >(party)
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_avss_coordinated_party_for_curve::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>(
                party,
            )
            .await
        }
        MpcCurveConfig::Secp256k1 => {
            run_avss_coordinated_party_for_curve::<ark_secp256k1::Fr, ark_secp256k1::Projective>(
                party,
            )
            .await
        }
        MpcCurveConfig::Secp256r1 => {
            run_avss_coordinated_party_for_curve::<ark_secp256r1::Fr, ark_secp256r1::Projective>(
                party,
            )
            .await
        }
    }
}

// Use a Tokio runtime for async operations
#[tokio::main]
async fn main() {
    // When spawned by the local coordinator runner, tie this process's lifetime
    // to its parent: if the parent (the test/CLI/SDK process) dies — including a
    // SIGKILL, where the parent's `kill_on_drop` cleanup cannot run — this party
    // would otherwise be re-parented to init/launchd and leak as an orphaned MPC
    // process. Poll the parent PID and exit promptly once it changes.
    if std::env::var_os("STOFFEL_DIE_WITH_PARENT").is_some() {
        // SAFETY: `getppid` is always safe to call and takes no arguments.
        let original_parent = unsafe { libc::getppid() };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                // SAFETY: see above.
                let current = unsafe { libc::getppid() };
                if current != original_parent || current <= 1 {
                    eprintln!(
                        "[watchdog] parent process exited (ppid {original_parent} -> {current}); shutting down"
                    );
                    std::process::exit(0);
                }
            }
        });
    }

    let raw_args = env::args().skip(1).collect::<Vec<_>>();

    if raw_args.is_empty() {
        print_usage_and_exit();
    }

    let mut entry: String = "main".to_string();

    let mut trace_instr = false;
    let mut trace_regs = false;
    let mut trace_stack = false;
    // `--leader` carried two unrelated meanings (docs/design/bootnode-elimination.md
    // §5, row 6): "run an in-process bootnode and register with it", and "advance
    // the off-chain coordinator's `Round`s". Stage 6 split the second out as
    // `--coord-driver`; Stage 8 deleted the bootnode, and `--leader` with it.
    //
    // Stage 9 deleted `--coord-driver` too. Coordinator `0.1.0` hard-gated
    // `transition` on `mpc_nodes[0]`, so exactly one party had to drive the
    // rounds; `0.2.0` records a vote from any roster member and applies a round
    // once `transition_quorum()` of them have proposed it. Every party therefore
    // proposes every transition, and a proposal for a round the quorum already
    // passed is a no-op rather than an error. There is no designated party left
    // on this path at all.
    let mut as_client = false;
    let mut bind_addr: Option<SocketAddr> = None;
    // `--party-id` is no longer an identity: every party index is derived from
    // the lexicographic order of the coordinator roster's DER SPKIs, and the runner has
    // discarded any externally assigned id since before this migration started.
    // It is not what selects party mode either — `--peers` is. What it still
    // does is label this node's on-disk state: the `--local-store` /
    // `--preproc-store` paths and the `party-N.redb` volumes the compose stacks
    // mount are named by it. It is not the *key* to that state — that is
    // `DurableIdentityDigest`, derived from this node's certificate — so a label
    // that disagrees with the derived rank is reported after the join and the
    // run continues on the derived index.
    let mut party_id: Option<usize> = None;
    let mut client_inputs: Option<String> = None;
    let mut output_fixed_point_fractional_bits: Option<usize> = None;
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut mpc_backend: Option<String> = None;
    let mut mpc_curve: Option<String> = None;
    let mut rpc_addr: Option<(String, u16)> = None;
    let mut coord_addr: Option<(String, u16)> = None;
    // `--coord-cert`: the coordinator certificate every coordinator connection
    // pins. Resolved into a `CoordinatorPin` once the flags are parsed.
    let mut coord_cert_path: Option<String> = None;
    // `--expect-roster-digest`, `--expect-n-parties`, `--expect-threshold`:
    // refusals of a coordinator roster other than the intended one (§9.D.2).
    let mut roster_expectations = RosterExpectations::default();
    let mut key_der: Option<Vec<u8>> = None;
    let mut cert_der: Option<Vec<u8>> = None;
    // `--cert`'s path, kept so a refusal can name the file.
    let mut cert_path: Option<String> = None;
    // `--peers`: addresses to try first. Hints, not membership — see
    // `SeedHints` and `docs/design/bootnode-elimination.md` §8. Membership is
    // the coordinator's node roster (§9.D).
    let mut peer_hints: Vec<SocketAddr> = Vec::new();
    let mut eth_node_addr: Option<String> = None;
    let mut wallet_sk_str: Option<String> = None;
    let mut contract_addr: Option<String> = None;
    let mut coordinator_client_slot: Option<ClientIndex> = None;
    // `--invitation` and `--expect-program-hash`: a coordinator client's invitation, and the
    // program it refuses to associate with any other one of (§9.E.2).
    let mut invitation_path: Option<String> = None;
    let mut expected_program_hash: Option<[u8; 32]> = None;
    let mut preproc_store_path: Option<String> = None;
    let mut local_store_path: Option<String> = None;
    // `--epoch-store`: where this node's monotone instance_id epoch lives
    // (blocker B5). See `stoffel_vm::net::mesh::epoch` for the path, the
    // environment variable and the compose volume it belongs on.
    let mut epoch_store_flag: Option<String> = None;
    // `--execution-id`: which program invocation this process belongs to.
    // Coordinator `0.2.0` keys every RPC on it — rounds, reserved indices,
    // masked inputs and output shares are all per-execution — so it replaces
    // `0.1.0`'s single implicit session and its `reset_coord` teardown. Required
    // whenever `--off-chain-coord` is given; the all-zero value is reserved and
    // rejected by the coordinator, so it is rejected here too.
    let mut execution_id: Option<ExecutionId> = None;
    let mut advertise_addr: Option<SocketAddr> = None;

    for arg in &raw_args {
        if arg == "-h" || arg == "--help" {
            print_usage_and_exit();
        } else if arg == "--trace-instr" {
            trace_instr = true;
        } else if arg == "--trace-regs" {
            trace_regs = true;
        } else if arg == "--trace-stack" {
            trace_stack = true;
        } else if arg == "--client" {
            as_client = true;
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--inputs") {
        } else if let Some(_rest) = arg.strip_prefix("--output-fixed-point-fractional-bits") {
        } else if let Some(_rest) = arg.strip_prefix("--servers") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-backend") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-curve") {
        } else if let Some(_rest) = arg.strip_prefix("--rpc-bind") {
        } else if let Some(_rest) = arg.strip_prefix("--off-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--coord-cert") {
        } else if let Some(_rest) = arg.strip_prefix("--on-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--eth-node") {
        } else if let Some(_rest) = arg.strip_prefix("--wallet-sk") {
        } else if let Some(_rest) = arg.strip_prefix("--key") {
        } else if let Some(_rest) = arg.strip_prefix("--cert") {
        } else if let Some(_rest) = arg.strip_prefix("--expect-roster-digest") {
        } else if let Some(_rest) = arg.strip_prefix("--expect-n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--expect-threshold") {
        } else if let Some(_rest) = arg.strip_prefix("--peers") {
        } else if let Some(_rest) = arg.strip_prefix("--client-slot") {
        } else if let Some(_rest) = arg.strip_prefix("--preproc-store") {
        } else if let Some(_rest) = arg.strip_prefix("--epoch-store") {
        } else if let Some(_rest) = arg.strip_prefix("--execution-id") {
        } else if let Some(_rest) = arg.strip_prefix("--local-store") {
        } else if let Some(_rest) = arg.strip_prefix("--advertise") {
        }
    }

    // `docs/design/bootnode-elimination.md` §9.D.3. The coordinator is the only
    // roster authority, and client participation is its per-execution admission,
    // so every flag that gave a node a membership list, a party count, a
    // threshold or a client list of its own fails by name. None of the hints
    // names a removed flag, so an operator is never sent from one refusal to the
    // next.
    for (flag, hint) in REMOVED_FLAGS {
        fail_removed_flag(&raw_args, flag, hint);
    }
    fail_removed_flag(
        &raw_args,
        "--node-ids",
        "On-chain coordinator mode is temporarily unavailable in the crates.io-ready build.",
    );
    fail_removed_flag(
        &raw_args,
        "--adkg-curve",
        "Use `--mpc-curve <name>` instead.",
    );
    // Stage 8 of `docs/design/bootnode-elimination.md`. Each of these names the
    // replacement rather than just disappearing: a flag that silently stops
    // being parsed turns a deployment that no longer forms a session into a
    // debugging session, and every one of these appeared in a shipped compose
    // file, script or README command line.
    fail_removed_flag(
        &raw_args,
        "--leader",
        "`--leader` meant two unrelated things and both are gone. Its bootnode half was \
         removed with the bootnode; its round-driver half was removed when coordinator \
         transitions became quorum-gated, so every party now proposes every round.",
    );
    fail_removed_flag(
        &raw_args,
        "--no-program-upload",
        "Nothing uploads program bytes during session formation any more. Mount the \
         program and pass its path, as every shipped stack already does.",
    );
    fail_removed_flag(
        &raw_args,
        "--nat",
        "The `nat` feature never worked and is removed (design doc §4): nothing read the \
         flag, and the shipped path ran no connectivity checks. Give every party a \
         reachable `--advertise` address.",
    );
    fail_removed_flag(
        &raw_args,
        "--stun-servers",
        "The `nat` feature never worked and is removed (design doc §4). Give every party \
         a reachable `--advertise` address.",
    );

    // collect positional args (non-flags)
    let mut positional = raw_args
        .into_iter()
        .filter(|a| !a.starts_with("--"))
        .collect::<Vec<_>>();

    if positional.is_empty() {
        print_usage_and_exit();
    }

    // Parse key-value style flags
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--bind" => {
                if let Some(v) = args_iter.next() {
                    bind_addr = Some(v.parse().expect("Invalid --bind addr"));
                }
            }
            "--party-id" => {
                if let Some(v) = args_iter.next() {
                    party_id = Some(v.parse().expect("Invalid --party-id"));
                }
            }
            "--inputs" => {
                if let Some(v) = args_iter.next() {
                    client_inputs = Some(v);
                }
            }
            "--output-fixed-point-fractional-bits" => {
                if let Some(v) = args_iter.next() {
                    output_fixed_point_fractional_bits = Some(
                        v.parse()
                            .expect("Invalid --output-fixed-point-fractional-bits"),
                    );
                }
            }
            "--servers" => {
                if let Some(v) = args_iter.next() {
                    server_addrs = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--mpc-backend" => {
                if let Some(v) = args_iter.next() {
                    mpc_backend = Some(v);
                }
            }
            "--mpc-curve" => {
                if let Some(v) = args_iter.next() {
                    mpc_curve = Some(v);
                }
            }
            "--rpc-bind" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --rpc-bind port");
                    let host = parts[1].to_string();
                    rpc_addr = Some((host, port));
                }
            }
            "--off-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --off-chain-coord port");
                    let host = parts[1].to_string();
                    coord_addr = Some((host, port));
                }
            }
            "--coord-cert" => {
                if let Some(v) = args_iter.next() {
                    coord_cert_path = Some(v);
                }
            }
            "--on-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    contract_addr = Some(v);
                }
            }
            "--eth-node" => {
                if let Some(v) = args_iter.next() {
                    eth_node_addr = Some(v);
                }
            }
            "--wallet-sk" => {
                if let Some(v) = args_iter.next() {
                    wallet_sk_str = Some(v);
                }
            }
            "--key" => {
                if let Some(v) = args_iter.next() {
                    key_der = Some(std::fs::read(&v).expect("Failed to read --key file"));
                }
            }
            "--cert" => {
                if let Some(v) = args_iter.next() {
                    cert_der = Some(std::fs::read(&v).expect("Failed to read --cert file"));
                    cert_path = Some(v);
                }
            }
            "--expect-roster-digest" => {
                if let Some(v) = args_iter.next() {
                    roster_expectations.digest =
                        Some(parse_expected_roster_digest(&v).unwrap_or_else(|message| {
                            eprintln!("Error: {message}");
                            exit(2);
                        }));
                }
            }
            "--expect-n-parties" => {
                if let Some(v) = args_iter.next() {
                    roster_expectations.n_parties = Some(
                        parse_expected_roster_size(RosterSizeFlag::NParties, &v).unwrap_or_else(
                            |message| {
                                eprintln!("Error: {message}");
                                exit(2);
                            },
                        ),
                    );
                }
            }
            "--expect-threshold" => {
                if let Some(v) = args_iter.next() {
                    roster_expectations.threshold = Some(
                        parse_expected_roster_size(RosterSizeFlag::Threshold, &v).unwrap_or_else(
                            |message| {
                                eprintln!("Error: {message}");
                                exit(2);
                            },
                        ),
                    );
                }
            }
            "--invitation" => {
                if let Some(v) = args_iter.next() {
                    invitation_path = Some(v);
                }
            }
            "--expect-program-hash" => {
                if let Some(v) = args_iter.next() {
                    expected_program_hash =
                        Some(parse_expected_program_hash(&v).unwrap_or_else(|message| {
                            eprintln!("Error: {message}");
                            exit(2);
                        }));
                }
            }
            "--client-slot" => {
                if let Some(v) = args_iter.next() {
                    coordinator_client_slot = Some(ClientIndex(v.parse().unwrap_or_else(|_| {
                        eprintln!("Error: --client-slot takes a slot number, got {v:?}");
                        exit(2);
                    })));
                }
            }
            "--preproc-store" => {
                if let Some(v) = args_iter.next() {
                    preproc_store_path = Some(v);
                }
            }
            "--local-store" => {
                if let Some(v) = args_iter.next() {
                    local_store_path = Some(v);
                }
            }
            "--epoch-store" => {
                if let Some(v) = args_iter.next() {
                    epoch_store_flag = Some(v);
                }
            }
            "--execution-id" => {
                if let Some(v) = args_iter.next() {
                    let parsed = ExecutionId::from_str(v.trim()).unwrap_or_else(|error| {
                        eprintln!("Error: invalid --execution-id: {error}");
                        exit(2);
                    });
                    if parsed.is_zero() {
                        eprintln!(
                            "Error: --execution-id must not be all zeros; the coordinator \
                             reserves that value and rejects it."
                        );
                        exit(2);
                    }
                    execution_id = Some(parsed);
                }
            }
            "--peers" => {
                if let Some(v) = args_iter.next() {
                    peer_hints = v
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse().expect("Invalid --peers address"))
                        .collect();
                }
            }
            "--advertise" => {
                if let Some(v) = args_iter.next() {
                    advertise_addr = Some(v.parse().expect("Invalid --advertise addr"));
                }
            }
            _ => {}
        }
    }

    let coordinator_output_format = match output_fixed_point_fractional_bits {
        Some(bits) => {
            if bits > 62 {
                eprintln!("Error: --output-fixed-point-fractional-bits must be <= 62");
                exit(2);
            }
            CoordinatorOutputFormat::FixedPoint {
                fractional_bits: bits,
            }
        }
        None => CoordinatorOutputFormat::FieldInteger,
    };
    let storage_identity = required_storage_identity(
        &cert_der,
        &key_der,
        local_store_path.is_some() || preproc_store_path.is_some(),
    );
    let coord_execution_id = resolve_coord_execution_id(coord_addr.is_some(), execution_id)
        .unwrap_or_else(|message| {
            eprintln!("Error: {message}");
            exit(2);
        });
    let coordinator_pin = resolve_coordinator_pin(coord_addr.is_some(), coord_cert_path.as_deref())
        .unwrap_or_else(|message| {
            eprintln!("Error: {message}");
            exit(2);
        });
    // §9.D.2: the `--expect-*` flags refuse a roster a coordinator served, so
    // without one they have nothing to refuse.
    if coord_addr.is_none() {
        if let Some(flag) = roster_expectations.first_flag() {
            eprintln!(
                "Error: {flag} is only meaningful with --off-chain-coord; it refuses a node \
                 roster the coordinator serves."
            );
            exit(2);
        }
    }

    // --- Seed hints (docs/design/bootnode-elimination.md §5, row 4) ---
    //
    // `--peers` is a list of addresses to try, not a statement of membership:
    // membership is the coordinator's node roster (§9.D), and every dial made
    // from a hint pins a roster certificate, so a wrong or hostile address costs
    // a failed handshake and nothing else.
    //
    // A *missing* address is not equally cheap. A first join forms out of dials,
    // and the peer book is exchanged inside the join handshake — after the mesh
    // is already complete — so PEX cannot supply an address the mesh needs in
    // order to form. The real requirement is per pair: for every two parties, at
    // least one of them must hold a hint for the other. Nothing here enforces
    // n-1 entries because a partial list can be covered from the other side, but
    // `build_session_join` warns when it is short of n-1.
    let seed_hints = SeedHints::new(peer_hints, advertise_addr.or(bind_addr));
    if !seed_hints.is_empty() {
        eprintln!(
            "[mesh] {} seed peer hint(s) recorded, not yet dialed: {}",
            seed_hints.len(),
            seed_hints
                .addrs()
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // --- The join (docs/design/bootnode-elimination.md §5) ---
    //
    // `--peers` is what makes this process a party rather than a local run:
    // there is no bootstrap process to register with any more, so seeds are the
    // only way into a session.
    let mesh_join_requested = !seed_hints.is_empty();

    // §9.D.3: a mesh's membership has exactly one source, so a party without a
    // coordinator has none. Refused before anything is opened or bound.
    if mesh_join_requested && !as_client && coord_addr.is_none() {
        eprintln!(
            "Error: --peers forms a mesh whose membership only the coordinator defines. Pass \
             --off-chain-coord <host:port>, --coord-cert <path> and --execution-id <64-hex>."
        );
        exit(2);
    }
    // A coordinated execution is run by a mesh of parties: the summary, the
    // agreement barriers and the admissions all belong to a party (§9.D.7).
    if coord_addr.is_some() && !as_client && !mesh_join_requested {
        CoordinatedRunError::Setup(
            "--off-chain-coord runs a party of a mesh; pass --peers so this node joins one"
                .to_owned(),
        )
        .exit();
    }
    // §9.D.1 step 1: a party's own identity is read before any network I/O.
    let party_identity = if mesh_join_requested && !as_client {
        match (
            cert_path.as_deref(),
            cert_der.as_deref(),
            key_der.as_deref(),
        ) {
            (Some(cert_path), Some(cert_der), Some(key_der)) => Some(NodeIdentity {
                cert_path,
                cert_der,
                key_der,
            }),
            _ => {
                eprintln!(
                    "Error: a party needs --cert and --key: the coordinator's node roster names \
                     nodes by certificate, and a node proves it is one of them with its key."
                );
                exit(2);
            }
        }
    } else {
        None
    };

    // Not opened for a client, which joins no session and derives no
    // `instance_id` of its own (blocker B5).
    let epoch_store: Option<Arc<EpochStore>> = if mesh_join_requested && !as_client {
        let path = epoch_store_path(epoch_store_flag.as_deref());
        match EpochStore::open(&path) {
            Ok(store) => {
                eprintln!("[mesh] session epoch store at {}", path.display());
                Some(Arc::new(store))
            }
            Err(error) => {
                eprintln!("Error: {}", error);
                exit(2);
            }
        }
    } else {
        None
    };

    if contract_addr.is_some() {
        let _ = (eth_node_addr.as_ref(), wallet_sk_str.as_ref());
        eprintln!(
            "Error: on-chain coordinator mode is temporarily unavailable in the crates.io-ready build"
        );
        exit(2);
    }

    // `--client-slot`, `--invitation` and `--expect-program-hash` shape a coordinator
    // client's association; nothing else associates.
    let is_coordinator_client = as_client && coord_addr.is_some();
    for (given, flag, meaning) in [
        (
            coordinator_client_slot.is_some(),
            "--client-slot",
            "it names the client slot to bind",
        ),
        (
            invitation_path.is_some(),
            "--invitation",
            "it is presented when the client associates",
        ),
        (
            expected_program_hash.is_some(),
            "--expect-program-hash",
            "it refuses to associate with an execution of another program",
        ),
    ] {
        if given && !is_coordinator_client {
            eprintln!(
                "Error: {flag} is only meaningful for a coordinator client (--client with \
                 --off-chain-coord); {meaning}."
            );
            exit(2);
        }
    }

    // Client mode: associate through the coordinator and provide inputs (§9.E.1).
    if as_client {
        // §9.E.3: a client reaching nodes through the mesh transport would need
        // every node to allowlist its key before the node's manager is shared —
        // an identity known in advance, which clients need not have — and that
        // allowlist is role-blind, so the key could dial as a node. Clients
        // therefore associate through the coordinator, and nothing else.
        let Some(coord) = coord_addr.clone() else {
            eprintln!(
                "Error: direct client mode was removed. A client associates with an execution \
                 through the coordinator: pass --off-chain-coord <host:port>, --coord-cert \
                 <path>, --execution-id <64-hex> and --servers <node RPC addresses>."
            );
            exit(2);
        };
        let coordinator_pin =
            coordinator_pin.expect("--coord-cert is resolved wherever --off-chain-coord is");
        let backend = match mpc_backend.as_deref() {
            Some(name) => MpcBackendKind::from_str(name).unwrap_or_else(|error| {
                eprintln!("Error: {error}");
                exit(2);
            }),
            None => MpcBackendKind::HoneyBadger,
        };
        let curve_config = match mpc_curve.as_deref() {
            Some(name) => MpcCurveConfig::from_str(name).unwrap_or_else(|error| {
                eprintln!("Error: {error}");
                exit(2);
            }),
            None => MpcCurveConfig::default(),
        };
        if let Err(error) = curve_config.validate_for_backend(backend) {
            eprintln!("Error: {error}");
            exit(2);
        }
        let (Some(cert_der), Some(key_der)) = (cert_der.clone(), key_der.clone()) else {
            eprintln!(
                "Error: a coordinator client needs --cert and --key: its admission is keyed on \
                 its certificate, and its key signs its inputs and opens its outputs."
            );
            exit(2);
        };
        // Checked before anything is dialed: an association is irrevocable, so a
        // client that could not reach a node after associating would hold its
        // slot until the coordinator's deadline aborted the execution.
        if server_addrs.is_empty() {
            eprintln!(
                "Error: a coordinator client needs --servers <node RPC addresses>: it fetches \
                 its masks from the parties' --rpc-bind listeners, each pinned to the \
                 coordinator's node roster."
            );
            exit(2);
        }
        let invitation = invitation_path.as_deref().map(|path| {
            read_invitation(path).unwrap_or_else(|message| {
                eprintln!("Error: {message}");
                exit(2);
            })
        });
        run_coordinator_client(ClientRunArgs {
            backend,
            curve_config,
            inputs: client_inputs,
            output_format: coordinator_output_format,
            coord_addr: coord,
            coordinator_pin,
            roster_expectations,
            expected_program_hash,
            request: AssociationRequest {
                slot: coordinator_client_slot,
                invitation,
            },
            server_addrs,
            cert_der,
            key_der,
            execution_id: coord_execution_id,
        })
        .await;
        return;
    }

    let path_opt = if !positional.is_empty() {
        Some(positional.remove(0))
    } else {
        None
    };
    entry = if !positional.is_empty() {
        positional.remove(0)
    } else {
        entry
    };

    let manifest_config = path_opt.as_ref().map(|path| {
        let file = File::open(path).unwrap_or_else(|error| {
            eprintln!(
                "Error: failed to open compiled program '{}': {}",
                path, error
            );
            exit(2);
        });
        let (_, bytecode_version, client_io_manifest) =
            CompiledBinary::try_for_each_vm_function_from_reader(&mut BufReader::new(file), |_| {
                Ok(())
            })
            .unwrap_or_else(|error| {
                eprintln!(
                    "Error: failed to deserialize compiled program '{}': {:?}",
                    path, error
                );
                exit(2);
            });
        let backend = (bytecode_version >= MPC_BACKEND_MANIFEST_FORMAT_VERSION)
            .then_some(MpcBackendKind::from(client_io_manifest.mpc_backend));
        let curve = (bytecode_version >= MPC_CURVE_MANIFEST_FORMAT_VERSION)
            .then_some(curve_config_from_manifest(client_io_manifest.mpc_curve));
        (backend, curve)
    });
    let manifest_backend = manifest_config.and_then(|(backend, _)| backend);
    let manifest_curve = manifest_config.and_then(|(_, curve)| curve);

    // Resolve MPC backend kind. v3+ binaries are authoritative; --mpc-backend
    // remains for client mode and legacy v1/v2 binaries without backend metadata.
    let backend_kind = if let Some(ref name) = mpc_backend {
        let cli_backend = match MpcBackendKind::from_str(name) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        };
        if let Some(manifest_backend) = manifest_backend {
            if cli_backend != manifest_backend {
                eprintln!(
                    "Error: --mpc-backend '{}' does not match program manifest backend '{}'",
                    cli_backend.name(),
                    manifest_backend.name()
                );
                exit(2);
            }
        }
        cli_backend
    } else if let Some(manifest_backend) = manifest_backend {
        manifest_backend
    } else {
        MpcBackendKind::default_backend()
    };

    let curve_config = if let Some(ref name) = mpc_curve {
        let cli_curve = match MpcCurveConfig::from_str(name) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        };
        if let Some(manifest_curve) = manifest_curve {
            if cli_curve != manifest_curve {
                eprintln!(
                    "Error: --mpc-curve '{}' does not match program manifest curve '{}'",
                    cli_curve.name(),
                    manifest_curve.name()
                );
                exit(2);
            }
        }
        cli_curve
    } else {
        manifest_curve.unwrap_or_default()
    };

    if let Err(e) = curve_config.validate_for_backend(backend_kind) {
        eprintln!("Error: {}", e);
        exit(2);
    }

    // Validate incompatible flag combinations
    if !backend_kind.supports_client_input() && as_client {
        eprintln!(
            "Error: {} backend does not support client mode",
            backend_kind.name()
        );
        exit(2);
    }

    // Optional: bring up networking in party mode when seeds were given.
    let mut net_opt: Option<Arc<QuicNetworkManager>> = None;
    let program_id: [u8; 32];
    let mut agreed_entry = entry.clone();
    let mut session_instance_id: Option<u64> = None;
    let mut session_n_parties: Option<usize> = None;
    let mut session_threshold: Option<usize> = None;
    // The mesh control plane's receive side, shared by every party receive loop
    // this process spawns (blocker B6). Built once, in party mode pinned to the
    // coordinator's node roster: an unpinned book lets any
    // transport-authenticated peer insert arbitrary SPKIs, while a pinned one
    // refuses anything outside the roster for one set lookup.
    let mesh_router: Arc<MeshRouter>;
    // The pinned coordinator link that fetched the roster (§9.D.1 step 2). It
    // becomes the round driver once the backend and curve are resolved (step
    // 10): no second connection and no second roster fetch.
    let mut coordinator_link: Option<CoordinatorLink> = None;

    if mesh_join_requested {
        // Party mode. One way in since Stage 8: form a roster-pinned mesh from
        // the seed addresses. There is no bootstrap process, no "leader mode"
        // that runs one in-process, and since Stage 9 no round driver either —
        // both halves of what `--leader` meant are gone. Since §9.D the roster
        // is the coordinator's, fetched once, before anything is bound.
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path in party mode
        if path_opt.is_none() {
            eprintln!("Error: party mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // §9.D.1 steps 2-5: the pinned coordinator link, the roster it served
        // (fetched once), this node's membership and the VM roster, all before
        // a socket is bound. `n` and `t` have exactly one source: that roster.
        let identity = party_identity
            .as_ref()
            .expect("a party's identity is read before any network I/O");
        let coord = coord_addr
            .as_ref()
            .expect("--peers without --off-chain-coord was refused above");
        let pin = coordinator_pin
            .as_ref()
            .expect("--coord-cert is resolved wherever --off-chain-coord is");
        let (link, roster) = fetch_node_roster(
            coord,
            pin,
            roster_expectations,
            NodeIdentity {
                cert_path: identity.cert_path,
                cert_der: identity.cert_der,
                key_der: identity.key_der,
            },
        )
        .await;
        coordinator_link = Some(link);
        let n = roster.n();
        let t = roster.t();

        // §9.D.1 step 6: the transport.
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        if let Err(e) =
            mgr.set_local_certificate_der(identity.cert_der.to_vec(), identity.key_der.to_vec())
        {
            eprintln!("Failed to configure local node certificate: {}", e);
            exit(11);
        }
        // Listen so peers can connect back directly
        if let Err(e) = mgr.listen(bind).await {
            eprintln!("Failed to listen on {}: {}", bind, e);
            exit(11);
        }

        // Note: if using port 0, the OS assigns a port. For now we use the bind address.
        // In a real deployment, you should use specific ports, not port 0.
        let actual_listen = bind;
        eprintln!(
            "[party {}] Listening on {}, forming a roster-pinned mesh from {} seed(s)",
            my_id,
            actual_listen,
            seed_hints.len()
        );

        // §9.D.1 step 7: the peer book, pinned to the roster.
        eprintln!(
            "[mesh] peer book pinned to the {}-node roster",
            roster.nodes().len()
        );
        mesh_router = Arc::new(MeshRouter::pinned_to(
            roster.nodes().iter().cloned(),
            PexLimits::default(),
        ));

        // §9.D.1 step 9: the join installs the roster as the transport's
        // allowlist (nodes only), and keys the epoch store by its digest.
        let join = match build_session_join(
            roster,
            &seed_hints,
            epoch_store.clone(),
            mesh_router.clone(),
        ) {
            Ok(join) => join,
            Err(reason) => {
                eprintln!("Error: {}", reason);
                exit(2);
            }
        };
        let session_info = match join
            .join(
                &mut mgr,
                JoinRequest {
                    my_party_id: my_id,
                    my_listen: advertise_addr.unwrap_or(actual_listen),
                    program_id,
                    entry: entry.clone(),
                    n_parties: n,
                    threshold: t,
                    execution_id: SessionExecutionId::from_bytes(*coord_execution_id.as_bytes()),
                    timeout: session_registration_timeout(),
                },
            )
            .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        // `--party-id` is not an identity any more, and it is not the storage
        // key either: persistent state is keyed by `DurableIdentityDigest`,
        // derived from this node's own certificate (`required_storage_identity`),
        // so a node holding `cert0` opens `cert0`'s store whatever number the
        // operator typed. What `--party-id` still does is *label* that state —
        // the `--local-store` / `--preproc-store` paths and the `party-N.redb`
        // volumes the compose stacks mount are named by it.
        //
        // The index this node is addressed by on the wire is its rank in the
        // roster's lexicographic SPKI order, which no operator can predict from
        // a certificate file name. The invariant that matters — roster rank ==
        // transport rank — is enforced inside the join itself
        // (`MeshError::RankMismatch`) and has already passed by the time we get
        // here. So a label that disagrees with the rank is confusing, not
        // wrong: it is reported once, by name, and the run continues on the
        // derived index.
        if let (Some(declared), Some(derived)) = (party_id, mgr.compute_local_party_id()) {
            if declared != derived {
                eprintln!(
                    "[party {}] note: --party-id {} names this node's on-disk state; on the \
                     wire this node is party {}, its rank in the lexicographic order of the \
                     coordinator roster's certificates, and that is the index the remaining log \
                     lines use. The two numbers are independent and need not agree: storage is \
                     keyed by this node's certificate, not by --party-id.",
                    declared, declared, derived
                );
            }
        }

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else {
        // A local run forms no mesh, so its router never sees a peer.
        mesh_router = Arc::new(MeshRouter::new());
        // local run: must have path
        if let Some(p) = &path_opt {
            let bytes = std::fs::read(p).expect("read program");
            program_id = program_id_from_bytes(&bytes);
        } else {
            eprintln!("Error: local run requires a program path");
            exit(2);
        }
    }

    // Load compiled binary from a file path
    let load_path: String = if let Some(p) = path_opt.clone() {
        p
    } else {
        // Content-addressed cache fallback: a program pulled from a peer
        // (`net::mesh::program`) lands under its own id.
        let p = stoffel_vm::net::program_sync::program_path(&program_id);
        p.to_string_lossy().to_string()
    };
    // Initialize VM
    let mut vm_builder = VirtualMachine::builder();
    if let Some(path) = &local_store_path {
        let storage = match RedbLocalStorage::new(path) {
            Ok(storage) => storage,
            Err(err) => {
                eprintln!("Error: failed to open local storage: {}", err);
                exit(3);
            }
        };
        vm_builder = vm_builder.with_local_storage(storage);
    }
    let mut vm = vm_builder.build();

    let (function_count, _bytecode_version, client_io_manifest) = if trace_instr {
        // Instruction tracing hooks need the source Instruction stream for each
        // program counter. Use the source-preserving loader only in traced mode;
        // normal execution keeps the low-peak streaming path below.
        let mut f = File::open(&load_path).expect("open binary file");
        let compiled = match CompiledBinary::deserialize(&mut f) {
            Ok(compiled) => compiled,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        };
        let bytecode_version = compiled.version;
        let client_io_manifest = compiled.client_io_manifest.clone();
        let functions = match compiled.try_to_vm_functions() {
            Ok(functions) => functions,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        };
        let function_count = functions.len();
        for function in functions {
            if let Err(err) = vm.try_register_function(function) {
                eprintln!("Error: invalid VM function: {}", err);
                exit(3);
            }
        }
        (function_count, bytecode_version, client_io_manifest)
    } else {
        // Register all functions as they are read and lowered to avoid retaining
        // the compiled or resolved function table beside the runtime program.
        let f = File::open(&load_path).expect("open binary file");
        match CompiledBinary::try_for_each_resolved_vm_function_from_reader(
            &mut BufReader::new(f),
            |header, stream| {
                let mut stream_error = None;
                let result = vm.try_register_resolved_function_without_source(header, || {
                    match stream.next_instruction() {
                        Ok(instruction) => instruction,
                        Err(err) => {
                            stream_error = Some(err);
                            None
                        }
                    }
                });
                if let Some(err) = stream_error {
                    return Err(err);
                }
                result.map_err(|err| {
                    BinaryError::InvalidData(format!("invalid VM function: {err}"))
                })?;
                Ok(())
            },
        ) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        }
    };
    let client_input_types = manifest_client_input_types(&client_io_manifest);
    let preprocessing_demand = client_io_manifest.preprocessing_demand;
    if function_count == 0 {
        eprintln!("Error: compiled program contains no functions");
        exit(3);
    }

    // Register debugging hooks based on flags
    if trace_instr {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(_) | HookEvent::AfterInstructionExecute(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] BEFORE {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                HookEvent::AfterInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] AFTER  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_regs {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::RegisterRead(idx, val) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let bank = if idx.is_secret() { "secret" } else { "clear" };
                    eprintln!(
                        "[regs][depth {}][{}] R{} ({}[{}]) -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx.index(),
                        bank,
                        idx.bank_index(),
                        val
                    );
                    Ok(())
                }
                HookEvent::RegisterWrite(idx, old, new) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let bank = if idx.is_secret() { "secret" } else { "clear" };
                    eprintln!(
                        "[regs][depth {}][{}] R{} ({}[{}]): {:?} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx.index(),
                        bank,
                        idx.bank_index(),
                        old,
                        new
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_stack {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeFunctionCall(_, _)
                        | HookEvent::AfterFunctionCall(_, _)
                        | HookEvent::StackPush(_)
                        | HookEvent::StackPop(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeFunctionCall(func, args) => {
                    eprintln!(
                        "[stack][depth {}] CALL {} with {:?}",
                        ctx.get_call_depth(),
                        func,
                        args
                    );
                    Ok(())
                }
                HookEvent::AfterFunctionCall(func, ret) => {
                    eprintln!(
                        "[stack][depth {}] RET  {} => {:?}",
                        ctx.get_call_depth(),
                        func,
                        ret
                    );
                    Ok(())
                }
                HookEvent::StackPush(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] PUSH {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                HookEvent::StackPop(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] POP  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if !trace_instr {
        vm.discard_vm_source_instructions();
    }

    // =====================================================================
    // COORDINATOR (or no coordinator)
    // =====================================================================

    // HoneyBadger coordinator connection. The AVSS party opens its own
    // (`run_avss_coordinated_party_for_curve`).
    let mut coord_opt: Option<HbOffChainCoordinator<ark_bls12_381::Fr>> = None;
    let mut node_rpc_opt: Option<OffChainNodeRPCServer> = None;
    let mut hb_bls12381_coord_engine: Option<
        Arc<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>>,
    > = None;
    // What a coordinated HoneyBadger party agreed (§9.D.7): the checked summary, and the
    // admission set every node of the mesh agreed on.
    let mut coord_summary: Option<ExecutionSummary> = None;
    let mut coord_admissions: Option<ClientAdmissionSet> = None;
    let mut digest_barriers: Option<DigestBarriers> = None;

    if matches!(backend_kind, MpcBackendKind::HoneyBadger) {
        // §9.D.1 step 10: the link that fetched the roster drives the rounds.
        if let Some(link) = coordinator_link.take() {
            coord_opt = Some(HbOffChainCoordinator::<ark_bls12_381::Fr>::from_link(
                link,
                coord_execution_id,
            ));

            if let Some(ref rpc) = rpc_addr {
                let node_rpc = OffChainNodeRPCServer::start_for_execution(
                    &rpc.0,
                    rpc.1,
                    coord_execution_id,
                    cert_der.clone().unwrap(),
                    key_der.clone().unwrap(),
                )
                .await
                .unwrap_or_else(|error| {
                    eprintln!("Failed to start node RPC server: {error}");
                    exit(13);
                });
                node_rpc_opt = Some(node_rpc);
            }
        }
    }

    // If in party mode, configure MPC engine based on selected backend
    if let Some(net) = net_opt.clone() {
        // The party index is the network-derived one (rank in the sorted public
        // key list), never anything a peer or a flag asserted, because send()
        // routes via sorted public keys.
        let my_id = net.local_party_id();
        // Session parameters, agreed all-to-all during the join.
        let n = session_n_parties.unwrap_or_else(|| net.parties().len());
        let t = session_threshold.unwrap_or(1);
        // The session instance_id, likewise agreed with every party.
        let instance_id =
            session_instance_id.expect("session instance_id should be set in party mode");

        eprintln!(
            "[party {}] Creating MPC engine (backend={}): instance_id={}, n={}, t={}",
            my_id,
            backend_kind.name(),
            instance_id,
            n,
            t
        );

        // Debug: print established connections (server connections are to other MPC parties)
        let connections = net.get_all_server_connections();
        let conn_ids: Vec<_> = connections.iter().map(|(id, _)| *id).collect();
        eprintln!(
            "[party {}] Connections before MPC: {:?} ({} total)",
            my_id,
            conn_ids,
            connections.len()
        );

        // §9.D.6: both agreement barriers exist before any receive loop is spawned.
        if coord_addr.is_some() {
            digest_barriers = Some(DigestBarriers::new(instance_id, n, my_id));
        }

        match backend_kind {
            MpcBackendKind::HoneyBadger => {
                // Phase 1: the execution summary, checked before any preprocessing
                // (§9.D.7 step 1), then the preprocessing proposal. Quorum-gated:
                // every party proposes, and the coordinator applies the round once
                // `transition_quorum()` of them have.
                let mut mask_count = 0usize;
                if let Some(ref coord) = coord_opt {
                    let summary = checked_execution_summary::<
                        ark_bls12_381::Fr,
                        HbCoordinatorShare<ark_bls12_381::Fr>,
                    >(
                        coord,
                        &SummaryExpectations {
                            execution_id: coord_execution_id,
                            program_hash: program_id,
                            backend: MpcBackendKind::HoneyBadger,
                            n,
                            t,
                            manifest: &client_io_manifest,
                        },
                    )
                    .await
                    .unwrap_or_else(|error| error.exit());
                    mask_count = mask_count_of(&summary).unwrap_or_else(|error| error.exit());
                    if mask_count > 0 && !matches!(curve_config, MpcCurveConfig::Bls12_381) {
                        CoordinatedRunError::UnsupportedInputCurve {
                            execution_id: coord_execution_id,
                            mask_count: mask_count as u64,
                            curve: curve_config.name(),
                        }
                        .exit();
                    }
                    coord_summary = Some(summary);
                    coord
                        .start_preprocessing()
                        .await
                        .unwrap_or_else(|error| CoordinatedRunError::from(error).exit());
                }
                // Phase 2: Create MPC engine + preprocessing + coordinator input phases
                macro_rules! setup_hb {
                    ($F:ty, $G:ty) => {{
                        match setup_hb_party_for_curve::<$F, $G>(
                            &mut vm,
                            HbPartySetup {
                                net: net.clone(),
                                my_id,
                                persistent_identity: storage_identity.unwrap_or_else(|| {
                                    DurableIdentityDigest::from_legacy_party_id(my_id)
                                }),
                                n,
                                t,
                                instance_id,
                                // Clients never reach the node mesh (§9.E.3): every party is coordinated,
                                // and its clients reach the node RPC listener.
                                expected_client_count: None,
                                coordinator_mask_count: 0,
                                client_input_count: 1,
                                client_input_types: &client_input_types,
                                preprocessing_demand,
                                program_hash: program_id,
                                preproc_store_path: preproc_store_path.as_deref(),
                                mesh_router: mesh_router.clone(),
                                digest_barriers: digest_barriers.clone(),
                            },
                        )
                        .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                                exit(13);
                            }
                        };
                    }};
                }

                // Bls12_381 path with coordinator support
                if coord_opt.is_some() && matches!(curve_config, MpcCurveConfig::Bls12_381) {
                    let engine = match setup_hb_party_for_curve::<
                        ark_bls12_381::Fr,
                        ark_bls12_381::G1Projective,
                    >(
                        &mut vm,
                        HbPartySetup {
                            net: net.clone(),
                            my_id,
                            persistent_identity: storage_identity.unwrap_or_else(|| {
                                DurableIdentityDigest::from_legacy_party_id(my_id)
                            }),
                            n,
                            t,
                            instance_id,
                            // Clients never reach the node mesh in a coordinated run.
                            expected_client_count: None,
                            coordinator_mask_count: mask_count,
                            client_input_count: 1,
                            client_input_types: &client_input_types,
                            preprocessing_demand,
                            program_hash: program_id,
                            preproc_store_path: preproc_store_path.as_deref(),
                            mesh_router: mesh_router.clone(),
                            digest_barriers: digest_barriers.clone(),
                        },
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                            exit(13);
                        }
                    };
                    engine.enable_client_output_capture().await;
                    hb_bls12381_coord_engine = Some(engine.clone());

                    // §9.D.7 steps 2-10: masks, reservations, agreed admissions and
                    // agreed masked inputs, stored by agreed client index.
                    if let Some(ref mut coord) = coord_opt {
                        if mask_count > 0 {
                            let node_rpc = node_rpc_opt
                                .as_ref()
                                .expect("--rpc-bind required with coordinator");
                            let summary = coord_summary
                                .as_ref()
                                .expect("the summary is checked before preprocessing");
                            let barriers = digest_barriers
                                .as_ref()
                                .expect("a coordinated party creates its agreement barriers");
                            let mask_shares = engine
                                .node_handle()
                                .lock()
                                .await
                                .preprocessing_material
                                .lock()
                                .await
                                .take_random_shares(mask_count)
                                .unwrap_or_else(|error| {
                                    CoordinatedRunError::Setup(format!(
                                        "Not enough random shares for {mask_count} input masks: {error}"
                                    ))
                                    .exit()
                                });
                            let (set, inputs) = collect_admitted_client_inputs(
                                coord,
                                node_rpc,
                                summary,
                                barriers,
                                net.as_ref(),
                                mask_shares,
                            )
                            .await
                            .unwrap_or_else(|error| error.exit());
                            for (client_index, shares) in inputs {
                                let slot = client_index.0 as usize;
                                let stored = match client_input_types.get(&slot) {
                                    Some(share_types) => vm.try_store_client_input_with_types(
                                        slot,
                                        shares,
                                        share_types,
                                    ),
                                    None => vm.try_store_client_input(slot, shares),
                                };
                                if let Err(error) = stored {
                                    CoordinatedRunError::Setup(format!(
                                        "Failed to store input shares for client slot {slot}: {error}"
                                    ))
                                    .exit();
                                }
                            }
                            coord_admissions = Some(set);
                        }
                    }
                } else {
                    // No coordinator or non-Bls12_381 curves
                    match curve_config {
                        MpcCurveConfig::Bls12_381 => {
                            setup_hb!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
                        }
                        MpcCurveConfig::Bn254 => {
                            setup_hb!(ark_bn254::Fr, ark_bn254::G1Projective)
                        }
                        MpcCurveConfig::Curve25519 => {
                            setup_hb!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
                        }
                        MpcCurveConfig::Ed25519 => {
                            setup_hb!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
                        }
                        MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1 => {
                            eprintln!(
                                "Error: curve {} is not supported by honeybadger backend",
                                curve_config.name()
                            );
                            exit(2);
                        }
                    }
                }

                eprintln!(
                    "[party {}] HoneyBadger MPC engine set, starting VM execution...",
                    my_id
                );
            }
            MpcBackendKind::Avss => {
                eprintln!(
                    "[party {}] Setting up AVSS backend (curve: {})...",
                    my_id,
                    curve_config.name()
                );

                if let Some(link) = coordinator_link.take() {
                    let rpc = rpc_addr.clone().unwrap_or_else(|| {
                        eprintln!("Error: --rpc-bind is required with AVSS coordinator mode");
                        exit(2);
                    });
                    let cert = cert_der.clone().unwrap_or_else(|| {
                        eprintln!("Error: --cert is required with AVSS coordinator mode");
                        exit(2);
                    });
                    let key = key_der.clone().unwrap_or_else(|| {
                        eprintln!("Error: --key is required with AVSS coordinator mode");
                        exit(2);
                    });
                    if let Err(error) = run_avss_coordinated_party(
                        curve_config,
                        CoordinatedAvssParty {
                            vm: &mut vm,
                            net: net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            link,
                            rpc_addr: rpc,
                            cert_der: cert,
                            key_der: key,
                            execution_id: coord_execution_id,
                            agreed_entry: &agreed_entry,
                            program_hash: program_id,
                            manifest: &client_io_manifest,
                            mesh_router: mesh_router.clone(),
                            digest_barriers: digest_barriers
                                .clone()
                                .expect("a coordinated party creates its agreement barriers"),
                        },
                    )
                    .await
                    {
                        error.exit();
                    }
                    return;
                }

                macro_rules! setup_avss {
                    ($F:ty, $G:ty) => {{
                        if let Err(e) = setup_avss_party_for_curve::<$F, $G>(
                            &mut vm,
                            net.clone(),
                            AvssPartySetup {
                                my_id,
                                local_identity: storage_identity.unwrap_or_else(|| {
                                    DurableIdentityDigest::from_legacy_party_id(my_id)
                                }),
                                n,
                                t,
                                instance_id,
                                // Clients never reach the node mesh (§9.E.3): every party is coordinated,
                                // and its clients reach the node RPC listener.
                                expected_client_count: None,
                                client_input_count: 1,
                                client_input_types: &client_input_types,
                                coordinator_mask_count: 0,
                                digest_barriers: None,
                                mesh_router: mesh_router.clone(),
                            },
                        )
                        .await
                        {
                            eprintln!("[party {}] AVSS setup failed: {}", my_id, e);
                            exit(13);
                        }
                    }};
                }

                match curve_config {
                    MpcCurveConfig::Bls12_381 => {
                        setup_avss!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
                    }
                    MpcCurveConfig::Bn254 => {
                        setup_avss!(ark_bn254::Fr, ark_bn254::G1Projective)
                    }
                    MpcCurveConfig::Curve25519 => {
                        setup_avss!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
                    }
                    MpcCurveConfig::Ed25519 => {
                        setup_avss!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
                    }
                    MpcCurveConfig::Secp256k1 => {
                        setup_avss!(ark_secp256k1::Fr, ark_secp256k1::Projective)
                    }
                    MpcCurveConfig::Secp256r1 => {
                        setup_avss!(ark_secp256r1::Fr, ark_secp256r1::Projective)
                    }
                }

                eprintln!(
                    "[party {}] AVSS engine set, starting VM execution...",
                    my_id
                );
            }
        }
    }

    // Coordinator: signal MPC execution phase
    if let Some(ref mut coord) = coord_opt {
        eprintln!("[party] coordinator -> MPCExecution");
        coord
            .start_mpc()
            .await
            .unwrap_or_else(|error| CoordinatedRunError::from(error).exit());
        coord
            .wait_for_round(Round::MPCExecution)
            .await
            .unwrap_or_else(|error| CoordinatedRunError::from(error).exit());
        let summary = coord_summary
            .as_ref()
            .expect("a coordinated party checks the summary before preprocessing");
        // An execution without inputs freezes its admissions when `MPCExecution` begins
        // (§9.D.7), so this node agrees them now, before running the program.
        if coord_admissions.is_none() {
            let net = net_opt
                .as_ref()
                .expect("a coordinated HoneyBadger run is a party");
            let barriers = digest_barriers
                .as_ref()
                .expect("a coordinated party creates its agreement barriers");
            coord_admissions = Some(
                agree_client_admissions(coord, summary, barriers, net.as_ref())
                    .await
                    .unwrap_or_else(|error| error.exit()),
            );
        }
        vm.set_client_roster(coordinated_client_roster(summary));
    }

    eprintln!("Starting VM execution of '{}'...", agreed_entry);

    // Execute entry function. Prefer the async MPC scheduler when an async-capable
    // engine was installed so secret-share operations yield instead of blocking
    // inside the synchronous VM instruction path.
    //
    // This call is the online phase (preprocessing is already done), so timing it
    // isolates online MPC cost from preprocessing for benchmarking.
    let online_started_at = std::time::Instant::now();
    let execution_result = if let Some(engine) = hb_bls12381_coord_engine.as_ref() {
        vm.execute_async(&agreed_entry, engine.as_ref()).await
    } else {
        vm.execute(&agreed_entry)
    };
    eprintln!(
        "online VM execution complete! elapsed_ms={}",
        online_started_at.elapsed().as_millis()
    );

    match execution_result {
        Ok(result) => {
            // §9.D.7 step 12: outputs come only from `send_to_client`, by agreed slot, and
            // every coordinated run reaches `ProgramFinished`.
            if let Some(ref coord) = coord_opt {
                let captured = match hb_bls12381_coord_engine.as_ref() {
                    Some(engine) => engine
                        .drain_client_output_records()
                        .await
                        .into_iter()
                        .map(|record| (record.client_id, record.shares))
                        .collect(),
                    None => Vec::new(),
                };
                finish_coordinated_execution(
                    coord,
                    coord_summary
                        .as_ref()
                        .expect("a coordinated party checks the summary before preprocessing"),
                    coord_admissions
                        .as_ref()
                        .expect("a coordinated party agrees the admissions before it runs"),
                    captured,
                    &agreed_entry,
                )
                .await
                .unwrap_or_else(|error| error.exit());
            }
            print_vm_result(&mut vm, result);
        }
        Err(err) => {
            eprintln!("Execution error in '{}': {}", agreed_entry, err);
            exit(4);
        }
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        r#"Stoffel VM Runner

Usage:
  stoffel-run <path-to-compiled-binary> [entry_function] [flags]

Flags:
  --trace-instr           Trace instructions before/after execution
  --trace-regs            Trace register reads/writes
  --trace-stack           Trace function calls and stack push/pop
  --execution-id <hex>    The program invocation this process joins, as 64
                          hexadecimal characters. Required with
                          --off-chain-coord and refused without it: the
                          coordinator keys rounds, reserved mask indices, masked
                          inputs and output shares on it, and has no reset, so
                          every party and client of one invocation passes the
                          same value and a later invocation passes a different
                          one. The all-zero value is reserved
  --client                Run as client (provide inputs to MPC network)
  --bind <addr:port>      Party listen address
  --advertise <addr:port> Address peers should dial to reach this party, when it differs
                          from --bind (a published container port, say). Defaults to
                          --bind
  --party-id <usize>      Labels this node's on-disk state (--local-store,
                          --preproc-store). NOT an identity: the index
                          this node is addressed by on the wire is its rank in the
                          lexicographic order of the coordinator roster's certificates,
                          and persistent storage is keyed by this node's certificate,
                          not by this flag. A --party-id that differs from the
                          derived rank is reported once and the run continues
  --mpc-backend <name>    MPC backend: honeybadger (default) or avss
  --mpc-curve <name>      MPC curve: bls12-381 (default), bn254, curve25519, ed25519;
                          AVSS also supports secp256k1 and p-256
  --inputs <values>       Comma-separated input values (client mode), one per input of
                          the client's slot; omitted for an output-only slot. A count
                          other than the slot's is refused (exit 2) before associating
                          whenever the slot is known
  --output-fixed-point-fractional-bits <n>
                          Decode coordinator client outputs as fixed-point values
                          with n fractional bits instead of raw field integers
  --servers <addrs>       Comma-separated node RPC addresses (client mode). Hints: every
                          leg is pinned to a member of the coordinator's node roster
  --off-chain-coord <addr:port>
                          Off-chain coordinator address. Required in party and client
                          mode. Requires --coord-cert
  --coord-cert <path>     DER-encoded X.509 certificate of the off-chain coordinator.
                          Required with --off-chain-coord and refused without it: every
                          coordinator connection pins this key, and a server presenting
                          any other key is refused (exit 13)
  --expect-roster-digest <64-hex>
                          Optional, party and client mode: refuse (exit 2) a node roster
                          whose digest is not this one. Carries no certificate: it can
                          only refuse what the coordinator serves
  --expect-n-parties <u64>, --expect-threshold <u64>
                          Optional, party and client mode: refuse (exit 2) a node roster
                          of another size
  --on-chain-coord <address>
                          Temporarily unavailable in the crates.io-ready build
  --eth-node <url>        Reserved for future on-chain coordinator support
  --wallet-sk <hex>       Reserved for future on-chain coordinator support
  --rpc-bind <addr:port>  Node RPC server bind address (for mask distribution)
  --cert <path>           Path to DER-encoded X.509 certificate. Required for a party:
                          it must be one of the coordinator's node roster
  --key <path>            Path to DER-encoded private key
  --client-slot <u32>     Client slot this coordinator client asks to bind; optional.
                          Without it a client takes the slot its certificate is
                          pre-registered to, its invitation's slot or, under open
                          admission, the lowest-numbered free slot (every slot must then
                          have one shape). Its input range and output count are the
                          coordinator's admission, never a flag
  --invitation <path>     A signed invitation (JSON, as issue-invitation writes it),
                          presented when this coordinator client associates. Required
                          under invitation admission, refused under any other
  --expect-program-hash <64-hex>
                          Optional, client mode: refuse (exit 2) to associate with an
                          execution registered for any other program
  --preproc-store <path>  Persistent HoneyBadger preprocessing store directory
  --local-store <path>    Persistent VM local storage database
  --epoch-store <dir>     Directory holding this node's monotone session epoch, keyed by
                          the coordinator's roster digest, which is what keeps instance_id
                          fresh across runs of one roster. Needed only with --peers.
                          Defaults to $STOFFEL_EPOCH_STORE, then to ~/.stoffel/epochs.
                          Must persist across restarts and must not be shared between nodes
  --peers <addrs>         Comma-separated peer addresses to try first, and the switch
                          that selects party mode. Seed hints, not membership:
                          membership is the coordinator's node roster, and every dial
                          pins a roster certificate, so a wrong address costs one
                          failed handshake. A missing one costs the mesh: peer exchange
                          runs inside the join handshake, after the mesh is already
                          complete, so it cannot fill an edge the mesh needs in order to
                          form. List every other party unless you know the ones you leave
                          out will dial this node themselves. Requires --off-chain-coord,
                          --coord-cert, --execution-id and an epoch store
  -h, --help              Show this help

Multi-Party Execution:
  The coordinator is the only roster authority. A party opens one connection to
  it, pinned to --coord-cert, and fetches the node roster (the node certificates
  and t) exactly once, before it binds anything. It refuses to run if its own
  --cert is not one of those nodes. It installs the roster as its transport's
  peer-certificate allowlist — nodes only; clients never reach the node mesh —
  and forms a mesh by dialing the seed addresses it was given. The session
  (program, entry, execution, n, t, instance_id) is agreed all-to-all once every
  party is connected. There is no bootstrap process and no shared bearer token.

  Party indices are derived locally from the lexicographic order of the roster's
  DER SubjectPublicKeyInfo bytes, so every party computes the same index for
  every other party without anyone announcing one.

  instance_id freshness comes from a monotone epoch persisted per node
  (--epoch-store) and keyed by the roster digest. Roster, program and entry are
  constant across runs of a deployment, so without it every run would reuse one
  MPC session namespace.

  Every party proposes every round transition, and the coordinator applies one
  once a quorum of the roster has proposed it. No party is designated. What
  every party and client must share is --execution-id, which names the
  invocation their rounds, inputs and outputs belong to. Clients associate with
  that execution through the coordinator, which admits them per execution, and
  reach the parties' --rpc-bind listeners.

Removed flags (each exits 2 naming its replacement):
  --roster, --n-parties, --threshold, --expected-clients, --wait-for-clients,
  --client-roster, --client-input-count, --client-input-slots,
  --client-input-total, --timestamp, --client-id, --client-index, --outputs

Examples:
  # Local execution (no MPC)
  stoffel-run program.stfbin
  stoffel-run program.stfbin main --trace-instr

  # Multi-party execution (3 parties). The coordinator at 127.0.0.1:31415 serves
  # the node roster and drives execution $EXEC; --peers are hints, and
  # --epoch-store keeps instance_id fresh across runs. Each party lists every
  # other party: a first mesh forms out of dials alone, so an address nobody
  # holds is an edge that never forms.
  COORD="--off-chain-coord 127.0.0.1:31415 --coord-cert coordinator.crt --execution-id $EXEC"
  stoffel-run program.stfbin main --party-id 0 --bind 127.0.0.1:9001 $COORD \
    --cert node0.crt --key node0.der --rpc-bind 127.0.0.1:10001 \
    --peers 127.0.0.1:9002,127.0.0.1:9003 --epoch-store /var/lib/stoffel/epochs-0
  stoffel-run program.stfbin main --party-id 1 --bind 127.0.0.1:9002 $COORD \
    --cert node1.crt --key node1.der --rpc-bind 127.0.0.1:10002 \
    --peers 127.0.0.1:9001,127.0.0.1:9003 --epoch-store /var/lib/stoffel/epochs-1
  stoffel-run program.stfbin main --party-id 2 --bind 127.0.0.1:9003 $COORD \
    --cert node2.crt --key node2.der --rpc-bind 127.0.0.1:10003 \
    --peers 127.0.0.1:9001,127.0.0.1:9002 --epoch-store /var/lib/stoffel/epochs-2

  # Client mode: associate with the execution through the coordinator — whose
  # admission, not this command line, decides the client's slot, input range and
  # outputs — fetch masks from the parties' node RPC listeners and submit masked
  # inputs. The client's certificate need not appear in any configuration.
  stoffel-run --client --inputs 10,20 $COORD --cert client.crt --key client.der \
    --servers 127.0.0.1:10001,127.0.0.1:10002,127.0.0.1:10003
"#
    );
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::{
        band_pow2, build_session_join, field_outputs_to_hex, format_coordinator_outputs,
        parse_expected_roster_digest, parse_expected_roster_size, plan_preprocessing,
        render_fixed_point_i64, resolve_coord_execution_id, CoordinatorOutputFormat, ExecutionId,
        RosterExpectations, RosterSizeFlag, UnexpectedRosterSize, REMOVED_FLAGS,
        UNUSED_EXECUTION_ID,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use stoffel_vm::net::mesh::{EpochStore, MeshRouter, Roster, SeedHints};
    use stoffel_vm::net::MpcCurveConfig;
    use stoffel_vm_types::compiled_binary::PreprocessingDemand;
    use stoffelnet::network_utils::NodePublicKey;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}")
            .parse()
            .expect("parse loopback address")
    }

    /// A three-node roster plus a scratch epoch store, so `build_session_join`
    /// can be driven with real values.
    fn roster_and_epochs() -> (Roster, Arc<EpochStore>, std::path::PathBuf) {
        // Distinct SPKI-shaped byte strings. `build_session_join` never looks
        // inside the roster, and minting real certificates here would test
        // `rcgen`.
        let keys = (1u8..=3)
            .map(|byte| NodePublicKey(vec![byte; 32]))
            .collect();
        let dir = std::env::temp_dir().join(format!(
            "stoffel-run-epochs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after the unix epoch")
                .as_nanos()
        ));
        let store = EpochStore::open(&dir).expect("open a scratch epoch store");
        (
            Roster::from_node_keys(keys, 1).expect("build a three-node roster"),
            Arc::new(store),
            dir,
        )
    }

    /// Stage 9: a coordinator-bearing run names the invocation it joins, and a
    /// run without a coordinator has nothing to name.
    ///
    /// Both directions are errors rather than defaults. Coordinator `0.2.0` has
    /// no `reset_coord`, so the id *is* what separates one run from the next; a
    /// defaulted one would silently attach this process to whatever execution
    /// happened to carry that value, on the leg that carries client inputs.
    #[test]
    fn a_coordinator_bearing_run_must_name_its_execution() {
        let id = ExecutionId::from_bytes([7u8; 32]);

        assert_eq!(resolve_coord_execution_id(true, Some(id)), Ok(id));

        let missing = resolve_coord_execution_id(true, None)
            .expect_err("a coordinator run without an execution id is a configuration error");
        assert!(missing.contains("--execution-id"), "{missing}");

        let unused = resolve_coord_execution_id(false, Some(id))
            .expect_err("an execution id without a coordinator names nothing");
        assert!(unused.contains("--off-chain-coord"), "{unused}");

        // The coordinator-less answer is the reserved value, which every
        // coordinator RPC rejects.
        assert_eq!(
            resolve_coord_execution_id(false, None),
            Ok(UNUSED_EXECUTION_ID)
        );
        assert!(UNUSED_EXECUTION_ID.is_zero());
    }

    /// The join the seam produces, stated where it is chosen.
    ///
    /// The assertion is over `Debug`, because `SessionJoin` is a trait object
    /// by the time it leaves this function — which is the point: the two call
    /// sites in `main` cannot tell one join from another, which is what let
    /// Stage 5 add a path without editing them and what will let stage 11 add
    /// the coordinator-issued one the same way.
    #[test]
    fn a_roster_seeds_and_an_epoch_store_build_the_mesh_join() {
        let (roster, epochs, dir) = roster_and_epochs();
        let router = Arc::new(MeshRouter::new());

        let mesh = build_session_join(
            roster,
            &SeedHints::new(vec![addr(9001)], None),
            Some(epochs),
            router,
        )
        .expect("a roster, seeds and an epoch store are a complete mesh configuration");

        assert!(format!("{mesh:?}").contains("MeshJoin"), "{mesh:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Both remaining mesh preconditions are configuration mistakes with
    /// one-line fixes, so they are refused where the choice is made rather than
    /// deep inside the join, where they would surface as a transport-level
    /// message.
    ///
    /// The membership precondition this test used to cover beside them — seeds
    /// without `--roster` — is now a type: the join takes the coordinator's
    /// [`Roster`], never an `Option`, and `--peers` without `--off-chain-coord`
    /// is refused before anything is bound
    /// (`tests/coordinator_pin.rs::peers_without_a_coordinator_are_refused`).
    #[test]
    fn the_mesh_join_refuses_to_form_without_seeds_or_freshness() {
        let (roster, epochs, dir) = roster_and_epochs();
        let router = Arc::new(MeshRouter::new());
        let seeds = SeedHints::new(vec![addr(9001)], None);

        let missing_epochs = build_session_join(roster.clone(), &seeds, None, router.clone())
            .expect_err("seeds without an epoch store cannot keep instance_id fresh");
        assert!(missing_epochs.contains("--epoch-store"), "{missing_epochs}");

        let nothing = build_session_join(roster, &SeedHints::default(), Some(epochs), router)
            .expect_err("a party with nothing to dial has no way into a session");
        assert!(nothing.contains("--peers"), "{nothing}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Design doc §9.D.3: no removed flag's hint names another removed flag, so
    /// an operator following one refusal is never sent to the next.
    #[test]
    fn no_removed_flag_hint_names_a_removed_flag() {
        for (flag, hint) in REMOVED_FLAGS {
            assert!(!hint.is_empty(), "{flag} has an empty hint");
            for (removed, _) in REMOVED_FLAGS {
                let named = hint
                    .split(|character: char| {
                        character.is_whitespace() || matches!(character, ',' | '(' | ')' | ';')
                    })
                    .any(|word| word.trim_end_matches('.') == *removed);
                assert!(
                    !named,
                    "the hint for {flag} names the removed {removed}: {hint}"
                );
            }
        }
        let mut flags: Vec<&str> = REMOVED_FLAGS.iter().map(|(flag, _)| *flag).collect();
        flags.sort_unstable();
        flags.dedup();
        assert_eq!(
            flags.len(),
            REMOVED_FLAGS.len(),
            "a removed flag is listed twice"
        );
    }

    /// `--expect-*` refuse a served roster of another size, name the flag and
    /// the served `n` and `t`, and accept the roster they describe.
    #[test]
    fn roster_expectations_refuse_another_size_by_flag() {
        use stoffel_mpc_coordinator_shared::{NodeCertificateDer, NodeRoster};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let roster = NodeRoster::new(
            1,
            (0..3)
                .map(|_| {
                    let generated =
                        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                            .expect("generate a node certificate");
                    NodeCertificateDer::from_der(generated.cert.der().to_vec())
                })
                .collect(),
        )
        .expect("three nodes at t = 1 are a roster");

        assert_eq!(RosterExpectations::default().check_size(&roster), Ok(()));
        let matching = RosterExpectations {
            n_parties: Some(3),
            threshold: Some(1),
            ..RosterExpectations::default()
        };
        assert_eq!(matching.check_size(&roster), Ok(()));

        let wrong_n = RosterExpectations {
            n_parties: Some(7),
            ..RosterExpectations::default()
        };
        let refusal = wrong_n
            .check_size(&roster)
            .expect_err("a roster of another size is refused");
        assert_eq!(
            refusal,
            UnexpectedRosterSize {
                n: 3,
                t: 1,
                flag: RosterSizeFlag::NParties,
                expected: 7,
            }
        );
        assert_eq!(
            refusal.to_string(),
            "the coordinator serves a roster of n = 3, t = 1, not the expected \
             --expect-n-parties 7; refusing to install it."
        );

        let wrong_t = RosterExpectations {
            threshold: Some(2),
            ..RosterExpectations::default()
        };
        assert_eq!(
            wrong_t.check_size(&roster).map_err(|error| error.flag),
            Err(RosterSizeFlag::Threshold)
        );
    }

    #[test]
    fn expectation_flags_parse_or_name_themselves() {
        assert_eq!(
            parse_expected_roster_size(RosterSizeFlag::NParties, "5"),
            Ok(5)
        );
        let refusal = parse_expected_roster_size(RosterSizeFlag::Threshold, "-1")
            .expect_err("a negative count is refused");
        assert!(
            refusal.starts_with("--expect-threshold must be a non-negative integer: "),
            "{refusal}"
        );

        let digest = "ab".repeat(32);
        assert_eq!(
            parse_expected_roster_digest(&digest.to_uppercase())
                .expect("64 hexadecimal characters parse in either case")
                .to_string(),
            digest
        );
        assert_eq!(
            parse_expected_roster_digest("abc").expect_err("three characters are too few"),
            "--expect-roster-digest: expected 64 hexadecimal characters, got 3"
        );
    }

    fn demand(triples: u64, prandbits: u64, prandints: u64, dynamic: bool) -> PreprocessingDemand {
        PreprocessingDemand {
            triples,
            randoms: 0,
            prandbits,
            prandints,
            dynamic,
        }
    }

    /// Blocker B6's seventh site, guarded where it lives.
    ///
    /// `setup_avss_party_for_curve` spawns the production AVSS *party* receive
    /// loop itself — it does not go through `AvssQuicServer::spawn_message_loops`
    /// — so `stoffel-vm`'s own
    /// `every_receive_loop_offers_its_payloads_to_the_mesh_router` cannot see
    /// it: that test `include_str!`s `hb_server.rs` and `avss_server.rs`, and a
    /// library test reaching across a crate boundary would break
    /// `cargo publish` for a `publish = true` crate. The guard therefore lives
    /// here, over this file.
    ///
    /// The failure it prevents is silent in both directions: a mesh control
    /// frame would be handed to `process_wrapped_message_with_network`, and the
    /// loop below discards "process failed" errors by name.
    #[test]
    fn the_avss_party_receive_loop_offers_its_payloads_to_the_mesh_router() {
        // Assembled at runtime so this assertion does not match itself.
        let needle = format!("mesh_router.try_handle_{}", "wire_message_from(");
        let source: String = include_str!("stoffel-run.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        assert_eq!(
            source.matches(&needle).count(),
            1,
            "the AVSS party receive loop must consume mesh control frames before \
             the AVSS engine sees them"
        );
    }

    #[test]
    fn band_pow2_rounds_up_to_eighth_octave_and_keeps_zero() {
        assert_eq!(band_pow2(0), 0);
        assert_eq!(band_pow2(1), 1);
        // Powers of two and their eighth-octave multiples are exact.
        assert_eq!(band_pow2(16), 16);
        assert_eq!(band_pow2(131072), 131072);
        // 50 → octave floor 32, eighth = 4, round up to 52.
        assert_eq!(band_pow2(50), 52);
        // The banded value never exceeds the demand by more than one eighth of
        // its octave, so a demand that fits the backend capacity stays fitting:
        // 165_696 bands to 180_224 (< the old 262_144 that tripped LimitError).
        assert_eq!(band_pow2(165_696), 180_224);
        for n in [1u64, 7, 9, 100, 1000, 60_000, 134_528, 165_696, 200_000] {
            let b = band_pow2(n);
            assert!(b >= n, "band must not under-provision");
            assert!(
                b <= n + (n / 8) + 8,
                "band over-provisions by at most ~1/8 octave"
            );
        }
    }

    #[test]
    fn plan_for_single_division_folds_prandbit_cost_into_triples_and_randoms() {
        // 16 prandbits + 1 prandint (one secure fix64 / constant). prandbit
        // generation consumes a triple + random per bit, so the planned triple
        // and random pools must cover the banded prandbit count. HoneyBadger
        // generates the random shares needed to build triples internally, so the
        // visible random pool is only the baseline plus prandbits.
        let plan = plan_preprocessing(&demand(0, 16, 1, false), 1, 0);
        assert_eq!(plan.n_prandbit, 16);
        assert_eq!(plan.n_prandint, 1);
        assert_eq!(plan.n_triples, 16);
        assert_eq!(plan.n_random, 18);
    }

    #[test]
    fn plan_for_clear_program_still_provisions_minimal_random_pool() {
        let plan = plan_preprocessing(&demand(0, 0, 0, false), 1, 0);
        assert_eq!(plan.n_prandbit, 0);
        assert_eq!(plan.n_prandint, 0);
        assert_eq!(plan.n_triples, 0);
        assert_eq!(plan.n_random, 2);
    }

    #[test]
    fn plan_for_secret_multiplication_floors_to_protocol_triple_batch() {
        // One triple demanded, but the protocol's minimum batch is 2t+1 = 3.
        // Eighth-octave banding leaves 3 as-is (its octave floor is 2, so the
        // granularity is 1). The requested random pool stays at the baseline
        // because HoneyBadger generates the random shares used to build triples
        // inside preprocessing.
        let plan = plan_preprocessing(&demand(1, 0, 0, false), 1, 0);
        assert_eq!(plan.n_prandbit, 0);
        assert_eq!(plan.n_triples, 3);
        assert_eq!(plan.n_random, 2);
    }

    #[test]
    fn plan_gives_dynamic_programs_an_extra_octave_of_headroom() {
        let stat = plan_preprocessing(&demand(0, 16, 1, false), 1, 0);
        let dyn_ = plan_preprocessing(&demand(0, 16, 1, true), 1, 0);
        // The dynamic flag doubles the estimate before banding, so the prandbit
        // pool is one octave larger than the static plan's.
        assert_eq!(stat.n_prandbit, 16);
        assert_eq!(dyn_.n_prandbit, 32);
        assert!(dyn_.n_triples >= stat.n_triples);
    }

    #[test]
    fn formats_negative_field_outputs_as_signed_i64s() {
        let outputs = vec![-ark_bls12_381::Fr::from(10u64)];
        assert_eq!(
            format_coordinator_outputs(&outputs, CoordinatorOutputFormat::FieldInteger),
            "[-10]"
        );
    }

    #[test]
    fn formats_positive_field_outputs_as_signed_i64s() {
        let outputs = vec![ark_bls12_381::Fr::from(10u64)];
        assert_eq!(
            format_coordinator_outputs(&outputs, CoordinatorOutputFormat::FieldInteger),
            "[10]"
        );
    }

    #[test]
    fn formats_fixed_point_outputs_without_raw_scale() {
        let outputs = vec![
            ark_bls12_381::Fr::from(524_288u64),
            ark_bls12_381::Fr::from(163_840u64),
        ];

        assert_eq!(
            format_coordinator_outputs(
                &outputs,
                CoordinatorOutputFormat::FixedPoint {
                    fractional_bits: 16
                }
            ),
            "[8, 2.5]"
        );
    }

    #[test]
    fn formats_negative_fixed_point_outputs_without_raw_scale() {
        assert_eq!(
            render_fixed_point_i64(-163_840, 16).as_deref(),
            Some("-2.5")
        );
    }

    #[test]
    fn avss_client_output_hex_concatenates_fixed_width_ecdsa_scalars() {
        let outputs = vec![ark_secp256k1::Fr::from(1u64), ark_secp256k1::Fr::from(2u64)];
        let output_hex = field_outputs_to_hex(&outputs, MpcCurveConfig::Secp256k1);

        assert_eq!(output_hex.len(), 128);
        assert_eq!(
            output_hex,
            format!("{}{}", "0".repeat(63) + "1", "0".repeat(63) + "2")
        );
    }
}
