use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField};
use stoffel_mpc_coordinator_off_chain::{
    CoordinatorRPCServerSharedBase, ExecutionRegistration, OffChainCoordinatorConnection,
    OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_shared::rpc::RpcServerLimits;
use stoffel_mpc_coordinator_shared::self_signed_certs;
use stoffel_mpc_coordinator_shared::{
    AdmissionPolicy, AssociationRequest, ClientAdmission, ClientIdentity, ClientIndex,
    ClientSlotSpec, ClientSlotTable, CoordinatorError, ExecutionDeadlines, ExecutionId,
    NodeCertificateDer, NodeRoster, OutputRights, SpkiDer, UnixSeconds,
};
use stoffel_vm_types::compiled_binary::{utils::save_to_file, CompiledBinary};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};

use crate::coordinator_client::{
    CoordinatorClientConfig, CoordinatorClientError, CoordinatorEndpoint,
};
use stoffel_vm::net::program_id_from_bytes;
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, thiserror::Error)]
pub enum LocalCoordinatorRunnerError {
    #[error("invalid local coordinator runner configuration: {0}")]
    Configuration(String),
    #[error("local coordinator runner IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("local coordinator error: {0}")]
    Coordinator(#[from] stoffel_mpc_coordinator_shared::CoordinatorError),
    /// A client of the run stopped (`docs/design/bootnode-elimination.md` §9.E.1).
    #[error("local coordinator client: {0}")]
    Client(#[from] CoordinatorClientError),
    #[error("local coordinator runner timed out after {0:?}")]
    Timeout(Duration),
    #[error("local party {name} timed out after {timeout:?}: {output}")]
    PartyTimeout {
        name: String,
        timeout: Duration,
        output: String,
    },
    #[error("local party {name} exited with {status}: {output}")]
    PartyExit {
        name: String,
        status: std::process::ExitStatus,
        output: String,
    },
    #[error("one or more local coordinator processes failed: {0}")]
    ProcessFailures(String),
    #[error("bytecode serialization failed: {0:?}")]
    Bytecode(stoffel_vm_types::compiled_binary::BinaryError),
}

pub type LocalCoordinatorRunnerResult<T> = Result<T, LocalCoordinatorRunnerError>;

#[derive(Debug, Clone)]
pub struct LocalCoordinatorRunner {
    runner_path: PathBuf,
    binary: CompiledBinary,
    entry: String,
    parties: usize,
    threshold: usize,
    backend: MpcBackendKind,
    curve_config: MpcCurveConfig,
    timeout: Duration,
    client_inputs: Vec<LocalClientInput>,
    expected_clients: Option<usize>,
    /// Per-client number of output values to receive via `send_to_client`.
    client_output_counts: std::collections::HashMap<u64, u64>,
    /// How the spawned parties find each other
    /// (`docs/design/bootnode-elimination.md`).
    topology: LocalTopology,
    /// How clients come to hold the run's client slots
    /// (`docs/design/bootnode-elimination.md` §9.F.4).
    admission: LocalAdmission,
}

/// How clients come to hold a local run's client slots
/// (`docs/design/bootnode-elimination.md` §9.C.2, §9.F.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LocalAdmission {
    /// The runner mints one certificate per client slot and pre-registers it,
    /// then submits each slot's `client_input` values itself.
    #[default]
    PreRegistered,
    /// No client identity appears anywhere in the run's configuration: the
    /// runner mints no client certificates, registers the slot table with
    /// deadlines (the run's `timeout` from registration) and starts no clients
    /// of its own. Any certificate holder that pins the run's coordinator may
    /// bind a free slot through [`run_offchain_client`], which is how a
    /// computation takes clients whose identities are not known in advance.
    ///
    /// Slot input counts come from the program's client IO manifest, so
    /// `client_input` values are refused: the runner submits nothing.
    Open,
}

impl LocalCoordinatorRunner {
    pub fn builder(
        runner_path: impl Into<PathBuf>,
        binary: CompiledBinary,
    ) -> LocalCoordinatorRunnerBuilder {
        let curve_config = local_runner_curve_from_manifest(binary.client_io_manifest.mpc_curve);
        LocalCoordinatorRunnerBuilder {
            runner: Self {
                runner_path: runner_path.into(),
                backend: MpcBackendKind::from(binary.client_io_manifest.mpc_backend),
                binary,
                entry: "main".to_owned(),
                parties: 5,
                threshold: 1,
                curve_config,
                timeout: DEFAULT_TIMEOUT,
                client_inputs: Vec::new(),
                expected_clients: None,
                client_output_counts: std::collections::HashMap::new(),
                topology: LocalTopology::default(),
                admission: LocalAdmission::default(),
            },
        }
    }

    /// [`start`](Self::start), one client per pre-registered slot with inputs,
    /// then [`RunningLocalCoordinator::finish`].
    ///
    /// Under [`LocalAdmission::Open`] with client slots nobody would bind a
    /// slot, and the run would hold at input collection until its deadline
    /// aborted it, so that is refused: use `start` and [`run_offchain_client`].
    pub async fn run(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput> {
        self.validate()?;
        self.refuse_open_without_clients()?;
        self.start().await?.finish().await
    }

    fn refuse_open_without_clients(&self) -> LocalCoordinatorRunnerResult<()> {
        if self.admission == LocalAdmission::Open && !self.client_slot_table()?.slots().is_empty() {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "run() starts only pre-registered clients; with LocalAdmission::Open use start() and run_offchain_client"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Starts the in-process coordinator and every party, and returns while they
    /// run. The returned handle owns the run: its directory, its coordinator and
    /// its parties live exactly as long as it does, and a second local run
    /// cannot start before it is dropped.
    pub async fn start(self) -> LocalCoordinatorRunnerResult<RunningLocalCoordinator> {
        self.validate()?;
        let local_run_guard = local_run_lock().lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();

        let temp = TempRunDir::new()?;
        let program_path = temp.path().join("program.stflb");
        save_to_file(&self.binary, &program_path).map_err(LocalCoordinatorRunnerError::Bytecode)?;
        let program_bytes = self.binary_bytes()?;
        let program_id = program_id_from_bytes(&program_bytes);

        let node_identities = write_node_identities(temp.path(), self.parties)?;
        let node_roster = NodeRoster::new(
            self.threshold as u64,
            node_identities
                .iter()
                .map(|identity| NodeCertificateDer::from_der(identity.cert_der.clone()))
                .collect(),
        )
        .map_err(CoordinatorError::from)?;
        let client_slots = self.client_slot_table()?;
        // Under `Open` no client identity exists before a client associates, so
        // the runner mints none: the slot table is the whole of what it knows.
        let local_clients = match self.admission {
            LocalAdmission::PreRegistered => {
                write_client_identities(temp.path(), &self.known_client_inputs())?
            }
            LocalAdmission::Open => Vec::new(),
        };

        let coord_port = reserve_port()?;
        let coord_cert = self_signed_certs::server_cert();
        let coord_cert_der = coord_cert.cert.der().to_vec();
        let coordinator_spki =
            SpkiDer::from_certificate_der(&coord_cert_der).map_err(CoordinatorError::from)?;
        // Every party pins this certificate with `--coord-cert`
        // (docs/design/bootnode-elimination.md §9.A, §9.F.4). It is public; the
        // key never leaves this process.
        let coord_cert_path = temp.path().join("coordinator.crt");
        std::fs::write(&coord_cert_path, &coord_cert_der)?;
        // Every RPC names the invocation it belongs to, and there is no reset.
        // A fresh id per run is what keeps two runs of this runner from sharing
        // coordinator state even when the program, roster and ports repeat. The
        // all-zero id is reserved and rejected, which `Uuid::new_v4` twice
        // cannot produce.
        let execution_id = mint_execution_id();
        let (admission, deadlines) = match self.admission {
            // It mints one certificate per client slot, and exactly those
            // identities take part.
            LocalAdmission::PreRegistered => (
                AdmissionPolicy::PreRegistered {
                    clients: local_clients
                        .iter()
                        .map(|client| client_identity_of(&client.cert_der))
                        .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?,
                },
                None,
            ),
            LocalAdmission::Open => (
                AdmissionPolicy::Open,
                Some(open_admission_deadlines(UnixSeconds::now(), self.timeout)),
            ),
        };
        let registration = ExecutionRegistration {
            execution_id,
            program_hash: program_id,
            client_slots,
            admission,
            deadlines,
        };
        let coord_state = CoordinatorRPCServerSharedBase::new_for_execution(
            node_roster,
            coordinator_spki,
            registration,
        )?;
        let coordinator = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
            coord_state,
            "127.0.0.1",
            coord_port,
            coord_cert_der.clone(),
            coord_cert.signing_key.serialize_der(),
            RpcServerLimits::default(),
        )
        .await?;

        let mut parties = Vec::with_capacity(self.parties);
        let mut node_rpc_addrs = Vec::with_capacity(self.parties);
        match self.topology {
            LocalTopology::RosterMesh => {
                let mesh = MeshLayout::reserve(temp.path(), &node_identities)?;
                // Symmetric: every party is spawned the same way, at the same
                // time, with the same flags bar its own identity, seeds and
                // epoch store.
                //
                // Starting all five at once is also the harshest case for mesh
                // formation: every party is missing every other one at the same
                // instant. `net::mesh::join::dials_towards` is what makes that
                // safe — a pair is dialed from one end only, so no connection is
                // ever torn down by stoffelnet's simultaneous-connect
                // tie-breaker.
                for (party_id, identity) in node_identities.iter().enumerate() {
                    parties.push(self.spawn_party(
                        &format!("party{party_id}"),
                        SpawnPartyContext {
                            program_path: &program_path,
                            identity,
                            role: mesh.role_for(party_id),
                            coord_port,
                            coord_cert_path: &coord_cert_path,
                            execution_id,
                        },
                        &mut node_rpc_addrs,
                    )?);
                }
            }
        }

        Ok(RunningLocalCoordinator {
            parties,
            pre_registered_clients: local_clients,
            endpoint: LocalClientEndpoint {
                coordinator: SocketAddr::from((Ipv4Addr::LOCALHOST, coord_port)),
                coordinator_cert_der: coord_cert_der,
                execution_id,
                node_rpc_addresses: node_rpc_addrs,
                backend: self.backend,
            },
            timeout: self.timeout,
            _coordinator: coordinator,
            _run_dir: temp,
            _local_run_guard: local_run_guard,
        })
    }

    fn collect_party_outputs(
        outputs: Vec<LocalCoordinatorRunnerResult<LocalPartyOutput>>,
    ) -> LocalCoordinatorRunnerResult<(String, Vec<LocalPartyOutput>)> {
        let mut combined_output = String::new();
        let mut party_outputs = Vec::with_capacity(outputs.len());
        let mut failures = Vec::new();
        for output in outputs {
            match output {
                Ok(output) => {
                    combined_output.push_str(&output.combined);
                    party_outputs.push(output);
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        if !failures.is_empty() {
            if !combined_output.is_empty() {
                failures.push(format!("completed process output:\n{combined_output}"));
            }
            return Err(LocalCoordinatorRunnerError::ProcessFailures(
                failures.join("\n\n"),
            ));
        }

        Ok((combined_output, party_outputs))
    }

    fn validate(&self) -> LocalCoordinatorRunnerResult<()> {
        if !self.runner_path.exists() {
            return Err(LocalCoordinatorRunnerError::Configuration(format!(
                "stoffel-run binary does not exist at {}",
                self.runner_path.display()
            )));
        }
        if self.binary.functions.is_empty() {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "program must contain at least one function".to_owned(),
            ));
        }
        if self.parties < 4 {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "local coordinator runner requires at least 4 parties".to_owned(),
            ));
        }
        if self.parties < self.threshold.saturating_mul(4).saturating_add(1) {
            return Err(LocalCoordinatorRunnerError::Configuration(format!(
                "parties ({}) must be >= 4 * threshold ({}) + 1",
                self.parties, self.threshold
            )));
        }
        self.curve_config
            .validate_for_backend(self.backend)
            .map_err(|error| LocalCoordinatorRunnerError::Configuration(error.to_string()))?;
        if matches!(self.backend, MpcBackendKind::Avss)
            && !self.client_inputs.is_empty()
            && !matches!(self.curve_config, MpcCurveConfig::Bls12_381)
        {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "local coordinator runner AVSS client inputs currently support the bls12-381 curve"
                    .to_owned(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "timeout must be greater than zero".to_owned(),
            ));
        }
        self.validate_expected_clients()?;
        self.validate_client_inputs()?;
        self.client_slot_table()?;
        Ok(())
    }

    fn validate_expected_clients(&self) -> LocalCoordinatorRunnerResult<()> {
        let Some(expected_clients) = self.expected_clients else {
            return Ok(());
        };
        if expected_clients == 0 {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "--expected-output-clients must be greater than 0".to_owned(),
            ));
        }
        let minimum = self
            .binary
            .client_io_manifest
            .clients
            .iter()
            .map(|schema| usize::try_from(schema.client_slot).unwrap_or(usize::MAX))
            .map(|slot| slot.saturating_add(1))
            .max()
            .unwrap_or(0);
        if minimum > expected_clients {
            return Err(LocalCoordinatorRunnerError::Configuration(format!(
                "program declares ClientStore slot(s) requiring expected_clients >= {minimum}, but expected_clients is {expected_clients}"
            )));
        }
        Ok(())
    }

    fn validate_client_inputs(&self) -> LocalCoordinatorRunnerResult<()> {
        if self.admission == LocalAdmission::Open {
            // Under `Open` the runner starts no client, so a value handed to it
            // would never be submitted; the clients bring their own inputs.
            if let Some(client) = self.client_inputs.iter().find(|client| client.has_input()) {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} was given inputs, but under LocalAdmission::Open the runner submits none: pass them to run_offchain_client",
                    client.client_slot
                )));
            }
            return Ok(());
        }
        if self.binary.client_io_manifest.clients.is_empty() && self.client_inputs.is_empty() {
            return Ok(());
        }
        // Clients may supply different numbers of inputs; `write_client_identities`
        // pads each input client up to the max so the reserved-index layout stays
        // uniform (the VM maps reserved_index -> client by dividing by that count)
        // without the caller having to pad by hand.
        if !self.binary.client_io_manifest.clients.is_empty()
            && self.client_inputs.is_empty()
            && self
                .binary
                .client_io_manifest
                .clients
                .iter()
                .any(|schema| !schema.inputs.is_empty())
        {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "program declares ClientStore input metadata; provide local client inputs"
                    .to_owned(),
            ));
        }
        if self.binary.client_io_manifest.clients.is_empty() {
            let mut seen_slots = HashSet::with_capacity(self.client_inputs.len());
            for client in &self.client_inputs {
                if !seen_slots.insert(client.client_slot) {
                    return Err(LocalCoordinatorRunnerError::Configuration(format!(
                        "client slot {} was provided more than once",
                        client.client_slot
                    )));
                }
            }
            return Ok(());
        }
        let mut seen_slots = HashSet::with_capacity(self.client_inputs.len());
        for client in &self.client_inputs {
            if !seen_slots.insert(client.client_slot) {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} was provided more than once",
                    client.client_slot
                )));
            }
            let Some(schema) = self
                .binary
                .client_io_manifest
                .clients
                .iter()
                .find(|schema| schema.client_slot == client.client_slot)
            else {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} is not declared in the program client IO manifest",
                    client.client_slot
                )));
            };
            if schema.inputs.len() != client.values.len() {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} expects {} inputs, got {}",
                    client.client_slot,
                    schema.inputs.len(),
                    client.values.len()
                )));
            }
        }
        for schema in &self.binary.client_io_manifest.clients {
            if !schema.inputs.is_empty() && !seen_slots.contains(&schema.client_slot) {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} is declared in the program client IO manifest but no input was provided",
                    schema.client_slot
                )));
            }
        }
        Ok(())
    }

    /// Number of output values a client receives via `send_to_client`: an
    /// explicit override if provided, else the statically recorded count from
    /// the program's client-IO manifest.
    fn output_count_for_slot(&self, client_slot: u64) -> u64 {
        // Prefer the statically recorded output count from the client-IO
        // manifest. Only when the program does not statically declare outputs
        // for this client (e.g. it sends to a parameterized slot) do we fall
        // back to a developer-provided count (SDK builder / `stoffel run
        // --outputs` / Stoffel.toml), threaded in via `client_output_counts`.
        let manifest_count = self
            .binary
            .client_io_manifest
            .clients
            .iter()
            .find(|schema| schema.client_slot == client_slot)
            .map(|schema| schema.outputs.len() as u64)
            .unwrap_or(0);
        if manifest_count > 0 {
            return manifest_count;
        }
        self.client_output_counts
            .get(&client_slot)
            .copied()
            .unwrap_or(0)
    }

    fn known_client_inputs(&self) -> Vec<LocalClientInput> {
        let mut slots = BTreeSet::new();
        for client in &self.client_inputs {
            slots.insert(client.client_slot);
        }
        for schema in &self.binary.client_io_manifest.clients {
            slots.insert(schema.client_slot);
        }
        if let Some(expected_clients) = self.expected_clients {
            for client_slot in 0..expected_clients {
                slots.insert(client_slot as u64);
            }
        }

        slots
            .into_iter()
            .map(|client_slot| {
                self.client_inputs
                    .iter()
                    .find(|input| input.client_slot == client_slot)
                    .cloned()
                    .unwrap_or_else(|| LocalClientInput::raw(client_slot, Vec::<String>::new()))
            })
            .collect()
    }

    fn binary_bytes(&self) -> LocalCoordinatorRunnerResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.binary
            .serialize(&mut std::io::Cursor::new(&mut bytes))
            .map_err(LocalCoordinatorRunnerError::Bytecode)?;
        Ok(bytes)
    }

    /// The number of inputs the program's client IO manifest declares for
    /// `client_slot`, if it declares that slot at all.
    fn manifest_input_count(&self, client_slot: u64) -> Option<u64> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .find(|schema| schema.client_slot == client_slot)
            .map(|schema| schema.inputs.len() as u64)
    }

    /// The coordinator's client slot table for this run: one slot per
    /// `known_client_inputs` entry, in slot order.
    ///
    /// A slot's position is its `ClientIndex`, so the slots must be exactly
    /// `0..k`. Its input count is the manifest's declared count or, for a slot
    /// the manifest does not declare, the number of values this runner submits
    /// for it — `validate_client_inputs` has already matched the two where
    /// both exist — and its output count is `output_count_for_slot`. The
    /// coordinator derives every slot's input range from these counts, in slot
    /// order, which is the same contiguous layout `write_client_identities`
    /// used to assign by hand.
    fn client_slot_table(&self) -> LocalCoordinatorRunnerResult<ClientSlotTable> {
        let slots = self
            .known_client_inputs()
            .into_iter()
            .enumerate()
            .map(|(position, client)| {
                if client.client_slot != position as u64 {
                    return Err(LocalCoordinatorRunnerError::Configuration(format!(
                        "client slots must be contiguous from 0; slot {position} has neither inputs nor outputs"
                    )));
                }
                let spec = ClientSlotSpec {
                    input_count: self
                        .manifest_input_count(client.client_slot)
                        .unwrap_or(client.values.len() as u64),
                    output_count: self.output_count_for_slot(client.client_slot),
                };
                if spec.input_count == 0 && spec.output_count == 0 {
                    return Err(LocalCoordinatorRunnerError::Configuration(format!(
                        "client slot {position} is output-only, but its output count is unknown: set client_output_count({position}, <count>)"
                    )));
                }
                Ok(spec)
            })
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        Ok(ClientSlotTable::new(slots))
    }

    /// The `stoffel-run` argv of one party, bar the program's own process
    /// settings.
    ///
    /// Membership, `n` and `t` are the in-process coordinator's node roster,
    /// which the party fetches once over the link `--coord-cert` pins
    /// (`docs/design/bootnode-elimination.md` §9.D.1, §9.F.4), so no `--roster`,
    /// `--n-parties` or `--threshold` is emitted — `stoffel-run` refuses each by
    /// name. No client identity, count or slot reaches a party either, under
    /// either admission policy (§3, §9.F.4): a coordinated party takes the slot
    /// table and the admitted clients from the coordinator, and clients reach it
    /// through its RPC listener, so a client certificate here would only have
    /// widened the mesh transport's allowlist to a non-node.
    fn party_args(&self, context: &SpawnPartyContext<'_>, rpc_addr: SocketAddr) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            context.program_path.into(),
            self.entry.clone().into(),
            "--mpc-backend".into(),
            self.backend.name().into(),
            "--curve".into(),
            self.curve_config.name().into(),
            "--off-chain-coord".into(),
            format!("127.0.0.1:{}", context.coord_port).into(),
            "--coord-cert".into(),
            context.coord_cert_path.into(),
            "--execution-id".into(),
            context.execution_id.to_string().into(),
            "--rpc-bind".into(),
            rpc_addr.to_string().into(),
            "--cert".into(),
            context.identity.cert_path.clone().into(),
            "--key".into(),
            context.identity.key_path.clone().into(),
        ];
        args.extend(context.role.runner_args().into_iter().map(OsString::from));
        args
    }

    fn spawn_party(
        &self,
        name: &str,
        context: SpawnPartyContext<'_>,
        node_rpc_addrs: &mut Vec<SocketAddr>,
    ) -> LocalCoordinatorRunnerResult<(String, Child)> {
        let rpc_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, reserve_port()?));
        node_rpc_addrs.push(rpc_addr);
        let mut command = Command::new(&self.runner_path);
        command
            .args(self.party_args(&context, rpc_addr))
            // Tie each spawned party to this runner's lifetime: `kill_on_drop`
            // handles a graceful drop, and the parent-death watchdog (keyed off
            // this env var) covers the case where the runner is force-killed
            // (SIGKILL) and cannot run drop cleanup, preventing orphaned parties.
            .env("STOFFEL_DIE_WITH_PARENT", "1")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = command.spawn()?;
        // Profiler attachment hooks. External `sample`/`ps` can't reliably discover
        // these short-lived child processes (PID races; TEE-buffered markers arrive
        // after the fast online window), so the runner attaches from spawn instead.
        if let Some(pid) = child.id() {
            if std::env::var("STOFFEL_PRINT_PARTY_PIDS").is_ok() {
                eprintln!("[local-runner] party '{name}' pid={pid}");
            }
            // Attach macOS `sample` to this child for STOFFEL_SAMPLE_CHILDREN seconds,
            // writing to /tmp/stoffel_child_sample_<name>_<pid>.txt. Detached — runs
            // independently of the runner, sampling the party across all its phases.
            if let Ok(dur) = std::env::var("STOFFEL_SAMPLE_CHILDREN") {
                let path = format!("/tmp/stoffel_child_sample_{name}_{pid}.txt");
                match std::process::Command::new("sample")
                    .arg(pid.to_string())
                    .arg(&dur)
                    .arg("-mayDie")
                    .arg("-file")
                    .arg(&path)
                    .spawn()
                {
                    Ok(_) => {
                        eprintln!(
                            "[local-runner] sampling party '{name}' (pid={pid}) for {dur}s -> {path}"
                        );
                    }
                    Err(error) => {
                        eprintln!("[local-runner] failed to attach sample to pid={pid}: {error}")
                    }
                }
            }
        }
        Ok((name.to_owned(), child))
    }
}

#[derive(Debug, Clone)]
pub struct LocalCoordinatorRunnerBuilder {
    runner: LocalCoordinatorRunner,
}

impl LocalCoordinatorRunnerBuilder {
    pub fn entry(mut self, entry: impl Into<String>) -> Self {
        self.runner.entry = entry.into();
        self
    }

    pub fn parties(mut self, parties: usize) -> Self {
        self.runner.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.runner.threshold = threshold;
        self
    }

    pub fn backend(mut self, backend: MpcBackendKind) -> Self {
        self.runner.backend = backend;
        self
    }

    pub fn curve(mut self, curve_config: MpcCurveConfig) -> Self {
        self.runner.curve_config = curve_config;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.runner.timeout = timeout;
        self
    }

    /// Choose how the spawned parties form their network.
    ///
    /// [`LocalTopology::RosterMesh`] is the only topology and the default;
    /// `docs/design/bootnode-elimination.md` Stage 8 removed the leader/bootnode
    /// one. The method stays so that a second way to form a session would be a
    /// variant, not a second runner.
    pub fn topology(mut self, topology: LocalTopology) -> Self {
        self.runner.topology = topology;
        self
    }

    pub fn client_input(mut self, client_slot: u64, values: impl IntoIterator<Item = i64>) -> Self {
        self.runner
            .client_inputs
            .push(LocalClientInput::new(client_slot, values));
        self
    }

    pub fn client_inputs(mut self, inputs: impl IntoIterator<Item = LocalClientInput>) -> Self {
        self.runner.client_inputs.extend(inputs);
        self
    }

    pub fn expected_output_clients(mut self, expected_clients: usize) -> Self {
        self.runner.expected_clients = Some(expected_clients);
        self
    }

    /// Override the number of output values a client receives via
    /// `send_to_client`. When unset, the count is taken from the program's
    /// client-IO manifest (the statically recorded output schema).
    pub fn client_output_count(mut self, client_slot: u64, count: u64) -> Self {
        self.runner.client_output_counts.insert(client_slot, count);
        self
    }

    /// How clients come to hold the run's client slots. Defaults to
    /// [`LocalAdmission::PreRegistered`].
    pub fn admission(mut self, admission: LocalAdmission) -> Self {
        self.runner.admission = admission;
        self
    }

    pub fn build(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunner> {
        self.runner.validate()?;
        Ok(self.runner)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClientInput {
    pub client_slot: u64,
    pub values: Vec<String>,
}

impl LocalClientInput {
    pub fn new(client_slot: u64, values: impl IntoIterator<Item = i64>) -> Self {
        Self {
            client_slot,
            values: values.into_iter().map(|value| value.to_string()).collect(),
        }
    }

    pub fn raw(client_slot: u64, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            client_slot,
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    fn has_input(&self) -> bool {
        !self.values.is_empty()
    }
}

/// A client's reconstructed output values, received via `send_to_client` and
/// reconstructed by the off-chain client (not a public reveal to the nodes).
#[derive(Debug, Clone)]
pub struct ClientOutputRecord {
    pub client_slot: u64,
    pub values: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct LocalCoordinatorRunOutput {
    pub combined_output: String,
    pub party_outputs: Vec<LocalPartyOutput>,
    pub client_outputs: Vec<ClientOutputRecord>,
}

impl LocalCoordinatorRunOutput {
    pub fn returned_values(&self) -> Vec<&str> {
        returned_values_from(&self.combined_output)
    }

    pub fn consistent_returned_values(&self) -> Result<Vec<String>, String> {
        let mut parties = self.party_outputs.iter();
        let Some(first_party) = parties.next() else {
            return Err("local coordinator run did not produce any party output".to_owned());
        };
        let first_values = first_party
            .returned_values()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if first_values.is_empty() {
            return Err(format!(
                "local party {} did not report a VM return value",
                first_party.name
            ));
        }

        for party in parties {
            let values = party
                .returned_values()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if values != first_values {
                return Err(format!(
                    "local party {} returned {:?}, expected {:?} from party {}",
                    party.name, values, first_values, first_party.name
                ));
            }
        }

        Ok(first_values)
    }
}

fn returned_values_from(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Program returned: "))
        .collect()
}

#[derive(Debug, Clone)]
pub struct LocalPartyOutput {
    pub name: String,
    pub stdout: String,
    pub stderr: String,
    pub combined: String,
}

impl LocalPartyOutput {
    pub fn returned_values(&self) -> Vec<&str> {
        returned_values_from(&self.combined)
    }
}

#[derive(Clone)]
struct NodeIdentity {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: Vec<u8>,
}

#[derive(Clone)]
struct LocalClientIdentity {
    input: LocalClientInput,
    key_path: PathBuf,
    cert_der: Vec<u8>,
    client_slot: u64,
}

/// Everything a client needs to reach a running local coordinator and its
/// nodes. It names no client: under [`LocalAdmission::Open`] any certificate
/// holder may use it to bind a free slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClientEndpoint {
    pub coordinator: SocketAddr,
    /// The in-process coordinator's certificate, pinned by every client
    /// connection (`docs/design/bootnode-elimination.md` §9.A).
    pub coordinator_cert_der: Vec<u8>,
    pub execution_id: ExecutionId,
    /// The parties' node RPC listeners, in spawn order.
    pub node_rpc_addresses: Vec<SocketAddr>,
    pub backend: MpcBackendKind,
}

/// What one client got from a local run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClientRun {
    /// The slot, input range and output rights the coordinator admitted it to.
    pub admission: ClientAdmission,
    /// Reconstructed outputs, each reduced to its low 64 bits (`fr_to_u64`);
    /// empty without output rights.
    pub outputs: Vec<u64>,
}

/// A local run started by [`LocalCoordinatorRunner::start`].
///
/// It owns everything the run needs for as long as it lasts: the lock that
/// keeps a second local run from overlapping it, the run directory (identities,
/// program, epoch stores, `coordinator.crt`), the in-process coordinator and
/// the party processes, which are killed when it is dropped.
///
/// Fields drop in declaration order, which is the teardown order: the parties
/// are killed before the coordinator stops, the run directory goes after both,
/// and the lock is released last, so a dropped run never overlaps the next one.
pub struct RunningLocalCoordinator {
    parties: Vec<(String, Child)>,
    pre_registered_clients: Vec<LocalClientIdentity>,
    endpoint: LocalClientEndpoint,
    timeout: Duration,
    _coordinator: OffChainCoordinatorServer<OffChainCoordinatorConnection>,
    _run_dir: TempRunDir,
    _local_run_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl RunningLocalCoordinator {
    /// Where a client of this run connects, and which coordinator key it pins.
    pub fn client_endpoint(&self) -> &LocalClientEndpoint {
        &self.endpoint
    }

    /// Runs one client per pre-registered slot with inputs, waits for every
    /// party to exit, and collects the run's output. Fails if a party exits
    /// before those clients finished.
    pub async fn finish(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput> {
        let Self {
            parties,
            pre_registered_clients,
            endpoint,
            timeout,
            _coordinator,
            _run_dir,
            _local_run_guard,
        } = self;

        let client_results_future = futures::future::join_all(
            pre_registered_clients
                .iter()
                .filter(|client| client.input.has_input())
                .map(|client| run_pre_registered_client(client, &endpoint, timeout)),
        );
        let party_outputs_future = futures::future::join_all(
            parties
                .into_iter()
                .map(|(name, child)| wait_for_child(name, child, timeout)),
        );

        tokio::pin!(client_results_future);
        tokio::pin!(party_outputs_future);

        let (client_results, combined_output, party_outputs) = tokio::select! {
            client_results = &mut client_results_future => {
                let outputs = party_outputs_future.await;
                let (combined_output, party_outputs) =
                    LocalCoordinatorRunner::collect_party_outputs(outputs)?;
                (client_results, combined_output, party_outputs)
            }
            outputs = &mut party_outputs_future => {
                let (combined_output, _party_outputs) =
                    LocalCoordinatorRunner::collect_party_outputs(outputs)?;
                return Err(LocalCoordinatorRunnerError::ProcessFailures(format!(
                    "local coordinator parties exited before client IO completed\n\ncompleted process output:\n{combined_output}"
                )));
            }
        };

        let mut client_outputs = Vec::new();
        for result in client_results {
            if let Some(record) = result? {
                client_outputs.push(record);
            }
        }

        Ok(LocalCoordinatorRunOutput {
            combined_output,
            party_outputs,
            client_outputs,
        })
    }
}

/// The deadlines an `Open` local run registers: the run's `timeout` from
/// registration for both, rounded up to whole seconds so that a sub-second
/// timeout still names a deadline later than the coordinator's clock.
fn open_admission_deadlines(registration: UnixSeconds, timeout: Duration) -> ExecutionDeadlines {
    let secs = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0))
        .max(1);
    let deadline = UnixSeconds(registration.0.saturating_add(secs));
    ExecutionDeadlines {
        association: deadline,
        input: deadline,
    }
}

/// A fresh, non-zero [`ExecutionId`] for one run.
///
/// Two v4 UUIDs supply the 32 bytes. Both carry fixed version/variant bits, so
/// the all-zero value the coordinator reserves cannot be produced.
fn mint_execution_id() -> ExecutionId {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    ExecutionId::from_bytes(bytes)
}

/// The coordinator identity form of a certificate's key: the `subject_public_key`
/// BIT STRING, derived through the one canonical derivation the coordinator uses.
fn client_identity_of(cert_der: &[u8]) -> LocalCoordinatorRunnerResult<ClientIdentity> {
    Ok(SpkiDer::from_certificate_der(cert_der)
        .map_err(CoordinatorError::from)?
        .client_identity())
}

/// §9.E.1 for one client against a running local coordinator
/// ([`crate::coordinator_client`]): pins the run's coordinator, checks the
/// execution's summary, associates with `request`, reserves, fetches masks for
/// and submits exactly the admitted input range, and — with output rights —
/// reconstructs its outputs from one signed item per node.
///
/// `cert_der` and `key_der` are the client's own identity; the runner need not
/// have seen it before. Under [`LocalAdmission::Open`] this is how a client
/// whose identity is not known in advance joins the computation.
pub async fn run_offchain_client(
    endpoint: &LocalClientEndpoint,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    request: AssociationRequest,
    inputs: &[String],
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<LocalClientRun> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let input_values = inputs
        .iter()
        .map(|value| parse_input_as_field(value))
        .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
    let config = CoordinatorClientConfig {
        coordinator: CoordinatorEndpoint {
            host: endpoint.coordinator.ip().to_string(),
            port: endpoint.coordinator.port(),
            pin: SpkiDer::from_certificate_der(&endpoint.coordinator_cert_der)
                .map_err(CoordinatorError::from)?,
        },
        execution_id: endpoint.execution_id,
        backend: endpoint.backend,
        cert_der,
        key_der,
        node_rpc_addresses: endpoint
            .node_rpc_addresses
            .iter()
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .collect(),
        request,
        expected_roster_digest: None,
        expected_program_hash: None,
        expected_output_count: None,
    };
    let run = tokio::time::timeout(timeout, async {
        match endpoint.backend {
            MpcBackendKind::HoneyBadger => {
                config
                    .connect_and_run::<Fr, RobustShare<Fr>>(input_values)
                    .await
            }
            MpcBackendKind::Avss => {
                config
                    .connect_and_run::<Fr, FeldmanShamirShare<Fr, G1Projective>>(input_values)
                    .await
            }
        }
    })
    .await
    .map_err(|_| LocalCoordinatorRunnerError::Timeout(timeout))??;
    Ok(LocalClientRun {
        admission: run.admission,
        outputs: run.outputs.iter().map(fr_to_u64).collect(),
    })
}

/// One pre-registered client of [`RunningLocalCoordinator::finish`]: binds the
/// slot its certificate was registered to and submits the runner's values.
async fn run_pre_registered_client(
    client: &LocalClientIdentity,
    endpoint: &LocalClientEndpoint,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<Option<ClientOutputRecord>> {
    let slot = u32::try_from(client.client_slot).map_err(|_| {
        LocalCoordinatorRunnerError::Configuration(format!(
            "client slot {} does not fit a coordinator client index",
            client.client_slot
        ))
    })?;
    let run = run_offchain_client(
        endpoint,
        client.cert_der.clone(),
        std::fs::read(&client.key_path)?,
        AssociationRequest {
            slot: Some(ClientIndex(slot)),
            invitation: None,
        },
        &client.input.values,
        timeout,
    )
    .await?;
    let receives = matches!(run.admission.output_rights, OutputRights::Receive { .. });
    Ok(receives.then_some(ClientOutputRecord {
        client_slot: client.client_slot,
        values: run.outputs,
    }))
}

/// Reduce a field element to its low 64 bits (exact for the small values —
/// bits, bytes — that client outputs carry in these examples).
fn fr_to_u64(value: &Fr) -> u64 {
    let bytes = value.into_bigint().to_bytes_le();
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(buf)
}

fn parse_input_as_field(value: &str) -> LocalCoordinatorRunnerResult<Fr> {
    let value = value.trim();
    // Booleans are advertised by the CLI as valid client inputs; share them
    // as the field bits 1/0 so secret-bool gates work on them.
    if value.eq_ignore_ascii_case("true") {
        return Ok(Fr::from(1u64));
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(Fr::from(0u64));
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        let mut hex = hex.to_owned();
        if hex.len() % 2 == 1 {
            hex.insert(0, '0');
        }
        let bytes = hex::decode(&hex).map_err(|error| {
            LocalCoordinatorRunnerError::Configuration(format!(
                "invalid hex client input '{value}': {error}"
            ))
        })?;
        return Ok(Fr::from_be_bytes_mod_order(&bytes));
    }
    let value = value.parse::<i64>().map_err(|error| {
        LocalCoordinatorRunnerError::Configuration(format!(
            "invalid integer client input '{value}': {error}"
        ))
    })?;
    Ok(stoffel_vm::net::field_from_i64::<Fr>(value))
}

/// How a local multi-party run forms its network.
///
/// Stage 7 of `docs/design/bootnode-elimination.md` flipped this to the mesh and
/// Stage 8 removed the alternative, so there is exactly one variant today. The
/// type survives its own collapse deliberately: it is the surface behind all
/// four local paths — `stoffel run --local`, `stoffel dev`, `stoffel test
/// --local` and the SDK's `execute_local_*`.
///
/// Nothing has to be configured for the mesh: its roster is the in-process
/// coordinator's node roster (design doc §9.D, §9.F.4), built from the node
/// certificates this runner mints and fetched by every party once, and its
/// per-party epoch stores go in the same temporary directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LocalTopology {
    /// Every party is symmetric: a roster-pinned mesh formed from `--peers`
    /// seed addresses, with no bootstrap process anywhere.
    ///
    /// The run's own node certificates are the in-process coordinator's node
    /// roster, which every party fetches over its pinned link; each party
    /// additionally gets its own epoch store directory, because two nodes
    /// sharing one would race on the monotone counter that keeps `instance_id`
    /// fresh (blocker B5).
    #[default]
    RosterMesh,
}

enum PartyRole {
    /// One member of a roster-pinned mesh.
    Mesh {
        party_id: usize,
        bind: SocketAddr,
        /// The other parties' listen addresses, as `--peers` seed hints.
        peers: Vec<SocketAddr>,
        /// This party's own epoch store directory.
        epoch_store: PathBuf,
    },
}

impl PartyRole {
    /// The `stoffel-run` flags this role contributes, in emission order.
    ///
    /// Split out from the spawn so that the flag set is assertable without
    /// starting five processes and a coordinator.
    fn runner_args(&self) -> Vec<String> {
        match self {
            PartyRole::Mesh {
                party_id,
                bind,
                peers,
                epoch_store,
            } => {
                // No round-driver flag: coordinator `0.2.0` applies a round once
                // a quorum of roster members has proposed it, so every party
                // proposes every transition and none of them is designated.
                vec![
                    "--party-id".to_owned(),
                    party_id.to_string(),
                    "--bind".to_owned(),
                    bind.to_string(),
                    "--peers".to_owned(),
                    peers
                        .iter()
                        .map(|addr| addr.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    "--epoch-store".to_owned(),
                    epoch_store.display().to_string(),
                ]
            }
        }
    }
}

/// The addresses and epoch stores one roster-pinned mesh run needs. The roster
/// itself is the coordinator's.
struct MeshLayout {
    binds: Vec<SocketAddr>,
    epoch_stores: Vec<PathBuf>,
}

impl MeshLayout {
    fn reserve(run_dir: &Path, identities: &[NodeIdentity]) -> LocalCoordinatorRunnerResult<Self> {
        let binds = identities
            .iter()
            .map(|_| reserve_party_port())
            .collect::<std::io::Result<Vec<_>>>()?;
        // One directory per node, never shared: `agree_epoch` is `max` over the
        // parties' proposals bounded by each node's own `last`, so two nodes
        // reading and writing one store would propose against a counter the
        // other had already moved.
        let epoch_stores = (0..identities.len())
            .map(|party_id| run_dir.join(format!("epochs-party-{party_id}")))
            .collect();
        Ok(Self {
            binds,
            epoch_stores,
        })
    }

    fn role_for(&self, party_id: usize) -> PartyRole {
        PartyRole::Mesh {
            party_id,
            bind: self.binds[party_id],
            // Every other party, so that no pair depends on a single node being
            // reachable first: the mesh forms out of dials, and peer exchange
            // happens after it is already complete.
            peers: self
                .binds
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != party_id)
                .map(|(_, addr)| *addr)
                .collect(),
            epoch_store: self.epoch_stores[party_id].clone(),
        }
    }
}

struct SpawnPartyContext<'a> {
    program_path: &'a Path,
    identity: &'a NodeIdentity,
    role: PartyRole,
    coord_port: u16,
    /// The in-process coordinator's certificate, which every party pins.
    coord_cert_path: &'a Path,
    execution_id: ExecutionId,
}

struct TempRunDir {
    path: PathBuf,
}

impl TempRunDir {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("stoffel-local-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Mint `count` node identities, indexed by the rank the mesh will derive.
///
/// The certificates are freshly generated, so their SPKI order is a fresh
/// permutation on every run. Sorting them here — by the same
/// `public_key_from_certificate_der` bytes stoffelnet ranks parties on, never
/// the bare BIT STRING (blocker B2) — makes spawn index *equal* roster rank by
/// construction. Nothing depends on that equality (the wire index is derived,
/// and persistent state is keyed by each node's certificate), but without it
/// this runner names a party's epoch store `epochs-party-3` while the mesh
/// addresses it as party 0, which is a confusing thing to hand a reader of the
/// logs. It also lines the coordinator's `mpc_nodes` registration order up with
/// the MPC party indices, since `run` registers these identities in order.
fn write_node_identities(
    path: &Path,
    count: usize,
) -> LocalCoordinatorRunnerResult<Vec<NodeIdentity>> {
    let mut minted = (0..count)
        .map(|_| {
            let cert = self_signed_certs::client_cert();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
            let spki = QuicNetworkManager::public_key_from_certificate_der(&cert_der).map_err(
                |reason| {
                    LocalCoordinatorRunnerError::Configuration(format!(
                        "derive SPKI from minted node certificate: {reason}"
                    ))
                },
            )?;
            Ok((spki.0, cert_der, key_der))
        })
        .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
    minted.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));

    minted
        .into_iter()
        .enumerate()
        .map(|(index, (_, cert_der, key_der))| {
            let cert_path = path.join(format!("node{index}.cert.der"));
            let key_path = path.join(format!("node{index}.key.der"));
            std::fs::write(&cert_path, &cert_der)?;
            std::fs::write(&key_path, key_der)?;
            Ok(NodeIdentity {
                cert_path,
                key_path,
                cert_der,
            })
        })
        .collect()
}

fn write_client_identities(
    path: &Path,
    inputs: &[LocalClientInput],
) -> LocalCoordinatorRunnerResult<Vec<LocalClientIdentity>> {
    let mut sorted_inputs = inputs.to_vec();
    // Slot order is registration order: the coordinator's `PreRegistered` policy
    // binds `clients[i]` to slot `i`, and derives each slot's contiguous input
    // range from the slot table (clients may supply different numbers of
    // inputs). The VM groups the returned shares per client (see
    // `store_reserved_client_inputs`), so no uniform padding is required.
    sorted_inputs.sort_by_key(|input| input.client_slot);
    sorted_inputs
        .into_iter()
        .map(|input| {
            let cert = self_signed_certs::client_cert();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
            // Only the key goes to disk, for the client this runner runs: the
            // certificate is registered with the coordinator from memory and
            // no party is ever given it.
            let key_path = path.join(format!("client{}.key.der", input.client_slot));
            std::fs::write(&key_path, key_der)?;
            Ok(LocalClientIdentity {
                client_slot: input.client_slot,
                input,
                key_path,
                cert_der,
            })
        })
        .collect()
}

async fn wait_for_child(
    name: String,
    mut child: Child,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<LocalPartyOutput> {
    let stdout_pipe = child.stdout.take().ok_or_else(|| {
        LocalCoordinatorRunnerError::Configuration("child stdout was not piped".to_owned())
    })?;
    let stderr_pipe = child.stderr.take().ok_or_else(|| {
        LocalCoordinatorRunnerError::Configuration("child stderr was not piped".to_owned())
    })?;
    let tee_output = std::env::var("STOFFEL_LOCAL_RUNNER_TEE")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let stdout_name = name.clone();
    let stdout_task = tokio::spawn(async move {
        read_child_output(stdout_name, "stdout", stdout_pipe, tee_output).await
    });
    let stderr_name = name.clone();
    let stderr_task = tokio::spawn(async move {
        read_child_output(stderr_name, "stderr", stderr_pipe, tee_output).await
    });

    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let stdout = stdout_task.await.map_err(|error| {
                LocalCoordinatorRunnerError::Configuration(format!("join stdout reader: {error}"))
            })??;
            let stderr = stderr_task.await.map_err(|error| {
                LocalCoordinatorRunnerError::Configuration(format!("join stderr reader: {error}"))
            })??;
            return Err(LocalCoordinatorRunnerError::PartyTimeout {
                name: name.clone(),
                timeout,
                output: format!("== {name} stdout ==\n{stdout}\n== {name} stderr ==\n{stderr}\n"),
            });
        }
    };

    let stdout = stdout_task.await.map_err(|error| {
        LocalCoordinatorRunnerError::Configuration(format!("join stdout reader: {error}"))
    })??;
    let stderr = stderr_task.await.map_err(|error| {
        LocalCoordinatorRunnerError::Configuration(format!("join stderr reader: {error}"))
    })??;
    let combined = format!("== {name} stdout ==\n{stdout}\n== {name} stderr ==\n{stderr}\n");
    if !status.success() {
        return Err(LocalCoordinatorRunnerError::PartyExit {
            name,
            status,
            output: combined,
        });
    }

    Ok(LocalPartyOutput {
        name,
        stdout,
        stderr,
        combined,
    })
}

async fn read_child_output<R>(
    name: String,
    stream: &'static str,
    pipe: R,
    tee_output: bool,
) -> std::io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(pipe);
    let mut output = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        if tee_output {
            eprint!("[{name} {stream}] {line}");
        }
        output.push_str(&line);
    }

    Ok(output)
}

fn reserve_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port())
}

fn local_run_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn local_runner_curve_from_manifest(
    curve: stoffel_vm_types::compiled_binary::MpcCurve,
) -> MpcCurveConfig {
    match curve {
        stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => MpcCurveConfig::Bls12_381,
        stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => MpcCurveConfig::Bn254,
        stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => MpcCurveConfig::Curve25519,
        stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => MpcCurveConfig::Ed25519,
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => MpcCurveConfig::Secp256k1,
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => MpcCurveConfig::Secp256r1,
    }
}

/// Reserve a free loopback port for one party to bind.
///
/// This used to be `socket_with_port_pair`, and it required *two* free ports —
/// `port` and `port + 1000` — because a leader bound its bootnode on one and its
/// own party listener on the other (`docs/design/bootnode-elimination.md` §7
/// lists all four homes of that convention). A mesh party binds one socket and
/// advertises the port it bound, so the pairing is gone and with it the
/// possibility of a party advertising a port nothing listens on.
fn reserve_party_port() -> std::io::Result<SocketAddr> {
    // Mix the wall-clock nanos with the process id and a per-call counter so
    // that runner processes launched concurrently (e.g. parallel CLI tests)
    // and successive calls within one process begin their scan from different
    // base ports instead of colliding on the same time-derived guess. The
    // chosen port is only checked for availability here and bound later by the
    // spawned child, so a shared starting point would otherwise let two runs
    // settle on the same port and race to bind it.
    static CALL_COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u16)
        .unwrap_or(0);
    let pid = std::process::id() as u16;
    let call = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = nanos
        .wrapping_add(pid.wrapping_mul(7))
        .wrapping_add(call.wrapping_mul(1009));
    for offset in 0..30_000u16 {
        let port = 20_000 + ((seed.wrapping_add(offset)) % 30_000);
        if port_is_free(port) {
            return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "could not reserve a free localhost party port in 20000..49999",
    ))
}

fn port_is_free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use stoffel_vm_types::compiled_binary::{ClientIoSchema, CompiledFunction, FunctionType};
    use stoffel_vm_types::core_types::ShareType;

    fn test_runner(mut binary: CompiledBinary) -> LocalCoordinatorRunnerBuilder {
        binary.functions.push(CompiledFunction {
            name: "main".to_owned(),
            register_count: 0,
            parameters: Vec::new(),
            parameter_types: Vec::new(),
            return_type: FunctionType::Unknown,
            upvalues: Vec::new(),
            parent: None,
            labels: HashMap::new(),
            instructions: Vec::new(),
        });
        LocalCoordinatorRunner::builder("/bin/sh", binary)
    }

    fn mesh_identity(dir: &Path, index: usize) -> NodeIdentity {
        NodeIdentity {
            cert_path: dir.join(format!("node{index}.cert.der")),
            key_path: dir.join(format!("node{index}.key.der")),
            cert_der: vec![index as u8; 4],
        }
    }

    /// `--party-id N` names this runner's `party-N` volumes, and the mesh
    /// addresses a node by its rank in the roster's lexicographic SPKI order.
    /// The two are independent quantities — a mismatch is reported and the run
    /// continues on the derived rank — but for freshly minted certificates the
    /// runner controls both, so it makes them equal rather than leaving a
    /// reader of the logs to reconcile `epochs-party-3` with `[party 0]`.
    #[test]
    fn minted_node_identities_are_indexed_by_the_rank_the_mesh_will_derive() {
        let dir = TempRunDir::new().expect("create run dir");
        let identities = write_node_identities(dir.path(), 5).expect("mint node identities");

        let ranks: Vec<Vec<u8>> = identities
            .iter()
            .map(|identity| {
                QuicNetworkManager::public_key_from_certificate_der(&identity.cert_der)
                    .expect("derive SPKI from minted certificate")
                    .0
            })
            .collect();
        let mut sorted = ranks.clone();
        sorted.sort();
        assert_eq!(
            ranks, sorted,
            "identity N must be the certificate the roster ranks N, so that the spawn index \
             this runner passes as --party-id is the index the mesh derives"
        );

        for (index, identity) in identities.iter().enumerate() {
            assert_eq!(
                identity.cert_path,
                dir.path().join(format!("node{index}.cert.der")),
                "the on-disk name must follow the rank, not the mint order"
            );
        }
    }

    /// Retargets `the_mesh_topology_replaces_bootstrap_with_seeds_a_roster_and_an_epoch_store`
    /// (design doc §9.H): a mesh party is pinned to the coordinator, from which it
    /// fetches the node roster, and names no roster, party count, threshold,
    /// timestamp or client of its own. Asserted over the whole argv without
    /// starting five processes and a coordinator.
    #[test]
    fn a_mesh_party_is_pinned_to_the_coordinator_and_names_no_roster_or_client() {
        let dir = Path::new("/tmp/stoffel-mesh-layout-test");
        let identities: Vec<NodeIdentity> = (0..3).map(|index| mesh_identity(dir, index)).collect();
        let layout = MeshLayout::reserve(dir, &identities).expect("reserve mesh layout");

        let party1 = layout.role_for(1).runner_args();
        let flags: Vec<&str> = party1
            .iter()
            .filter(|arg| arg.starts_with("--"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            flags,
            vec!["--party-id", "--bind", "--peers", "--epoch-store"],
            "a mesh party is spelled by its identity, its seeds and its epoch store; \
             membership is the coordinator's"
        );

        let runner = test_runner(CompiledBinary::new()).build().expect("runner");
        let coord_cert_path = dir.join("coordinator.crt");
        let argv: Vec<String> = runner
            .party_args(
                &SpawnPartyContext {
                    program_path: &dir.join("program.stflb"),
                    identity: &identities[1],
                    role: layout.role_for(1),
                    coord_port: 31415,
                    coord_cert_path: &coord_cert_path,
                    execution_id: ExecutionId::from_bytes([7u8; 32]),
                },
                SocketAddr::from((Ipv4Addr::LOCALHOST, 10001)),
            )
            .into_iter()
            .map(|arg| arg.into_string().expect("utf-8 argv"))
            .collect();
        let value_of = |flag: &str| {
            argv.iter()
                .position(|arg| arg == flag)
                .map(|index| argv[index + 1].as_str())
        };
        assert_eq!(value_of("--off-chain-coord"), Some("127.0.0.1:31415"));
        assert_eq!(
            value_of("--coord-cert"),
            coord_cert_path.to_str(),
            "every party pins the in-process coordinator's certificate"
        );
        assert_eq!(
            value_of("--cert"),
            identities[1].cert_path.to_str(),
            "a party presents its own node certificate"
        );
        for absent in [
            "--roster",
            "--expected-clients",
            "--n-parties",
            "--threshold",
            "--timestamp",
            "--wait-for-clients",
            "--client-input-count",
            "--client-roster",
        ] {
            assert!(
                !argv.iter().any(|arg| arg == absent),
                "{absent} must not reach a party: {argv:?}"
            );
        }

        let peers = &party1[party1.iter().position(|arg| arg == "--peers").unwrap() + 1];
        assert_eq!(
            peers,
            &format!("{},{}", layout.binds[0], layout.binds[2]),
            "every other party, and never this party's own address"
        );

        let epochs = &party1[party1
            .iter()
            .position(|arg| arg == "--epoch-store")
            .unwrap()
            + 1];
        assert_eq!(epochs, &dir.join("epochs-party-1").display().to_string());
        let all_stores: BTreeSet<&PathBuf> = layout.epoch_stores.iter().collect();
        assert_eq!(
            all_stores.len(),
            identities.len(),
            "two nodes sharing one epoch store would race on the counter that keeps \
             instance_id fresh (blocker B5)"
        );
    }

    /// No party drives the coordinator's rounds any more.
    ///
    /// This case is the record of Stage 9: it used to assert that exactly one
    /// party carried `--coord-driver`, because published coordinator `0.1.0`
    /// hard-gated `transition` on `mpc_nodes[0]`. `0.2.0` records a vote from
    /// any roster member and applies a round at `transition_quorum()`, so the
    /// designated party is gone and every party's argv is the same bar its own
    /// identity, seeds and epoch store — which is what makes the symmetry claim
    /// in `LocalTopology::RosterMesh` literally true.
    #[test]
    fn no_mesh_party_is_designated_to_drive_the_coordinator() {
        let dir = Path::new("/tmp/stoffel-mesh-driver-test");
        let identities: Vec<NodeIdentity> = (0..3).map(|index| mesh_identity(dir, index)).collect();
        let layout = MeshLayout::reserve(dir, &identities).expect("reserve mesh layout");

        for party_id in 0..identities.len() {
            let args = layout.role_for(party_id).runner_args();
            assert!(
                !args.iter().any(|arg| arg == "--coord-driver"),
                "party {party_id} still emits a round-driver flag: {args:?}"
            );
        }

        // Symmetry, stated over the flag names rather than their values: every
        // party emits the same flags, and only the values differ.
        let flags = |party_id: usize| {
            layout
                .role_for(party_id)
                .runner_args()
                .into_iter()
                .filter(|arg| arg.starts_with("--"))
                .collect::<Vec<_>>()
        };
        for party_id in 1..identities.len() {
            assert_eq!(flags(0), flags(party_id));
        }
    }

    /// Every coordinator-bearing party is spawned with the run's `--execution-id`.
    ///
    /// Coordinator `0.2.0` keys rounds, reserved indices, masked inputs and
    /// output shares on it, and dropped `0.1.0`'s `reset_coord`: a fresh id per
    /// run is what keeps two runs of this runner from sharing coordinator state.
    #[test]
    fn a_spawned_party_carries_the_runs_execution_id() {
        let execution_id = mint_execution_id();
        assert!(!execution_id.is_zero());
        assert_ne!(execution_id, mint_execution_id());

        let rendered = execution_id.to_string();
        assert_eq!(rendered.len(), 64);
        assert_eq!(
            rendered.parse::<ExecutionId>().expect("round trip"),
            execution_id
        );
    }

    /// Stage 7's whole point, and Stage 8's confirmation of it.
    ///
    /// This case has been rewritten twice and the direction of travel is the
    /// record: it first asserted that a mesh run was opt-in, then (Stage 7) that
    /// the mesh was the default and the bootnode the opt-out. Stage 8 deleted
    /// the opt-out, so there is one topology and it is the mesh.
    #[test]
    fn a_local_run_meshes_and_has_no_other_topology() {
        assert_eq!(LocalTopology::default(), LocalTopology::RosterMesh);
        let runner = test_runner(CompiledBinary::new()).build().expect("runner");
        assert_eq!(runner.topology, LocalTopology::RosterMesh);

        let explicit = test_runner(CompiledBinary::new())
            .topology(LocalTopology::RosterMesh)
            .build()
            .expect("runner");
        assert_eq!(explicit.topology, LocalTopology::RosterMesh);
    }

    /// A party binds one port and advertises the port it bound.
    ///
    /// The `bind_port + 1000` convention this replaced existed only because a
    /// leader ran a bootnode on one port and its own party listener on the
    /// other. Stage 8 removed it from all four of its homes at once
    /// (`docs/design/bootnode-elimination.md` §7): here, in `stoffel-run`, in
    /// `docker/entrypoint.sh` and in the `Dockerfile`'s `EXPOSE`. Removing it
    /// from some and not others makes a party advertise a port nothing listens
    /// on, which is a hang rather than an error.
    #[test]
    fn a_mesh_party_reserves_one_port_and_does_not_pair_it() {
        let dir = Path::new("/tmp/stoffel-mesh-port-test");
        let identities: Vec<NodeIdentity> = (0..3).map(|index| mesh_identity(dir, index)).collect();
        let layout = MeshLayout::reserve(dir, &identities).expect("reserve mesh layout");

        for bind in &layout.binds {
            assert!(
                port_is_free(bind.port()),
                "a reserved party port must still be free until the child binds it"
            );
        }

        let party1 = layout.role_for(1).runner_args();
        let bind = &party1[party1.iter().position(|arg| arg == "--bind").unwrap() + 1];
        let peers = &party1[party1.iter().position(|arg| arg == "--peers").unwrap() + 1];
        assert_eq!(bind, &layout.binds[1].to_string());
        assert_eq!(
            peers,
            &format!("{},{}", layout.binds[0], layout.binds[2]),
            "peers are the other parties' bind addresses, with no port arithmetic"
        );
    }

    /// Retargeted for coordinator `0.3.0` (docs/design/bootnode-elimination.md
    /// §9.F.4): this used to assert `coordinator_client_io_binding`'s
    /// `(n_inputs, output_clients)`, which no longer exists. The coordinator's
    /// slot table refuses a slot with neither inputs nor outputs, so an
    /// output-only slot of a program with dynamic outputs must be given its
    /// output count, and a builder without one fails naming the fix rather than
    /// reaching the coordinator as `EmptyClientSlot`.
    #[test]
    fn expected_clients_create_output_identities_for_dynamic_outputs() {
        let runner = test_runner(CompiledBinary::new())
            .expected_output_clients(2)
            .client_output_count(0, 1)
            .client_output_count(1, 1)
            .build()
            .expect("runner");

        let known_clients = runner.known_client_inputs();
        assert_eq!(
            known_clients
                .iter()
                .map(|client| client.client_slot)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(known_clients.iter().all(|client| client.values.is_empty()));

        let table = runner.client_slot_table().expect("slot table");
        assert_eq!(
            table.slots(),
            &[
                ClientSlotSpec {
                    input_count: 0,
                    output_count: 1
                },
                ClientSlotSpec {
                    input_count: 0,
                    output_count: 1
                },
            ]
        );

        let error = test_runner(CompiledBinary::new())
            .expected_output_clients(2)
            .build()
            .expect_err("an output-only slot without an output count is refused");
        assert!(
            error
                .to_string()
                .contains("client_output_count(0, <count>)"),
            "{error}"
        );
    }

    /// Retargeted with the test above: the slot table replaces the
    /// `(n_inputs, output_clients)` binding it used to assert.
    #[test]
    fn expected_clients_union_keeps_manifest_inputs_and_output_only_slots() {
        let mut binary = CompiledBinary::new();
        binary.client_io_manifest.clients = vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        }];

        let runner = test_runner(binary)
            .expected_output_clients(2)
            .client_input(0, [42])
            .client_output_count(1, 1)
            .build()
            .expect("runner");

        let known_clients = runner.known_client_inputs();
        assert_eq!(
            known_clients
                .iter()
                .map(|client| client.client_slot)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(known_clients[0].values, vec!["42".to_owned()]);
        assert!(known_clients[1].values.is_empty());

        let table = runner.client_slot_table().expect("slot table");
        assert_eq!(
            table.slots(),
            &[
                ClientSlotSpec {
                    input_count: 1,
                    output_count: 0
                },
                ClientSlotSpec {
                    input_count: 0,
                    output_count: 1
                },
            ]
        );
    }

    fn manifest_with_input_slots(slots: &[u64]) -> CompiledBinary {
        let mut binary = CompiledBinary::new();
        binary.client_io_manifest.clients = slots
            .iter()
            .map(|&client_slot| ClientIoSchema {
                client_slot,
                inputs: vec![ShareType::default_secret_int()],
                outputs: Vec::new(),
            })
            .collect();
        binary
    }

    /// §9.F.4: under `Open` the runner knows no client, so a slot's input
    /// count comes from the manifest, and a value handed to the runner — which
    /// it would never submit — is refused rather than silently dropped.
    #[test]
    fn open_admission_takes_slot_inputs_from_the_manifest_and_refuses_runner_inputs() {
        let runner = test_runner(manifest_with_input_slots(&[0, 1]))
            .admission(LocalAdmission::Open)
            .build()
            .expect("open admission needs no runner inputs");
        assert_eq!(
            runner.client_slot_table().expect("slot table").slots(),
            &[
                ClientSlotSpec {
                    input_count: 1,
                    output_count: 0
                },
                ClientSlotSpec {
                    input_count: 1,
                    output_count: 0
                },
            ]
        );

        let error = test_runner(manifest_with_input_slots(&[0, 1]))
            .admission(LocalAdmission::Open)
            .client_input(0, [15])
            .build()
            .expect_err("runner inputs under open admission are refused");
        assert!(
            error.to_string().contains("LocalAdmission::Open"),
            "{error}"
        );

        // The default is unchanged: pre-registered, and the manifest's input
        // slots still need the runner's values.
        assert_eq!(LocalAdmission::default(), LocalAdmission::PreRegistered);
        let error = test_runner(manifest_with_input_slots(&[0, 1]))
            .build()
            .expect_err("pre-registered input slots need runner inputs");
        assert!(
            error.to_string().contains("provide local client inputs"),
            "{error}"
        );
    }

    /// `run()` starts only pre-registered clients, so under `Open` with client
    /// slots nobody would bind them; it refuses before anything is started.
    #[tokio::test]
    async fn run_refuses_open_admission_with_client_slots() {
        let error = test_runner(manifest_with_input_slots(&[0]))
            .admission(LocalAdmission::Open)
            .build()
            .expect("runner")
            .run()
            .await
            .expect_err("run() under open admission with slots is refused");
        assert_eq!(
            error.to_string(),
            "invalid local coordinator runner configuration: run() starts only \
             pre-registered clients; with LocalAdmission::Open use start() and run_offchain_client"
        );
    }

    /// The coordinator refuses a deadline that is not later than its clock, so
    /// a sub-second timeout still names the next whole second.
    #[test]
    fn open_admission_deadlines_are_the_timeout_rounded_up() {
        let at = UnixSeconds(1_000);
        for (timeout, expected) in [
            (Duration::from_secs(180), 1_180),
            (Duration::from_millis(1_500), 1_002),
            (Duration::from_millis(1), 1_001),
        ] {
            let deadlines = open_admission_deadlines(at, timeout);
            assert_eq!(deadlines.association, UnixSeconds(expected), "{timeout:?}");
            assert_eq!(deadlines.input, UnixSeconds(expected), "{timeout:?}");
        }
    }
}
