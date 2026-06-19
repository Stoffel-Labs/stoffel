use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField};
use stoffel_mpc_coordinator::off_chain::{
    node_rpc::NodeRPCClient as OffChainNodeRPCClient, OffChainCoordinatorClient,
    OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator::self_signed_certs;
use stoffel_mpc_coordinator::tests::fake_coord::off_chain::{
    FakeCoordinatorConnection, FakeCoordinatorRPCServerSharedBase,
};
use stoffel_mpc_coordinator::Coordinator;
use stoffel_vm_types::compiled_binary::{utils::save_to_file, CompiledBinary};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::net::program_id_from_bytes;
use crate::net::{MpcBackendKind, MpcCurveConfig};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);
const DEFAULT_AUTH_TOKEN: &str = "stoffel-local-coordinator-runner";

#[derive(Debug, thiserror::Error)]
pub enum LocalCoordinatorRunnerError {
    #[error("invalid local coordinator runner configuration: {0}")]
    Configuration(String),
    #[error("local coordinator runner IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("local coordinator error: {0}")]
    Coordinator(#[from] stoffel_mpc_coordinator::CoordinatorError),
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
    auth_token: String,
    client_inputs: Vec<LocalClientInput>,
    expected_clients: Option<usize>,
    /// Per-client number of output values to receive via `send_to_client`.
    client_output_counts: std::collections::HashMap<u64, u64>,
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
                auth_token: DEFAULT_AUTH_TOKEN.to_owned(),
                client_inputs: Vec::new(),
                expected_clients: None,
                client_output_counts: std::collections::HashMap::new(),
            },
        }
    }

    pub async fn run(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput> {
        self.validate()?;
        let _local_run_guard = local_run_lock().lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();

        let temp = TempRunDir::new()?;
        let program_path = temp.path().join("program.stflb");
        save_to_file(&self.binary, &program_path).map_err(LocalCoordinatorRunnerError::Bytecode)?;
        let program_bytes = self.binary_bytes()?;
        let program_id = program_id_from_bytes(&program_bytes);

        let node_identities = write_node_identities(temp.path(), self.parties)?;
        let node_public_keys = node_identities
            .iter()
            .map(|identity| public_key_from_cert(&identity.cert_der))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        let known_client_inputs = self.known_client_inputs();
        let mut local_clients = write_client_identities(temp.path(), &known_client_inputs)?;
        for client in local_clients.iter_mut() {
            client.output_count = self.output_count_for_slot(client.client_slot);
        }
        let client_bindings = local_clients
            .iter()
            .map(|client| Ok((client.client_slot, public_key_from_cert(&client.cert_der)?)))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;

        let coord_port = reserve_port()?;
        let coord_cert = self_signed_certs::server_cert();
        let (n_inputs, output_clients) = self.coordinator_client_io_binding(&client_bindings)?;
        let coord_state = FakeCoordinatorRPCServerSharedBase::new(
            program_id,
            self.parties as u64,
            self.threshold as u64,
            node_public_keys,
            n_inputs,
            output_clients,
        );
        let coord = OffChainCoordinatorServer::<FakeCoordinatorConnection>::start_coord(
            coord_state,
            "127.0.0.1",
            coord_port,
            self.threshold as u64,
            coord_cert.cert.der().to_vec(),
            coord_cert.signing_key.serialize_der(),
        )
        .await?;

        let bootnode = socket_with_port_pair()?;
        let mut children = Vec::with_capacity(self.parties + local_clients.len());
        let mut node_rpc_addrs = Vec::with_capacity(self.parties);
        children.push(self.spawn_party(
            "leader",
            SpawnPartyContext {
                program_path: &program_path,
                identity: &node_identities[0],
                role: PartyRole::Leader { bootnode },
                clients: &local_clients,
                coord_port,
                timestamp: coord.get_timestamp(),
            },
            &mut node_rpc_addrs,
        )?);

        tokio::time::sleep(Duration::from_millis(500)).await;

        for (party_id, identity) in node_identities.iter().enumerate().skip(1) {
            children.push(self.spawn_party(
                &format!("party{party_id}"),
                SpawnPartyContext {
                    program_path: &program_path,
                    identity,
                    role: PartyRole::Follower {
                        party_id,
                        bootnode,
                        bind: socket_with_port_pair()?,
                    },
                    clients: &local_clients,
                    coord_port,
                    timestamp: coord.get_timestamp(),
                },
                &mut node_rpc_addrs,
            )?);
        }

        let timeout = self.timeout;
        let threshold = self.threshold;
        let timestamp = coord.get_timestamp();
        let client_results_future = async {
            match self.backend {
                MpcBackendKind::HoneyBadger => {
                    futures::future::join_all(
                        local_clients
                            .iter()
                            .filter(|client| client.input.has_input())
                            .cloned()
                            .map(|client| {
                                run_honeybadger_offchain_client(
                                    client,
                                    node_rpc_addrs.clone(),
                                    coord_port,
                                    timestamp,
                                    threshold,
                                    timeout,
                                )
                            }),
                    )
                    .await
                }
                MpcBackendKind::Avss => {
                    futures::future::join_all(
                        local_clients
                            .iter()
                            .filter(|client| client.input.has_input())
                            .cloned()
                            .map(|client| {
                                run_avss_offchain_client(
                                    client,
                                    node_rpc_addrs.clone(),
                                    coord_port,
                                    timestamp,
                                    threshold,
                                    timeout,
                                )
                            }),
                    )
                    .await
                }
            }
        };
        let party_outputs_future = futures::future::join_all(
            children
                .into_iter()
                .map(|(name, child)| wait_for_child(name, child, timeout)),
        );

        tokio::pin!(client_results_future);
        tokio::pin!(party_outputs_future);

        let (client_results, combined_output, party_outputs) = tokio::select! {
            client_results = &mut client_results_future => {
                let outputs = party_outputs_future.await;
                let (combined_output, party_outputs) = Self::collect_party_outputs(outputs)?;
                (client_results, combined_output, party_outputs)
            }
            outputs = &mut party_outputs_future => {
                let (combined_output, _party_outputs) = Self::collect_party_outputs(outputs)?;
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

    fn coordinator_client_io_binding(
        &self,
        client_bindings: &[(u64, Vec<u8>)],
    ) -> LocalCoordinatorRunnerResult<(u64, Vec<Vec<u8>>)> {
        let mut n_inputs = 0_u64;
        let output_clients = client_bindings
            .iter()
            .map(|(_slot, identity)| identity.clone())
            .collect::<Vec<_>>();
        if self.binary.client_io_manifest.clients.is_empty() {
            for input in &self.client_inputs {
                client_bindings
                    .iter()
                    .find(|(slot, _identity)| *slot == input.client_slot)
                    .ok_or_else(|| {
                        LocalCoordinatorRunnerError::Configuration(format!(
                            "client slot {} does not have a local client identity",
                            input.client_slot
                        ))
                    })?;
                n_inputs += input.values.len() as u64;
            }
            return Ok((n_inputs, output_clients));
        }

        for schema in &self.binary.client_io_manifest.clients {
            client_bindings
                .iter()
                .find(|(slot, _identity)| *slot == schema.client_slot)
                .ok_or_else(|| {
                    LocalCoordinatorRunnerError::Configuration(format!(
                        "client slot {} does not have a local client identity",
                        schema.client_slot
                    ))
                })?;
            n_inputs += schema.inputs.len() as u64;
        }
        Ok((n_inputs, output_clients))
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
            .arg(context.program_path)
            .arg(&self.entry)
            .arg("--n-parties")
            .arg(self.parties.to_string())
            .arg("--threshold")
            .arg(self.threshold.to_string())
            .arg("--mpc-backend")
            .arg(self.backend.name())
            .arg("--curve")
            .arg(self.curve_config.name())
            .arg("--off-chain-coord")
            .arg(format!("127.0.0.1:{}", context.coord_port))
            .arg("--rpc-bind")
            .arg(rpc_addr.to_string())
            .arg("--cert")
            .arg(&context.identity.cert_path)
            .arg("--key")
            .arg(&context.identity.key_path)
            .arg("--timestamp")
            .arg(context.timestamp.to_string())
            .env("STOFFEL_AUTH_TOKEN", &self.auth_token)
            // Tie each spawned party to this runner's lifetime: `kill_on_drop`
            // handles a graceful drop, and the parent-death watchdog (keyed off
            // this env var) covers the case where the runner is force-killed
            // (SIGKILL) and cannot run drop cleanup, preventing orphaned parties.
            .env("STOFFEL_DIE_WITH_PARENT", "1")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !context.clients.is_empty() {
            command
                .arg("--expected-clients")
                .arg(
                    context
                        .clients
                        .iter()
                        .map(|client| client.cert_path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .arg("--client-input-count")
                .arg(self.max_client_input_count().to_string())
                .arg("--client-input-total")
                .arg(self.total_client_input_count().to_string());
            command.arg("--client-roster").arg(
                context
                    .clients
                    .iter()
                    .map(|client| client.client_slot.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
            command.arg("--client-input-slots").arg(
                context
                    .clients
                    .iter()
                    .filter(|client| client.input.has_input())
                    .map(|client| client.client_slot.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        match context.role {
            PartyRole::Leader { bootnode } => {
                command
                    .arg("--leader")
                    .arg("--bind")
                    .arg(bootnode.to_string());
            }
            PartyRole::Follower {
                party_id,
                bootnode,
                bind,
            } => {
                command
                    .arg("--party-id")
                    .arg(party_id.to_string())
                    .arg("--bootstrap")
                    .arg(bootnode.to_string())
                    .arg("--bind")
                    .arg(bind.to_string());
            }
        }

        Ok((name.to_owned(), command.spawn()?))
    }

    fn max_client_input_count(&self) -> usize {
        self.client_inputs
            .iter()
            .filter(|client| !client.values.is_empty())
            .map(|client| client.values.len())
            .max()
            .unwrap_or(0)
    }

    /// Total number of input values across all clients (sum of per-client
    /// counts). Clients may supply different numbers of inputs, so the input
    /// mask reservation/wait must use this actual total, not `num_clients * max`.
    fn total_client_input_count(&self) -> usize {
        self.client_inputs
            .iter()
            .map(|client| client.values.len())
            .sum()
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

    pub fn auth_token(mut self, auth_token: impl Into<String>) -> Self {
        self.runner.auth_token = auth_token.into();
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
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: Vec<u8>,
    reserved_index_start: u64,
    client_slot: u64,
    /// Number of output values this client receives via `send_to_client`.
    output_count: u64,
}

async fn run_honeybadger_offchain_client(
    client: LocalClientIdentity,
    node_rpc_addrs: Vec<SocketAddr>,
    coord_port: u16,
    timestamp: u64,
    threshold: usize,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<Option<ClientOutputRecord>> {
    tokio::time::timeout(timeout, async move {
        eprintln!(
            "[local-client {}] starting off-chain coordinator input submission",
            client.client_slot
        );
        let input_values = client
            .input
            .values
            .iter()
            .map(|value| parse_input_as_field(value))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        eprintln!(
            "[local-client {}] connecting coordinator",
            client.client_slot
        );
        let mut coord: OffChainCoordinatorClient<Fr, RobustShare<Fr>> =
            OffChainCoordinatorClient::start_rpc_client(
                "127.0.0.1",
                coord_port,
                timestamp,
                threshold as u64,
                client.output_count,
                client.cert_der.clone(),
                std::fs::read(&client.key_path)?,
            )
            .await?;

        for offset in 0..input_values.len() {
            let index = client.reserved_index_start + offset as u64;
            eprintln!(
                "[local-client {}] reserving mask index {}",
                client.client_slot, index
            );
            reserve_mask_index_when_ready(&mut coord, index, timeout).await?;
        }

        eprintln!("[local-client {}] connecting node RPC", client.client_slot);
        let rpc_addrs = node_rpc_addrs
            .iter()
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .collect::<Vec<_>>();
        let node_rpc: OffChainNodeRPCClient<Fr, RobustShare<Fr>> =
            OffChainNodeRPCClient::start_rpc_client(
                threshold,
                rpc_addrs,
                client.cert_der,
                std::fs::read(&client.key_path)?,
            )
            .await?;

        let mut masks = Vec::with_capacity(input_values.len());
        for _ in 0..input_values.len() {
            eprintln!("[local-client {}] receiving mask", client.client_slot);
            masks.push(node_rpc.receive_mask().await?);
        }

        for (offset, (input, mask)) in input_values.into_iter().zip(masks).enumerate() {
            let index = client.reserved_index_start + offset as u64;
            eprintln!(
                "[local-client {}] submitting masked input {}",
                client.client_slot, index
            );
            send_masked_input_when_ready(&coord, input + mask, index, timeout).await?;
        }
        eprintln!(
            "[local-client {}] input submission complete",
            client.client_slot
        );

        if client.output_count == 0 {
            return Ok(None);
        }

        eprintln!(
            "[local-client {}] obtaining {} client output value(s)",
            client.client_slot, client.output_count
        );
        let output_values: Vec<Fr> = coord.obtain_outputs().await?;
        eprintln!(
            "[local-client {}] received {} client output value(s)",
            client.client_slot,
            output_values.len()
        );
        let values = output_values.iter().map(fr_to_u64).collect::<Vec<_>>();
        Ok(Some(ClientOutputRecord {
            client_slot: client.client_slot,
            values,
        }))
    })
    .await
    .map_err(|_| LocalCoordinatorRunnerError::Timeout(timeout))?
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

async fn run_avss_offchain_client(
    client: LocalClientIdentity,
    node_rpc_addrs: Vec<SocketAddr>,
    coord_port: u16,
    timestamp: u64,
    threshold: usize,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<Option<ClientOutputRecord>> {
    tokio::time::timeout(timeout, async move {
        eprintln!(
            "[local-client {}] starting AVSS off-chain coordinator input submission",
            client.client_slot
        );
        let input_values = client
            .input
            .values
            .iter()
            .map(|value| parse_input_as_field(value))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        let mut coord: OffChainCoordinatorClient<Fr, FeldmanShamirShare<Fr, G1Projective>> =
            OffChainCoordinatorClient::start_rpc_client(
                "127.0.0.1",
                coord_port,
                timestamp,
                threshold as u64,
                input_values.len() as u64,
                client.cert_der.clone(),
                std::fs::read(&client.key_path)?,
            )
            .await?;

        for offset in 0..input_values.len() {
            let index = client.reserved_index_start + offset as u64;
            eprintln!(
                "[local-client {}] reserving AVSS mask index {}",
                client.client_slot, index
            );
            reserve_avss_mask_index_when_ready(&mut coord, index, timeout).await?;
        }

        let rpc_addrs = node_rpc_addrs
            .iter()
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .collect::<Vec<_>>();
        let node_rpc: OffChainNodeRPCClient<Fr, FeldmanShamirShare<Fr, G1Projective>> =
            OffChainNodeRPCClient::start_rpc_client(
                threshold,
                rpc_addrs,
                client.cert_der,
                std::fs::read(&client.key_path)?,
            )
            .await?;

        let mut masks = Vec::with_capacity(input_values.len());
        for _ in 0..input_values.len() {
            eprintln!("[local-client {}] receiving AVSS mask", client.client_slot);
            masks.push(node_rpc.receive_mask().await?);
        }

        for (offset, (input, mask)) in input_values.into_iter().zip(masks).enumerate() {
            let index = client.reserved_index_start + offset as u64;
            eprintln!(
                "[local-client {}] submitting AVSS masked input {}",
                client.client_slot, index
            );
            send_avss_masked_input_when_ready(&coord, input + mask, index, timeout).await?;
        }
        eprintln!(
            "[local-client {}] AVSS input submission complete",
            client.client_slot
        );
        // AVSS client-output reconstruction is not yet wired into the local
        // runner; HoneyBadger is the path exercised by the client-IO examples.
        Ok(None)
    })
    .await
    .map_err(|_| LocalCoordinatorRunnerError::Timeout(timeout))?
}

async fn reserve_mask_index_when_ready(
    coord: &mut OffChainCoordinatorClient<Fr, RobustShare<Fr>>,
    index: u64,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match coord.reserve_mask_index(index).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(LocalCoordinatorRunnerError::Timeout(timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn reserve_avss_mask_index_when_ready(
    coord: &mut OffChainCoordinatorClient<Fr, FeldmanShamirShare<Fr, G1Projective>>,
    index: u64,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match coord.reserve_mask_index(index).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(LocalCoordinatorRunnerError::Timeout(timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn send_masked_input_when_ready(
    coord: &OffChainCoordinatorClient<Fr, RobustShare<Fr>>,
    masked_input: Fr,
    index: u64,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match coord.send_masked_input(masked_input, index).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(LocalCoordinatorRunnerError::Timeout(timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn send_avss_masked_input_when_ready(
    coord: &OffChainCoordinatorClient<Fr, FeldmanShamirShare<Fr, G1Projective>>,
    masked_input: Fr,
    index: u64,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match coord.send_masked_input(masked_input, index).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(LocalCoordinatorRunnerError::Timeout(timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn coordinator_wrong_round(error: &stoffel_mpc_coordinator::CoordinatorError) -> bool {
    let message = error.to_string();
    message.contains("WrongRound")
        || message.contains("Need round")
        || message.contains("current round is")
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
    Ok(crate::net::field_from_i64::<Fr>(value))
}

enum PartyRole {
    Leader {
        bootnode: SocketAddr,
    },
    Follower {
        party_id: usize,
        bootnode: SocketAddr,
        bind: SocketAddr,
    },
}

struct SpawnPartyContext<'a> {
    program_path: &'a Path,
    identity: &'a NodeIdentity,
    role: PartyRole,
    clients: &'a [LocalClientIdentity],
    coord_port: u16,
    timestamp: u64,
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

fn write_node_identities(
    path: &Path,
    count: usize,
) -> LocalCoordinatorRunnerResult<Vec<NodeIdentity>> {
    (0..count)
        .map(|index| {
            let cert = self_signed_certs::client_cert();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
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
    sorted_inputs.sort_by_key(|input| input.client_slot);
    // Reserve a contiguous block per client in slot order (clients may supply
    // different numbers of inputs). The VM groups the returned shares per client
    // (see `store_reserved_client_inputs`), so no uniform padding is required.
    let mut next_reserved_index = 0_u64;
    sorted_inputs
        .into_iter()
        .map(|input| {
            let cert = self_signed_certs::client_cert();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
            let cert_path = path.join(format!("client{}.cert.der", input.client_slot));
            let key_path = path.join(format!("client{}.key.der", input.client_slot));
            std::fs::write(&cert_path, &cert_der)?;
            std::fs::write(&key_path, key_der)?;
            let reserved_index_start = next_reserved_index;
            next_reserved_index += input.values.len() as u64;
            Ok(LocalClientIdentity {
                client_slot: input.client_slot,
                input,
                cert_path,
                key_path,
                cert_der,
                reserved_index_start,
                output_count: 0,
            })
        })
        .collect()
}

fn public_key_from_cert(cert_der: &[u8]) -> LocalCoordinatorRunnerResult<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|error| {
        LocalCoordinatorRunnerError::Configuration(format!("parse node certificate: {error:?}"))
    })?;
    Ok(cert.public_key().subject_public_key.data.as_ref().to_vec())
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

fn socket_with_port_pair() -> std::io::Result<SocketAddr> {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u16)
        .unwrap_or(0);
    for offset in 0..30_000u16 {
        let port = 20_000 + ((seed.wrapping_add(offset)) % 30_000);
        if port_is_free(port) && port_is_free(port + 1000) {
            return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "could not reserve a localhost bootnode port with a free +1000 party port in 20000..50999",
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

    #[test]
    fn expected_clients_create_output_identities_for_dynamic_outputs() {
        let runner = test_runner(CompiledBinary::new())
            .expected_output_clients(2)
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

        let (n_inputs, output_clients) = runner
            .coordinator_client_io_binding(&[(0, vec![10]), (1, vec![11])])
            .expect("binding");
        assert_eq!(n_inputs, 0);
        assert_eq!(output_clients, vec![vec![10], vec![11]]);
    }

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

        let (n_inputs, output_clients) = runner
            .coordinator_client_io_binding(&[(0, vec![10]), (1, vec![11])])
            .expect("binding");
        assert_eq!(n_inputs, 1);
        assert_eq!(output_clients, vec![vec![10], vec![11]]);
    }
}
