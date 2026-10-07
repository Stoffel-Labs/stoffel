//! Server-side builder, state, health, and metrics access.
//!
//! The builder validates operational configuration and captures program
//! metadata. Starting a live server remains a lower-layer networking/VM
//! integration concern and is not simulated by the SDK.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::backend::avss::AvssEngine;
use crate::config::{
    validate_socket_address, Curve, MpcBackend, MpcConfig, NetworkConfig, NetworkDeployment,
    PreprocessingConfig,
};
use crate::consensus::VerifiedOrdering;
use crate::error::{Error, Result};
use crate::observability::{HealthStatus, ServerMetrics};
use crate::program::Program;
use crate::types::{GeneratedProgramManifest, PartyId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    Created,
    Running,
    Shutdown,
}

impl ServerState {
    const fn as_u8(self) -> u8 {
        match self {
            ServerState::Created => 0,
            ServerState::Running => 1,
            ServerState::Shutdown => 2,
        }
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            1 => ServerState::Running,
            2 => ServerState::Shutdown,
            _ => ServerState::Created,
        }
    }
}

impl fmt::Display for ServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ServerState::Created => "created",
            ServerState::Running => "running",
            ServerState::Shutdown => "shutdown",
        })
    }
}

impl FromStr for ServerState {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "created" => Ok(ServerState::Created),
            "running" => Ok(ServerState::Running),
            "shutdown" => Ok(ServerState::Shutdown),
            state => Err(Error::Configuration(format!(
                "unsupported server state '{state}'; expected 'created', 'running', or 'shutdown'"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerBuilder {
    party_id: PartyId,
    bind_addr: Option<String>,
    peers: Vec<(usize, String)>,
    program: Option<Program>,
    triples: usize,
    random_shares: usize,
    expected_clients: usize,
    consensus_timeout: Duration,
    backend: MpcBackend,
    mpc_config: Option<MpcConfig>,
    avss_engine: Option<AvssEngine>,
    verified_ordering: Option<VerifiedOrdering>,
    runner_path: Option<PathBuf>,
    bootstrap_addr: Option<String>,
    advertise_addr: Option<SocketAddr>,
    entry: String,
    offchain_coordinator: Option<OffChainServerConfig>,
    config_error: Option<String>,
}

impl ServerBuilder {
    pub fn new(party_id: PartyId) -> Self {
        Self {
            party_id,
            bind_addr: None,
            peers: Vec::new(),
            program: None,
            triples: 1000,
            random_shares: 500,
            expected_clients: 0,
            consensus_timeout: Duration::from_secs(60),
            backend: MpcBackend::HoneyBadger,
            mpc_config: None,
            avss_engine: None,
            verified_ordering: None,
            runner_path: None,
            bootstrap_addr: None,
            advertise_addr: None,
            entry: "main".to_owned(),
            offchain_coordinator: None,
            config_error: None,
        }
    }

    pub fn bind<A: ToSocketAddrs>(mut self, addr: A) -> Self {
        match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                self.bind_addr = addrs.next().map(|addr| addr.to_string());
                if self.bind_addr.is_none() {
                    self.config_error = Some("server bind address did not resolve".to_owned());
                }
            }
            Err(error) => {
                self.config_error = Some(format!("invalid server bind address: {error}"));
            }
        }
        self
    }

    pub fn peers<I, S>(mut self, peers: I) -> Self
    where
        I: IntoIterator<Item = (usize, S)>,
        S: Into<String>,
    {
        self.peers = peers
            .into_iter()
            .map(|(party_id, address)| (party_id, address.into()))
            .collect();
        self
    }

    pub fn with_peers(self, peers: &[(usize, &str)]) -> Self {
        self.peers(peers.iter().copied())
    }

    pub fn peer(mut self, party_id: usize, address: impl Into<String>) -> Self {
        self.peers.push((party_id, address.into()));
        self
    }

    pub fn with_program(mut self, program: Program) -> Self {
        self.program = Some(program);
        self
    }

    pub fn with_preprocessing(mut self, triples: usize, random_shares: usize) -> Self {
        self.triples = triples;
        self.random_shares = random_shares;
        self
    }

    pub fn expected_clients(mut self, n: usize) -> Self {
        self.expected_clients = n;
        self
    }

    pub fn consensus_timeout(mut self, duration: Duration) -> Self {
        self.consensus_timeout = duration;
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.backend = backend;
        if let Some(config) = &mut self.mpc_config {
            config.backend = backend;
        }
        self
    }

    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    pub fn honeybadger(self) -> Self {
        self.backend(MpcBackend::HoneyBadger)
    }

    pub fn avss(self, curve: Curve) -> Self {
        self.backend(MpcBackend::Avss { curve })
    }

    pub fn mpc_config(mut self, config: &MpcConfig) -> Self {
        self.backend = config.backend;
        self.mpc_config = Some(config.clone());
        self
    }

    /// Attach a VM-backed AVSS engine that this server should expose.
    ///
    /// The builder validates that the selected backend is AVSS and that the
    /// engine curve matches the backend curve. The SDK does not construct live
    /// AVSS engines on its own.
    pub fn with_avss_engine(mut self, engine: AvssEngine) -> Self {
        self.avss_engine = Some(engine);
        self
    }

    pub fn with_verified_ordering(mut self, ordering: VerifiedOrdering) -> Self {
        self.verified_ordering = Some(ordering);
        self
    }

    /// Override the `stoffel-run` binary used by [`StoffelServer::start`].
    pub fn runner_path(mut self, path: impl AsRef<Path>) -> Self {
        self.runner_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the entrypoint passed to `stoffel-run`. Default is `main`.
    pub fn entry(mut self, entry: impl Into<String>) -> Self {
        self.entry = entry.into();
        self
    }

    /// Configure this server as a follower of an existing bootnode.
    ///
    /// Without a bootstrap address, party 0 starts as the leader/bootnode.
    pub fn bootstrap(mut self, address: impl Into<String>) -> Self {
        self.bootstrap_addr = Some(address.into());
        self
    }

    /// Set the address other parties dial to reach this party's mesh listener.
    ///
    /// The address is forwarded to `stoffel-run` as `--advertise` and is what
    /// the bootnode hands to the other parties, so it must be reachable from
    /// them. The port must be the party mesh port: for the leader (party 0
    /// without a bootstrap address) that is the bind port + 1000, for every
    /// other party it is the bind port itself.
    ///
    /// Host names are resolved once, here, preferring IPv4. When unset, the
    /// runner advertises the address derived from the bind address, which is
    /// only dialable by other hosts if the bind address itself is routable.
    pub fn advertise<A: ToSocketAddrs>(mut self, addr: A) -> Self {
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                self.advertise_addr = addrs
                    .iter()
                    .find(|addr| addr.is_ipv4())
                    .or_else(|| addrs.first())
                    .copied();
                if self.advertise_addr.is_none() {
                    self.config_error = Some("server advertise address did not resolve".to_owned());
                }
            }
            Err(error) => {
                self.config_error = Some(format!("invalid server advertise address: {error}"));
            }
        }
        self
    }

    /// Configure the off-chain coordinator flags passed to `stoffel-run`.
    ///
    /// This is required when the attached program declares ClientStore IO.
    pub fn offchain_coordinator(mut self, config: OffChainServerConfig) -> Self {
        self.offchain_coordinator = Some(config);
        self
    }

    pub fn configured_party_id(&self) -> PartyId {
        self.party_id
    }

    pub fn configured_bind_addr(&self) -> Option<&str> {
        self.bind_addr.as_deref()
    }

    pub fn configured_peers(&self) -> &[(usize, String)] {
        &self.peers
    }

    pub fn configured_program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn has_configured_program(&self) -> bool {
        self.program.is_some()
    }

    pub fn configured_preprocessing(&self) -> (usize, usize) {
        (self.triples, self.random_shares)
    }

    pub fn configured_expected_clients(&self) -> usize {
        self.expected_clients
    }

    pub fn configured_consensus_timeout(&self) -> Duration {
        self.consensus_timeout
    }

    pub fn configured_backend(&self) -> MpcBackend {
        self.backend
    }

    pub fn configured_mpc_config(&self) -> Option<&MpcConfig> {
        self.mpc_config.as_ref()
    }

    pub fn configured_avss_engine(&self) -> Option<&AvssEngine> {
        self.avss_engine.as_ref()
    }

    pub fn has_configured_avss_engine(&self) -> bool {
        self.avss_engine.is_some()
    }

    pub fn configured_verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    pub fn has_configured_verified_ordering(&self) -> bool {
        self.verified_ordering.is_some()
    }

    pub fn configured_runner_path(&self) -> Option<&Path> {
        self.runner_path.as_deref()
    }

    pub fn configured_entry(&self) -> &str {
        &self.entry
    }

    pub fn configured_bootstrap(&self) -> Option<&str> {
        self.bootstrap_addr.as_deref()
    }

    pub fn configured_advertise(&self) -> Option<SocketAddr> {
        self.advertise_addr
    }

    pub fn configured_offchain_coordinator(&self) -> Option<&OffChainServerConfig> {
        self.offchain_coordinator.as_ref()
    }

    pub fn network_config(mut self, config: &NetworkConfig) -> Self {
        if let Err(error) = config.validate_server_addresses() {
            self.config_error = Some(error.to_string());
            return self;
        }
        if config.network.party_id != self.party_id {
            self.config_error = Some(format!(
                "network config party_id {} does not match server builder party_id {}",
                config.network.party_id, self.party_id
            ));
            return self;
        }
        self.bind_addr = Some(config.network.bind_address.clone());
        self.peers = config
            .network
            .peers
            .iter()
            .map(|(party_id, address)| (*party_id, address.clone()))
            .collect();
        self.expected_clients = config.network.expected_clients;
        self.consensus_timeout = Duration::from_millis(config.network.consensus_timeout_ms);
        self.triples = config.preprocessing.triples;
        self.random_shares = config.preprocessing.random_shares;
        let instance_id = self
            .mpc_config
            .as_ref()
            .map(|config| config.instance_id)
            .unwrap_or_default();
        match config.to_mpc_config(instance_id) {
            Ok(mpc_config) => {
                self.backend = mpc_config.backend;
                self.mpc_config = Some(mpc_config);
            }
            Err(error) => self.config_error = Some(error.to_string()),
        }
        self
    }

    /// Configure this server from the matching party config in a deployment.
    pub fn network_deployment(self, deployment: &NetworkDeployment) -> Self {
        match deployment.config(self.party_id) {
            Some(config) => self.network_config(config),
            None => {
                let party_id = self.party_id;
                self.configuration_error(format!(
                    "network deployment does not contain party_id {party_id}"
                ))
            }
        }
    }

    pub fn network_config_file(mut self, path: impl AsRef<Path>) -> Self {
        match NetworkConfig::from_toml_file(path) {
            Ok(config) => self.network_config(&config),
            Err(error) => {
                self.config_error = Some(error.to_string());
                self
            }
        }
    }

    pub(crate) fn configuration_error(mut self, error: impl Into<String>) -> Self {
        self.config_error = Some(error.into());
        self
    }

    pub fn build(self) -> Result<StoffelServer> {
        if let Some(error) = self.config_error {
            return Err(Error::Configuration(error));
        }
        if self.bind_addr.is_none() {
            return Err(Error::Configuration(
                "server bind address is required".to_owned(),
            ));
        }
        if let Some(advertise) = self.advertise_addr {
            if advertise.ip().is_unspecified() {
                return Err(Error::Configuration(format!(
                    "server advertise address must be a routable address, not {advertise}"
                )));
            }
            if advertise.port() == 0 {
                return Err(Error::Configuration(format!(
                    "server advertise address must have a non-zero port, not {advertise}"
                )));
            }
        }
        if self.consensus_timeout.is_zero() {
            return Err(Error::Configuration(
                "server consensus timeout must be greater than zero".to_owned(),
            ));
        }
        PreprocessingConfig {
            triples: self.triples,
            random_shares: self.random_shares,
        }
        .validate()?;
        let mut peer_ids = BTreeSet::new();
        for (party_id, address) in &self.peers {
            if !peer_ids.insert(*party_id) {
                return Err(Error::Configuration(format!(
                    "duplicate peer party_id {party_id}"
                )));
            }
            if *party_id == self.party_id {
                return Err(Error::Configuration(format!(
                    "peer party_id {party_id} must not match this server's party_id"
                )));
            }
            if address.trim().is_empty() {
                return Err(Error::Configuration(format!(
                    "peer address for party_id {party_id} must not be empty"
                )));
            }
            validate_socket_address(&format!("peer address for party_id {party_id}"), address)?;
        }
        if let Some(mpc_config) = &self.mpc_config {
            mpc_config.validate()?;
            if self.party_id >= mpc_config.parties {
                return Err(Error::Configuration(format!(
                    "server party_id {} must be less than configured party count {}",
                    self.party_id, mpc_config.parties
                )));
            }
            for peer_id in &peer_ids {
                if *peer_id >= mpc_config.parties {
                    return Err(Error::Configuration(format!(
                        "peer party_id {peer_id} must be less than configured party count {}",
                        mpc_config.parties
                    )));
                }
            }
            for party_id in 0..mpc_config.parties {
                if party_id != self.party_id && !peer_ids.contains(&party_id) {
                    return Err(Error::Configuration(format!(
                        "missing peer address for configured party_id {party_id}"
                    )));
                }
            }
        }
        if let Some(program) = &self.program {
            program.validate_expected_clients(self.expected_clients)?;
        }
        if let Some(config) = &self.offchain_coordinator {
            config.validate(self.expected_clients)?;
        }
        if let Some(engine) = &self.avss_engine {
            match self.backend {
                MpcBackend::Avss { curve } if curve == engine.curve() => {}
                MpcBackend::Avss { curve } => {
                    return Err(Error::Configuration(format!(
                        "configured AVSS engine curve {} does not match server backend curve {}",
                        engine.curve(),
                        curve
                    )));
                }
                MpcBackend::HoneyBadger => {
                    return Err(Error::Configuration(
                        "configured AVSS engine requires MpcBackend::Avss".to_owned(),
                    ));
                }
            }
        }
        let metrics = ServerMetrics::default();
        metrics.record_preprocessing_remaining(self.triples as u64, self.random_shares as u64);
        Ok(StoffelServer {
            party_id: self.party_id,
            bind_addr: self.bind_addr.unwrap(),
            peers: self.peers,
            program: self.program,
            triples: self.triples,
            random_shares: self.random_shares,
            expected_clients: self.expected_clients,
            consensus_timeout: self.consensus_timeout,
            backend: self.backend,
            mpc_config: self.mpc_config,
            avss_engine: self.avss_engine,
            state: Arc::new(AtomicU8::new(ServerState::Created.as_u8())),
            verified_ordering: self.verified_ordering,
            runner_path: self.runner_path,
            bootstrap_addr: self.bootstrap_addr,
            advertise_addr: self.advertise_addr,
            entry: self.entry,
            offchain_coordinator: self.offchain_coordinator,
            process: Arc::new(Mutex::new(None)),
            metrics,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffChainServerConfig {
    pub coordinator_address: String,
    pub rpc_bind_address: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub timestamp: u64,
    pub expected_client_certs: Vec<PathBuf>,
}

impl OffChainServerConfig {
    pub fn builder() -> OffChainServerConfigBuilder {
        OffChainServerConfigBuilder::default()
    }

    pub fn validate(&self, expected_clients: usize) -> Result<()> {
        validate_socket_address("off-chain coordinator address", &self.coordinator_address)?;
        validate_socket_address("off-chain node RPC bind address", &self.rpc_bind_address)?;
        if self.timestamp == 0 {
            return Err(Error::Configuration(
                "off-chain coordinator timestamp must be greater than zero".to_owned(),
            ));
        }
        validate_existing_file("off-chain server certificate", &self.cert_path)?;
        validate_existing_file("off-chain server private key", &self.key_path)?;
        for path in &self.expected_client_certs {
            validate_existing_file("expected off-chain client certificate", path)?;
        }
        if expected_clients > 0 && self.expected_client_certs.len() != expected_clients {
            return Err(Error::Configuration(format!(
                "expected_clients is {expected_clients}, but {} expected client certificate(s) were configured",
                self.expected_client_certs.len()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct OffChainServerConfigBuilder {
    coordinator_address: Option<String>,
    rpc_bind_address: Option<String>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    timestamp: Option<u64>,
    expected_client_certs: Vec<PathBuf>,
}

impl OffChainServerConfigBuilder {
    pub fn coordinator(mut self, address: impl Into<String>) -> Self {
        self.coordinator_address = Some(address.into());
        self
    }

    pub fn rpc_bind(mut self, address: impl Into<String>) -> Self {
        self.rpc_bind_address = Some(address.into());
        self
    }

    pub fn identity_files(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Self {
        self.cert_path = Some(cert_path.as_ref().to_path_buf());
        self.key_path = Some(key_path.as_ref().to_path_buf());
        self
    }

    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn expected_client_cert(mut self, path: impl AsRef<Path>) -> Self {
        self.expected_client_certs.push(path.as_ref().to_path_buf());
        self
    }

    pub fn expected_client_certs<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.expected_client_certs = paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();
        self
    }

    pub fn build(self) -> Result<OffChainServerConfig> {
        let config = OffChainServerConfig {
            coordinator_address: self.coordinator_address.ok_or_else(|| {
                Error::Configuration("off-chain coordinator address is required".to_owned())
            })?,
            rpc_bind_address: self.rpc_bind_address.ok_or_else(|| {
                Error::Configuration("off-chain node RPC bind address is required".to_owned())
            })?,
            cert_path: self.cert_path.ok_or_else(|| {
                Error::Configuration("off-chain server certificate path is required".to_owned())
            })?,
            key_path: self.key_path.ok_or_else(|| {
                Error::Configuration("off-chain server private key path is required".to_owned())
            })?,
            timestamp: self.timestamp.ok_or_else(|| {
                Error::Configuration("off-chain coordinator timestamp is required".to_owned())
            })?,
            expected_client_certs: self.expected_client_certs,
        };
        config.validate(config.expected_client_certs.len())?;
        Ok(config)
    }
}

#[derive(Debug)]
pub struct StoffelServer {
    party_id: PartyId,
    bind_addr: String,
    peers: Vec<(usize, String)>,
    program: Option<Program>,
    triples: usize,
    random_shares: usize,
    expected_clients: usize,
    consensus_timeout: Duration,
    backend: MpcBackend,
    mpc_config: Option<MpcConfig>,
    avss_engine: Option<AvssEngine>,
    state: Arc<AtomicU8>,
    verified_ordering: Option<VerifiedOrdering>,
    runner_path: Option<PathBuf>,
    bootstrap_addr: Option<String>,
    advertise_addr: Option<SocketAddr>,
    entry: String,
    offchain_coordinator: Option<OffChainServerConfig>,
    process: Arc<Mutex<Option<ServerProcess>>>,
    metrics: ServerMetrics,
}

#[derive(Debug)]
struct ServerProcess {
    child: Child,
    _tempdir: tempfile::TempDir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSummary {
    pub party_id: PartyId,
    pub bind_addr: String,
    pub peer_count: usize,
    pub expected_clients: usize,
    pub preprocessing_triples: usize,
    pub preprocessing_random_shares: usize,
    pub consensus_timeout_ms: u64,
    pub backend: MpcBackend,
    pub mpc_parties: Option<usize>,
    pub mpc_threshold: Option<usize>,
    pub mpc_instance_id: Option<u64>,
    pub avss_engine_configured: bool,
    pub avss_engine_live: bool,
    pub has_verified_ordering: bool,
    pub state: ServerState,
    pub ready: bool,
    pub health: HealthStatus,
}

impl StoffelServer {
    pub fn builder(party_id: PartyId) -> ServerBuilder {
        ServerBuilder::new(party_id)
    }

    #[tracing::instrument(skip_all, fields(party_id = self.party_id, bind_addr = %self.bind_addr))]
    pub async fn start(&self) -> Result<()> {
        if self.state() == ServerState::Shutdown {
            return Err(Error::Configuration(
                "cannot start a server after shutdown".to_owned(),
            ));
        }
        if self.state() == ServerState::Running {
            return Ok(());
        }
        let program = self.program.as_ref().ok_or_else(|| {
            Error::Configuration("server start requires a compiled program".to_owned())
        })?;
        if (program.has_client_io() || self.expected_clients > 0)
            && self.offchain_coordinator.is_none()
        {
            return Err(Error::Configuration(
                "server start for ClientStore IO requires off-chain coordinator configuration"
                    .to_owned(),
            ));
        }
        let mpc_config = self
            .mpc_config
            .as_ref()
            .ok_or_else(|| Error::Configuration("MPC configuration is required".to_owned()))?;
        if self.party_id != 0 && self.bootstrap_addr.is_none() {
            return Err(Error::Configuration(
                "non-leader server start requires a bootstrap address".to_owned(),
            ));
        }

        let runner_path = resolve_stoffel_run_binary(self.runner_path.as_deref())?;
        eprintln!(
            "[stoffel] using stoffel-run binary: {}",
            runner_path.display()
        );
        let tempdir = tempfile::tempdir()?;
        let program_path = tempdir.path().join("program.stflb");
        program.save_bytecode(&program_path)?;

        let args = self.runner_args(&program_path, mpc_config)?;
        if self.advertise_addr.is_none() && bind_ip_is_unspecified(&self.bind_addr) {
            eprintln!(
                "[stoffel] warning: party {} binds {} without an advertise address; parties on other hosts cannot dial it",
                self.party_id, self.bind_addr
            );
        }

        let mut command = Command::new(runner_path);
        command
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command.spawn()?;
        *self.process.lock().map_err(|_| {
            Error::Computation("server process state lock was poisoned".to_owned())
        })? = Some(ServerProcess {
            child,
            _tempdir: tempdir,
        });
        self.set_state(ServerState::Running);
        Ok(())
    }

    /// Build the `stoffel-run` argument list for this server.
    fn runner_args(&self, program_path: &Path, mpc_config: &MpcConfig) -> Result<Vec<OsString>> {
        let mut args: Vec<OsString> = vec![
            program_path.into(),
            (&self.entry).into(),
            "--n-parties".into(),
            mpc_config.parties.to_string().into(),
            "--threshold".into(),
            mpc_config.threshold.to_string().into(),
            "--bind".into(),
            (&self.bind_addr).into(),
            "--mpc-backend".into(),
            server_backend_name(self.backend).into(),
        ];
        if let Some(curve) = self.backend.curve() {
            args.push("--mpc-curve".into());
            args.push(curve.to_string().into());
        }
        if let Some(advertise) = self.advertise_addr {
            args.push("--advertise".into());
            args.push(advertise.to_string().into());
        }
        if let Some(config) = &self.offchain_coordinator {
            config.validate(self.expected_clients)?;
            args.push("--off-chain-coord".into());
            args.push((&config.coordinator_address).into());
            args.push("--rpc-bind".into());
            args.push((&config.rpc_bind_address).into());
            args.push("--key".into());
            args.push((&config.key_path).into());
            args.push("--cert".into());
            args.push((&config.cert_path).into());
            args.push("--timestamp".into());
            args.push(config.timestamp.to_string().into());
            if !config.expected_client_certs.is_empty() {
                args.push("--expected-clients".into());
                args.push(
                    config
                        .expected_client_certs
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                        .into(),
                );
            }
        }
        if let Some(bootstrap) = &self.bootstrap_addr {
            args.push("--party-id".into());
            args.push(self.party_id.to_string().into());
            args.push("--bootstrap".into());
            args.push(bootstrap.into());
        } else {
            if self.party_id != 0 {
                return Err(Error::Configuration(
                    "only party 0 can start as leader without bootstrap".to_owned(),
                ));
            }
            args.push("--leader".into());
        }
        Ok(args)
    }

    #[tracing::instrument(skip_all, fields(party_id = self.party_id, bind_addr = %self.bind_addr))]
    pub async fn run_forever(self) -> Result<()> {
        self.start().await?;
        let process = self
            .process
            .lock()
            .map_err(|_| Error::Computation("server process state lock was poisoned".to_owned()))?
            .take();
        let status = if let Some(mut process) = process {
            process.child.wait()?
        } else {
            std::future::pending::<std::process::ExitStatus>().await
        };
        self.set_state(ServerState::Shutdown);
        if !status.success() {
            return Err(Error::Computation(format!(
                "stoffel-run for party {} exited unsuccessfully: {status}",
                self.party_id
            )));
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(party_id = self.party_id))]
    pub async fn shutdown(self) -> Result<()> {
        let process = self
            .process
            .lock()
            .map_err(|_| Error::Computation("server process state lock was poisoned".to_owned()))?
            .take();
        if let Some(mut process) = process {
            let _ = process.child.kill();
            let _ = process.child.wait();
        }
        self.set_state(ServerState::Shutdown);
        Ok(())
    }

    pub fn party_id(&self) -> PartyId {
        self.party_id
    }

    pub fn state(&self) -> ServerState {
        ServerState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    pub fn metrics(&self) -> &ServerMetrics {
        &self.metrics
    }

    pub fn summary(&self) -> ServerSummary {
        let (preprocessing_triples, preprocessing_random_shares) = self.preprocessing();
        ServerSummary {
            party_id: self.party_id,
            bind_addr: self.bind_addr.clone(),
            peer_count: self.peers.len(),
            expected_clients: self.expected_clients,
            preprocessing_triples,
            preprocessing_random_shares,
            consensus_timeout_ms: self
                .consensus_timeout
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            backend: self.backend,
            mpc_parties: self.mpc_config.as_ref().map(|config| config.parties),
            mpc_threshold: self.mpc_config.as_ref().map(|config| config.threshold),
            mpc_instance_id: self.mpc_config.as_ref().map(|config| config.instance_id),
            avss_engine_configured: self.avss_engine.is_some(),
            avss_engine_live: self.avss_engine.as_ref().is_some_and(AvssEngine::is_live),
            has_verified_ordering: self.verified_ordering.is_some(),
            state: self.state(),
            ready: self.ready(),
            health: self.health(),
        }
    }

    pub fn health(&self) -> HealthStatus {
        match self.state() {
            ServerState::Created => HealthStatus::Degraded {
                reason: "server has been configured but not started by a live networking backend"
                    .to_owned(),
            },
            ServerState::Running => HealthStatus::Healthy,
            ServerState::Shutdown => HealthStatus::Unhealthy {
                reason: "server has been shut down".to_owned(),
            },
        }
    }

    pub fn ready(&self) -> bool {
        self.state() == ServerState::Running
    }

    #[tracing::instrument(skip_all, fields(party_id = self.party_id))]
    pub async fn create_avss_engine(&self) -> Result<AvssEngine> {
        match self.backend {
            MpcBackend::Avss { curve } => Ok(self
                .avss_engine
                .clone()
                .unwrap_or_else(|| AvssEngine::unavailable(curve))),
            MpcBackend::HoneyBadger => Err(Error::Configuration(
                "AVSS engine requires MpcBackend::Avss".to_owned(),
            )),
        }
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }

    pub fn peers(&self) -> &[(usize, String)] {
        &self.peers
    }

    pub fn program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn preprocessing(&self) -> (usize, usize) {
        (self.triples, self.random_shares)
    }

    pub fn expected_clients(&self) -> usize {
        self.expected_clients
    }

    pub fn consensus_timeout(&self) -> Duration {
        self.consensus_timeout
    }

    pub fn backend(&self) -> MpcBackend {
        self.backend
    }

    pub fn mpc_config(&self) -> Option<&MpcConfig> {
        self.mpc_config.as_ref()
    }

    pub fn avss_engine(&self) -> Option<&AvssEngine> {
        self.avss_engine.as_ref()
    }

    pub fn runner_path(&self) -> Option<&Path> {
        self.runner_path.as_deref()
    }

    pub fn bootstrap_addr(&self) -> Option<&str> {
        self.bootstrap_addr.as_deref()
    }

    /// The address forwarded to `stoffel-run` as `--advertise`, if any.
    pub fn advertise_addr(&self) -> Option<SocketAddr> {
        self.advertise_addr
    }

    pub fn offchain_coordinator(&self) -> Option<&OffChainServerConfig> {
        self.offchain_coordinator.as_ref()
    }

    pub fn entry(&self) -> &str {
        &self.entry
    }

    fn set_state(&self, state: ServerState) {
        self.state.store(state.as_u8(), Ordering::Release);
    }
}

fn server_backend_name(backend: MpcBackend) -> &'static str {
    match backend {
        MpcBackend::HoneyBadger => "honeybadger",
        MpcBackend::Avss { .. } => "avss",
    }
}

fn bind_ip_is_unspecified(bind_addr: &str) -> bool {
    bind_addr
        .parse::<SocketAddr>()
        .is_ok_and(|addr| addr.ip().is_unspecified())
}

fn resolve_stoffel_run_binary(explicit_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit_path {
        return path.exists().then(|| path.to_path_buf()).ok_or_else(|| {
            Error::Unsupported(format!(
                "server start requires an existing stoffel-run binary; configured path does not exist: {}",
                path.display()
            ))
        });
    }
    if let Some(path) = std::env::var_os("STOFFEL_RUN_BIN").map(PathBuf::from) {
        return path.exists().then_some(path.clone()).ok_or_else(|| {
            Error::Unsupported(format!(
                "server start requires an existing stoffel-run binary; STOFFEL_RUN_BIN points to a missing path: {}",
                path.display()
            ))
        });
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("target").join("debug").join("stoffel-run"));
    candidate
        .filter(|path| path.exists())
        .ok_or_else(|| {
            Error::Unsupported(
                "server start requires a built stoffel-run binary; set STOFFEL_RUN_BIN, call runner_path, or build `cargo build -p stoffel-vm-runner --bin stoffel-run`"
                    .to_owned(),
            )
        })
}

fn validate_existing_file(label: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::Configuration(format!(
            "{label} path must not be empty"
        )));
    }
    if !path.is_file() {
        return Err(Error::Configuration(format!(
            "{label} path does not exist or is not a file: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_avss_engine_is_returned_by_server_api() -> Result<()> {
        let engine = AvssEngine::unavailable(Curve::Bls12_381);
        let server = StoffelServer::builder(0)
            .bind("127.0.0.1:1")
            .avss(Curve::Bls12_381)
            .with_avss_engine(engine)
            .build()?;

        assert!(server.avss_engine().is_some());
        assert!(server.summary().avss_engine_configured);
        let returned = server.create_avss_engine().await?;
        assert_eq!(returned.curve(), Curve::Bls12_381);
        assert!(!returned.is_live());
        Ok(())
    }

    #[test]
    fn configured_avss_engine_requires_matching_avss_backend() {
        let err = StoffelServer::builder(0)
            .bind("127.0.0.1:1")
            .honeybadger()
            .with_avss_engine(AvssEngine::unavailable(Curve::Bls12_381))
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Configuration(_)));

        let err = StoffelServer::builder(0)
            .bind("127.0.0.1:1")
            .avss(Curve::Bn254)
            .with_avss_engine(AvssEngine::unavailable(Curve::Bls12_381))
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Configuration(_)));
    }

    fn runner_args_for(server: &StoffelServer) -> Result<Vec<OsString>> {
        let mpc_config = server
            .mpc_config()
            .expect("test server has an MPC configuration");
        server.runner_args(Path::new("program.stflb"), mpc_config)
    }

    fn five_party_builder(party_id: PartyId) -> ServerBuilder {
        let mpc_config = MpcConfig::default();
        StoffelServer::builder(party_id)
            .bind("127.0.0.1:19200")
            .mpc_config(&mpc_config)
            .peers(
                (0..5)
                    .filter(|peer| *peer != party_id)
                    .map(|peer| (peer, format!("127.0.0.1:{}", 19300 + peer))),
            )
    }

    fn advertise_values(args: &[OsString]) -> Vec<&OsString> {
        args.iter()
            .zip(args.iter().skip(1))
            .filter(|(flag, _)| *flag == "--advertise")
            .map(|(_, value)| value)
            .collect()
    }

    #[test]
    fn advertise_defaults_to_unset_and_is_not_forwarded() -> Result<()> {
        let builder = five_party_builder(0);
        assert_eq!(builder.configured_advertise(), None);

        let server = builder.build()?;
        assert_eq!(server.advertise_addr(), None);
        let args = runner_args_for(&server)?;
        assert!(!args.iter().any(|arg| arg == "--advertise"));
        assert_eq!(
            args.last().map(OsString::as_os_str),
            Some("--leader".as_ref())
        );
        Ok(())
    }

    #[test]
    fn advertise_round_trips_and_is_forwarded_for_leader_and_follower() -> Result<()> {
        let expected: SocketAddr = "10.0.0.5:20200".parse().expect("numeric socket address");

        let builder = five_party_builder(0).advertise("10.0.0.5:20200");
        assert_eq!(builder.configured_advertise(), Some(expected));
        let leader = builder.build()?;
        assert_eq!(leader.advertise_addr(), Some(expected));
        let args = runner_args_for(&leader)?;
        assert_eq!(advertise_values(&args), ["10.0.0.5:20200"]);
        assert!(args.iter().any(|arg| arg == "--leader"));

        let follower = five_party_builder(2)
            .bootstrap("10.0.0.4:19200")
            .advertise(expected)
            .build()?;
        let args = runner_args_for(&follower)?;
        assert_eq!(advertise_values(&args), ["10.0.0.5:20200"]);
        assert!(args.iter().any(|arg| arg == "--bootstrap"));
        assert!(!args.iter().any(|arg| arg == "--leader"));
        Ok(())
    }

    #[test]
    fn advertise_accepts_loopback_for_single_host_networks() -> Result<()> {
        let server = five_party_builder(0).advertise("127.0.0.1:20200").build()?;
        assert_eq!(
            server.advertise_addr(),
            Some("127.0.0.1:20200".parse().expect("numeric socket address"))
        );
        Ok(())
    }

    #[test]
    fn advertise_rejects_undialable_addresses() {
        for address in ["0.0.0.0:20200", "[::]:20200", "10.0.0.5:0"] {
            let err = five_party_builder(0)
                .advertise(address)
                .build()
                .unwrap_err();
            assert!(
                matches!(&err, Error::Configuration(message) if message.contains("advertise")),
                "{address}: {err}"
            );
        }

        let err = five_party_builder(0)
            .advertise("not a socket address")
            .build()
            .unwrap_err();
        assert!(
            matches!(&err, Error::Configuration(message) if message.contains("invalid server advertise address")),
            "{err}"
        );
    }

    #[test]
    fn non_leader_without_bootstrap_has_no_runner_args() -> Result<()> {
        let server = five_party_builder(1).build()?;
        let err = runner_args_for(&server).unwrap_err();
        assert!(matches!(err, Error::Configuration(_)));
        Ok(())
    }

    #[test]
    fn unspecified_bind_detection_only_matches_wildcard_addresses() {
        assert!(bind_ip_is_unspecified("0.0.0.0:19200"));
        assert!(bind_ip_is_unspecified("[::]:19200"));
        assert!(!bind_ip_is_unspecified("127.0.0.1:19200"));
        assert!(!bind_ip_is_unspecified("10.0.0.5:19200"));
    }
}
