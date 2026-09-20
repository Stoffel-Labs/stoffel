//! Server-side builder, state, health, and metrics access.
//!
//! The builder validates operational configuration and captures program
//! metadata. Starting a live server remains a lower-layer networking/VM
//! integration concern and is not simulated by the SDK.

use std::collections::BTreeSet;
use std::fmt;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use stoffel_mpc_coordinator_shared::{ExecutionId, RosterDigest};

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

/// How a spawned server finds the rest of its session.
///
/// `docs/design/bootnode-elimination.md`. Stage 7 added this type with two
/// variants and deliberately left the default on the bootnode, because flipping
/// it would have turned every existing SDK server into a build error — the hard
/// break §8 of the design doc ruled out for this crate while the bootnode still
/// existed. Stage 8 deleted the bootnode, so the variant goes and the required
/// arguments change with the rest of the SDK's break: a mesh server needs
/// [`ServerBuilder::peers`], [`ServerBuilder::offchain_coordinator`],
/// [`ServerBuilder::identity_files`] and [`ServerBuilder::epoch_store`], all of
/// which are values only the caller has.
///
/// One variant, kept as an enum rather than collapsed away. §9.E.2 renamed it
/// from `RosterMesh`: the coordinator is the only roster authority (§8, §9 rule
/// 1), so the variant names the only way a server learns who is in its
/// session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServerTopology {
    /// A mesh pinned to the coordinator's node roster: the configured peer
    /// addresses are seed hints, and the node roster the pinned coordinator
    /// serves — fetched once at startup — is the membership.
    #[default]
    CoordinatorRosterMesh,
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
    bootstrap_seed: Option<String>,
    entry: String,
    identity: Option<ServerIdentity>,
    topology: ServerTopology,
    epoch_store: Option<PathBuf>,
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
            bootstrap_seed: None,
            entry: "main".to_owned(),
            identity: None,
            topology: ServerTopology::default(),
            epoch_store: None,
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

    /// Deprecated: there is no bootstrap process to follow.
    ///
    /// Stage 8 of `docs/design/bootnode-elimination.md` deleted the bootnode.
    /// This is a shim rather than a removal so that existing callers keep
    /// compiling: the address is carried through as one more `--peers` seed
    /// hint, which is the only thing it can honestly mean now. A seed carries no
    /// identity — membership is the coordinator's node roster — so an address
    /// that is not a roster member simply fails its TLS handshake and costs
    /// nothing.
    ///
    /// Prefer [`ServerBuilder::peers`] or [`ServerBuilder::peer`], which name
    /// the party each address belongs to.
    #[deprecated(
        note = "the bootnode is gone; a bootstrap address is now just a peer seed hint. \
                Use peers() or peer() instead."
    )]
    pub fn bootstrap(mut self, address: impl Into<String>) -> Self {
        self.bootstrap_seed = Some(address.into());
        self
    }

    /// Configure the off-chain coordinator flags passed to `stoffel-run`.
    ///
    /// This is required when the attached program declares ClientStore IO.
    /// The certificate and key this server presents on the mesh.
    ///
    /// The certificate must be one of the coordinator's node roster. The
    /// [`OffChainServerConfig`] carries the same pair, and the two must agree.
    pub fn identity_files(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Self {
        self.identity = Some(ServerIdentity::new(cert_path, key_path));
        self
    }

    /// Choose how this server forms its session.
    ///
    /// [`ServerTopology::CoordinatorRosterMesh`] is the only topology and the
    /// default. The method stays so that a second way to be told the membership
    /// would be a variant, not a second builder.
    pub fn topology(mut self, topology: ServerTopology) -> Self {
        self.topology = topology;
        self
    }

    /// Where this node keeps its monotone session epoch (`--epoch-store`).
    ///
    /// Only read on the mesh path, where it is what makes `instance_id` fresh
    /// across runs of one roster (blocker B5). One directory per node; two nodes
    /// must not share one. Unset leaves `stoffel-run` to its own default
    /// (`$STOFFEL_EPOCH_STORE`, then `$HOME/.stoffel/epochs`).
    pub fn epoch_store(mut self, path: impl AsRef<Path>) -> Self {
        self.epoch_store = Some(path.as_ref().to_path_buf());
        self
    }

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

    /// Deprecated: the address configured through the [`ServerBuilder::bootstrap`]
    /// shim, which is now an extra `--peers` seed hint.
    #[deprecated(note = "the bootnode is gone; read the seed addresses with peers() instead.")]
    pub fn configured_bootstrap(&self) -> Option<&str> {
        self.bootstrap_seed.as_deref()
    }

    pub fn configured_offchain_coordinator(&self) -> Option<&OffChainServerConfig> {
        self.offchain_coordinator.as_ref()
    }

    pub fn configured_identity(&self) -> Option<&ServerIdentity> {
        self.identity.as_ref()
    }

    pub fn configured_topology(&self) -> ServerTopology {
        self.topology
    }

    pub fn configured_epoch_store(&self) -> Option<&Path> {
        self.epoch_store.as_deref()
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
            config.validate()?;
        }
        if let Some(identity) = &self.identity {
            identity.validate()?;
            if let Some(config) = &self.offchain_coordinator {
                if identity.cert_path != config.cert_path || identity.key_path != config.key_path {
                    return Err(Error::Configuration(
                        "server identity files must match the off-chain coordinator identity files"
                            .to_owned(),
                    ));
                }
            }
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
            bootstrap_seed: self.bootstrap_seed,
            entry: self.entry,
            identity: self.identity,
            topology: self.topology,
            epoch_store: self.epoch_store,
            offchain_coordinator: self.offchain_coordinator,
            process: Arc::new(Mutex::new(None)),
            metrics,
        })
    }
}

/// The transport identity a spawned server presents, independent of whether it
/// talks to an off-chain coordinator.
///
/// Stage 3 of `docs/design/bootnode-elimination.md` makes certificates — not a
/// shared bearer token — the definition of membership, and §7 flags this type's
/// absence: the SDK used to pass `--cert`/`--key` only from
/// [`OffChainServerConfig`], so an SDK-spawned server with no coordinator had
/// no certificate and could never join a roster-pinned mesh. Configure it with
/// [`ServerBuilder::identity_files`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl ServerIdentity {
    pub fn new(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Self {
        Self {
            cert_path: cert_path.as_ref().to_path_buf(),
            key_path: key_path.as_ref().to_path_buf(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_existing_file("server certificate", &self.cert_path)?;
        validate_existing_file("server private key", &self.key_path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffChainServerConfig {
    pub coordinator_address: String,
    /// The coordinator's DER X.509 certificate, emitted as `--coord-cert`. The
    /// party pins its key on every coordinator connection
    /// (`docs/design/bootnode-elimination.md` §9.A).
    pub coordinator_cert_path: PathBuf,
    pub rpc_bind_address: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Which program invocation this party serves.
    ///
    /// Coordinator `0.2.0` keys rounds, reserved indices, masked inputs and
    /// output shares on this, and `0.1.0`'s `reset_coord` teardown is gone: a
    /// fresh id is what makes a run fresh. Every party and client of one
    /// invocation must carry the same value.
    pub execution_id: ExecutionId,
    /// The node roster digest this party refuses any other than, emitted as
    /// `--expect-roster-digest` (`docs/design/bootnode-elimination.md` §9.D.2).
    /// Carries no certificate: it can only refuse what the coordinator serves.
    #[serde(default)]
    pub expected_roster_digest: Option<RosterDigest>,
}

impl OffChainServerConfig {
    pub fn builder() -> OffChainServerConfigBuilder {
        OffChainServerConfigBuilder::default()
    }

    /// Checks this party's own coordinator configuration.
    ///
    /// It names no client: which clients take part is the coordinator's
    /// per-execution admission, and a coordinated party refuses every flag that
    /// would give it a client certificate (`docs/design/bootnode-elimination.md`
    /// §9, decision 3; §9.E.2).
    pub fn validate(&self) -> Result<()> {
        validate_socket_address("off-chain coordinator address", &self.coordinator_address)?;
        validate_socket_address("off-chain node RPC bind address", &self.rpc_bind_address)?;
        if self.execution_id.is_zero() {
            return Err(Error::Configuration(
                "off-chain coordinator execution ID must not be all zeros; the coordinator \
                 reserves that value and rejects it"
                    .to_owned(),
            ));
        }
        validate_existing_file("off-chain server certificate", &self.cert_path)?;
        validate_existing_file("off-chain server private key", &self.key_path)?;
        validate_existing_file(
            "off-chain coordinator certificate",
            &self.coordinator_cert_path,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct OffChainServerConfigBuilder {
    coordinator_address: Option<String>,
    coordinator_cert_path: Option<PathBuf>,
    rpc_bind_address: Option<String>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    execution_id: Option<ExecutionId>,
    execution_id_error: Option<String>,
    expected_roster_digest: Option<RosterDigest>,
}

impl OffChainServerConfigBuilder {
    pub fn coordinator(mut self, address: impl Into<String>) -> Self {
        self.coordinator_address = Some(address.into());
        self
    }

    /// The coordinator's DER X.509 certificate, which the party pins. Required,
    /// and emitted as `--coord-cert`.
    pub fn coordinator_cert(mut self, path: impl AsRef<Path>) -> Self {
        self.coordinator_cert_path = Some(path.as_ref().to_path_buf());
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

    /// The program invocation this party serves. Required, and emitted as
    /// `--execution-id`.
    pub fn execution_id(mut self, execution_id: ExecutionId) -> Self {
        self.execution_id = Some(execution_id);
        self
    }

    /// Convenience form of [`Self::execution_id`] taking the 64-character
    /// hexadecimal spelling the `--execution-id` flag uses.
    pub fn execution_id_hex(mut self, execution_id: &str) -> Self {
        match ExecutionId::from_str(execution_id.trim()) {
            Ok(parsed) => self.execution_id = Some(parsed),
            Err(error) => {
                self.execution_id_error = Some(format!("invalid off-chain execution ID: {error}"))
            }
        }
        self
    }

    /// Refuse a coordinator that serves any node roster but the one with this
    /// digest. Optional; emitted as `--expect-roster-digest`.
    pub fn expected_roster_digest(mut self, digest: RosterDigest) -> Self {
        self.expected_roster_digest = Some(digest);
        self
    }

    pub fn build(self) -> Result<OffChainServerConfig> {
        if let Some(error) = self.execution_id_error {
            return Err(Error::Configuration(error));
        }
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
            execution_id: self.execution_id.ok_or_else(|| {
                Error::Configuration(
                    "off-chain execution ID is required; every party and client of one \
                     invocation must carry the same --execution-id"
                        .to_owned(),
                )
            })?,
            expected_roster_digest: self.expected_roster_digest,
            coordinator_cert_path: self.coordinator_cert_path.ok_or_else(|| {
                Error::Configuration(
                    "off-chain coordinator certificate path is required; the party pins the \
                     coordinator's key with --coord-cert"
                        .to_owned(),
                )
            })?,
        };
        config.validate()?;
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
    bootstrap_seed: Option<String>,
    entry: String,
    identity: Option<ServerIdentity>,
    topology: ServerTopology,
    epoch_store: Option<PathBuf>,
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
        // What a mesh member needs in order to be one. Stage 8 of
        // `docs/design/bootnode-elimination.md` deleted the two guards that used
        // to stand here — "non-leader server start requires a bootstrap address"
        // and "only party 0 can start as leader without bootstrap" — because
        // both described a topology that no longer exists. These replace them.
        //
        // Checked at `start` rather than at `build`: `build` is a
        // configuration-capture step that plenty of callers use without ever
        // spawning anything, while these three are what the spawned process
        // cannot do without. Each names the builder method rather than letting
        // the child exit 2 with a flag name.
        if self.seed_addresses().is_empty() {
            return Err(Error::Configuration(
                "a mesh server forms its session by dialing the other members, so it needs \
                 peer addresses: configure them with peers() or network_config()"
                    .to_owned(),
            ));
        }
        let Some(offchain_coordinator) = &self.offchain_coordinator else {
            return Err(Error::Configuration(
                "a mesh server needs offchain_coordinator(): membership is the coordinator's \
                 node roster, fetched once at startup, and a seed address is only a hint"
                    .to_owned(),
            ));
        };
        if self.epoch_store.is_none() {
            // Blocker B5. Without a path, `epoch_store_path(None)` resolves to
            // `$HOME/.stoffel/epochs`, which every co-located party shares, and
            // the record inside is keyed by roster digest — so the parties of
            // one roster share one counter. They all read `last`, all propose
            // `last + 1`, all agree on it, and then `EpochStore::commit`
            // re-reads `last` under its write transaction: the first party
            // commits, and every other one fails `NotMonotone` and aborts the
            // join. One directory per node, never shared.
            return Err(Error::Configuration(
                "a mesh server needs epoch_store(): a per-node directory, never shared, or \
                 co-located parties race one counter and all but the first abort the join \
                 with NotMonotone"
                    .to_owned(),
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

        let mut command = Command::new(runner_path);
        // `n` and `t` come from the coordinator's node roster (§9.D.2), so the
        // configured `parties` and `threshold` are emitted as refusals: a server
        // configured for five parties at `t = 1` refuses to run against a
        // coordinator whose roster is anything else, instead of silently
        // joining it.
        command
            .arg(&program_path)
            .arg(&self.entry)
            .arg("--expect-n-parties")
            .arg(mpc_config.parties.to_string())
            .arg("--expect-threshold")
            .arg(mpc_config.threshold.to_string())
            .arg("--bind")
            .arg(&self.bind_addr)
            .arg("--mpc-backend")
            .arg(server_backend_name(self.backend))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(curve) = self.backend.curve() {
            command.arg("--mpc-curve").arg(curve.to_string());
        }
        // The transport identity: the coordinator's node roster names nodes by
        // certificate, and every mesh connection is authenticated by one.
        // `build()` has already checked the two sources agree when both exist.
        let identity = self.effective_identity();
        if let Some(identity) = &identity {
            identity.validate()?;
            command
                .arg("--key")
                .arg(&identity.key_path)
                .arg("--cert")
                .arg(&identity.cert_path);
        }
        {
            let config = offchain_coordinator;
            config.validate()?;
            command
                .arg("--off-chain-coord")
                .arg(&config.coordinator_address)
                .arg("--coord-cert")
                .arg(&config.coordinator_cert_path)
                .arg("--execution-id")
                .arg(config.execution_id.to_string())
                .arg("--rpc-bind")
                .arg(&config.rpc_bind_address);
            if let Some(digest) = &config.expected_roster_digest {
                command
                    .arg("--expect-roster-digest")
                    .arg(digest.to_string());
            }
            // No `--roster`, `--expected-clients` or `--timestamp`:
            // `stoffel-run` refuses each by name. Membership is the
            // coordinator's node roster, and clients are admitted by the
            // coordinator and reach this party's RPC listener, never its mesh
            // transport.
        }
        match self.topology {
            // `--peers` are seed addresses, the coordinator's node roster is the
            // membership, and no process here is anybody's bootstrap. Nor is any
            // party the coordinator's round driver: transitions are
            // quorum-gated, so every party proposes and none is designated.
            ServerTopology::CoordinatorRosterMesh => {
                command
                    .arg("--party-id")
                    .arg(self.party_id.to_string())
                    .arg("--peers")
                    .arg(self.seed_addresses().join(","));
                // Always present: `start` refuses without one, because the
                // default path is shared between co-located parties and that is
                // a failed join, not a slow one (blocker B5).
                if let Some(epoch_store) = &self.epoch_store {
                    command.arg("--epoch-store").arg(epoch_store);
                }
            }
        }

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

    #[tracing::instrument(skip_all, fields(party_id = self.party_id, bind_addr = %self.bind_addr))]
    pub async fn run_forever(self) -> Result<()> {
        self.start().await?;
        let process = self
            .process
            .lock()
            .map_err(|_| Error::Computation("server process state lock was poisoned".to_owned()))?
            .take();
        if let Some(mut process) = process {
            process.child.wait()?;
        } else {
            std::future::pending::<()>().await;
        }
        self.set_state(ServerState::Shutdown);
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

    /// Deprecated: the address configured through the [`ServerBuilder::bootstrap`]
    /// shim, which is now an extra `--peers` seed hint.
    #[deprecated(note = "the bootnode is gone; read the seed addresses with peers() instead.")]
    pub fn bootstrap_addr(&self) -> Option<&str> {
        self.bootstrap_seed.as_deref()
    }

    pub fn offchain_coordinator(&self) -> Option<&OffChainServerConfig> {
        self.offchain_coordinator.as_ref()
    }

    /// The identity configured with [`ServerBuilder::identity_files`], if any.
    pub fn identity(&self) -> Option<&ServerIdentity> {
        self.identity.as_ref()
    }

    /// Every address this server will offer the mesh as a seed hint.
    ///
    /// The configured peers, plus whatever the deprecated
    /// [`ServerBuilder::bootstrap`] shim was given. A seed is a hint and nothing
    /// more — membership is the coordinator's node roster — so the two collapse
    /// into one list with no ordering significance.
    fn seed_addresses(&self) -> Vec<String> {
        self.peers
            .iter()
            .map(|(_party_id, address)| address.clone())
            .chain(self.bootstrap_seed.clone())
            .collect()
    }

    /// The certificate and key this server actually presents: the configured
    /// identity, or the off-chain coordinator's pair when only that is set.
    pub fn effective_identity(&self) -> Option<ServerIdentity> {
        self.identity.clone().or_else(|| {
            self.offchain_coordinator
                .as_ref()
                .map(|config| ServerIdentity::new(&config.cert_path, &config.key_path))
        })
    }

    /// How this server forms its session.
    pub fn topology(&self) -> ServerTopology {
        self.topology
    }

    /// Where this server keeps its monotone session epoch, if configured.
    pub fn epoch_store(&self) -> Option<&Path> {
        self.epoch_store.as_deref()
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
}
