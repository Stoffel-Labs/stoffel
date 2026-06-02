//! Client-side builders and computation handles.
//!
//! The SDK validates client configuration and program input arity here. Live
//! submission and ordering verification remain delegated to `stoffel-networking`
//! and the MPC runtime instead of being simulated in the SDK.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark_bls12_381::{Fr, G1Projective};
use serde::{Deserialize, Serialize};
use stoffel_mpc_coordinator::off_chain::{
    encode_clear_input, node_rpc::NodeRPCClient as OffChainNodeRPCClient, ClearShareValue,
    OffChainCoordinatorClient, TypedMaskedInput,
};
use stoffel_mpc_coordinator::rpc::ValueWrapper;
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::Network as _;
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::config::{validate_socket_address, Curve, MpcBackend, NetworkConfig, NetworkDeployment};
use crate::consensus::VerifiedOrdering;
use crate::error::{Error, Result};
use crate::program::Program;
use crate::types::{ClientId, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    Disconnected,
    Connected,
}

impl fmt::Display for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ClientState::Disconnected => "disconnected",
            ClientState::Connected => "connected",
        })
    }
}

impl FromStr for ClientState {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "disconnected" => Ok(ClientState::Disconnected),
            "connected" => Ok(ClientState::Connected),
            state => Err(Error::Configuration(format!(
                "unsupported client state '{state}'; expected 'disconnected' or 'connected'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputationStatus {
    Pending,
    Completed,
    Cancelled,
}

impl fmt::Display for ComputationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ComputationStatus::Pending => "pending",
            ComputationStatus::Completed => "completed",
            ComputationStatus::Cancelled => "cancelled",
        })
    }
}

impl FromStr for ComputationStatus {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "pending" => Ok(ComputationStatus::Pending),
            "completed" => Ok(ComputationStatus::Completed),
            "cancelled" => Ok(ComputationStatus::Cancelled),
            status => Err(Error::Configuration(format!(
                "unsupported computation status '{status}'; expected 'pending', 'completed', or 'cancelled'"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    servers: Vec<String>,
    program: Option<Program>,
    client_id: ClientId,
    verified_ordering: Option<VerifiedOrdering>,
    connection_timeout: Duration,
    offchain_io: Option<OffChainClientConfig>,
    config_error: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            program: None,
            client_id: 0,
            verified_ordering: None,
            connection_timeout: Duration::from_secs(10),
            offchain_io: None,
            config_error: None,
        }
    }

    pub fn servers<I, S>(mut self, servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.servers = servers.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_servers(self, servers: &[&str]) -> Self {
        self.servers(servers.iter().copied())
    }

    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.servers.push(server.into());
        self
    }

    pub fn client_id(mut self, client_id: ClientId) -> Self {
        self.client_id = client_id;
        self
    }

    pub fn with_program(mut self, program: Program) -> Self {
        self.program = Some(program);
        self
    }

    pub fn with_verified_ordering(mut self, ordering: VerifiedOrdering) -> Self {
        self.verified_ordering = Some(ordering);
        self
    }

    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn offchain_io(mut self, config: OffChainClientConfig) -> Self {
        self.offchain_io = Some(config);
        self
    }

    pub fn configured_servers(&self) -> &[String] {
        &self.servers
    }

    pub fn configured_client_id(&self) -> ClientId {
        self.client_id
    }

    pub fn configured_program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn has_configured_program(&self) -> bool {
        self.program.is_some()
    }

    pub fn configured_verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    pub fn has_configured_verified_ordering(&self) -> bool {
        self.verified_ordering.is_some()
    }

    pub fn configured_connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    pub fn configured_offchain_io(&self) -> Option<&OffChainClientConfig> {
        self.offchain_io.as_ref()
    }

    pub fn has_configured_offchain_io(&self) -> bool {
        self.offchain_io.is_some()
    }

    pub fn network_config(mut self, config: &NetworkConfig) -> Self {
        match config.server_addresses() {
            Ok(addresses) => {
                self.servers = addresses;
            }
            Err(error) => {
                self.config_error = Some(error.to_string());
            }
        }
        self
    }

    /// Use all server addresses from a validated deployment plan.
    ///
    /// This only configures the client builder; live connection and submission
    /// still belong to `stoffel-networking` integration.
    pub fn network_deployment(mut self, deployment: &NetworkDeployment) -> Self {
        self.servers = deployment.server_addresses();
        self
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

    pub fn build(self) -> Result<StoffelClient> {
        if let Some(error) = self.config_error {
            return Err(Error::Configuration(error));
        }
        if self.connection_timeout.is_zero() {
            return Err(Error::Configuration(
                "client connection timeout must be greater than zero".to_owned(),
            ));
        }
        if let Some(config) = &self.offchain_io {
            config.validate()?;
        }
        if self.servers.is_empty() {
            return Err(Error::Configuration(
                "client requires at least one server address".to_owned(),
            ));
        }
        if let Some(index) = self
            .servers
            .iter()
            .position(|server| server.trim().is_empty())
        {
            return Err(Error::Configuration(format!(
                "client server address at index {index} must not be empty"
            )));
        }
        for (index, server) in self.servers.iter().enumerate() {
            validate_socket_address(&format!("client server address at index {index}"), server)?;
        }
        let mut server_addresses = BTreeSet::new();
        for server in &self.servers {
            if !server_addresses.insert(server.as_str()) {
                return Err(Error::Configuration(format!(
                    "duplicate client server address '{server}'"
                )));
            }
        }
        Ok(StoffelClient {
            servers: self.servers,
            program: self.program,
            client_id: self.client_id,
            transport_client_id: None,
            verified_ordering: self.verified_ordering,
            network: None,
            offchain_io: self.offchain_io,
            state: ClientState::Disconnected,
        })
    }

    #[tracing::instrument(skip_all, fields(server_count = self.servers.len()))]
    pub async fn connect(self) -> Result<StoffelClient> {
        let connection_timeout = self.connection_timeout;
        let mut client = self.build()?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut network = QuicNetworkManager::new();

        for server in &client.servers {
            let address = server.parse::<SocketAddr>().map_err(|error| {
                Error::Configuration(format!("invalid client server address '{server}': {error}"))
            })?;
            match tokio::time::timeout(connection_timeout, network.connect_as_client(address)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    return Err(Error::NetworkConnection(format!(
                        "failed to connect to server '{server}': {error}"
                    )));
                }
                Err(_) => {
                    return Err(Error::NetworkConnection(format!(
                        "timed out after {:?} connecting to server '{server}'",
                        connection_timeout
                    )));
                }
            }
        }

        client.transport_client_id = Some(network.local_derived_id());
        client.network = Some(network);
        client.state = ClientState::Connected;
        Ok(client)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffChainClientConfig {
    pub coordinator_host: String,
    pub coordinator_port: u16,
    pub timestamp: u64,
    pub parties: usize,
    pub threshold: usize,
    pub backend: MpcBackend,
    pub node_rpc_addresses: Vec<String>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub output_count: u64,
    #[serde(with = "duration_millis")]
    pub timeout: Duration,
}

impl OffChainClientConfig {
    pub fn builder() -> OffChainClientConfigBuilder {
        OffChainClientConfigBuilder::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.coordinator_host.trim().is_empty() {
            return Err(Error::Configuration(
                "off-chain coordinator host must not be empty".to_owned(),
            ));
        }
        if self.timestamp == 0 {
            return Err(Error::Configuration(
                "off-chain coordinator timestamp must be greater than zero".to_owned(),
            ));
        }
        if self.threshold == 0 {
            return Err(Error::Configuration(
                "off-chain client threshold must be greater than zero".to_owned(),
            ));
        }
        if self.parties < 5 {
            return Err(Error::Configuration(
                "off-chain client parties must be at least 5".to_owned(),
            ));
        }
        if let MpcBackend::Avss { curve } = self.backend {
            if curve != Curve::Bls12_381 {
                return Err(Error::Unsupported(
                    "off-chain client IO currently supports AVSS over bls12_381".to_owned(),
                ));
            }
        }
        if self.parties < 4 * self.threshold + 1 {
            return Err(Error::Unsupported(
                "off-chain client IO requires parties >= 4 * threshold + 1".to_owned(),
            ));
        }
        if self.node_rpc_addresses.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires at least one node RPC address".to_owned(),
            ));
        }
        for (index, address) in self.node_rpc_addresses.iter().enumerate() {
            validate_socket_address(&format!("node RPC address at index {index}"), address)?;
        }
        if self.cert_der.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires a client certificate DER".to_owned(),
            ));
        }
        if self.key_der.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires a client key DER".to_owned(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(Error::Configuration(
                "off-chain client IO timeout must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    fn node_rpc_endpoints(&self) -> Result<Vec<(String, u16)>> {
        self.node_rpc_addresses
            .iter()
            .map(|address| {
                let parsed = address.parse::<SocketAddr>().map_err(|error| {
                    Error::Configuration(format!("invalid node RPC address '{address}': {error}"))
                })?;
                Ok((parsed.ip().to_string(), parsed.port()))
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct OffChainClientConfigBuilder {
    coordinator_host: String,
    coordinator_port: Option<u16>,
    timestamp: Option<u64>,
    parties: usize,
    threshold: usize,
    backend: MpcBackend,
    node_rpc_addresses: Vec<String>,
    cert_der: Option<Vec<u8>>,
    key_der: Option<Vec<u8>>,
    output_count: u64,
    timeout: Duration,
    config_error: Option<String>,
}

impl OffChainClientConfigBuilder {
    pub fn coordinator(mut self, host: impl Into<String>, port: u16) -> Self {
        self.coordinator_host = host.into();
        self.coordinator_port = Some(port);
        self
    }

    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn parties(mut self, parties: usize) -> Self {
        self.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn honeybadger(mut self) -> Self {
        self.backend = MpcBackend::HoneyBadger;
        self
    }

    pub fn avss(mut self, curve: Curve) -> Self {
        self.backend = MpcBackend::Avss { curve };
        self
    }

    pub fn node_rpc_addresses<I, S>(mut self, addresses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.node_rpc_addresses = addresses.into_iter().map(Into::into).collect();
        self
    }

    pub fn node_rpc_address(mut self, address: impl Into<String>) -> Self {
        self.node_rpc_addresses.push(address.into());
        self
    }

    pub fn identity_der(mut self, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        self.cert_der = Some(cert_der);
        self.key_der = Some(key_der);
        self
    }

    pub fn identity_files(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Self {
        match std::fs::read(cert_path)
            .and_then(|cert| std::fs::read(key_path).map(|key| (cert, key)))
        {
            Ok((cert, key)) => {
                self.cert_der = Some(cert);
                self.key_der = Some(key);
            }
            Err(error) => {
                self.config_error = Some(error.to_string());
            }
        }
        self
    }

    pub fn output_count(mut self, output_count: u64) -> Self {
        self.output_count = output_count;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn build(self) -> Result<OffChainClientConfig> {
        if let Some(error) = self.config_error {
            return Err(Error::Io(std::io::Error::other(error)));
        }
        let config = OffChainClientConfig {
            coordinator_host: self.coordinator_host,
            coordinator_port: self.coordinator_port.ok_or_else(|| {
                Error::Configuration("off-chain coordinator port is required".to_owned())
            })?,
            timestamp: self.timestamp.ok_or_else(|| {
                Error::Configuration("off-chain coordinator timestamp is required".to_owned())
            })?,
            parties: self.parties,
            threshold: self.threshold,
            backend: self.backend,
            node_rpc_addresses: self.node_rpc_addresses,
            cert_der: self.cert_der.ok_or_else(|| {
                Error::Configuration("off-chain client certificate DER is required".to_owned())
            })?,
            key_der: self.key_der.ok_or_else(|| {
                Error::Configuration("off-chain client key DER is required".to_owned())
            })?,
            output_count: self.output_count,
            timeout: self.timeout,
        };
        config.validate()?;
        Ok(config)
    }
}

impl Default for OffChainClientConfigBuilder {
    fn default() -> Self {
        Self {
            coordinator_host: "127.0.0.1".to_owned(),
            coordinator_port: None,
            timestamp: None,
            parties: 5,
            threshold: 1,
            backend: MpcBackend::HoneyBadger,
            node_rpc_addresses: Vec::new(),
            cert_der: None,
            key_der: None,
            output_count: 0,
            timeout: Duration::from_secs(30),
            config_error: None,
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StoffelClient {
    servers: Vec<String>,
    program: Option<Program>,
    client_id: ClientId,
    transport_client_id: Option<ClientId>,
    verified_ordering: Option<VerifiedOrdering>,
    network: Option<QuicNetworkManager>,
    offchain_io: Option<OffChainClientConfig>,
    state: ClientState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSummary {
    pub client_id: ClientId,
    pub transport_client_id: Option<ClientId>,
    pub server_count: usize,
    pub has_program: bool,
    pub has_verified_ordering: bool,
    pub has_offchain_io: bool,
    pub connected: bool,
    pub state: ClientState,
}

impl StoffelClient {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    #[tracing::instrument(skip_all, fields(server_count = servers.len()))]
    pub async fn connect(servers: &[&str]) -> Result<Self> {
        ClientBuilder::new()
            .servers(servers.iter().copied())
            .connect()
            .await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn disconnect(self) -> Result<()> {
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, input_count = inputs.len()))]
    pub async fn run<V>(&self, inputs: &[V]) -> Result<Vec<Value>>
    where
        V: Clone + Into<Value>,
    {
        self.run_function("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name, input_count = inputs.len()))]
    pub async fn run_function<V>(&self, name: &str, inputs: &[V]) -> Result<Vec<Value>>
    where
        V: Clone + Into<Value>,
    {
        let inputs = inputs
            .iter()
            .map(|value| value.clone().into())
            .collect::<Vec<Value>>();
        self.validate_submission_inputs(name, inputs.len())?;
        self.run_offchain_inputs(&inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, input_count = inputs.len()))]
    pub async fn submit<V>(&self, inputs: &[V]) -> Result<ComputationHandle>
    where
        V: Clone + Into<Value>,
    {
        self.submit_function("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name, input_count = inputs.len()))]
    pub async fn submit_function<V>(&self, name: &str, inputs: &[V]) -> Result<ComputationHandle>
    where
        V: Clone + Into<Value>,
    {
        let inputs = inputs
            .iter()
            .map(|value| value.clone().into())
            .collect::<Vec<Value>>();
        self.validate_submission_inputs(name, inputs.len())?;
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        tokio::spawn(async move {
            let result = run_offchain_inputs_with_config(&config, &inputs).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn verify_ordering(&self) -> Result<VerifiedOrdering> {
        if let Some(ordering) = &self.verified_ordering {
            return Ok(ordering.clone());
        }
        if let Some(ordering) = self
            .network
            .as_ref()
            .and_then(|network| network.verified_ordering())
        {
            return Ok(ordering);
        }
        Err(Error::Unsupported(
            "ordering verification is performed by stoffel-networking over live QUIC connections"
                .to_owned(),
        ))
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn summary(&self) -> ClientSummary {
        ClientSummary {
            client_id: self.client_id,
            transport_client_id: self.transport_client_id,
            server_count: self.servers.len(),
            has_program: self.has_program(),
            has_verified_ordering: self.verified_ordering.is_some(),
            has_offchain_io: self.offchain_io.is_some(),
            connected: self.is_connected(),
            state: self.state,
        }
    }

    pub fn client_id(&self) -> ClientId {
        self.client_id
    }

    pub fn transport_client_id(&self) -> Option<ClientId> {
        self.transport_client_id
    }

    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    pub fn program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    pub fn network_manager(&self) -> Option<&QuicNetworkManager> {
        self.network.as_ref()
    }

    pub fn offchain_io(&self) -> Option<&OffChainClientConfig> {
        self.offchain_io.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected && self.network.is_some()
    }

    pub fn has_program(&self) -> bool {
        self.program.is_some()
    }

    async fn run_offchain_inputs(&self, inputs: &[Value]) -> Result<Vec<Value>> {
        let config = self.offchain_io.as_ref().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        run_offchain_inputs_with_config(config, inputs).await
    }

    fn validate_submission_inputs(&self, name: &str, input_count: usize) -> Result<()> {
        if let Some(program) = &self.program {
            if program.has_client_io() {
                let client_slot = u64::try_from(self.client_id).map_err(|_| {
                    Error::InvalidInput(format!(
                        "client id {} cannot be represented as a ClientStore slot",
                        self.client_id
                    ))
                })?;
                let client = program.client(client_slot).ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "program does not declare ClientStore metadata for client slot {client_slot}"
                    ))
                })?;
                if client.input_count() != input_count {
                    return Err(Error::InvalidInput(format!(
                        "client slot {client_slot} expects {} inputs, got {input_count}",
                        client.input_count()
                    )));
                }
                return Ok(());
            }
        }
        self.validate_function_inputs(name, input_count)
    }

    fn validate_function_inputs(&self, name: &str, input_count: usize) -> Result<()> {
        if let Some(program) = &self.program {
            let function = program
                .function(name)
                .ok_or_else(|| Error::FunctionNotFound(name.to_owned()))?;
            if function.arg_count() != input_count {
                return Err(Error::InvalidInput(format!(
                    "function '{name}' expects {} inputs, got {input_count}",
                    function.arg_count()
                )));
            }
        }
        Ok(())
    }
}

async fn run_offchain_inputs_with_config(
    config: &OffChainClientConfig,
    inputs: &[Value],
) -> Result<Vec<Value>> {
    match config.backend {
        MpcBackend::HoneyBadger => run_offchain_with_share::<RobustShare<Fr>>(config, inputs).await,
        MpcBackend::Avss {
            curve: Curve::Bls12_381,
        } => run_offchain_with_share::<FeldmanShamirShare<Fr, G1Projective>>(config, inputs).await,
        MpcBackend::Avss { curve } => Err(Error::Unsupported(format!(
            "off-chain client IO does not support AVSS curve {curve}"
        ))),
    }
}

async fn run_offchain_with_share<S>(
    config: &OffChainClientConfig,
    inputs: &[Value],
) -> Result<Vec<Value>>
where
    S: stoffel_mpc_coordinator::ShareBound<Fr, ValueType = Fr>,
{
    tokio::time::timeout(config.timeout, async {
        let coord = OffChainCoordinatorClient::<Fr, S>::start_rpc_client_with_parties(
            &config.coordinator_host,
            config.coordinator_port,
            config.timestamp,
            config.threshold as u64,
            config.parties as u64,
            config.output_count,
            config.cert_der.clone(),
            config.key_der.clone(),
        )
        .await?;
        let schema = coord.get_client_io_schema().await?;
        if schema.inputs.len() != inputs.len() {
            return Err(Error::InvalidInput(format!(
                "client slot {} expects {} inputs, got {}",
                schema.client_slot,
                schema.inputs.len(),
                inputs.len()
            )));
        }
        let reservations = coord.reserve_mask_indices(inputs.len() as u64).await?;
        let node_rpc = OffChainNodeRPCClient::<Fr, S>::start_rpc_client(
            config.threshold,
            config.node_rpc_endpoints()?,
            config.cert_der.clone(),
            config.key_der.clone(),
        )
        .await?;
        let masks = node_rpc.receive_typed_masks(inputs.len()).await?;
        let mut masked_inputs = Vec::with_capacity(inputs.len());
        for (ordinal, (input, share_type)) in inputs.iter().zip(schema.inputs.iter()).enumerate() {
            let reservation = reservations
                .iter()
                .find(|reservation| reservation.input_ordinal as usize == ordinal)
                .ok_or_else(|| {
                    Error::Coordinator(stoffel_mpc_coordinator::CoordinatorError::JSONError(
                        format!("missing typed mask reservation for input ordinal {ordinal}"),
                    ))
                })?;
            let (_, mask) = masks
                .iter()
                .find(|(metadata, _)| {
                    metadata.reserved_index == reservation.reserved_index
                        && metadata.input_ordinal == reservation.input_ordinal
                        && metadata.share_type == reservation.share_type
                })
                .ok_or_else(|| {
                    Error::Coordinator(stoffel_mpc_coordinator::CoordinatorError::JSONError(
                        format!("missing typed mask for input ordinal {ordinal}"),
                    ))
                })?;
            let clear = value_to_clear_share_value(input, *share_type)?;
            let field_input = encode_clear_input::<Fr>(*share_type, clear)?;
            masked_inputs.push(TypedMaskedInput {
                reserved_index: reservation.reserved_index,
                input_ordinal: reservation.input_ordinal,
                share_type: reservation.share_type,
                masked_input: ValueWrapper {
                    value: field_input + *mask,
                },
            });
        }
        coord.submit_masked_inputs(masked_inputs).await?;
        typed_outputs_to_values(coord.obtain_typed_outputs().await?)
    })
    .await
    .map_err(|_| {
        Error::NetworkConnection(format!(
            "off-chain client IO timed out after {:?}",
            config.timeout
        ))
    })?
}

fn value_to_clear_share_value(value: &Value, share_type: ShareType) -> Result<ClearShareValue> {
    match (share_type, value) {
        (ShareType::SecretInt { bit_length: 1 }, Value::Bool(value)) => {
            Ok(ClearShareValue::Boolean(*value))
        }
        (ShareType::SecretInt { bit_length: 1 }, Value::I64(value)) => {
            Ok(ClearShareValue::Boolean(*value != 0))
        }
        (ShareType::SecretInt { .. }, Value::I64(value)) => Ok(ClearShareValue::Integer(*value)),
        (ShareType::SecretInt { .. }, Value::U64(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                Error::InvalidInput("u64 secret integer input exceeds i64 range".to_owned())
            })?;
            Ok(ClearShareValue::Integer(value))
        }
        (ShareType::SecretFixedPoint { .. }, Value::Float(value)) => {
            Ok(ClearShareValue::FixedPoint(*value))
        }
        (ShareType::SecretFixedPoint { .. }, Value::I64(value)) => {
            Ok(ClearShareValue::Integer(*value))
        }
        (ShareType::SecretFixedPoint { .. }, Value::U64(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                Error::InvalidInput("u64 fixed-point input exceeds i64 range".to_owned())
            })?;
            Ok(ClearShareValue::Integer(value))
        }
        _ => Err(Error::InvalidInput(format!(
            "value kind '{}' is not compatible with share type {share_type:?}",
            value.kind()
        ))),
    }
}

fn typed_outputs_to_values(
    outputs: Vec<stoffel_mpc_coordinator::off_chain::TypedClearOutput>,
) -> Result<Vec<Value>> {
    let mut values = outputs
        .into_iter()
        .map(|output| {
            let value = match output.value {
                ClearShareValue::Integer(value) => Value::I64(value),
                ClearShareValue::Boolean(value) => Value::Bool(value),
                ClearShareValue::FixedPoint(value) => Value::Float(value),
            };
            Ok((output.output_ordinal, value))
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort_by_key(|(ordinal, _)| *ordinal);
    Ok(values.into_iter().map(|(_, value)| value).collect())
}

mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(
            duration
                .as_millis()
                .try_into()
                .map_err(|_| serde::ser::Error::custom("duration milliseconds exceed u64 range"))?,
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

#[derive(Debug, Clone)]
pub struct ComputationHandle {
    state: Arc<Mutex<ComputationState>>,
    notify: Arc<tokio::sync::Notify>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationSummary {
    pub status: ComputationStatus,
    pub has_result: bool,
    pub result_count: usize,
}

#[derive(Debug)]
struct ComputationState {
    status: ComputationStatus,
    result: Option<Result<Vec<Value>>>,
    awaitable: bool,
}

impl ComputationHandle {
    pub fn pending() -> Self {
        Self {
            state: Arc::new(Mutex::new(ComputationState {
                status: ComputationStatus::Pending,
                result: None,
                awaitable: false,
            })),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn submitted() -> Self {
        Self {
            state: Arc::new(Mutex::new(ComputationState {
                status: ComputationStatus::Pending,
                result: None,
                awaitable: true,
            })),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn completed(result: Vec<Value>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ComputationState {
                status: ComputationStatus::Completed,
                result: Some(Ok(result)),
                awaitable: true,
            })),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn await_result(self) -> Result<Vec<Value>> {
        loop {
            let result = {
                let state = self.state.lock().map_err(|_| {
                    Error::Computation("computation handle state lock was poisoned".to_owned())
                })?;
                match (state.status, state.result.as_ref()) {
                    (ComputationStatus::Cancelled, _) => Some(Err(Error::Computation(
                        "computation was cancelled".to_owned(),
                    ))),
                    (_, Some(Ok(result))) => Some(Ok(result.clone())),
                    (_, Some(Err(error))) => Some(Err(clone_error_for_handle(error))),
                    (ComputationStatus::Pending, None) if !state.awaitable => {
                        Some(Err(Error::Unsupported(
                            "computation has not been submitted to a live network".to_owned(),
                        )))
                    }
                    _ => None,
                }
            };
            if let Some(result) = result {
                return result;
            }
            self.notify.notified().await;
        }
    }

    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            if state.status == ComputationStatus::Pending {
                state.status = ComputationStatus::Cancelled;
                state.result = None;
                self.notify.notify_waiters();
            }
        }
    }

    pub(crate) fn complete(&self, result: Result<Vec<Value>>) {
        if let Ok(mut state) = self.state.lock() {
            if state.status == ComputationStatus::Pending {
                state.status = ComputationStatus::Completed;
                state.result = Some(result);
                self.notify.notify_waiters();
            }
        }
    }

    pub fn status(&self) -> ComputationStatus {
        self.state
            .lock()
            .map(|state| state.status)
            .unwrap_or(ComputationStatus::Cancelled)
    }

    pub fn summary(&self) -> ComputationSummary {
        self.state
            .lock()
            .map(|state| ComputationSummary {
                status: state.status,
                has_result: state.result.as_ref().is_some_and(|result| result.is_ok()),
                result_count: state
                    .result
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map_or(0, Vec::len),
            })
            .unwrap_or(ComputationSummary {
                status: ComputationStatus::Cancelled,
                has_result: false,
                result_count: 0,
            })
    }

    pub fn is_pending(&self) -> bool {
        self.status() == ComputationStatus::Pending
    }

    pub fn is_completed(&self) -> bool {
        self.status() == ComputationStatus::Completed
    }

    pub fn is_cancelled(&self) -> bool {
        self.status() == ComputationStatus::Cancelled
    }
}

fn clone_error_for_handle(error: &Error) -> Error {
    match error {
        Error::Compilation(message) => Error::Compilation(message.clone()),
        Error::Configuration(message) => Error::Configuration(message.clone()),
        Error::Network(error) => Error::NetworkConnection(error.to_string()),
        Error::NetworkConnection(message) => Error::NetworkConnection(message.clone()),
        Error::Consensus(error) => Error::Computation(error.to_string()),
        Error::Coordinator(error) => Error::Coordinator(error.clone()),
        Error::Preprocessing(message) => Error::Preprocessing(message.clone()),
        Error::Computation(message) => Error::Computation(message.clone()),
        Error::FunctionNotFound(name) => Error::FunctionNotFound(name.clone()),
        Error::InvalidInput(message) => Error::InvalidInput(message.clone()),
        Error::Unsupported(message) => Error::Unsupported(message.clone()),
        Error::Io(error) => Error::Io(std::io::Error::new(error.kind(), error.to_string())),
        Error::Bytecode(message) => Error::Bytecode(message.clone()),
        Error::ConfigParse(error) => Error::Configuration(error.to_string()),
        Error::ConfigSerialize(error) => Error::Configuration(error.to_string()),
    }
}
