//! Client-side builders and computation handles.
//!
//! The SDK validates client configuration and program input arity here. A
//! client reaches an execution only through the coordinator: it pins the
//! coordinator, associates, and submits and receives within its admission
//! (`docs/design/bootnode-elimination.md` §9.E), through the one client flow
//! `stoffel_vm_runner::coordinator_client` implements.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use stoffel_mpc_coordinator_off_chain::CoordinatorLink;
use stoffel_mpc_coordinator_shared::{
    AssociationRequest, ClientAdmission, ClientIndex, ExecutionId, NodeRoster, RosterDigest,
    SignedInvitation, SpkiDer,
};
use stoffel_vm::net::MpcBackendKind;
use stoffel_vm_runner::coordinator_client::{
    BindableSlots, CoordinatorClientConfig, CoordinatorClientError, CoordinatorEndpoint,
};
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::config::{validate_socket_address, Curve, MpcBackend};
use crate::consensus::VerifiedOrdering;
use crate::error::{Error, Result};
use crate::program::Program;
use crate::types::{
    ClientValueType, GeneratedProgramManifest, TypedClientInputs, TypedClientOutputs, Value,
};

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

/// Builds a [`StoffelClient`].
///
/// A client reaches an execution only through the coordinator
/// (`docs/design/bootnode-elimination.md` §9.E.3): it pins the coordinator,
/// associates with the execution, and uses exactly the slot, input range and
/// output rights its admission names. Its node addresses are
/// [`OffChainClientConfig::node_rpc_addresses`], each leg pinned to the
/// coordinator's node roster, and its slot is a request
/// ([`OffChainClientConfig::client_slot`]) the admission answers. There is no
/// direct mode dialing the node mesh: nodes allowlist node certificates only.
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    program: Option<Program>,
    verified_ordering: Option<VerifiedOrdering>,
    connection_timeout: Duration,
    offchain_io: Option<OffChainClientConfig>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            program: None,
            verified_ordering: None,
            connection_timeout: Duration::from_secs(10),
            offchain_io: None,
        }
    }

    pub fn with_program(mut self, program: Program) -> Self {
        self.program = Some(program);
        self
    }

    pub fn with_verified_ordering(mut self, ordering: VerifiedOrdering) -> Self {
        self.verified_ordering = Some(ordering);
        self
    }

    /// How long [`Self::connect`] waits for the pinned coordinator connection.
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn offchain_io(mut self, config: OffChainClientConfig) -> Self {
        self.offchain_io = Some(config);
        self
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

    pub fn build(self) -> Result<StoffelClient> {
        if self.connection_timeout.is_zero() {
            return Err(Error::Configuration(
                "client connection timeout must be greater than zero".to_owned(),
            ));
        }
        if let Some(config) = &self.offchain_io {
            config.validate()?;
        }
        Ok(StoffelClient {
            program: self.program,
            verified_ordering: self.verified_ordering,
            offchain_io: self.offchain_io,
            node_roster: None,
            session: ClientSession::default(),
            state: ClientState::Disconnected,
        })
    }

    /// Opens the pinned coordinator link (§9.E.1 step 1) and keeps the node
    /// roster it served. The link is used by this client's first run; nothing
    /// dials a node until then, and every node leg is pinned to that roster.
    #[tracing::instrument(skip_all)]
    pub async fn connect(self) -> Result<StoffelClient> {
        let connection_timeout = self.connection_timeout;
        let mut client = self.build()?;
        let config = client.offchain_io.as_ref().ok_or_else(|| {
            Error::Configuration(
                "a client connects through the coordinator: configure offchain_io(...)".to_owned(),
            )
        })?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let flow = config.coordinator_client_config()?;
        let link = tokio::time::timeout(connection_timeout, flow.connect())
            .await
            .map_err(|_| {
                Error::NetworkConnection(format!(
                    "timed out after {connection_timeout:?} connecting to the coordinator at {}:{}",
                    config.coordinator_host, config.coordinator_port
                ))
            })?
            .map_err(client_flow_error)?;
        client.node_roster = Some(link.node_roster().clone());
        *client.session.link.lock().await = Some(link);
        client.state = ClientState::Connected;
        Ok(client)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffChainClientConfig {
    pub coordinator_host: String,
    pub coordinator_port: u16,
    /// The coordinator's DER X.509 certificate. Every coordinator connection pins
    /// its key, and a server presenting any other key is refused with
    /// `CoordinatorError::ServerPinMismatch`
    /// (`docs/design/bootnode-elimination.md` §9.A).
    pub coordinator_cert_der: Vec<u8>,
    /// Which program invocation this client's inputs and outputs belong to.
    ///
    /// The coordinator keys every RPC on this, so it must match the
    /// `--execution-id` the servers were started with. There is no default: the
    /// reserved all-zero value is rejected, and guessing one would silently
    /// submit a secret input to somebody else's execution.
    pub execution_id: ExecutionId,
    /// The slot this client asks the coordinator to bind it to, sent as
    /// `AssociationRequest::slot` (`docs/design/bootnode-elimination.md`
    /// §9.C.4, §9.E.2).
    ///
    /// `None` asks for the lowest-numbered free slot under open admission, and
    /// for the invitation's slot under invitation admission. Under
    /// pre-registration a slot other than the one registered to this client's
    /// certificate is refused by the coordinator. Either way the slot, input
    /// range and output rights this client uses are the ones the coordinator's
    /// admission returns, never a layout this config computes.
    #[serde(default)]
    pub client_slot: Option<ClientIndex>,
    /// Presented when this client associates. Required under invitation
    /// admission, refused under any other.
    #[serde(default)]
    pub invitation: Option<SignedInvitation>,
    /// Refuse to associate with an execution registered for any other program
    /// (the coordinator's `program_hash_of`).
    #[serde(default)]
    pub expected_program_hash: Option<[u8; 32]>,
    /// Refuse a coordinator that serves any other node roster. The client's
    /// node legs are pinned to whatever roster it is served, so this is its
    /// defense when it knows the intended node set.
    #[serde(default)]
    pub expected_roster_digest: Option<RosterDigest>,
    pub backend: MpcBackend,
    /// Node RPC addresses. Hints only: every leg is pinned to a member of the
    /// coordinator's node roster.
    pub node_rpc_addresses: Vec<String>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub input_types: Vec<ShareType>,
    /// The types of the outputs this client decodes. An admission granting any
    /// other number of outputs is refused right after association.
    pub output_types: Vec<ShareType>,
    #[serde(with = "duration_millis")]
    pub timeout: Duration,
}

impl OffChainClientConfig {
    pub fn builder() -> OffChainClientConfigBuilder {
        OffChainClientConfigBuilder::default()
    }

    /// The slot this client will hold when it is settled before associating
    /// (`docs/design/bootnode-elimination.md` §9.E.1 step 2): the one
    /// [`Self::client_slot`] asks for, else the one [`Self::invitation`]
    /// names. `None` leaves the choice to the coordinator's association: the
    /// lowest free slot under open admission, or the slot registered to this
    /// client's certificate under pre-registration.
    pub fn settled_slot(&self) -> Option<ClientIndex> {
        self.client_slot.or_else(|| {
            self.invitation
                .as_ref()
                .map(|signed| signed.invitation.client_index)
        })
    }

    /// Checks what can be checked without the coordinator. The topology is the
    /// served roster's and is checked against the backend when the client
    /// associates (`Error::Unsupported` for a roster the backend cannot
    /// reconstruct at).
    pub fn validate(&self) -> Result<()> {
        if self.coordinator_host.trim().is_empty() {
            return Err(Error::Configuration(
                "off-chain coordinator host must not be empty".to_owned(),
            ));
        }
        if self.execution_id.is_zero() {
            return Err(Error::Configuration(
                "off-chain client execution ID must not be all zeros; the coordinator \
                 reserves that value and rejects it"
                    .to_owned(),
            ));
        }
        if let MpcBackend::Avss { curve } = self.backend {
            if curve != Curve::Bls12_381 {
                return Err(Error::Unsupported(
                    "off-chain client IO currently supports AVSS over bls12_381".to_owned(),
                ));
            }
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
        self.coordinator_spki()?;
        Ok(())
    }

    /// The pinned coordinator key, derived from `coordinator_cert_der`.
    fn coordinator_spki(&self) -> Result<SpkiDer> {
        if self.coordinator_cert_der.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires the coordinator certificate DER (coordinator_cert_der); every coordinator connection pins it"
                    .to_owned(),
            ));
        }
        SpkiDer::from_certificate_der(&self.coordinator_cert_der).map_err(|error| {
            Error::Configuration(format!(
                "off-chain coordinator certificate is not a usable DER X.509 certificate: {error}"
            ))
        })
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

    /// The §9.E.1 flow's view of this config.
    fn coordinator_client_config(&self) -> Result<CoordinatorClientConfig> {
        Ok(CoordinatorClientConfig {
            coordinator: CoordinatorEndpoint {
                host: self.coordinator_host.clone(),
                port: self.coordinator_port,
                pin: self.coordinator_spki()?,
            },
            execution_id: self.execution_id,
            backend: match self.backend {
                MpcBackend::HoneyBadger => MpcBackendKind::HoneyBadger,
                MpcBackend::Avss { .. } => MpcBackendKind::Avss,
            },
            cert_der: self.cert_der.clone(),
            key_der: self.key_der.clone(),
            node_rpc_addresses: self.node_rpc_endpoints()?,
            request: AssociationRequest {
                slot: self.client_slot,
                invitation: self.invitation.clone(),
            },
            expected_roster_digest: self.expected_roster_digest,
            expected_program_hash: self.expected_program_hash,
            expected_output_count: Some(self.output_types.len() as u64),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OffChainClientConfigBuilder {
    coordinator_host: String,
    coordinator_port: Option<u16>,
    coordinator_cert_der: Option<Vec<u8>>,
    execution_id: Option<ExecutionId>,
    client_slot: Option<ClientIndex>,
    invitation: Option<SignedInvitation>,
    expected_program_hash: Option<[u8; 32]>,
    expected_roster_digest: Option<RosterDigest>,
    backend: MpcBackend,
    node_rpc_addresses: Vec<String>,
    cert_der: Option<Vec<u8>>,
    key_der: Option<Vec<u8>>,
    input_types: Vec<ShareType>,
    output_types: Vec<ShareType>,
    timeout: Duration,
    config_error: Option<String>,
}

impl OffChainClientConfigBuilder {
    pub fn coordinator(mut self, host: impl Into<String>, port: u16) -> Self {
        self.coordinator_host = host.into();
        self.coordinator_port = Some(port);
        self
    }

    /// The coordinator's DER X.509 certificate, which every coordinator
    /// connection pins. Required.
    pub fn coordinator_cert_der(mut self, cert_der: Vec<u8>) -> Self {
        self.coordinator_cert_der = Some(cert_der);
        self
    }

    /// Reads the coordinator's DER X.509 certificate from `path`; see
    /// [`Self::coordinator_cert_der`].
    pub fn coordinator_cert_file(mut self, path: impl AsRef<Path>) -> Self {
        match std::fs::read(path) {
            Ok(cert_der) => self.coordinator_cert_der = Some(cert_der),
            Err(error) => self.config_error = Some(error.to_string()),
        }
        self
    }

    /// The program invocation these inputs belong to. Required: it must be the
    /// same value the servers were given as `--execution-id`.
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
                self.config_error = Some(format!("invalid off-chain execution ID: {error}"))
            }
        }
        self
    }

    /// Ask the coordinator for `client_slot` when associating; see
    /// [`OffChainClientConfig::client_slot`]. Without it the client takes the
    /// slot the coordinator's admission policy assigns.
    pub fn client_slot(mut self, client_slot: ClientIndex) -> Self {
        self.client_slot = Some(client_slot);
        self
    }

    /// The invitation presented when associating; see
    /// [`OffChainClientConfig::invitation`].
    pub fn invitation(mut self, invitation: SignedInvitation) -> Self {
        self.invitation = Some(invitation);
        self
    }

    /// Reads a signed invitation from `path`, as JSON (what `issue-invitation
    /// --out` writes).
    pub fn invitation_file(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<SignedInvitation>(&bytes) {
                Ok(invitation) => self.invitation = Some(invitation),
                Err(error) => {
                    self.config_error = Some(format!(
                        "{} is not a signed invitation: {error}",
                        path.display()
                    ))
                }
            },
            Err(error) => self.config_error = Some(error.to_string()),
        }
        self
    }

    /// Refuse to associate with an execution of any other program; see
    /// [`OffChainClientConfig::expected_program_hash`].
    pub fn expected_program_hash(mut self, program_hash: [u8; 32]) -> Self {
        self.expected_program_hash = Some(program_hash);
        self
    }

    /// Refuse a coordinator that serves any other node roster; see
    /// [`OffChainClientConfig::expected_roster_digest`].
    pub fn expected_roster_digest(mut self, digest: RosterDigest) -> Self {
        self.expected_roster_digest = Some(digest);
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
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

    pub fn input_types<I>(mut self, input_types: I) -> Self
    where
        I: IntoIterator<Item = ShareType>,
    {
        self.input_types = input_types.into_iter().collect();
        self
    }

    pub fn output_types<I>(mut self, output_types: I) -> Self
    where
        I: IntoIterator<Item = ShareType>,
    {
        self.output_types = output_types.into_iter().collect();
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
            // Checked last, by `validate`, so a configuration missing an earlier
            // field still names that field.
            coordinator_cert_der: self.coordinator_cert_der.unwrap_or_default(),
            execution_id: self.execution_id.ok_or_else(|| {
                Error::Configuration(
                    "off-chain execution ID is required; pass the same --execution-id the \
                     servers were started with"
                        .to_owned(),
                )
            })?,
            client_slot: self.client_slot,
            invitation: self.invitation,
            expected_program_hash: self.expected_program_hash,
            expected_roster_digest: self.expected_roster_digest,
            backend: self.backend,
            node_rpc_addresses: self.node_rpc_addresses,
            cert_der: self.cert_der.ok_or_else(|| {
                Error::Configuration("off-chain client certificate DER is required".to_owned())
            })?,
            key_der: self.key_der.ok_or_else(|| {
                Error::Configuration("off-chain client key DER is required".to_owned())
            })?,
            input_types: self.input_types,
            output_types: self.output_types,
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
            coordinator_cert_der: None,
            execution_id: None,
            client_slot: None,
            invitation: None,
            expected_program_hash: None,
            expected_roster_digest: None,
            backend: MpcBackend::HoneyBadger,
            node_rpc_addresses: Vec::new(),
            cert_der: None,
            key_der: None,
            input_types: Vec::new(),
            output_types: Vec::new(),
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

/// A client's coordinator link, opened by [`ClientBuilder::connect`] and taken
/// by its first run, and the admission that run was given. Shared by clones so
/// a submission's background task records the admission where the client that
/// submitted it can read it.
#[derive(Clone, Default)]
struct ClientSession {
    link: Arc<tokio::sync::Mutex<Option<CoordinatorLink>>>,
    admission: Arc<Mutex<Option<ClientAdmission>>>,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSession")
            .field("admission", &self.admission())
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    fn admission(&self) -> Option<ClientAdmission> {
        self.admission
            .lock()
            .map(|admission| admission.clone())
            .unwrap_or(None)
    }

    /// §9.E.1 over the link [`ClientBuilder::connect`] opened, or a new one,
    /// checking `slot_check` against the slot the association binds before any
    /// input is sent.
    async fn run(
        &self,
        config: &OffChainClientConfig,
        inputs: &[Value],
        slot_check: &SlotCheck,
    ) -> Result<Vec<Value>> {
        let link = self.link.lock().await.take();
        let (outputs, admission) =
            run_offchain_inputs_with_config(config, link, inputs, slot_check).await?;
        if let Ok(mut slot) = self.admission.lock() {
            *slot = Some(admission);
        }
        Ok(outputs)
    }
}

#[derive(Debug, Clone)]
pub struct StoffelClient {
    program: Option<Program>,
    verified_ordering: Option<VerifiedOrdering>,
    offchain_io: Option<OffChainClientConfig>,
    /// The node roster the pinned coordinator served at [`ClientBuilder::connect`].
    node_roster: Option<NodeRoster>,
    session: ClientSession,
    state: ClientState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSummary {
    /// The coordinator's roster size `n`, once connected.
    pub node_count: Option<u64>,
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

    #[tracing::instrument(skip_all)]
    pub async fn disconnect(self) -> Result<()> {
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(input_count = inputs.len()))]
    pub async fn run<V>(&self, inputs: &[V]) -> Result<Vec<Value>>
    where
        V: Clone + Into<Value>,
    {
        self.run_function("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(function = name, input_count = inputs.len()))]
    pub async fn run_function<V>(&self, name: &str, inputs: &[V]) -> Result<Vec<Value>>
    where
        V: Clone + Into<Value>,
    {
        let inputs = inputs
            .iter()
            .map(|value| value.clone().into())
            .collect::<Vec<Value>>();
        let slot_check =
            self.prepare_slot_check(name, None, SubmittedInputs::Count(inputs.len()), None)?;
        self.run_offchain_inputs(&inputs, &slot_check).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn run_typed<I, O>(&self, inputs: I) -> Result<O>
    where
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        self.run_function_typed("main", inputs).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn run_typed_with_manifest<M, I, O>(&self, inputs: I) -> Result<O>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        self.run_function_typed_with_manifest::<M, I, O>("main", inputs)
            .await
    }

    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn run_function_typed<I, O>(&self, name: &str, inputs: I) -> Result<O>
    where
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        let slot_check = self.prepare_slot_check(
            name,
            None,
            SubmittedInputs::Typed(I::value_types()),
            Some(O::value_types()),
        )?;
        let outputs = self
            .run_offchain_inputs(&inputs.into_values(), &slot_check)
            .await?;
        O::from_values(outputs)
    }

    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn run_function_typed_with_manifest<M, I, O>(
        &self,
        name: &str,
        inputs: I,
    ) -> Result<O>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        let slot_check = self.prepare_slot_check(
            name,
            Some(ManifestSlots::of::<M>()),
            SubmittedInputs::Typed(I::value_types()),
            Some(O::value_types()),
        )?;
        self.validate_generated_backend::<M>()?;
        let outputs = self
            .run_offchain_inputs(&inputs.into_values(), &slot_check)
            .await?;
        O::from_values(outputs)
    }

    #[tracing::instrument(skip_all, fields(input_count = inputs.len()))]
    pub async fn submit<V>(&self, inputs: &[V]) -> Result<ComputationHandle>
    where
        V: Clone + Into<Value>,
    {
        self.submit_function("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(function = name, input_count = inputs.len()))]
    pub async fn submit_function<V>(&self, name: &str, inputs: &[V]) -> Result<ComputationHandle>
    where
        V: Clone + Into<Value>,
    {
        let inputs = inputs
            .iter()
            .map(|value| value.clone().into())
            .collect::<Vec<Value>>();
        let slot_check =
            self.prepare_slot_check(name, None, SubmittedInputs::Count(inputs.len()), None)?;
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        let session = self.session.clone();
        tokio::spawn(async move {
            let result = session.run(&config, &inputs, &slot_check).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all)]
    pub async fn submit_typed<I>(&self, inputs: I) -> Result<ComputationHandle>
    where
        I: TypedClientInputs,
    {
        self.submit_function_typed("main", inputs).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn submit_typed_with_manifest<M, I>(&self, inputs: I) -> Result<ComputationHandle>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
    {
        self.submit_function_typed_with_manifest::<M, I>("main", inputs)
            .await
    }

    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn submit_function_typed<I>(&self, name: &str, inputs: I) -> Result<ComputationHandle>
    where
        I: TypedClientInputs,
    {
        let slot_check =
            self.prepare_slot_check(name, None, SubmittedInputs::Typed(I::value_types()), None)?;
        let inputs = inputs.into_values();
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        let session = self.session.clone();
        tokio::spawn(async move {
            let result = session.run(&config, &inputs, &slot_check).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn submit_function_typed_with_manifest<M, I>(
        &self,
        name: &str,
        inputs: I,
    ) -> Result<ComputationHandle>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
    {
        let slot_check = self.prepare_slot_check(
            name,
            Some(ManifestSlots::of::<M>()),
            SubmittedInputs::Typed(I::value_types()),
            None,
        )?;
        self.validate_generated_backend::<M>()?;
        let inputs = inputs.into_values();
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        let session = self.session.clone();
        tokio::spawn(async move {
            let result = session.run(&config, &inputs, &slot_check).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all)]
    pub async fn verify_ordering(&self) -> Result<VerifiedOrdering> {
        if let Some(ordering) = &self.verified_ordering {
            return Ok(ordering.clone());
        }
        Err(Error::Unsupported(
            "a client has no node transport to verify an ordering over; attach one with \
             ClientBuilder::with_verified_ordering"
                .to_owned(),
        ))
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn summary(&self) -> ClientSummary {
        ClientSummary {
            node_count: self.node_roster.as_ref().map(NodeRoster::n),
            has_program: self.has_program(),
            has_verified_ordering: self.verified_ordering.is_some(),
            has_offchain_io: self.offchain_io.is_some(),
            connected: self.is_connected(),
            state: self.state,
        }
    }

    pub fn program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    /// The node roster the pinned coordinator served at
    /// [`ClientBuilder::connect`]: the nodes every node RPC leg is pinned to.
    pub fn node_roster(&self) -> Option<&NodeRoster> {
        self.node_roster.as_ref()
    }

    /// The slot, input range and output rights the coordinator admitted this
    /// client to, once a run has associated.
    pub fn admission(&self) -> Option<ClientAdmission> {
        self.session.admission()
    }

    pub fn offchain_io(&self) -> Option<&OffChainClientConfig> {
        self.offchain_io.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected && self.node_roster.is_some()
    }

    pub fn has_program(&self) -> bool {
        self.program.is_some()
    }

    async fn run_offchain_inputs(
        &self,
        inputs: &[Value],
        slot_check: &SlotCheck,
    ) -> Result<Vec<Value>> {
        let config = self.offchain_io.as_ref().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        self.session.run(config, inputs, slot_check).await
    }

    /// What a run checks of the client slot it will hold, checked now as far
    /// as the slot is known before connecting, and returned so the run checks
    /// it against every slot the execution's summary says the association can
    /// bind (§9.E.1 step 2) and again against the slot it bound.
    ///
    /// When [`OffChainClientConfig::settled_slot`] names the slot, the inputs
    /// and outputs are checked against that slot. Otherwise the coordinator
    /// binds the slot, and a submission no slot of the program accepts is
    /// refused here, before anything is sent: under open admission every slot
    /// must accept it, under pre-registration the registered one.
    fn prepare_slot_check(
        &self,
        name: &str,
        manifest: Option<ManifestSlots>,
        inputs: SubmittedInputs,
        outputs: Option<Vec<ClientValueType>>,
    ) -> Result<SlotCheck> {
        let program = self
            .program
            .as_ref()
            .filter(|program| program.has_client_io())
            .cloned();
        let check = SlotCheck {
            program,
            manifest,
            inputs,
            outputs,
        };
        match self
            .offchain_io
            .as_ref()
            .and_then(OffChainClientConfig::settled_slot)
        {
            Some(slot) => check.check(u64::from(slot.0))?,
            None => check.check_some_declared_slot()?,
        }
        if check.program.is_none() {
            self.validate_function_inputs(name, check.inputs.len())?;
        }
        Ok(check)
    }

    fn validate_generated_backend<M: GeneratedProgramManifest>(&self) -> Result<()> {
        if let Some(program) = &self.program {
            let program_backend = sdk_backend_from_program(program);
            if program_backend != M::BACKEND {
                return Err(Error::InvalidInput(format!(
                    "generated manifest backend {} does not match loaded program backend {}",
                    M::BACKEND,
                    program_backend
                )));
            }
        }
        Ok(())
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

/// The inputs a run submits, as its [`SlotCheck`] sees them.
#[derive(Debug, Clone)]
enum SubmittedInputs {
    /// Untyped values: only their number is checked.
    Count(usize),
    /// Typed values, checked against the slot's share types.
    Typed(Vec<ClientValueType>),
}

impl SubmittedInputs {
    fn len(&self) -> usize {
        match self {
            Self::Count(count) => *count,
            Self::Typed(types) => types.len(),
        }
    }
}

/// A generated manifest's per-slot types, as function pointers so that a
/// background submission can carry them.
#[derive(Clone, Copy)]
struct ManifestSlots {
    input_types: fn(u64) -> Option<&'static [ClientValueType]>,
    output_types: fn(u64) -> Option<&'static [ClientValueType]>,
}

impl ManifestSlots {
    fn of<M: GeneratedProgramManifest>() -> Self {
        Self {
            input_types: M::client_input_types,
            output_types: M::client_output_types,
        }
    }
}

/// What one run checks of the client slot it holds.
///
/// The slot is settled before associating only when the config asks for one or
/// its invitation names one (§9.E.1 step 2). Otherwise the coordinator binds
/// it — the lowest free slot under open admission, the registered slot under
/// pre-registration. An association is irrevocable, so the run checks every
/// slot the execution's summary says it can bind before associating
/// ([`Self::check_bindable`]), and the slot it bound right after association,
/// before any input is sent.
#[derive(Clone)]
struct SlotCheck {
    /// The program, when it declares client IO.
    program: Option<Program>,
    manifest: Option<ManifestSlots>,
    inputs: SubmittedInputs,
    /// The typed outputs this run decodes, when it decodes typed outputs.
    outputs: Option<Vec<ClientValueType>>,
}

impl SlotCheck {
    fn check(&self, client_slot: u64) -> Result<()> {
        if let Some(manifest) = self.manifest {
            let undeclared = || {
                Error::InvalidInput(format!(
                    "generated manifest does not declare client slot {client_slot}"
                ))
            };
            let expected_inputs = (manifest.input_types)(client_slot).ok_or_else(undeclared)?;
            let expected_outputs = match self.outputs {
                Some(_) => Some((manifest.output_types)(client_slot).ok_or_else(undeclared)?),
                None => None,
            };
            if let SubmittedInputs::Typed(input_types) = &self.inputs {
                validate_client_value_types_from_values(
                    "input",
                    client_slot,
                    expected_inputs,
                    input_types,
                )?;
            }
            if let (Some(expected_outputs), Some(output_types)) = (expected_outputs, &self.outputs)
            {
                validate_client_value_types_from_values(
                    "output",
                    client_slot,
                    expected_outputs,
                    output_types,
                )?;
            }
        }
        if let Some(program) = &self.program {
            let client = program.client(client_slot).ok_or_else(|| {
                Error::InvalidInput(format!(
                    "program does not declare ClientStore metadata for client slot {client_slot}"
                ))
            })?;
            match &self.inputs {
                SubmittedInputs::Count(input_count) => {
                    if client.input_count() != *input_count {
                        return Err(Error::InvalidInput(format!(
                            "client slot {client_slot} expects {} inputs, got {input_count}",
                            client.input_count()
                        )));
                    }
                }
                SubmittedInputs::Typed(input_types) => {
                    validate_client_value_types("input", client_slot, client.inputs(), input_types)?
                }
            }
            if let Some(output_types) = &self.outputs {
                validate_client_value_types("output", client_slot, client.outputs(), output_types)?;
            }
        }
        Ok(())
    }

    /// Before connecting without a settled slot: refuses a submission that no
    /// slot the program declares accepts, which no admission policy can bind
    /// to an accepting slot. Without a program there is nothing to enumerate
    /// yet; the execution's summary names the slots, and
    /// [`Self::check_bindable`] probes each of them before associating.
    fn check_some_declared_slot(&self) -> Result<()> {
        let Some(program) = &self.program else {
            return Ok(());
        };
        let mut refusals = Vec::new();
        for client_slot in program.client_slots() {
            match self.check(client_slot) {
                Ok(()) => return Ok(()),
                Err(refusal) => refusals.push(refusal),
            }
        }
        if refusals.len() <= 1 {
            return refusals.pop().map_or(Ok(()), Err);
        }
        Err(Error::InvalidInput(format!(
            "no client slot of this program accepts this submission, and none was requested: {}",
            refusals
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )))
    }

    /// Before associating, once the execution's summary names the slots the
    /// association can bind (§9.E.1 step 2): every one of them must accept this
    /// submission, since the client cannot choose among them and cannot take an
    /// association back. Under pre-registration the summary does not name the
    /// registered slot, and it is checked on the admission.
    fn check_bindable(&self, slots: &BindableSlots) -> Result<()> {
        match slots {
            BindableSlots::Settled(slot) => self.check(u64::from(slot.0)),
            BindableSlots::AnyOf(slots) => {
                for slot in slots {
                    self.check(u64::from(slot.0)).map_err(|refusal| {
                        Error::InvalidInput(format!(
                            "under open admission a client that asks for no slot is bound to \
                             the lowest free of client slots {}, and an association cannot be \
                             taken back, so every one of them must accept this submission, but \
                             {refusal}; set client_slot to the slot this submission is for",
                            slots
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    })?;
                }
                Ok(())
            }
            BindableSlots::Registered | BindableSlots::Nothing => Ok(()),
        }
    }
}

fn validate_client_value_types(
    direction: &str,
    client_slot: u64,
    share_types: &[ShareType],
    value_types: &[ClientValueType],
) -> Result<()> {
    if share_types.len() != value_types.len() {
        return Err(Error::InvalidInput(format!(
            "client slot {client_slot} expects {} typed {direction}s, got {}",
            share_types.len(),
            value_types.len()
        )));
    }
    for (ordinal, (share_type, value_type)) in share_types.iter().zip(value_types).enumerate() {
        if !value_type.is_compatible_with_share_type(*share_type) {
            return Err(Error::InvalidInput(format!(
                "client slot {client_slot} {direction} {ordinal} expects {share_type:?}, got {value_type:?}"
            )));
        }
    }
    Ok(())
}

fn validate_client_value_types_from_values(
    direction: &str,
    client_slot: u64,
    expected: &[ClientValueType],
    actual: &[ClientValueType],
) -> Result<()> {
    if expected.len() != actual.len() {
        return Err(Error::InvalidInput(format!(
            "generated manifest client slot {client_slot} expects {} typed {direction}s, got {}",
            expected.len(),
            actual.len()
        )));
    }
    for (ordinal, (expected_type, actual_type)) in expected.iter().zip(actual).enumerate() {
        if expected_type != actual_type {
            return Err(Error::InvalidInput(format!(
                "generated manifest client slot {client_slot} {direction} {ordinal} expects {expected_type:?}, got {actual_type:?}"
            )));
        }
    }
    Ok(())
}

fn sdk_backend_from_program(program: &Program) -> MpcBackend {
    match program.bytecode_backend() {
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger => MpcBackend::HoneyBadger,
        stoffel_vm_types::compiled_binary::MpcBackend::Avss => MpcBackend::Avss {
            curve: match program.bytecode_curve() {
                stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => Curve::Bls12_381,
                stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => Curve::Bn254,
                stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => Curve::Curve25519,
                stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => Curve::Ed25519,
                stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => Curve::Secp256k1,
                stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => Curve::Secp256r1,
            },
        },
    }
}

/// §9.E.1 for one run (`stoffel_vm_runner::coordinator_client`), over `link`
/// when [`ClientBuilder::connect`] opened one. Returns the outputs and the
/// admission the run was given.
async fn run_offchain_inputs_with_config(
    config: &OffChainClientConfig,
    link: Option<CoordinatorLink>,
    inputs: &[Value],
    slot_check: &SlotCheck,
) -> Result<(Vec<Value>, ClientAdmission)> {
    match config.backend {
        MpcBackend::HoneyBadger => {
            run_offchain_with_share::<RobustShare<Fr>>(config, link, inputs, slot_check).await
        }
        MpcBackend::Avss {
            curve: Curve::Bls12_381,
        } => {
            run_offchain_with_share::<FeldmanShamirShare<Fr, G1Projective>>(
                config, link, inputs, slot_check,
            )
            .await
        }
        MpcBackend::Avss { curve } => Err(Error::Unsupported(format!(
            "off-chain client IO does not support AVSS curve {curve}"
        ))),
    }
}

async fn run_offchain_with_share<S>(
    config: &OffChainClientConfig,
    link: Option<CoordinatorLink>,
    inputs: &[Value],
    slot_check: &SlotCheck,
) -> Result<(Vec<Value>, ClientAdmission)>
where
    S: stoffel_mpc_coordinator_shared::ShareBound<Fr, ValueType = Fr>,
{
    if config.input_types.len() != inputs.len() {
        return Err(Error::InvalidInput(format!(
            "off-chain client config {} has {} input type(s), got {} input value(s)",
            requested_slot_description(config.client_slot),
            config.input_types.len(),
            inputs.len()
        )));
    }
    let field_inputs = inputs
        .iter()
        .zip(config.input_types.iter())
        .map(|(input, share_type)| value_to_field(input, *share_type))
        .collect::<Result<Vec<_>>>()?;
    let flow = config.coordinator_client_config()?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let run = tokio::time::timeout(config.timeout, async {
        let link = match link {
            Some(link) => link,
            None => flow.connect().await.map_err(client_flow_error)?,
        };
        let pending = flow
            .inspect::<Fr, S>(link, field_inputs.len() as u64)
            .await
            .map_err(client_flow_error)?;
        // An association is irrevocable (§9.E.1 step 2): every slot it can
        // bind must accept this submission before it is made.
        slot_check.check_bindable(&pending.bindable_slots())?;
        let admitted = pending.associate().await.map_err(client_flow_error)?;
        // Under pre-registration only the admission names the slot. Wherever
        // the summary settled it, this repeats the check above for the slot
        // the coordinator actually bound. Nothing has reached a node yet.
        slot_check.check(u64::from(admitted.admission().client_index.0))?;
        admitted
            .complete(field_inputs)
            .await
            .map_err(client_flow_error)
    })
    .await
    .map_err(|_| {
        Error::NetworkConnection(format!(
            "off-chain client IO timed out after {:?}",
            config.timeout
        ))
    })??;
    let outputs = outputs_to_values(run.outputs, &config.output_types)?;
    Ok((outputs, run.admission))
}

/// How the SDK reports a §9.E.1 refusal: a roster the backend cannot
/// reconstruct at is `Unsupported`, everything this client refuses of what it
/// was asked to join is `Configuration`, and whatever the coordinator or a node
/// did is `Coordinator`.
fn client_flow_error(error: CoordinatorClientError) -> Error {
    match error {
        error @ CoordinatorClientError::TopologyUnsupported { .. } => {
            Error::Unsupported(error.to_string())
        }
        CoordinatorClientError::InputCountMismatch {
            client_index,
            count,
            given,
        } => Error::Configuration(format!(
            "client slot {client_index} takes {count} inputs, but this client has {given} input value(s)"
        )),
        CoordinatorClientError::SlotShapesDiffer { execution_id } => {
            Error::Configuration(format!(
                "execution {execution_id} has client slots of different shapes; request one with \
                 OffChainClientConfigBuilder::client_slot"
            ))
        }
        error @ (CoordinatorClientError::ProgramMismatch { .. }
        | CoordinatorClientError::SealedOutputsTooLarge { .. }
        | CoordinatorClientError::NoSuchSlot { .. }
        | CoordinatorClientError::OutputCountMismatch { .. }
        | CoordinatorClientError::SlotNotGranted { .. }
        | CoordinatorClientError::WrongExecution { .. }
        | CoordinatorClientError::SlotTable { .. }) => Error::Configuration(error.to_string()),
        CoordinatorClientError::Connect(error)
        | CoordinatorClientError::Association(error)
        | CoordinatorClientError::NodeRpc(error)
        | CoordinatorClientError::Coordinator(error) => Error::Coordinator(error),
    }
}

/// How an error message names the slot a client asked for.
fn requested_slot_description(client_slot: Option<ClientIndex>) -> String {
    match client_slot {
        Some(slot) => format!("for client slot {slot}"),
        None => "without a requested client slot".to_owned(),
    }
}

fn value_to_field(value: &Value, share_type: ShareType) -> Result<Fr> {
    match (share_type, value) {
        (ShareType::SecretInt { bit_length: 1 }, Value::Bool(value)) => Ok(Fr::from(*value as u64)),
        (ShareType::SecretInt { bit_length: 1 }, Value::I64(value)) => {
            Ok(Fr::from((*value != 0) as u64))
        }
        (ShareType::SecretInt { .. }, Value::I64(value)) => Ok(i64_to_field(*value)),
        (ShareType::SecretInt { .. }, Value::U64(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                Error::InvalidInput("u64 secret integer input exceeds i64 range".to_owned())
            })?;
            Ok(i64_to_field(value))
        }
        (ShareType::SecretUInt { bit_length }, Value::U64(value)) => {
            validate_secret_uint_range(*value, bit_length)?;
            Ok(Fr::from(*value))
        }
        (ShareType::SecretUInt { bit_length }, Value::I64(value)) => {
            let value = u64::try_from(*value).map_err(|_| {
                Error::InvalidInput(
                    "signed input for secret unsigned integer must be non-negative".to_owned(),
                )
            })?;
            validate_secret_uint_range(value, bit_length)?;
            Ok(Fr::from(value))
        }
        (ShareType::SecretFixedPoint { .. }, Value::Float(value)) => {
            encode_fixed_point(*value, share_type)
        }
        (ShareType::SecretFixedPoint { .. }, Value::I64(value)) => {
            encode_fixed_point(*value as f64, share_type)
        }
        (ShareType::SecretFixedPoint { .. }, Value::U64(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                Error::InvalidInput("u64 fixed-point input exceeds i64 range".to_owned())
            })?;
            encode_fixed_point(value as f64, share_type)
        }
        _ => Err(Error::InvalidInput(format!(
            "value kind '{}' is not compatible with share type {share_type:?}",
            value.kind()
        ))),
    }
}

fn validate_secret_uint_range(value: u64, bit_length: usize) -> Result<()> {
    if bit_length >= 64 {
        return Ok(());
    }
    let max = (1u64 << bit_length) - 1;
    if value <= max {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "secret unsigned integer input {value} does not fit in {bit_length} bit(s)"
        )))
    }
}

fn encode_fixed_point(value: f64, share_type: ShareType) -> Result<Fr> {
    let ShareType::SecretFixedPoint { precision } = share_type else {
        return Err(Error::InvalidInput(format!(
            "cannot encode fixed-point value with share type {share_type:?}"
        )));
    };
    let scale = 2f64.powi(precision.fractional_bits() as i32);
    Ok(i64_to_field((value * scale).round() as i64))
}

fn i64_to_field(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

fn field_to_i64(value: Fr) -> Result<i64> {
    let positive = value.into_bigint();
    if positive.as_ref()[1..].iter().all(|limb| *limb == 0)
        && positive.as_ref()[0] <= i64::MAX as u64
    {
        return Ok(positive.as_ref()[0] as i64);
    }

    let negative = (-value).into_bigint();
    if negative.as_ref()[1..].iter().all(|limb| *limb == 0)
        && negative.as_ref()[0] <= i64::MAX as u64 + 1
    {
        let magnitude = negative.as_ref()[0];
        return if magnitude == (i64::MAX as u64 + 1) {
            Ok(i64::MIN)
        } else {
            Ok(-(magnitude as i64))
        };
    }

    Err(Error::InvalidInput(
        "field output cannot be represented as i64".to_owned(),
    ))
}

fn field_to_u64(value: Fr, bit_length: usize) -> Result<u64> {
    let positive = value.into_bigint();
    if positive.as_ref()[1..].iter().all(|limb| *limb == 0) {
        let value = positive.as_ref()[0];
        validate_secret_uint_range(value, bit_length)?;
        return Ok(value);
    }

    Err(Error::InvalidInput(
        "field output cannot be represented as u64".to_owned(),
    ))
}

fn field_to_value(value: Fr, share_type: ShareType) -> Result<Value> {
    match share_type {
        ShareType::SecretInt { bit_length: 1 } => Ok(Value::Bool(!value.is_zero())),
        ShareType::SecretInt { .. } => Ok(Value::I64(field_to_i64(value)?)),
        ShareType::SecretUInt { bit_length } => Ok(Value::U64(field_to_u64(value, bit_length)?)),
        ShareType::SecretFixedPoint { precision } => {
            let scaled = field_to_i64(value)?;
            let scale = 2f64.powi(precision.fractional_bits() as i32);
            Ok(Value::Float(scaled as f64 / scale))
        }
    }
}

fn outputs_to_values(outputs: Vec<Fr>, output_types: &[ShareType]) -> Result<Vec<Value>> {
    if outputs.len() != output_types.len() {
        return Err(Error::InvalidInput(format!(
            "expected {} outputs, got {}",
            output_types.len(),
            outputs.len()
        )));
    }
    outputs
        .into_iter()
        .zip(output_types.iter().copied())
        .map(|(output, share_type)| field_to_value(output, share_type))
        .collect()
}

#[allow(dead_code)]
fn bound_outputs_to_values(
    outputs: Vec<(u64, Fr)>,
    output_types: &[ShareType],
) -> Result<Vec<Value>> {
    if outputs.len() != output_types.len() {
        return Err(Error::InvalidInput(format!(
            "expected {} assigned outputs, got {}",
            output_types.len(),
            outputs.len()
        )));
    }
    let mut values = outputs
        .into_iter()
        .map(|(output_ordinal, share)| {
            let share_type = output_types
                .get(output_ordinal as usize)
                .copied()
                .ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "assigned output ordinal {} is out of range",
                        output_ordinal
                    ))
                })?;
            let value = field_to_value(share, share_type)?;
            Ok((output_ordinal, value))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_uint_values_encode_and_decode_as_unsigned() -> Result<()> {
        let share_type = ShareType::secret_uint(8);
        let field = value_to_field(&Value::U64(255), share_type)?;
        assert_eq!(field_to_value(field, share_type)?, Value::U64(255));
        Ok(())
    }

    #[test]
    fn secret_uint_encoding_rejects_negative_or_out_of_range_values() {
        let share_type = ShareType::secret_uint(8);

        assert!(value_to_field(&Value::I64(-1), share_type).is_err());
        assert!(value_to_field(&Value::U64(256), share_type).is_err());
    }

    /// Slot 0 takes one input, slot 1 two.
    fn two_shaped_slot_program() -> Result<Program> {
        crate::compiler::compile_source(
            r#"
def main() -> int64:
  var first = ClientStore.take_share(0, 0)
  var second = ClientStore.take_share(1, 0)
  var third = ClientStore.take_share(1, 1)
  var difference = first - second - third
  return difference.open()
"#,
            "two_shaped_slots.stfl",
            MpcBackend::HoneyBadger,
        )
    }

    /// The check a run makes right after association, when the coordinator
    /// bound the slot: the same submission is accepted for one admitted slot
    /// and refused for the other, before any input is sent.
    #[test]
    fn a_slot_check_follows_the_slot_the_association_binds() -> Result<()> {
        let check = SlotCheck {
            program: Some(two_shaped_slot_program()?),
            manifest: None,
            inputs: SubmittedInputs::Count(2),
            outputs: None,
        };
        check.check_some_declared_slot()?;
        check.check(1)?;
        let refused = check.check(0).unwrap_err();
        assert!(
            matches!(&refused, Error::InvalidInput(message)
                if message.contains("client slot 0 expects 1 inputs, got 2")),
            "{refused}"
        );
        Ok(())
    }

    struct SlotOneManifest;

    impl GeneratedProgramManifest for SlotOneManifest {
        const BACKEND: MpcBackend = MpcBackend::HoneyBadger;

        fn client_input_types(client_slot: u64) -> Option<&'static [ClientValueType]> {
            (client_slot == 1).then_some(&[ClientValueType::Integer, ClientValueType::Integer])
        }

        fn client_output_types(client_slot: u64) -> Option<&'static [ClientValueType]> {
            (client_slot == 1).then_some(&[])
        }
    }

    /// A manifest cannot list its slots, so without a program nothing is
    /// refused before connecting. The execution's summary names the slots the
    /// association can bind, and each is probed through the manifest before
    /// associating; under pre-registration the admitted slot is checked after.
    #[test]
    fn a_manifest_only_slot_check_probes_every_slot_the_summary_names() {
        let check = SlotCheck {
            program: None,
            manifest: Some(ManifestSlots::of::<SlotOneManifest>()),
            inputs: SubmittedInputs::Typed(vec![ClientValueType::Integer; 2]),
            outputs: Some(Vec::new()),
        };
        assert!(check.check_some_declared_slot().is_ok());
        assert!(check.check(1).is_ok());
        assert!(matches!(check.check(0), Err(Error::InvalidInput(message))
            if message.contains("generated manifest does not declare client slot 0")));

        // Open admission, no slot requested: slot 0 could be bound, and the
        // manifest declares no slot 0, so the run never associates.
        let refused = check
            .check_bindable(&BindableSlots::AnyOf(vec![ClientIndex(0), ClientIndex(1)]))
            .unwrap_err();
        assert!(
            matches!(&refused, Error::InvalidInput(message)
                if message.contains("lowest free of client slots 0, 1")
                    && message.contains("generated manifest does not declare client slot 0")),
            "{refused}"
        );
        assert!(check
            .check_bindable(&BindableSlots::AnyOf(vec![ClientIndex(1)]))
            .is_ok());
        assert!(check
            .check_bindable(&BindableSlots::Settled(ClientIndex(1)))
            .is_ok());
        assert!(check.check_bindable(&BindableSlots::Registered).is_ok());
    }

    /// Slot 0 takes one boolean, slot 1 one integer: the same count, different
    /// types.
    fn same_count_different_types_program() -> Result<Program> {
        crate::compiler::compile_source(
            r#"
def main() -> int64:
  var flag = ClientStore.take_share_bool(0, 0)
  var amount = ClientStore.take_share(1, 0)
  var opened_flag = flag.open()
  var opened: int64 = amount.open()
  return opened
"#,
            "same_count_different_types.stfl",
            MpcBackend::HoneyBadger,
        )
    }

    /// Under open admission without a requested slot the coordinator binds
    /// the lowest free slot, and an association cannot be taken back
    /// (§9.E.1 step 2). A submission some slot accepts is therefore still
    /// refused before associating unless every slot the summary names accepts
    /// it: associating to slot 0 and then refusing it would hold slot 0 until
    /// the association deadline aborted the execution for everyone.
    #[test]
    fn an_open_association_is_made_only_when_every_bindable_slot_accepts() -> Result<()> {
        let check = SlotCheck {
            program: Some(same_count_different_types_program()?),
            manifest: None,
            inputs: SubmittedInputs::Typed(vec![ClientValueType::Integer]),
            outputs: None,
        };
        // Slot 1 takes an integer, so the submission passes before connecting.
        check.check_some_declared_slot()?;
        check.check(1)?;

        let refused = check
            .check_bindable(&BindableSlots::AnyOf(vec![ClientIndex(0), ClientIndex(1)]))
            .unwrap_err();
        assert!(
            matches!(&refused, Error::InvalidInput(message)
                if message.contains("lowest free of client slots 0, 1")
                    && message.contains("client slot 0 input 0 expects SecretInt { bit_length: 1 }")
                    && message.contains("set client_slot")),
            "{refused}"
        );
        // A requested slot, or the invitation's, is bound exactly.
        check.check_bindable(&BindableSlots::Settled(ClientIndex(1)))?;
        assert!(check
            .check_bindable(&BindableSlots::Settled(ClientIndex(0)))
            .is_err());
        // Under pre-registration the registered slot is checked on the admission.
        check.check_bindable(&BindableSlots::Registered)?;
        check.check_bindable(&BindableSlots::Nothing)?;

        // With every slot of one shape, the coordinator's pick is safe.
        let untyped = SlotCheck {
            inputs: SubmittedInputs::Count(1),
            ..check
        };
        untyped.check_bindable(&BindableSlots::AnyOf(vec![ClientIndex(0), ClientIndex(1)]))?;
        Ok(())
    }
}
