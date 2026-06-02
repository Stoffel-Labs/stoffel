//! Reference Rust SDK for building Stoffel MPC applications.
//!
//! The SDK provides a small public entry point, [`Stoffel`], for compiling
//! Stoffel-Lang programs, loading bytecode, configuring MPC runtime settings,
//! executing local development programs, and constructing client/server
//! participants.
//!
//! ```
//! use stoffel::prelude::*;
//!
//! # fn main() -> stoffel::Result<()> {
//! let result = Stoffel::compile(
//!     "def main(a: int64, b: int64) -> int64:\n  return a + b",
//! )?
//! .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
//! .execute_clear()?;
//!
//! assert_eq!(result[0].as_i64(), Some(100));
//! # Ok(())
//! # }
//! ```
//!
//! Local MPC development uses the same builder, but delegates to
//! `stoffel-vm`'s real localhost coordinator runner and a built `stoffel-run`
//! binary instead of simulating the protocol in the SDK:
//!
//! ```no_run
//! use stoffel::prelude::*;
//!
//! # async fn example() -> stoffel::Result<()> {
//! let result = Stoffel::compile(
//!     "def main() -> int64:\n  var share = ClientStore.take_share(0, 0)\n  return share.open()",
//! )?
//! .parties(5)
//! .threshold(1)
//! .with_client_input(0, &[42_i64])
//! .execute_local()
//! .await?;
//!
//! assert_eq!(result[0].as_i64(), Some(42));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod backend;
pub mod client;
pub mod codegen;
pub mod compiler;
pub mod config;
pub mod consensus;
pub mod coordinator;
pub mod error;
pub mod networking;
pub mod observability;
pub mod prelude;
pub mod program;
pub mod runtime;
pub mod server;
pub mod types;
pub mod vm;

use std::path::{Path, PathBuf};

pub use backend::{
    avss::{AvssBackend, AvssEngine},
    honeybadger::HoneyBadgerBackend,
    Backend, MpcBackend,
};
pub use client::{
    ClientBuilder, ClientState, ClientSummary, ComputationHandle, ComputationStatus,
    ComputationSummary, OffChainClientConfig, OffChainClientConfigBuilder, StoffelClient,
};
pub use codegen::{generate_bindings, generate_bindings_with_config, BindingsConfig};
pub use config::{
    Curve, MpcConfig, MpcConfigBuilder, MpcConfigSummary, MpcSection, NetworkConfig,
    NetworkConfigBuilder, NetworkConfigSummary, NetworkDeployment, NetworkDeploymentBuilder,
    NetworkSection, PreprocessingConfig,
};
pub use consensus::{ConsensusGate, NodePublicKey, VerifiedOrdering};
pub use coordinator::{
    BlsOnChainAvssCoordinator, Coordinator, CoordinatorEvent, CoordinatorEventStream,
    HoneyBadgerOnChainCoordinator, OffChainCoordinator, OffChainCoordinatorClient,
    OffChainCoordinatorServer, OnChainClientIdentity, OnChainCoordinator, OnChainCoordinatorConfig,
    OnChainCoordinatorConfigBuilder, OnChainCoordinatorConfigSummary, OnChainCoordinatorHandle,
    OnChainCoordinatorSummary, ShareBound,
};
pub use error::{ConsensusError, CoordinatorError, Error, ErrorCategory, NetworkError, Result};
pub use networking::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
pub use observability::{
    init_tracing, HealthStatus, OpenTelemetryGuard, ServerMetrics, ServerMetricsSnapshot,
    TracingConfig, TracingConfigBuilder, TracingConfigSummary,
};
pub use program::{
    BytecodeSummary, ClientMetadata, ClientMetadataSummary, FunctionMetadata, FunctionSummary,
    Program, ProgramSummary,
};
pub use runtime::{LocalNetworkBuilder, RuntimeSummary, StoffelRuntime};
pub use server::{
    OffChainServerConfig, OffChainServerConfigBuilder, ServerBuilder, ServerState, ServerSummary,
    StoffelServer,
};
pub use types::{
    ClientId, ClientInputValue, ClientOutputValue, ClientValueType, FieldElement,
    GeneratedProgramManifest, GroupElement, MaskIndex, PartyId, PublicKey, Round, Share,
    TypedClientInputs, TypedClientOutputs, Value, ValueSummary,
};

#[derive(Debug, Clone)]
enum ProgramSource {
    Source { source: String, filename: String },
    File { path: std::path::PathBuf },
    Bytecode(Vec<u8>),
}

/// SDK entry point and builder.
#[derive(Debug, Clone)]
pub struct Stoffel {
    source: Option<ProgramSource>,
    mpc_config: MpcConfig,
    backend_explicit: bool,
    network_config: Option<NetworkConfig>,
    local_runner_path: Option<PathBuf>,
    config_error: Option<String>,
    inputs: Vec<(String, Value)>,
    client_inputs: Vec<(u64, Vec<Value>)>,
}

impl Stoffel {
    /// Compile a Stoffel-Lang source string.
    pub fn compile(source: &str) -> Result<Self> {
        Ok(Self::from_source(ProgramSource::Source {
            source: source.to_owned(),
            filename: "<sdk>".to_owned(),
        }))
    }

    /// Compile a Stoffel-Lang file.
    pub fn compile_file(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_source(ProgramSource::File {
            path: path.as_ref().to_path_buf(),
        }))
    }

    /// Load serialized Stoffel bytecode.
    pub fn load(bytecode: &[u8]) -> Result<Self> {
        Ok(Self::from_source(ProgramSource::Bytecode(
            bytecode.to_vec(),
        )))
    }

    /// Load serialized Stoffel bytecode from a file.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytecode = std::fs::read(path)?;
        Self::load(&bytecode)
    }

    /// Set the number of MPC parties. Default is 5.
    pub fn parties(mut self, n: usize) -> Self {
        self.mpc_config.parties = n;
        self
    }

    /// Set the Byzantine threshold. Default is 1.
    pub fn threshold(mut self, t: usize) -> Self {
        self.mpc_config.threshold = t;
        self
    }

    /// Set the MPC instance identifier. Default is generated from process-local time.
    pub fn instance_id(mut self, id: u64) -> Self {
        self.mpc_config.instance_id = id;
        self
    }

    /// Select an MPC backend. Default is HoneyBadger.
    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.mpc_config.backend = backend;
        self.backend_explicit = true;
        self
    }

    /// Select the backend and curve declared by generated program bindings.
    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    /// Select the HoneyBadger backend.
    pub fn honeybadger(mut self) -> Self {
        self.mpc_config.backend = MpcBackend::HoneyBadger;
        self.backend_explicit = true;
        self
    }

    /// Select the AVSS backend with the given curve.
    pub fn avss(mut self, curve: Curve) -> Self {
        self.mpc_config.backend = MpcBackend::Avss { curve };
        self.backend_explicit = true;
        self
    }

    /// Select the AVSS curve. This also selects the AVSS backend.
    pub fn curve(mut self, curve: Curve) -> Self {
        self.mpc_config.backend = MpcBackend::Avss { curve };
        self.backend_explicit = true;
        self
    }

    /// Attach named inputs for local execution.
    pub fn with_inputs<V>(mut self, inputs: &[(&str, V)]) -> Self
    where
        V: Clone + Into<Value>,
    {
        self.inputs = inputs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone().into()))
            .collect();
        self
    }

    /// Attach one named input for local execution.
    pub fn with_input<V>(mut self, name: impl Into<String>, value: V) -> Self
    where
        V: Into<Value>,
    {
        self.inputs.push((name.into(), value.into()));
        self
    }

    /// Attach one coordinator client input set for local networked execution.
    ///
    /// This is distinct from named function parameters. It feeds programs that
    /// read secret client values through `ClientStore.take_share(client_slot, i)`.
    pub fn with_client_input<V>(mut self, client_slot: u64, values: &[V]) -> Self
    where
        V: Clone + Into<Value>,
    {
        self.client_inputs.push((
            client_slot,
            values.iter().cloned().map(Into::into).collect(),
        ));
        self
    }

    /// Replace all coordinator client input sets for local networked execution.
    pub fn with_client_inputs<V>(mut self, inputs: &[(u64, &[V])]) -> Self
    where
        V: Clone + Into<Value>,
    {
        self.client_inputs = inputs
            .iter()
            .map(|(client_slot, values)| {
                (
                    *client_slot,
                    values.iter().cloned().map(Into::into).collect(),
                )
            })
            .collect();
        self
    }

    /// Attach explicit network configuration.
    pub fn network_config(mut self, config: NetworkConfig) -> Self {
        self.network_config = Some(config);
        self
    }

    /// Load network configuration from a TOML file.
    pub fn network_config_file(mut self, path: impl AsRef<Path>) -> Self {
        match NetworkConfig::from_toml_file(path) {
            Ok(config) => self.network_config = Some(config),
            Err(error) => self.config_error = Some(error.to_string()),
        }
        self
    }

    /// Set the `stoffel-run` binary path used by local coordinator execution.
    pub fn local_runner_path(mut self, path: impl AsRef<Path>) -> Self {
        self.local_runner_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build a runtime from the configured program and MPC settings.
    pub fn build(self) -> Result<StoffelRuntime> {
        if let Some(error) = self.config_error {
            return Err(Error::Configuration(error));
        }
        let mut mpc_config = self.mpc_config;
        let mut backend_explicit = self.backend_explicit;
        if let Some(config) = &self.network_config {
            mpc_config = config.to_mpc_config(mpc_config.instance_id)?;
            backend_explicit = true;
        }
        mpc_config.validate()?;

        let source = self
            .source
            .ok_or_else(|| Error::Configuration("no program source configured".to_owned()))?;
        let program = match source {
            ProgramSource::Source { source, filename } => {
                compiler::compile_source(&source, &filename, mpc_config.backend)?
            }
            ProgramSource::File { path } => compiler::compile_file(&path, mpc_config.backend)?,
            ProgramSource::Bytecode(bytecode) => {
                let program = Program::from_bytecode(&bytecode)?;
                let bytecode_backend =
                    backend_from_bytecode(program.bytecode_backend(), program.bytecode_curve())?;
                if backend_explicit {
                    validate_bytecode_backend(&program, mpc_config.backend)?;
                } else {
                    mpc_config.backend = bytecode_backend;
                }
                program
            }
        };
        validate_bytecode_backend(&program, mpc_config.backend)?;
        if program.is_empty() {
            return Err(Error::Configuration(
                "program must contain at least one function".to_owned(),
            ));
        }
        if let Some(config) = &self.network_config {
            validate_program_network_config(&program, config)?;
        }
        Ok(StoffelRuntime::new(
            program,
            Some(mpc_config),
            self.network_config,
            self.local_runner_path,
            self.inputs,
            self.client_inputs,
        ))
    }

    /// Validate attached coordinator client inputs against compiled program metadata.
    pub fn validate_client_inputs(self) -> Result<()> {
        let runtime = self.build()?;
        runtime.validate_client_inputs()
    }

    /// Execute locally using real MPC nodes.
    ///
    /// This delegates to `stoffel-vm`'s local coordinator runner, which starts a
    /// real localhost party mesh via `stoffel-run`. HoneyBadger supports
    /// no-argument `ClientStore` entrypoints and named [`Self::with_inputs`]
    /// values, which are adapted into local coordinator client input by a
    /// generated bytecode wrapper. AVSS local execution supports no-input
    /// programs and BLS12-381 local client input through the same lower runner.
    #[tracing::instrument(skip_all)]
    pub async fn execute_local(self) -> Result<Vec<Value>> {
        self.execute_local_function("main").await
    }

    /// Execute a named function locally using real MPC nodes.
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function(self, name: &str) -> Result<Vec<Value>> {
        let (runtime, entry) = self.build_for_local_execution(name)?;
        vm::execute_local(&runtime, &entry).await
    }

    /// Execute a cleartext Stoffel program with the embedded VM.
    ///
    /// This is intended for local development of non-secret logic. Secret MPC
    /// programs should use [`Self::execute_local`], which is reserved for the
    /// PRD's full multi-node localhost execution model.
    pub fn execute_clear(self) -> Result<Vec<Value>> {
        self.execute_clear_function("main")
    }

    /// Execute a named cleartext function with the embedded VM.
    pub fn execute_clear_function(self, name: &str) -> Result<Vec<Value>> {
        let runtime = self.build()?;
        vm::execute_clear(&runtime, name)
    }

    /// Create a server builder without compiling a program.
    pub fn server(party_id: usize) -> ServerBuilder {
        ServerBuilder::new(party_id)
    }

    /// Create a client builder.
    pub fn client() -> ClientBuilder {
        ClientBuilder::new()
    }

    fn from_source(source: ProgramSource) -> Self {
        Self {
            source: Some(source),
            mpc_config: MpcConfig::default(),
            backend_explicit: false,
            network_config: None,
            local_runner_path: None,
            config_error: None,
            inputs: Vec::new(),
            client_inputs: Vec::new(),
        }
    }

    fn build_for_local_execution(self, name: &str) -> Result<(StoffelRuntime, String)> {
        if self.inputs.is_empty() {
            return Ok((self.build()?, name.to_owned()));
        }
        if !self.client_inputs.is_empty() {
            return Err(Error::Configuration(
                "`with_inputs` and `with_client_input` cannot be combined for local execution"
                    .to_owned(),
            ));
        }
        let mut probe = self.clone();
        probe.inputs.clear();
        let probe_runtime = probe.build()?;
        if probe_runtime.program().has_client_io() {
            return Err(Error::Unsupported(
                "SDK local named-input adapter does not support programs that already declare ClientStore input metadata"
                    .to_owned(),
            ));
        }

        let function = probe_runtime
            .program()
            .function(name)
            .ok_or_else(|| Error::FunctionNotFound(name.to_owned()))?;
        let ordered_inputs =
            ordered_inputs_for_parameters(&self.inputs, name, function.parameters())?;
        let entry = unique_local_entry_name(probe_runtime.program(), "__stoffel_sdk_local_entry");
        let wrapped_program = probe_runtime.program().with_local_client_input_wrapper(
            name,
            &entry,
            ordered_inputs.len(),
        )?;
        Ok((
            probe_runtime
                .with_program_and_client_inputs(wrapped_program, vec![(0, ordered_inputs)]),
            entry,
        ))
    }
}

fn ordered_inputs_for_parameters(
    inputs: &[(String, Value)],
    function_name: &str,
    parameters: &[String],
) -> Result<Vec<Value>> {
    for (name, _) in inputs {
        if !parameters.iter().any(|parameter| parameter == name) {
            return Err(Error::InvalidInput(format!(
                "unexpected input '{name}' for function '{function_name}'"
            )));
        }
    }

    let mut values = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let mut matches = inputs
            .iter()
            .filter(|(name, _)| name == parameter)
            .map(|(_, value)| value);
        let Some(value) = matches.next() else {
            return Err(Error::InvalidInput(format!(
                "missing input '{parameter}' for function '{function_name}'"
            )));
        };
        if matches.next().is_some() {
            return Err(Error::InvalidInput(format!(
                "duplicate input '{parameter}' for function '{function_name}'"
            )));
        }
        values.push(value.clone());
    }
    Ok(values)
}

fn unique_local_entry_name(program: &Program, base: &str) -> String {
    if program.function(base).is_none() {
        return base.to_owned();
    }
    for suffix in 1.. {
        let candidate = format!("{base}_{suffix}");
        if program.function(&candidate).is_none() {
            return candidate;
        }
    }
    unreachable!("unbounded suffix search should always find a unique function name")
}

fn backend_from_bytecode(
    backend: stoffel_vm_types::compiled_binary::MpcBackend,
    curve: stoffel_vm_types::compiled_binary::MpcCurve,
) -> Result<MpcBackend> {
    match backend {
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger => Ok(MpcBackend::HoneyBadger),
        stoffel_vm_types::compiled_binary::MpcBackend::Avss => Ok(MpcBackend::Avss {
            curve: curve_from_bytecode(curve),
        }),
    }
}

fn curve_from_bytecode(curve: stoffel_vm_types::compiled_binary::MpcCurve) -> Curve {
    match curve {
        stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => Curve::Bls12_381,
        stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => Curve::Bn254,
        stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => Curve::Curve25519,
        stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => Curve::Ed25519,
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => Curve::Secp256k1,
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => Curve::Secp256r1,
    }
}

fn validate_bytecode_backend(program: &Program, expected: MpcBackend) -> Result<()> {
    let actual = program.bytecode_backend();
    if actual != expected.compiler_backend() {
        return Err(Error::Configuration(format!(
            "bytecode MPC backend ({actual:?}) does not match runtime backend ({expected})"
        )));
    }
    let Some(expected_curve) = expected.curve() else {
        return Ok(());
    };
    let actual_curve = curve_from_bytecode(program.bytecode_curve());
    if actual_curve != expected_curve {
        return Err(Error::Configuration(format!(
            "bytecode AVSS curve ({actual_curve}) does not match runtime backend ({expected})"
        )));
    }
    Ok(())
}

fn validate_program_network_config(program: &Program, config: &NetworkConfig) -> Result<()> {
    config.validate_server_addresses()?;
    program.validate_expected_clients(config.network.expected_clients)
}
