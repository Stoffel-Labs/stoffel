use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use jsonrpsee::{core::RpcResult, server::RpcModule};
use stoffel_mpc_coordinator_off_chain::{
    ClientIdentity, CoordinatorRPCBaseServer, CoordinatorRPCServerConnectionBase,
    CoordinatorRPCServerSharedBase, ExecutionRequest, OffChainCoordinatorServer,
    StoffelCoordinatorRPCServer,
};
use stoffel_mpc_coordinator_shared::rpc::{caller_identity, RPCServerConnection, RpcServerLimits};
use stoffel_mpc_coordinator_shared::{
    AdmissionPolicy, ClientSlotSpec, ClientSlotTable, ExecutionDeadlines, ExecutionId,
    NodeCertificateDer, NodeRoster, Round, SpkiDer, UnixSeconds,
};
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "Run one long-lived off-chain coordinator. It is the roster authority: the node \
roster is fixed at startup and served, verified, to every node and client. It is also the only \
party that decides what runs: it mints every execution identity itself and publishes each \
execution down to the roster, and nodes learn their executions from it rather than registering \
any upwards. An operator listed in --operator-certs submits executions over the authenticated \
link; one may also be registered at startup with --hash."
)]
struct Args {
    /// Program hash of an execution to register at startup. The coordinator
    /// mints its identity and prints it.
    #[arg(long, requires = "client_slots")]
    hash: Option<String>,

    /// The entry function nodes call in that program.
    #[arg(long, default_value = "main")]
    entry: String,

    /// `<inputs>:<outputs>` per client slot, in slot order.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    client_slots: Vec<String>,

    /// Seconds from startup by which every client slot must be bound.
    #[arg(long, default_value_t = 3600)]
    association_timeout_secs: u64,

    /// Seconds from startup by which every masked input must be submitted.
    #[arg(long, default_value_t = 7200)]
    input_timeout_secs: u64,

    /// The node roster: one certificate per MPC node. Membership is fixed for
    /// this process's whole life, and a different roster is a different
    /// coordinator.
    #[arg(long, required = true, value_delimiter = ',', num_args = 1..)]
    node_roster: Vec<String>,

    /// The coordinator's certificate (DER). Nodes and clients pin its key.
    #[arg(long)]
    server_cert: String,

    /// The coordinator's private key (PKCS#8 DER), matching `--server-cert`.
    #[arg(long)]
    server_key: String,

    /// The operators allowed to submit and abort executions: one certificate
    /// each. The certificate an operator opens its link with is the whole
    /// authorization, and the list is fixed for this process's life. With none,
    /// this coordinator runs only what its own command line registered.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    operator_certs: Vec<String>,

    /// The corruption threshold of the node roster. `n` is the number of
    /// `--node-roster` entries.
    #[arg(long)]
    t: u64,

    /// Listen address.
    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    /// Listen port.
    #[arg(long, default_value_t = 31415)]
    port: u16,
}

/// Parses one `<inputs>:<outputs>` client slot.
fn parse_client_slot(value: &str) -> ClientSlotSpec {
    let (inputs, outputs) = value
        .split_once(':')
        .unwrap_or_else(|| panic!("--client-slots entry {value:?} must be <inputs>:<outputs>"));
    ClientSlotSpec {
        input_count: inputs
            .trim()
            .parse()
            .unwrap_or_else(|error| panic!("--client-slots input count in {value:?}: {error}")),
        output_count: outputs
            .trim()
            .parse()
            .unwrap_or_else(|error| panic!("--client-slots output count in {value:?}: {error}")),
    }
}

#[derive(Clone)]
struct CoordinatorConnection {
    base: CoordinatorRPCServerConnectionBase,
}

impl RPCServerConnection for CoordinatorConnection {
    type Internal = CoordinatorRPCServerSharedBase;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self {
            base: CoordinatorRPCServerConnectionBase::new(internal, id),
        }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut rpc = StoffelCoordinatorRPCServer::into_rpc(self.clone());
        rpc.merge(CoordinatorRPCBaseServer::into_rpc(self.base))
            .expect("merge coordinator RPC modules");
        rpc
    }
}

#[async_trait]
impl StoffelCoordinatorRPCServer for CoordinatorConnection {
    async fn start_preprocessing(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::Preprocessing)
            .await
    }

    async fn reserve_input_masks(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputMaskReservation)
            .await
    }

    async fn collect_inputs(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputCollection)
            .await
    }

    async fn start_mpc(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::MPCExecution)
            .await
    }

    async fn send_output(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::OutputDistribution)
            .await
    }

    async fn finalize(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::ProgramFinished)
            .await
    }
}

#[tokio::main]
async fn main() {
    // The coordinator reports every refusal it makes below the RPC layer through `tracing`:
    // a caller certificate it will not admit, a TLS handshake that failed, a connection pool
    // that is full for one identity, a subscriber that fell behind. Without a subscriber
    // installed those all become a bare connection reset at the caller with no reason
    // anywhere, which is exactly what made a full connection pool take hours to identify.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    let args = Args::parse();
    let node_roster = NodeRoster::new(args.t, read_node_certificates(&args.node_roster))
        .expect("invalid coordinator node roster");

    let cert = fs::read(&args.server_cert).expect("could not read server cert");
    let key = fs::read(&args.server_key).expect("could not read server key");
    let server_spki =
        SpkiDer::from_certificate_der(&cert).expect("--server-cert is not a usable certificate");

    // The digest an operator pins with the nodes' `--expect-roster-digest`
    // (design doc §9.D.2). It is printed before anything can connect, so the
    // value a deployment pins is the value this process actually serves.
    println!(
        "Serving node roster n={}, t={}, digest={}",
        node_roster.n(),
        node_roster.t(),
        node_roster.digest()
    );

    let operators = read_operator_identities(&args.operator_certs);
    println!(
        "Operators authorized to submit executions: {}",
        operators.len()
    );
    let mut state =
        CoordinatorRPCServerSharedBase::new(node_roster, server_spki).with_operators(operators);
    if let Some(hash) = args.hash.as_deref() {
        let program_hash: [u8; 32] = hex::decode(hash)
            .expect("invalid hash")
            .try_into()
            .expect("hash must be 32 bytes");
        let now = UnixSeconds::now();
        let registered = state
            .register_execution(ExecutionRequest {
                program_hash,
                entry: args.entry.clone(),
                client_slots: ClientSlotTable::new(
                    args.client_slots
                        .iter()
                        .map(|slot| parse_client_slot(slot))
                        .collect(),
                ),
                // Clients bind their slot at run time, so a client the
                // deployment never listed can take part.
                admission: AdmissionPolicy::Open,
                deadlines: Some(ExecutionDeadlines {
                    association: UnixSeconds(now.0.saturating_add(args.association_timeout_secs)),
                    input: UnixSeconds(now.0.saturating_add(args.input_timeout_secs)),
                }),
            })
            .expect("invalid initial execution");
        println!(
            "Minted execution {} (registration nonce {})",
            registered.execution_id, registered.registration_nonce
        );
    }

    let coord = OffChainCoordinatorServer::<CoordinatorConnection>::start_coord(
        state,
        &args.bind_addr,
        args.port,
        cert,
        key,
        RpcServerLimits::default(),
    )
    .await
    .expect("failed to start coordinator");

    println!("Listening on {}:{}", args.bind_addr, args.port);
    wait_for_shutdown_signal().await;
    coord.shutdown().await;
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.expect("install SIGINT handler"),
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install interrupt handler");
}

/// Reads the operator certificates and derives the caller identity each one
/// authenticates as, which is the identity the coordinator gates submissions on.
fn read_operator_identities(cert_files: &[String]) -> Vec<ClientIdentity> {
    cert_files
        .iter()
        .map(|cert_file| {
            let cert_der = fs::read(cert_file)
                .unwrap_or_else(|_| panic!("could not read operator certificate file {cert_file}"));
            caller_identity(&cert_der).unwrap_or_else(|error| {
                panic!("operator certificate {cert_file} is not usable: {error}")
            })
        })
        .collect()
}

/// Reads the roster's certificates. The coordinator derives every identity and
/// every pinned key from the certificate itself, so nothing here extracts a
/// public key by hand.
fn read_node_certificates(cert_files: &[String]) -> Vec<NodeCertificateDer> {
    cert_files
        .iter()
        .map(|cert_file| {
            let cert_der = fs::read(cert_file)
                .unwrap_or_else(|_| panic!("could not read certificate file {cert_file}"));
            NodeCertificateDer::from_der(cert_der)
        })
        .collect()
}
