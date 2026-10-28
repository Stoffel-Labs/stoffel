//! Run one execution on a running standing mesh: admit it, drive every client
//! slot of the program, and return what the clients received.
//!
//! The clients are the same off-chain clients [`crate::LocalCoordinatorRunner`]
//! drives, so a program behaves the same under `--local` and on a mesh.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::{
    encode_execution_frame, ExecutionMessageKind, MpcBackendKind, EXECUTION_CLIENT_ROUTE_HELLO_V1,
};
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::local_runner::{
    run_avss_offchain_client_for_curve, run_honeybadger_offchain_client, LocalClientIdentity,
    LocalClientRunContext,
};
use crate::standing_control::{StandingProgram, StandingProgramCatalog};
use crate::{
    AdmitTimeouts, ClientOutputRecord, LocalClientInput, LocalCoordinatorRunnerError,
    StandingAdmitError, StandingClientAdmissionV1, StandingMeshInfo,
};

const ROUTE_ATTEMPTS: usize = 10;
const ROUTE_RETRY_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
pub enum StandingRunError {
    #[error("{0}")]
    Program(String),
    #[error("{0}")]
    Inputs(String),
    #[error("admission failed: {0}")]
    Admission(#[from] StandingAdmitError),
    #[error("execution {execution_id}: {source}")]
    Client {
        execution_id: ExecutionId,
        #[source]
        source: LocalCoordinatorRunnerError,
    },
    #[error("execution {execution_id}: timed out after {timeout:?}")]
    Timeout {
        execution_id: ExecutionId,
        timeout: Duration,
    },
}

pub type StandingRunResult<T> = Result<T, StandingRunError>;

#[derive(Debug, Clone, Copy)]
pub struct StandingRunTimeouts {
    pub admission: AdmitTimeouts,
    /// From admission until every client has its outputs.
    pub execution: Duration,
}

impl Default for StandingRunTimeouts {
    fn default() -> Self {
        Self {
            admission: AdmitTimeouts::default(),
            execution: Duration::from_secs(180),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StandingRunOutput {
    pub execution_id: ExecutionId,
    /// Outputs of every client slot that receives any, by slot.
    pub client_outputs: Vec<ClientOutputRecord>,
}

/// What to run on the mesh.
#[derive(Debug, Clone)]
pub struct StandingRunRequest {
    pub program_id: [u8; 32],
    pub entry: String,
    /// Raw field inputs per client slot, as for
    /// [`crate::LocalCoordinatorRunnerBuilder::client_inputs`].
    pub client_inputs: Vec<LocalClientInput>,
    /// Output counts for slots whose outputs the program does not declare.
    pub client_output_counts: HashMap<u64, u64>,
    pub timeouts: StandingRunTimeouts,
}

/// Admit `request` on the mesh described by `info` and drive its clients.
/// Cancels the execution if any client fails.
pub async fn run_on_standing_mesh(
    info: &StandingMeshInfo,
    request: StandingRunRequest,
) -> StandingRunResult<StandingRunOutput> {
    let program = load_program(info, request.program_id)?;
    let clients = plan_clients(info, &program, &request)?;
    let roster = clients
        .iter()
        .map(|client| StandingClientAdmissionV1 {
            certificate: format!("client{}.crt", client.client_slot),
            manifest_slot: client.client_slot as usize,
        })
        .collect();

    let admitter = info.admitter();
    let execution_id = admitter
        .admit(
            request.program_id,
            &request.entry,
            roster,
            request.timeouts.admission,
        )
        .await?;
    eprintln!("[stoffel] admitted execution {execution_id}");

    let result = drive_clients(info, &program, execution_id, clients, request.timeouts).await;
    if result.is_err() {
        let _ = admitter
            .cancel(execution_id, request.timeouts.admission.acknowledgement)
            .await;
    }
    result.map(|client_outputs| StandingRunOutput {
        execution_id,
        client_outputs,
    })
}

fn load_program(
    info: &StandingMeshInfo,
    program_id: [u8; 32],
) -> StandingRunResult<Arc<StandingProgram>> {
    // Reading leniently is fine: the nodes decided at startup which programs
    // they accept, and admission is refused for any other.
    let catalog =
        StandingProgramCatalog::load_with_dynamic_preprocessing(&info.layout.programs_dir())
            .map_err(|error| StandingRunError::Program(error.to_string()))?;
    catalog.get(&program_id).ok_or_else(|| {
        StandingRunError::Program(format!(
            "program {} was not installed when the mesh started; restart the mesh with it",
            hex::encode(program_id)
        ))
    })
}

/// One client per manifest slot, in slot order, which is also the order the
/// nodes number input clients in when they register the execution with the
/// coordinator. Each input client's reserved index block follows from that
/// order.
fn plan_clients(
    info: &StandingMeshInfo,
    program: &StandingProgram,
    request: &StandingRunRequest,
) -> StandingRunResult<Vec<LocalClientIdentity>> {
    let schemas = program
        .client_io_manifest
        .clients
        .iter()
        .map(|schema| (schema.client_slot, schema))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = BTreeMap::new();
    for input in &request.client_inputs {
        let Some(schema) = schemas.get(&input.client_slot) else {
            return Err(StandingRunError::Inputs(format!(
                "the program has no client slot {}",
                input.client_slot
            )));
        };
        if input.values.len() != schema.inputs.len() {
            return Err(StandingRunError::Inputs(format!(
                "client slot {} takes {} input(s), got {}",
                input.client_slot,
                schema.inputs.len(),
                input.values.len()
            )));
        }
        if inputs.insert(input.client_slot, input.clone()).is_some() {
            return Err(StandingRunError::Inputs(format!(
                "client slot {} has inputs more than once",
                input.client_slot
            )));
        }
    }

    let mut next_input_index = 0u64;
    let mut clients = Vec::with_capacity(schemas.len());
    for (&slot, schema) in &schemas {
        if !info.client_slots.contains(&slot) {
            return Err(StandingRunError::Program(format!(
                "the mesh has no identity for client slot {slot}; restart it so it creates one"
            )));
        }
        let input = match inputs.remove(&slot) {
            Some(input) => input,
            None if schema.inputs.is_empty() => LocalClientInput::raw(slot, Vec::<String>::new()),
            None => {
                return Err(StandingRunError::Inputs(format!(
                    "client slot {slot} takes {} input(s); pass them with --client-input {slot}=…",
                    schema.inputs.len()
                )))
            }
        };
        let output_count = match schema.outputs.len() as u64 {
            0 => request
                .client_output_counts
                .get(&slot)
                .copied()
                .unwrap_or(0),
            declared => declared,
        };
        let cert_path = info.layout.client_cert_path(slot);
        let cert_der = std::fs::read(&cert_path).map_err(|error| {
            StandingRunError::Program(format!("read {}: {error}", cert_path.display()))
        })?;
        clients.push(LocalClientIdentity {
            input,
            key_path: info.layout.client_key_path(slot),
            cert_path,
            cert_der,
            reserved_index_start: next_input_index,
            client_slot: slot,
            output_count,
        });
        next_input_index += schema.inputs.len() as u64;
    }
    Ok(clients)
}

async fn drive_clients(
    info: &StandingMeshInfo,
    program: &StandingProgram,
    execution_id: ExecutionId,
    clients: Vec<LocalClientIdentity>,
    timeouts: StandingRunTimeouts,
) -> StandingRunResult<Vec<ClientOutputRecord>> {
    let deadline = Instant::now() + timeouts.execution;
    let context = LocalClientRunContext {
        execution_id,
        node_rpc_addrs: info.node_rpc.clone(),
        coord_port: info.coordinator.port(),
        parties: info.parties,
        threshold: info.threshold,
        deadline,
        timeout: timeouts.execution,
    };
    let mut tasks = JoinSet::new();
    for client in clients {
        let output_only = client.input.values.is_empty() && client.output_count > 0;
        if client.input.values.is_empty() && client.output_count == 0 {
            continue;
        }
        let backend = program.backend;
        let curve = program.curve;
        let context = context.clone();
        let mesh = info.node_mesh.clone();
        tasks.spawn(async move {
            let cert_der = client.cert_der.clone();
            let key_path = client.key_path.clone();
            let run = async move {
                match backend {
                    MpcBackendKind::HoneyBadger => {
                        run_honeybadger_offchain_client(client, context).await
                    }
                    MpcBackendKind::Avss => {
                        run_avss_offchain_client_for_curve(curve, client, context).await
                    }
                }
            };
            if !output_only {
                return run.await;
            }
            // Standing nodes hold an execution until each output-only client
            // has opened its route to them. Open it while the client is
            // already waiting for its outputs, as stoffel-run's client does: a
            // fast program could otherwise finish and be retired before the
            // client asks. The route stays open until the client is done.
            let (route, result) = tokio::join!(
                open_output_route(execution_id, &mesh, &cert_der, &key_path),
                run
            );
            route?;
            result
        });
    }

    let mut outputs = Vec::new();
    loop {
        let next = tokio::time::timeout_at(deadline, tasks.join_next()).await;
        let Ok(next) = next else {
            tasks.abort_all();
            return Err(StandingRunError::Timeout {
                execution_id,
                timeout: timeouts.execution,
            });
        };
        let Some(joined) = next else { break };
        let result = joined.unwrap_or_else(|error| {
            Err(LocalCoordinatorRunnerError::ParticipantFailure {
                participant: "client task".to_owned(),
                phase: "task supervision",
                error: error.to_string(),
            })
        });
        match result {
            Ok(Some(output)) => outputs.push(output),
            Ok(None) => {}
            Err(source) => {
                tasks.abort_all();
                return Err(StandingRunError::Client {
                    execution_id,
                    source,
                });
            }
        }
    }
    outputs.sort_by_key(|output| output.client_slot);
    Ok(outputs)
}

/// Open an authenticated connection to every party and announce this client
/// on it for `execution_id`. The connections must stay open until the client
/// has its outputs.
async fn open_output_route(
    execution_id: ExecutionId,
    mesh: &[SocketAddr],
    cert_der: &[u8],
    key_path: &std::path::Path,
) -> Result<QuicNetworkManager, LocalCoordinatorRunnerError> {
    let route_error = |error: String| LocalCoordinatorRunnerError::ParticipantFailure {
        participant: "output client".to_owned(),
        phase: "execution route",
        error,
    };
    let key_der = std::fs::read(key_path)?;
    let mut network = QuicNetworkManager::new();
    network
        .set_local_certificate_der(cert_der.to_vec(), key_der)
        .map_err(|error| route_error(error.to_string()))?;
    let hello = encode_execution_frame(
        execution_id,
        ExecutionMessageKind::Control,
        EXECUTION_CLIENT_ROUTE_HELLO_V1,
    )
    .map_err(|error| route_error(error.to_string()))?;

    let mut connections = Vec::with_capacity(mesh.len());
    for &address in mesh {
        let mut attempt = 0;
        let connection = loop {
            attempt += 1;
            match network.connect_as_client(address).await {
                Ok(connection) => break connection,
                Err(error) if attempt >= ROUTE_ATTEMPTS => {
                    return Err(route_error(format!("connect to {address}: {error}")))
                }
                Err(_) => tokio::time::sleep(ROUTE_RETRY_DELAY).await,
            }
        };
        connections.push(connection);
    }
    // The hello is a control frame that a node may not be ready to route yet;
    // repeating it is harmless and covers that window.
    for _ in 0..3 {
        for connection in &connections {
            connection
                .send(&hello)
                .await
                .map_err(|error| route_error(error.to_string()))?;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(network)
}
