//! Start a standing mesh on this machine: an in-process coordinator and one
//! `stoffel-run --standing-node` child process per party.
//!
//! The mesh lives in one directory ([`StandingMeshLayout`]). Its programs and
//! client identities are read once when the nodes start, so both are fixed for
//! the life of the mesh; restart it to change them. Identities, the pool
//! identity and every node's preprocessing and admission state persist in the
//! directory, so a restarted mesh reuses its preprocessing.
//!
//! Executions are admitted onto a running mesh with
//! [`crate::StandingAdmitter`], from this process or any other, using
//! [`StandingMeshInfo::admitter`].

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    HoneyBadgerCoordinatorConnection, HoneyBadgerCoordinatorRPCServerSharedBase,
};
use stoffel_mpc_coordinator_off_chain::OffChainCoordinatorServer;
use stoffel_mpc_coordinator_shared::self_signed_certs;
use stoffel_vm::net::program_id_from_bytes;
use stoffel_vm::net::session::ExecutionId;
use tokio::process::{Child, Command};
use tokio::time::Instant;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::standing_control::{StandingProgram, StandingProgramCatalog};
use crate::StandingAdmitter;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const LOG_TAIL_LINES: usize = 40;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum StandingMeshError {
    #[error("standing mesh IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("standing mesh configuration: {0}")]
    Configuration(String),
    #[error("the standing mesh's programs are invalid: {0}")]
    Programs(String),
    #[error("the standing coordinator failed to start: {0}")]
    Coordinator(String),
    #[error("party {party} exited ({status}) during {phase}; last lines of {log}:\n{tail}")]
    NodeExited {
        party: usize,
        status: ExitStatus,
        phase: &'static str,
        log: PathBuf,
        tail: String,
    },
    #[error("timed out after {timeout:?} waiting for party {party} to finish {phase}; see {log}")]
    Timeout {
        party: usize,
        phase: &'static str,
        timeout: Duration,
        log: PathBuf,
    },
}

pub type StandingMeshResult<T> = Result<T, StandingMeshError>;

/// Where everything of one mesh lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingMeshLayout {
    root: PathBuf,
}

impl StandingMeshLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Content-addressed programs, `<program id>.stflb`.
    pub fn programs_dir(&self) -> PathBuf {
        self.root.join("programs")
    }

    /// Party certificates `cert<i>.crt` and keys `key<i>.der`.
    pub fn party_cert_dir(&self) -> PathBuf {
        self.root.join("ids").join("nodes")
    }

    /// Client certificates `client<slot>.crt`. Nodes read every file here as a
    /// client identity, so the keys live in [`Self::client_key_dir`].
    pub fn client_cert_dir(&self) -> PathBuf {
        self.root.join("ids").join("clients")
    }

    /// Client keys `client<slot>.der`.
    pub fn client_key_dir(&self) -> PathBuf {
        self.root.join("ids").join("client-keys")
    }

    pub fn client_cert_path(&self, slot: u64) -> PathBuf {
        self.client_cert_dir().join(format!("client{slot}.crt"))
    }

    pub fn client_key_path(&self, slot: u64) -> PathBuf {
        self.client_key_dir().join(format!("client{slot}.der"))
    }

    pub fn node_dir(&self, party: usize) -> PathBuf {
        self.root.join("nodes").join(format!("party{party}"))
    }

    pub fn node_log(&self, party: usize) -> PathBuf {
        self.node_dir(party).join("node.log")
    }

    pub fn control_dir(&self, party: usize) -> PathBuf {
        self.node_dir(party).join("control")
    }

    /// The lock every [`StandingAdmitter`] of this mesh publishes under.
    pub fn admission_lock(&self) -> PathBuf {
        self.root.join("admit.lock")
    }

    /// Facts that must stay the same across restarts of the mesh.
    fn state_path(&self) -> PathBuf {
        self.root.join("mesh-state.json")
    }

    fn runtime_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// Copy a compiled program into the mesh under its content address and
    /// return its program ID. Nodes only see programs installed before they
    /// start.
    pub fn install_program(&self, bytes: &[u8]) -> StandingMeshResult<[u8; 32]> {
        let program_id = program_id_from_bytes(bytes);
        let directory = self.programs_dir();
        create_dir(&directory)?;
        let path = directory.join(format!("{}.stflb", hex::encode(program_id)));
        if !path.is_file() {
            write_atomically(&path, bytes)?;
        }
        Ok(program_id)
    }

    /// Whether a program with this ID is installed.
    pub fn has_program(&self, program_id: [u8; 32]) -> bool {
        self.programs_dir()
            .join(format!("{}.stflb", hex::encode(program_id)))
            .is_file()
    }
}

/// What it takes to start a mesh.
#[derive(Debug, Clone)]
pub struct StandingMeshConfig {
    /// The `stoffel-run` binary each party runs.
    pub runner_path: PathBuf,
    pub layout: StandingMeshLayout,
    pub parties: usize,
    pub threshold: usize,
    /// Client identities to create, at least. The mesh always has one per
    /// client slot any of its programs declares.
    pub min_clients: usize,
    pub reservoir_burst_capacity: usize,
    pub allow_dynamic_preprocessing: bool,
    /// How long the parties may take to form the mesh and warm every program's
    /// preprocessing reservoir.
    pub startup_timeout: Duration,
}

impl StandingMeshConfig {
    pub fn new(runner_path: impl Into<PathBuf>, layout: StandingMeshLayout) -> Self {
        Self {
            runner_path: runner_path.into(),
            layout,
            parties: 5,
            threshold: 1,
            min_clients: 0,
            reservoir_burst_capacity: 9,
            allow_dynamic_preprocessing: false,
            startup_timeout: Duration::from_secs(600),
        }
    }
}

/// How to reach a running mesh. Everything a client or admitter needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingMeshInfo {
    pub layout: StandingMeshLayout,
    pub parties: usize,
    pub threshold: usize,
    pub coordinator: SocketAddr,
    /// Mask-RPC address of each party, by party ID.
    pub node_rpc: Vec<SocketAddr>,
    /// Mesh address of each party, which output-only clients open their
    /// execution route to.
    pub node_mesh: Vec<SocketAddr>,
    /// Client slots with an identity in the mesh.
    pub client_slots: Vec<u64>,
    /// Programs the nodes loaded, by hex program ID.
    pub programs: Vec<String>,
    /// The process that owns the coordinator and the nodes.
    pub pid: u32,
}

impl StandingMeshInfo {
    pub fn admitter(&self) -> StandingAdmitter {
        StandingAdmitter::new(
            (0..self.parties)
                .map(|party| self.layout.control_dir(party))
                .collect(),
            self.layout.admission_lock(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MeshState {
    parties: usize,
    threshold: usize,
    pool_id: ExecutionId,
    auth_token: String,
}

struct Node {
    party: usize,
    child: Child,
    ready_marker: PathBuf,
}

/// A running mesh. Dropping it kills the nodes; prefer [`Self::shutdown`].
pub struct StandingMesh {
    info: StandingMeshInfo,
    nodes: Vec<Node>,
    coordinator: Option<OffChainCoordinatorServer<HoneyBadgerCoordinatorConnection>>,
}

impl StandingMesh {
    /// Validate the installed programs, create or reuse identities, start the
    /// coordinator and every party, and return once every party is ready.
    pub async fn start(config: StandingMeshConfig) -> StandingMeshResult<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if config.parties == 0 || config.threshold == 0 || config.threshold >= config.parties {
            return Err(StandingMeshError::Configuration(format!(
                "need 0 < threshold < parties, got {} parties with threshold {}",
                config.parties, config.threshold
            )));
        }
        let layout = &config.layout;
        create_dir(layout.root())?;

        let catalog = if config.allow_dynamic_preprocessing {
            StandingProgramCatalog::load_with_dynamic_preprocessing(&layout.programs_dir())
        } else {
            StandingProgramCatalog::load(&layout.programs_dir())
        }
        .map_err(|error| StandingMeshError::Programs(error.to_string()))?;
        let programs = catalog.programs().collect::<Vec<_>>();
        if programs.is_empty() {
            return Err(StandingMeshError::Programs(format!(
                "no programs are installed in {}",
                layout.programs_dir().display()
            )));
        }

        let state = load_or_create_state(layout, config.parties, config.threshold)?;
        let node_public_keys = ensure_node_identities(layout, config.parties)?;
        let client_slots = ensure_client_identities(layout, &programs, config.min_clients)?;
        let (coordinator_cert, coordinator_key) = ensure_coordinator_identity(layout)?;
        let runtime = layout.runtime_dir();
        let _ = fs::remove_dir_all(&runtime);
        create_dir(&runtime)?;

        // Ports are reserved by binding them and released just before use. A
        // process that grabs one in between makes a node fail to bind, which is
        // reported like any other startup failure.
        let coordinator_port = free_tcp_port()?;
        let leader_port = reserve_leader_ports()?;
        let mut mesh_ports = vec![leader_port];
        for _ in 1..config.parties {
            mesh_ports.push(free_udp_port()?);
        }
        let rpc_ports = (0..config.parties)
            .map(|_| free_tcp_port())
            .collect::<StandingMeshResult<Vec<_>>>()?;

        let shared = HoneyBadgerCoordinatorRPCServerSharedBase::new(
            config.parties as u64,
            config.threshold as u64,
            node_public_keys,
        )
        .map_err(|error| StandingMeshError::Coordinator(error.to_string()))?;
        let coordinator =
            OffChainCoordinatorServer::<HoneyBadgerCoordinatorConnection>::start_coord(
                shared,
                "127.0.0.1",
                coordinator_port,
                config.threshold as u64,
                coordinator_cert,
                coordinator_key,
            )
            .await
            .map_err(|error| StandingMeshError::Coordinator(error.to_string()))?;

        let localhost = |port: u16| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let info = StandingMeshInfo {
            layout: layout.clone(),
            parties: config.parties,
            threshold: config.threshold,
            coordinator: localhost(coordinator_port),
            node_rpc: rpc_ports.iter().copied().map(localhost).collect(),
            // The leader's bootnode owns its configured port; the leader joins
            // the mesh 1000 ports above it.
            node_mesh: mesh_ports
                .iter()
                .enumerate()
                .map(|(party, port)| localhost(if party == 0 { port + 1000 } else { *port }))
                .collect(),
            client_slots,
            programs: programs
                .iter()
                .map(|program| hex::encode(program.program_id))
                .collect(),
            pid: std::process::id(),
        };
        let mut mesh = Self {
            info,
            nodes: Vec::with_capacity(config.parties),
            coordinator: Some(coordinator),
        };

        let deadline = Instant::now() + config.startup_timeout;
        let bootnode_marker = runtime.join("party0.bootnode-ready");
        let leader = mesh.spawn_node(
            &config,
            &state,
            0,
            &mesh_ports,
            &rpc_ports,
            &bootnode_marker,
        )?;
        mesh.nodes.push(leader);
        if let Err(error) = mesh
            .wait_for_marker(
                0,
                &bootnode_marker,
                "bootnode startup",
                deadline,
                config.startup_timeout,
            )
            .await
        {
            mesh.shutdown().await;
            return Err(error);
        }
        for party in 1..config.parties {
            match mesh.spawn_node(
                &config,
                &state,
                party,
                &mesh_ports,
                &rpc_ports,
                &bootnode_marker,
            ) {
                Ok(node) => mesh.nodes.push(node),
                Err(error) => {
                    mesh.shutdown().await;
                    return Err(error);
                }
            }
        }
        for party in 0..config.parties {
            let marker = mesh.nodes[party].ready_marker.clone();
            if let Err(error) = mesh
                .wait_for_marker(
                    party,
                    &marker,
                    "standing node startup",
                    deadline,
                    config.startup_timeout,
                )
                .await
            {
                mesh.shutdown().await;
                return Err(error);
            }
        }
        Ok(mesh)
    }

    pub fn info(&self) -> &StandingMeshInfo {
        &self.info
    }

    /// Resolve when a party exits. A mesh missing a party cannot run anything,
    /// so the caller should shut the mesh down.
    pub async fn wait_for_failure(&mut self) -> StandingMeshError {
        loop {
            for index in 0..self.nodes.len() {
                if let Some(error) = self.check_exited(index, "standing operation") {
                    return error;
                }
            }
            tokio::time::sleep(POLL_INTERVAL * 5).await;
        }
    }

    /// Stop every party, then the coordinator.
    pub async fn shutdown(&mut self) {
        for node in &self.nodes {
            if let Some(pid) = node.child.id() {
                // SAFETY: `kill` only sends a signal to the child we spawned.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
            }
        }
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        for node in &mut self.nodes {
            if tokio::time::timeout_at(deadline, node.child.wait())
                .await
                .is_err()
            {
                let _ = node.child.kill().await;
            }
        }
        self.nodes.clear();
        if let Some(coordinator) = self.coordinator.take() {
            coordinator.shutdown().await;
        }
    }

    fn spawn_node(
        &self,
        config: &StandingMeshConfig,
        state: &MeshState,
        party: usize,
        mesh_ports: &[u16],
        rpc_ports: &[u16],
        bootnode_marker: &Path,
    ) -> StandingMeshResult<Node> {
        let layout = &config.layout;
        let node_dir = layout.node_dir(party);
        let preproc = node_dir.join("preproc");
        create_dir(&preproc)?;
        let log_path = layout.node_log(party);
        let log = File::options()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|source| io_error(&log_path, source))?;
        let stderr = log
            .try_clone()
            .map_err(|source| io_error(&log_path, source))?;
        let ready_marker = layout.runtime_dir().join(format!("party{party}.ready"));
        let localhost = |port: u16| SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string();

        let mut command = Command::new(&config.runner_path);
        command
            .arg("--standing-node")
            .arg("--control-dir")
            .arg(layout.control_dir(party))
            .arg("--program-dir")
            .arg(layout.programs_dir())
            .arg("--client-cert-dir")
            .arg(layout.client_cert_dir())
            .arg("--party-cert-dir")
            .arg(layout.party_cert_dir())
            .arg("--reservoir-burst-capacity")
            .arg(config.reservoir_burst_capacity.to_string())
            .arg("--pool-id")
            .arg(state.pool_id.to_string())
            .arg("--off-chain-coord")
            .arg(self.info.coordinator.to_string())
            .arg("--rpc-bind")
            .arg(localhost(rpc_ports[party]))
            .arg("--party-id")
            .arg(party.to_string())
            .arg("--bind")
            .arg(localhost(mesh_ports[party]))
            .arg("--advertise")
            .arg(self.info.node_mesh[party].to_string())
            .arg("--n-parties")
            .arg(config.parties.to_string())
            .arg("--threshold")
            .arg(config.threshold.to_string())
            .arg("--cert")
            .arg(layout.party_cert_dir().join(format!("cert{party}.crt")))
            .arg("--key")
            .arg(layout.party_cert_dir().join(format!("key{party}.der")))
            .arg("--preproc-store")
            .arg(&preproc)
            .arg("--local-store")
            .arg(node_dir.join("local.redb"))
            .env("STOFFEL_AUTH_TOKEN", &state.auth_token)
            .env("STOFFEL_STANDING_READY_FILE", &ready_marker)
            // Tie the party to this process's lifetime, including a SIGKILL of
            // this process, where `kill_on_drop` cannot run.
            .env("STOFFEL_DIE_WITH_PARENT", "1")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr));
        if party == 0 {
            command
                .arg("--leader")
                .env("STOFFEL_LOCAL_BOOTNODE_READY_FILE", bootnode_marker);
        } else {
            command.arg("--bootstrap").arg(localhost(mesh_ports[0]));
        }
        if config.allow_dynamic_preprocessing {
            command.arg("--allow-dynamic-preprocessing");
        }
        let child = command
            .spawn()
            .map_err(|source| io_error(&config.runner_path, source))?;
        Ok(Node {
            party,
            child,
            ready_marker,
        })
    }

    async fn wait_for_marker(
        &mut self,
        party: usize,
        marker: &Path,
        phase: &'static str,
        deadline: Instant,
        timeout: Duration,
    ) -> StandingMeshResult<()> {
        loop {
            if marker.is_file() {
                return Ok(());
            }
            for index in 0..self.nodes.len() {
                if let Some(error) = self.check_exited(index, phase) {
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                return Err(StandingMeshError::Timeout {
                    party,
                    phase,
                    timeout,
                    log: self.info.layout.node_log(party),
                });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn check_exited(&mut self, index: usize, phase: &'static str) -> Option<StandingMeshError> {
        let node = &mut self.nodes[index];
        match node.child.try_wait() {
            Ok(Some(status)) => {
                let log = self.info.layout.node_log(node.party);
                Some(StandingMeshError::NodeExited {
                    party: node.party,
                    status,
                    phase,
                    tail: log_tail(&log),
                    log,
                })
            }
            Ok(None) | Err(_) => None,
        }
    }
}

fn load_or_create_state(
    layout: &StandingMeshLayout,
    parties: usize,
    threshold: usize,
) -> StandingMeshResult<MeshState> {
    let path = layout.state_path();
    match fs::read(&path) {
        Ok(bytes) => {
            let state: MeshState = serde_json::from_slice(&bytes).map_err(|error| {
                StandingMeshError::Configuration(format!("read {}: {error}", path.display()))
            })?;
            if state.parties != parties || state.threshold != threshold {
                return Err(StandingMeshError::Configuration(format!(
                    "the mesh in {} was created with {} parties and threshold {}; start it with the same values or use a new mesh",
                    layout.root().display(),
                    state.parties,
                    state.threshold
                )));
            }
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let state = MeshState {
                parties,
                threshold,
                pool_id: ExecutionId::new(),
                auth_token: ExecutionId::new().to_string(),
            };
            let bytes = serde_json::to_vec_pretty(&state).map_err(|error| {
                StandingMeshError::Configuration(format!("encode mesh state: {error}"))
            })?;
            write_atomically(&path, &bytes)?;
            Ok(state)
        }
        Err(source) => Err(io_error(&path, source)),
    }
}

/// Create party identities that do not exist yet and return every party's
/// public key, which the coordinator authenticates the parties by.
fn ensure_node_identities(
    layout: &StandingMeshLayout,
    parties: usize,
) -> StandingMeshResult<Vec<Vec<u8>>> {
    let directory = layout.party_cert_dir();
    create_dir(&directory)?;
    (0..parties)
        .map(|party| {
            let cert_path = directory.join(format!("cert{party}.crt"));
            let key_path = directory.join(format!("key{party}.der"));
            let cert_der = ensure_identity(&cert_path, &key_path)?;
            public_key_from_cert(&cert_der, &cert_path)
        })
        .collect()
}

/// Create one client identity per client slot any program declares (and at
/// least `min_clients`), and return the slots that have one.
fn ensure_client_identities(
    layout: &StandingMeshLayout,
    programs: &[Arc<StandingProgram>],
    min_clients: usize,
) -> StandingMeshResult<Vec<u64>> {
    let mut slots = (0..min_clients as u64).collect::<BTreeSet<_>>();
    for program in programs {
        slots.extend(
            program
                .client_io_manifest
                .clients
                .iter()
                .map(|schema| schema.client_slot),
        );
    }
    create_dir(&layout.client_cert_dir())?;
    create_dir(&layout.client_key_dir())?;
    for &slot in &slots {
        ensure_identity(
            &layout.client_cert_path(slot),
            &layout.client_key_path(slot),
        )?;
    }
    Ok(slots.into_iter().collect())
}

fn ensure_coordinator_identity(
    layout: &StandingMeshLayout,
) -> StandingMeshResult<(Vec<u8>, Vec<u8>)> {
    let directory = layout.root().join("ids");
    create_dir(&directory)?;
    let cert_path = directory.join("coordinator.crt");
    let key_path = directory.join("coordinator.der");
    if cert_path.is_file() && key_path.is_file() {
        return Ok((read(&cert_path)?, read(&key_path)?));
    }
    let certified = self_signed_certs::server_cert();
    let cert = certified.cert.der().to_vec();
    let key = certified.signing_key.serialize_der();
    write_atomically(&key_path, &key)?;
    write_atomically(&cert_path, &cert)?;
    Ok((cert, key))
}

/// Return the certificate at `cert_path`, creating a self-signed identity there
/// and at `key_path` if either is missing.
fn ensure_identity(cert_path: &Path, key_path: &Path) -> StandingMeshResult<Vec<u8>> {
    if cert_path.is_file() && key_path.is_file() {
        return read(cert_path);
    }
    let certified = self_signed_certs::client_cert();
    let cert = certified.cert.der().to_vec();
    write_atomically(key_path, &certified.signing_key.serialize_der())?;
    write_atomically(cert_path, &cert)?;
    Ok(cert)
}

fn public_key_from_cert(cert_der: &[u8], path: &Path) -> StandingMeshResult<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|error| {
        StandingMeshError::Configuration(format!("parse {}: {error:?}", path.display()))
    })?;
    Ok(cert.public_key().subject_public_key.data.as_ref().to_vec())
}

fn free_tcp_port() -> StandingMeshResult<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|source| io_error(Path::new("127.0.0.1:0/tcp"), source))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|source| io_error(Path::new("127.0.0.1:0/tcp"), source))
}

fn free_udp_port() -> StandingMeshResult<u16> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|source| io_error(Path::new("127.0.0.1:0/udp"), source))?;
    socket
        .local_addr()
        .map(|address| address.port())
        .map_err(|source| io_error(Path::new("127.0.0.1:0/udp"), source))
}

/// A UDP port for the leader's bootnode whose +1000 neighbour, where the leader
/// joins the mesh, is free too.
fn reserve_leader_ports() -> StandingMeshResult<u16> {
    let sockets = crate::local_runner::reserve_udp_port_pair()
        .map_err(|source| io_error(Path::new("127.0.0.1/udp"), source))?;
    sockets[0]
        .local_addr()
        .map(|address| address.port())
        .map_err(|source| io_error(Path::new("127.0.0.1/udp"), source))
}

fn log_tail(path: &Path) -> String {
    let Ok(log) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines = log.lines().collect::<Vec<_>>();
    lines[lines.len().saturating_sub(LOG_TAIL_LINES)..].join("\n")
}

fn read(path: &Path) -> StandingMeshResult<Vec<u8>> {
    fs::read(path).map_err(|source| io_error(path, source))
}

fn create_dir(path: &Path) -> StandingMeshResult<()> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))
}

fn write_atomically(path: &Path, bytes: &[u8]) -> StandingMeshResult<()> {
    if let Some(parent) = path.parent() {
        create_dir(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|source| io_error(&temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: std::io::Error) -> StandingMeshError {
    StandingMeshError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installing_a_program_stores_it_under_its_content_address() {
        let temporary = tempfile::tempdir().unwrap();
        let layout = StandingMeshLayout::new(temporary.path());
        let program_id = layout.install_program(b"not really a program").unwrap();
        assert!(layout.has_program(program_id));
        assert!(layout
            .programs_dir()
            .join(format!("{}.stflb", hex::encode(program_id)))
            .is_file());
        // Installing it again is a no-op.
        assert_eq!(
            layout.install_program(b"not really a program").unwrap(),
            program_id
        );
    }

    #[test]
    fn mesh_state_is_reused_and_must_keep_its_topology() {
        let temporary = tempfile::tempdir().unwrap();
        let layout = StandingMeshLayout::new(temporary.path());
        let first = load_or_create_state(&layout, 4, 1).unwrap();
        assert_eq!(load_or_create_state(&layout, 4, 1).unwrap(), first);
        let error = load_or_create_state(&layout, 5, 1).unwrap_err();
        assert!(error.to_string().contains("4 parties"), "{error}");
    }

    #[test]
    fn identities_are_created_once_and_then_reused() {
        let temporary = tempfile::tempdir().unwrap();
        let layout = StandingMeshLayout::new(temporary.path());
        let first = ensure_node_identities(&layout, 3).unwrap();
        assert_eq!(first.len(), 3);
        assert_eq!(ensure_node_identities(&layout, 3).unwrap(), first);
        assert!(layout.party_cert_dir().join("cert2.crt").is_file());
        assert!(layout.party_cert_dir().join("key2.der").is_file());

        let slots = ensure_client_identities(&layout, &[], 2).unwrap();
        assert_eq!(slots, vec![0, 1]);
        // The client certificate directory holds certificates only: nodes
        // parse every file in it as a client identity.
        let mut names = fs::read_dir(layout.client_cert_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, vec!["client0.crt", "client1.crt"]);
        assert!(layout.client_key_path(1).is_file());
    }
}
