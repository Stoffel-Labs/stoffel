//! Long-lived MPC node process.
//!
//! Application feature logic does not belong here. Nodes load the compiled
//! program and deployment configuration, then serve participant clients.
//! Guide: https://docs.stoffelmpc.com/developer-skills/stoffel-app-network-and-offchain-integration

use serde::Deserialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use stoffel::prelude::{OffChainServerConfig, Stoffel, StoffelServer};

#[derive(Clone, Deserialize)]
struct ProjectConfig {
    mpc: MpcConfigFile,
}

#[derive(Clone, Deserialize)]
struct MpcConfigFile {
    parties: usize,
    threshold: usize,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn settings() -> Result<MpcConfigFile, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(project_root().join("Stoffel.toml"))?;
    Ok(toml::from_str::<ProjectConfig>(&text)?.mpc)
}

fn env_or(name: &str, fallback: String) -> String {
    std::env::var(name).unwrap_or(fallback)
}

/// Resolves an MPC listener or bootstrap address to the numeric socket address
/// the node runtime requires.
///
/// Numeric addresses pass through unchanged. A host name (for example a
/// Compose service name) is resolved once at startup, preferring IPv4 so every
/// node picks the same address family. The bootnode hands each node's bind
/// address to the other parties, so a host name must resolve to an address
/// they can reach.
fn resolve_socket_address(
    label: &str,
    address: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(numeric) = address.parse::<SocketAddr>() {
        return Ok(numeric);
    }
    let candidates: Vec<SocketAddr> = address
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve MPC {label} address {address}: {error}"))?
        .collect();
    let resolved = candidates
        .iter()
        .find(|candidate| candidate.is_ipv4())
        .or_else(|| candidates.first())
        .copied()
        .ok_or_else(|| format!("MPC {label} address {address} resolved to no socket addresses"))?;
    if resolved.ip().is_unspecified() || resolved.ip().is_loopback() {
        return Err(format!(
            "MPC {label} address {address} resolved to {resolved}, which other nodes cannot reach; \
             use a host name that resolves to a routable address or a numeric address"
        )
        .into());
    }
    Ok(resolved)
}

#[derive(Deserialize)]
struct DeploymentAddresses {
    coordinator_host: String,
    coordinator_port: u16,
    timestamp: u64,
    node_bind_addresses: Vec<String>,
    servers: Vec<String>,
    node_rpc_addresses: Vec<String>,
}

fn identity_path(party_id: usize, suffix: &str) -> PathBuf {
    project_root().join(format!("deploy/local/node-{party_id}.{suffix}.der"))
}

fn client_certificate() -> PathBuf {
    project_root().join("deploy/local/client-0.cert.der")
}

fn deployment_addresses() -> Result<DeploymentAddresses, Box<dyn std::error::Error>> {
    let path = project_root().join("deploy/local/deployment.json");
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

pub async fn start_party(party_id: usize) -> Result<StoffelServer, Box<dyn std::error::Error>> {
    let config = settings()?;
    let deployment = deployment_addresses()?;
    if party_id >= config.parties {
        return Err(format!("party {party_id} is outside mpc.parties={}", config.parties).into());
    }
    if deployment.node_bind_addresses.len() != config.parties
        || deployment.servers.len() != config.parties
        || deployment.node_rpc_addresses.len() != config.parties
    {
        return Err("deployment address counts must match mpc.parties".into());
    }

    let artifact = project_root().join("artifacts/program.stflb");
    if !artifact.exists() {
        return Err("missing artifacts/program.stflb; run `stoffel build --output artifacts/program.stflb` first".into());
    }
    // INTEGRATION STEP 5: every node loads the same artifact as the client.
    let runtime = Stoffel::load_file(&artifact)?
        .parties(config.parties)
        .threshold(config.threshold)
        .build()?;
    let offchain = OffChainServerConfig::builder()
        .coordinator(env_or(
            "STOFFEL_COORDINATOR_ADDRESS",
            format!(
                "{}:{}",
                deployment.coordinator_host, deployment.coordinator_port
            ),
        ))
        .rpc_bind(env_or(
            "STOFFEL_RPC_BIND_ADDRESS",
            deployment.node_rpc_addresses[party_id].clone(),
        ))
        .identity_files(
            identity_path(party_id, "cert"),
            identity_path(party_id, "key"),
        )
        .timestamp(deployment.timestamp)
        .expected_client_cert(client_certificate())
        .build()?;

    // Other parties dial the address this node binds: the bootnode records it
    // and announces it to the session. Party 0's party listener uses the bind
    // port + 1000; the bind port itself serves the bootnode.
    let bind_address = resolve_socket_address(
        "bind",
        &env_or(
            "STOFFEL_BIND_ADDRESS",
            deployment.node_bind_addresses[party_id].clone(),
        ),
    )?;

    let mut builder = runtime
        .server(party_id)
        .bind(bind_address)
        .peers(
            (0..config.parties)
                .filter(|peer_id| *peer_id != party_id)
                .map(|peer_id| (peer_id, deployment.servers[peer_id].clone())),
        )
        .expected_clients(1)
        .offchain_coordinator(offchain);
    if party_id > 0 {
        let bootstrap_address = resolve_socket_address(
            "bootstrap",
            &env_or(
                "STOFFEL_BOOTSTRAP_ADDRESS",
                deployment.node_bind_addresses[0].clone(),
            ),
        )?;
        builder = builder.bootstrap(bootstrap_address.to_string());
    }
    if let Some(path) = std::env::var_os("STOFFEL_RUN_BIN") {
        builder = builder.runner_path(path);
    }
    let server = builder.build()?;
    server.start().await?;
    Ok(server)
}

pub async fn start_all() -> Result<Vec<StoffelServer>, Box<dyn std::error::Error>> {
    let config = settings()?;
    let mut servers = Vec::with_capacity(config.parties);
    for party_id in 0..config.parties {
        servers.push(start_party(party_id).await?);
    }
    wait_for_rpc_services(config.parties).await?;
    Ok(servers)
}

async fn wait_for_rpc_services(parties: usize) -> Result<(), Box<dyn std::error::Error>> {
    let deployment = deployment_addresses()?;
    let deadline = Instant::now() + Duration::from_secs(90);
    for party_id in 0..parties {
        let address = &deployment.node_rpc_addresses[party_id];
        loop {
            if tokio::net::TcpStream::connect(&address).await.is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for MPC node RPC at {address}").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(())
}

pub async fn shutdown_all(servers: Vec<StoffelServer>) -> Result<(), Box<dyn std::error::Error>> {
    for server in servers.into_iter().rev() {
        server.shutdown().await?;
    }
    Ok(())
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let party_id = std::env::args()
        .nth(1)
        .ok_or("usage: stoffel-server <party-id>")?
        .parse::<usize>()?;
    let server = start_party(party_id).await?;
    eprintln!("MPC server {party_id} started; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    server.shutdown().await?;
    Ok(())
}
