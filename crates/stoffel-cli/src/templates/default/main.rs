//! Reusable client-side Stoffel integration.
//!
//! This module joins exact bytecode, generated types, deployment endpoints, and
//! participant identity material. Application feature code belongs in the caller.
//! Guide: https://docs.stoffelmpc.com/rust-sdk/app-integration

use serde::Deserialize;
use std::path::{Path, PathBuf};
use stoffel::prelude::{NetworkDeployment, Stoffel, StoffelClient};

// INTEGRATION STEP 3: these types are generated from artifacts/program.stflb.
// Rebuild bytecode before `cargo build` whenever ClientStore or MpcOutput changes.
#[allow(dead_code, unused_mut, unused_variables)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/stoffel_bindings.rs"));
}

/// App-facing deployment inputs needed to connect a participant client.
///
/// The single-host development deployment writes this shape to
/// deploy/local/deployment.json. In an operator-managed environment, supply
/// equivalent endpoints and identity paths through your deployment system.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    program: PathBuf,
    coordinator_host: String,
    coordinator_port: u16,
    timestamp: u64,
    parties: usize,
    threshold: usize,
    node_bind_addresses: Vec<String>,
    servers: Vec<String>,
    node_rpc_addresses: Vec<String>,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl Deployment {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        if config.node_bind_addresses.len() != config.parties
            || config.servers.len() != config.parties
            || config.node_rpc_addresses.len() != config.parties
        {
            return Err("deployment address counts must match mpc.parties".into());
        }
        let root = path.parent().unwrap_or(Path::new("."));
        config.program = root.join(config.program);
        config.client_cert = root.join(config.client_cert);
        config.client_key = root.join(config.client_key);
        Ok(config)
    }
}

/// INTEGRATION STEP 4: build an ephemeral participant client for long-lived services.
///
/// Keep this function in the participant-owned application process. It loads the
/// same bytecode used by the services, validates it with the generated manifest,
/// and connects client slot 0 to the configured coordinator and node RPC endpoints.
pub fn client() -> Result<StoffelClient, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = std::env::var_os("STOFFEL_DEPLOYMENT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/local/deployment.json")
        });
    let config = Deployment::load(&config_path)?;

    // Exact bytecode + generated manifest form the client/application contract.
    let runtime = Stoffel::load_file(&config.program)?
        .manifest::<bindings::ProgramManifest>()
        .parties(config.parties)
        .threshold(config.threshold)
        .build()?;

    // NetworkDeployment describes the independently operated MPC service plane.
    let network = NetworkDeployment::builder(config.servers)
        .expected_clients(1)
        .threshold(config.threshold)
        .honeybadger()
        .build()?;

    // Off-chain config binds this participant slot to endpoints and identity.
    let offchain = runtime
        .offchain_client_config(0)?
        .coordinator(config.coordinator_host, config.coordinator_port)
        .timestamp(config.timestamp)
        .node_rpc_addresses(config.node_rpc_addresses)
        .identity_files(config.client_cert, config.client_key)
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    Ok(runtime
        .client_for_deployment(&network)
        // Keep this client id aligned with ClientStore slot 0 and Client0Inputs.
        .client_id(0)
        .offchain_io(offchain)
        .build()?)
}