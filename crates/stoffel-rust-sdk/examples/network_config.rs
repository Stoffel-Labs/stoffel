use stoffel::prelude::*;

fn main() -> stoffel::Result<()> {
    let deployment = NetworkDeployment::builder([
        "127.0.0.1:19200",
        "127.0.0.1:19201",
        "127.0.0.1:19202",
        "127.0.0.1:19203",
        "127.0.0.1:19204",
    ])
    .expected_clients(1)
    .threshold(1)
    .backend(MpcBackend::HoneyBadger)
    .preprocessing(1000, 500)
    .build()?;

    let config_dir = std::env::temp_dir().join("stoffel-sdk-network-configs");
    let paths = deployment.save_toml_files(&config_dir)?;
    let reparsed = NetworkConfig::from_toml_file(&paths[0])?;
    let _ = std::fs::remove_dir_all(&config_dir);

    let server = StoffelServer::builder(0)
        .network_deployment(&deployment)
        .build()?;
    // Network configs describe the servers' deployment. A client never dials
    // the node mesh: it reaches an execution through the coordinator, with an
    // `OffChainClientConfig` (see the `client_server` example).
    println!(
        "Configured party {} on {} with {} peer(s); reparsed party {} config",
        server.party_id(),
        server.bind_addr(),
        server.peers().len(),
        reparsed.party_id()
    );
    Ok(())
}
