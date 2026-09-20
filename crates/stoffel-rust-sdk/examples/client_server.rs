use std::time::Duration;

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
    .honeybadger()
    .consensus_timeout(Duration::from_secs(60))
    .preprocessing(1000, 500)
    .build()?;

    let runtime = Stoffel::compile(
        "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
    )?
    .build()?;

    let server_builders = runtime.servers_for_deployment(&deployment);
    let server = server_builders[0].clone().build()?;
    // A client reaches the execution through the coordinator only: it pins
    // the coordinator's certificate, associates with the execution, and uses
    // the slot, input range and outputs its admission names. Its node RPC
    // addresses are hints; every leg is pinned to the coordinator's node
    // roster. Here the coordinator certificate and the client identity are
    // minted in place; a deployment reads its own.
    let coordinator_cert = stoffel_mpc_coordinator_shared::self_signed_certs::server_cert();
    let client_identity = stoffel_mpc_coordinator_shared::self_signed_certs::client_cert();
    let client_config = OffChainClientConfig::builder()
        .coordinator("127.0.0.1", 31415)
        .coordinator_cert_der(coordinator_cert.cert.der().to_vec())
        .execution_id_hex("0707070707070707070707070707070707070707070707070707070707070707")
        .honeybadger()
        .node_rpc_addresses([
            "127.0.0.1:10000",
            "127.0.0.1:10001",
            "127.0.0.1:10002",
            "127.0.0.1:10003",
            "127.0.0.1:10004",
        ])
        .identity_der(
            client_identity.cert.der().to_vec(),
            client_identity.signing_key.serialize_der(),
        )
        .build()?;
    let client = runtime.client().offchain_io(client_config).build()?;

    println!(
        "Configured party {} on {} with {} peer(s); client configured for execution {}",
        server.party_id(),
        server.bind_addr(),
        server.peers().len(),
        client
            .offchain_io()
            .map(|config| config.execution_id.to_string())
            .unwrap_or_default()
    );
    Ok(())
}
