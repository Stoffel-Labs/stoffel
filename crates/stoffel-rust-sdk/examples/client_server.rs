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
    let client = runtime
        .client_for_deployment(&deployment)
        .client_id(7)
        .build()?;

    println!(
        "Configured party {} on {} with {} peer(s); client {} sees {} server(s)",
        server.party_id(),
        server.bind_addr(),
        server.peers().len(),
        client.client_id(),
        client.servers().len()
    );
    Ok(())
}
