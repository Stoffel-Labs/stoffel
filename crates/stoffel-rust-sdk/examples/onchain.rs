use stoffel::prelude::*;

#[tokio::main]
async fn main() -> stoffel::Result<()> {
    let handle = OnChainCoordinatorHandle::new("0x0000000000000000000000000000000000000000");

    match handle.current_round().await {
        Ok(round) => println!("Current round: {round:?}"),
        Err(error) => println!("On-chain provider not configured: {error}"),
    }

    let Some(endpoint) = std::env::var("STOFFEL_ONCHAIN_WS").ok() else {
        println!("Set STOFFEL_ONCHAIN_WS and STOFFEL_ONCHAIN_PRIVATE_KEY to connect a provider");
        return Ok(());
    };
    let Some(private_key) = std::env::var("STOFFEL_ONCHAIN_PRIVATE_KEY").ok() else {
        println!("Set STOFFEL_ONCHAIN_PRIVATE_KEY to connect a provider");
        return Ok(());
    };

    let config = OnChainCoordinatorConfig::builder()
        .contract_address("0x0000000000000000000000000000000000000000")
        .websocket_endpoint(endpoint)
        .wallet_private_key(private_key)
        .threshold(1)
        .output_count(1)
        .honeybadger()
        .build()?;

    let _coordinator = config.connect_honeybadger().await?;
    println!("Connected provider-backed on-chain coordinator");
    Ok(())
}
