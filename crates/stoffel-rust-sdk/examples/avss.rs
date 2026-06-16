use stoffel::prelude::*;

#[tokio::main]
async fn main() -> stoffel::Result<()> {
    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:19300")
        .avss(Curve::Bls12_381)
        .build()?;

    let engine = server.create_avss_engine().await?;
    println!("Live AVSS engine: {}", engine.is_live());
    match engine.generate_random_share("threshold-key").await {
        Ok(()) => println!("Generated AVSS key on {:?}", engine.curve()),
        Err(error) => println!("Attach a live VM AVSS engine before protocol operations: {error}"),
    }
    Ok(())
}
