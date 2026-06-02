use std::time::Duration;

use stoffel::prelude::*;
use tracing::Level;

fn main() -> stoffel::Result<()> {
    let tracing = TracingConfig::builder()
        .service_name("stoffel-observability-example")
        .max_level(Level::INFO)
        .ansi(false)
        .build();
    println!(
        "Tracing service={} level={:?}",
        tracing.service_name(),
        tracing.max_level()
    );
    println!("Tracing summary: {:?}", tracing.summary());

    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:19400")
        .with_preprocessing(100, 50)
        .build()?;

    server.metrics().record_connected_peers(4);
    server.metrics().record_connected_clients(1);
    server.metrics().record_preprocessing_remaining(80, 40);
    server
        .metrics()
        .record_computation_latency(Duration::from_millis(25));
    server.metrics().increment_computations_completed();

    let snapshot = server.metrics().snapshot();
    println!(
        "health={} peers={} completed={}",
        server.health(),
        snapshot.connected_peers,
        snapshot.computations_completed
    );

    let error = Error::Preprocessing("not enough triples".to_owned());
    println!(
        "error_category={} recoverable={} hint={:?}",
        error.category(),
        error.is_recoverable(),
        error.recovery_hint()
    );

    Ok(())
}
