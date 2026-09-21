#[path = "main.rs"]
mod app;

use app::bindings::{Client0Inputs, Client0Outputs};

/// This participant-owned client may connect, submit, receive its authorized
/// output, and exit without controlling the coordinator or MPC nodes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "42".to_owned())
        .parse::<i64>()?;
    let output: Client0Outputs = app::client()?
        .run_typed(Client0Inputs { input_0: input })
        .await?;

    println!("Doubled result: {}", output.output_0);
    Ok(())
}