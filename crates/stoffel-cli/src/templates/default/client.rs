//! Example participant-owned application boundary.
//!
//! Follow the `INTEGRATION STEP` comments when moving this flow into your app.
//! Guide: https://docs.stoffelmpc.com/rust-sdk/app-integration

#[path = "main.rs"]
mod app;

use app::bindings::{Client0Inputs, Client0Outputs};

/// Maps one application value through the generated Stoffel client contract.
async fn run_private_feature(input: i64) -> Result<i64, Box<dyn std::error::Error>> {
    // INTEGRATION STEP 4: map your domain type into generated client inputs.
    let inputs = Client0Inputs { input_0: input };

    // The participant-owned process submits directly to the MPC services.
    let output: Client0Outputs = app::client()?.run_typed(inputs).await?;

    // Map the authorized typed output back into your application's domain type.
    Ok(output.output_0)
}

/// CLI shell for the example. Replace this with your UI, service, or device flow.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "42".to_owned())
        .parse::<i64>()?;

    println!("Doubled result: {}", run_private_feature(input).await?);
    Ok(())
}