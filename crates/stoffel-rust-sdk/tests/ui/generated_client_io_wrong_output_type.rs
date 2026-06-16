mod bindings {
    include!("../fixtures/mpc_client_federated_average_bindings.rs");
}

use bindings::{Client0Inputs, Client0Outputs};

struct WrongOutputs {
    output_0: i64,
}

async fn run(client: stoffel::StoffelClient) -> stoffel::Result<()> {
    let _outputs: WrongOutputs = client
        .run_typed::<Client0Inputs, Client0Outputs>(Client0Inputs {
            input_0: 1.0,
            input_1: 2.0,
            input_2: 3.0,
            input_3: 4.0,
            input_4: 5.0,
            input_5: 6.0,
        })
        .await?;
    Ok(())
}

fn main() {}
