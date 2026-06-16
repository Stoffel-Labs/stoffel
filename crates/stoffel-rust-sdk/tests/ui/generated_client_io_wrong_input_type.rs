mod bindings {
    include!("../fixtures/mpc_client_federated_average_bindings.rs");
}

use bindings::Client0Inputs;

fn main() {
    let _inputs = Client0Inputs {
        input_0: 1_i64,
        input_1: 2.0,
        input_2: 3.0,
        input_3: 4.0,
        input_4: 5.0,
        input_5: 6.0,
    };
}
