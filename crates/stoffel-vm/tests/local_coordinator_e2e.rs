use std::collections::HashMap;
use std::time::Duration;

use stoffel_vm::net::{
    LocalClientInput, LocalCoordinatorRunOutput, LocalCoordinatorRunner, LocalPartyOutput,
    MpcBackendKind, MpcCurveConfig,
};
use stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema, CompiledBinary};
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh"]
async fn local_offchain_coordinator_runs_networked_vm_without_docker_compose() {
    let function = VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    );
    let binary = CompiledBinary::from_vm_functions(&[function]);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local coordinator run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
    assert!(
        output
            .combined_output
            .contains("coordinator -> MPCExecution"),
        "expected leader to drive the off-chain coordinator into MPCExecution; output:\n{}",
        output.combined_output
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh"]
async fn local_offchain_coordinator_runs_avss_networked_vm_without_docker_compose() {
    let function = VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    );
    let mut binary = CompiledBinary::from_vm_functions(&[function]);
    binary.client_io_manifest.mpc_backend = stoffel_vm_types::compiled_binary::MpcBackend::Avss;

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local AVSS coordinator run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh"]
async fn local_offchain_coordinator_runs_compiled_avss_networked_vm_without_docker_compose() {
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::Avss,
        ..Default::default()
    };
    let compiled = stoffellang::compile(
        "def main() -> int64:\n  return 7",
        "<local-avss-runner-e2e>",
        &options,
    )
    .expect("compile AVSS no-input program");
    let binary = stoffellang::convert_to_binary(&compiled);
    assert_eq!(
        binary.client_io_manifest.mpc_backend,
        stoffel_vm_types::compiled_binary::MpcBackend::Avss
    );

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local compiled AVSS coordinator run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, AVSS MPC party mesh, and coordinator client"]
async fn local_offchain_coordinator_submits_avss_clientstore_inputs_without_docker_compose() {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::Avss,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-avss-runner-client-e2e>", &options)
        .expect("compile AVSS client input program");
    let binary = stoffellang::convert_to_binary(&compiled);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .client_inputs([LocalClientInput::raw(0, ["42"])])
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local AVSS coordinator client input run");

    assert_eq!(output.returned_values(), vec!["47", "47", "47", "47", "47"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["47"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn local_offchain_coordinator_submits_clientstore_inputs_without_docker_compose() {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-e2e>", &options)
        .expect("compile client input program");
    let binary = stoffellang::convert_to_binary(&compiled);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .client_inputs([LocalClientInput::raw(0, ["42"])])
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local coordinator run");

    assert_eq!(output.returned_values(), vec!["47", "47", "47", "47", "47"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["47"]);
    assert!(
        output
            .combined_output
            .contains("coordinator -> MPCExecution"),
        "expected leader to drive the off-chain coordinator into MPCExecution; output:\n{}",
        output.combined_output
    );
}

#[test]
fn local_run_output_reports_consistent_party_return_values() {
    let output = LocalCoordinatorRunOutput {
        combined_output: "Program returned: 5\nProgram returned: 5\n".to_owned(),
        party_outputs: vec![
            party_output("party0", "Program returned: 5\n"),
            party_output("party1", "Program returned: 5\n"),
        ],
    };

    assert_eq!(output.returned_values(), vec!["5", "5"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["5"]);
}

#[test]
fn local_run_output_rejects_inconsistent_party_return_values() {
    let output = LocalCoordinatorRunOutput {
        combined_output: "Program returned: 5\nProgram returned: 6\n".to_owned(),
        party_outputs: vec![
            party_output("party0", "Program returned: 5\n"),
            party_output("party1", "Program returned: 6\n"),
        ],
    };

    let err = output.consistent_returned_values().unwrap_err();
    assert!(
        err.contains("returned"),
        "expected consistency error, got: {err}"
    );
}

fn party_output(name: &str, combined: &str) -> LocalPartyOutput {
    LocalPartyOutput {
        name: name.to_owned(),
        stdout: combined.to_owned(),
        stderr: String::new(),
        combined: combined.to_owned(),
    }
}

#[test]
fn local_runner_rejects_missing_clientstore_inputs_before_spawning_parties() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        }],
    };

    let err = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .build()
        .unwrap_err();

    assert!(
        err.to_string().contains("provide local client inputs"),
        "unexpected error: {err}"
    );
}

#[test]
fn local_runner_accepts_static_output_only_clients_without_inputs() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: Vec::new(),
            outputs: vec![ShareType::default_secret_int()],
        }],
    };

    LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .build()
        .expect("output-only client manifests should not require client input");
}

#[test]
fn local_runner_rejects_expected_output_clients_below_static_manifest_slots() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 2,
            inputs: Vec::new(),
            outputs: vec![ShareType::default_secret_int()],
        }],
    };

    let err = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .expected_output_clients(2)
        .build()
        .unwrap_err();

    assert!(
        err.to_string().contains("expected_clients >= 3"),
        "unexpected error: {err}"
    );
}

#[test]
fn local_runner_rejects_duplicate_client_input_slots() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        }],
    };

    let err = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .client_inputs([LocalClientInput::new(0, [1]), LocalClientInput::new(0, [2])])
        .build()
        .unwrap_err();

    assert!(
        err.to_string().contains("provided more than once"),
        "unexpected error: {err}"
    );
}
