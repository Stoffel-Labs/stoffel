use std::collections::HashMap;
use std::time::Duration;

use stoffel_vm_runner::{
    run_on_standing_mesh, LocalClientInput, StandingMesh, StandingMeshConfig, StandingMeshLayout,
    StandingRunRequest, StandingRunTimeouts,
};
use stoffel_vm_types::compiled_binary::MpcBackend;

const PARTIES: usize = 5;
const THRESHOLD: usize = 1;

/// Two input clients, one of them also receiving the sum.
const SUM_OF_THREE: &str = r#"
def main() -> int64:
  var a = ClientStore.take_share(0, 0)
  var b = ClientStore.take_share(1, 0)
  var c = ClientStore.take_share(1, 1)
  var sum = a.add(b).add(c)
  sum.send_to_client(0)
  return sum.open()
"#;

/// No clients at all; the result is only the VM return.
const NO_CLIENTS: &str = "def main() -> int64:\n  var share = Share.from_clear_int(6, 64)\n  var product = share.mul(Share.from_clear_int(7, 64))\n  return product.open()";

/// A client that only receives.
const OUTPUT_ONLY: &str = "def main() -> int64:\n  var share = Share.from_clear_int(7, 64)\n  MpcOutput.send_to_client(0, [share])\n  return 7";

fn compile(source: &str, backend: MpcBackend) -> Vec<u8> {
    let options = stoffellang::CompilerOptions {
        mpc_backend: backend,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<standing-mesh-e2e>", &options).unwrap();
    let mut bytes = Vec::new();
    stoffellang::convert_to_binary(&compiled)
        .serialize(&mut std::io::Cursor::new(&mut bytes))
        .unwrap();
    bytes
}

fn config(layout: &StandingMeshLayout) -> StandingMeshConfig {
    let mut config = StandingMeshConfig::new(env!("CARGO_BIN_EXE_stoffel-run"), layout.clone());
    config.parties = PARTIES;
    config.threshold = THRESHOLD;
    config.reservoir_burst_capacity = 4;
    config.startup_timeout = Duration::from_secs(300);
    config
}

fn request(program_id: [u8; 32], inputs: Vec<LocalClientInput>) -> StandingRunRequest {
    StandingRunRequest {
        program_id,
        entry: "main".to_owned(),
        client_inputs: inputs,
        client_output_counts: HashMap::new(),
        timeouts: StandingRunTimeouts::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real standing mesh of stoffel-run processes"]
async fn parallel_executions_share_one_standing_mesh_and_survive_a_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let layout = StandingMeshLayout::new(temporary.path());
    let sum = layout
        .install_program(&compile(SUM_OF_THREE, MpcBackend::HoneyBadger))
        .unwrap();
    let output_only = layout
        .install_program(&compile(OUTPUT_ONLY, MpcBackend::HoneyBadger))
        .unwrap();
    let no_clients = layout
        .install_program(&compile(NO_CLIENTS, MpcBackend::HoneyBadger))
        .unwrap();

    let mut mesh = StandingMesh::start(config(&layout))
        .await
        .expect("start the standing mesh");
    let info = mesh.info().clone();
    assert_eq!(info.client_slots, vec![0, 1]);
    let pids = info.pid;

    // Three executions at once: the same program with different inputs, and
    // another program whose only client receives.
    let (first, second, third) = tokio::join!(
        run_on_standing_mesh(
            &info,
            request(
                sum,
                vec![
                    LocalClientInput::new(0, [1]),
                    LocalClientInput::new(1, [2, 3])
                ]
            )
        ),
        run_on_standing_mesh(
            &info,
            request(
                sum,
                vec![
                    LocalClientInput::new(0, [10]),
                    LocalClientInput::new(1, [20, 30])
                ]
            )
        ),
        run_on_standing_mesh(&info, request(output_only, Vec::new())),
    );
    let first = first.expect("first sum");
    let second = second.expect("second sum");
    let third = third.expect("output-only run");
    assert_ne!(first.execution_id, second.execution_id);
    assert_eq!(first.client_outputs.len(), 1);
    assert_eq!(first.client_outputs[0].client_slot, 0);
    assert_eq!(first.client_outputs[0].values, vec![6]);
    assert_eq!(second.client_outputs[0].values, vec![60]);
    assert_eq!(third.client_outputs[0].values, vec![7]);
    assert_eq!(first.returned_value, "6");
    assert_eq!(second.returned_value, "60");
    assert_eq!(third.returned_value, "7");

    // A program without any client still reports what it returned.
    let clientless = run_on_standing_mesh(&info, request(no_clients, Vec::new()))
        .await
        .expect("client-free run");
    assert!(clientless.client_outputs.is_empty());
    assert_eq!(clientless.returned_value, "42");

    // Bad inputs are refused before anything is admitted.
    let error = run_on_standing_mesh(&info, request(sum, vec![LocalClientInput::new(0, [1])]))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("client slot 1"), "{error}");

    mesh.shutdown().await;

    // A restarted mesh reuses its identities and keeps serving.
    let mut mesh = StandingMesh::start(config(&layout))
        .await
        .expect("restart the standing mesh");
    assert_eq!(mesh.info().pid, pids);
    let again = run_on_standing_mesh(
        mesh.info(),
        request(
            sum,
            vec![
                LocalClientInput::new(0, [4]),
                LocalClientInput::new(1, [5, 6]),
            ],
        ),
    )
    .await
    .expect("sum after restart");
    assert_eq!(again.client_outputs[0].values, vec![15]);
    assert_eq!(again.returned_value, "15");
    mesh.shutdown().await;
}
