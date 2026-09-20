use std::collections::HashMap;
use std::num::NonZeroU64;
use std::time::Duration;

use ark_bls12_381::Fr;
use stoffel_mpc_coordinator_off_chain::OffChainCoordinatorClient;
use stoffel_mpc_coordinator_shared::{
    self_signed_certs, AdmissionError, AdmissionPolicyKind, AssociationRequest, ClientIndex,
    ClientSlotSpec, CoordinatorError, InputRange, OutputRights, SpkiDer,
};
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm_runner::{
    run_offchain_client, CoordinatorClientError, LocalAdmission, LocalClientInput,
    LocalCoordinatorRunOutput, LocalCoordinatorRunner, LocalCoordinatorRunnerError,
    LocalPartyOutput, LocalTopology,
};
use stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema, CompiledBinary};
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

/// A five-party HoneyBadger run over a real localhost coordinator, end to end.
///
/// This case used to have a bootnode twin it was compared against; Stage 8 of
/// `docs/design/bootnode-elimination.md` deleted the bootnode, so the twin is
/// gone and the mesh assertions moved here. They are kept as *positive and
/// negative* pairs — "forming a roster-pinned mesh" appears, "connecting to
/// bootnode" does not — because a regression that reintroduced a bootstrap step
/// would otherwise still satisfy every value assertion.
///
/// A mesh that forms only *most* of the time is the one way this can turn green
/// stacks red, so run it in a loop (10+ consecutive passes) whenever anything
/// under `net/mesh/` changes, not once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and a roster-pinned MPC party mesh"]
async fn local_offchain_coordinator_runs_networked_vm_over_a_roster_mesh() {
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
        // Named rather than left to the default, so that a future second
        // topology cannot silently take this case over.
        .topology(LocalTopology::RosterMesh)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local coordinator mesh run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
    // Assert on what the run actually *prints*, not on the flag spelling:
    // `--bootstrap` is now refused by name, so it appears in no successful run's
    // output at all. This line is emitted by the party itself, at the point it
    // picks a join.
    assert!(
        output
            .combined_output
            .contains("forming a roster-pinned mesh"),
        "the mesh path must form a roster-pinned mesh; output:\n{}",
        output.combined_output
    );
    assert!(
        !output.combined_output.contains("connecting to bootnode"),
        "no party may dial a bootstrap process; output:\n{}",
        output.combined_output
    );
    // Membership is the coordinator's node roster, fetched once by every party
    // (docs/design/bootnode-elimination.md §9.D.1), never a list a party carries.
    assert_eq!(
        output
            .combined_output
            .matches("serves 5 nodes (n=5, t=1, digest=")
            .count(),
        5,
        "every party must fetch the coordinator's node roster exactly once; output:\n{}",
        output.combined_output
    );
    assert!(
        output
            .combined_output
            .contains("coordinator -> MPCExecution"),
        "expected the parties to propose the off-chain coordinator into MPCExecution \
         — since Stage 9 every party proposes and the coordinator applies the round at \
         quorum, so this line must appear whoever got there first; output:\n{}",
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
    // Pre-registered is still a coordinator decision, not node configuration
    // (decision 3 of docs/design/bootnode-elimination.md §9): the client's
    // certificate goes to the coordinator's registration alone, and no party's
    // transport allowlist names it. A party's allowlist is the coordinator's
    // node roster and nothing else (§9.D.4), so what is asserted is that every
    // party installed exactly that: five nodes.
    assert!(
        output
            .combined_output
            .contains("serves 5 nodes (n=5, t=1, digest="),
        "every party's allowlist is the coordinator's five-node roster; output:\n{}",
        output.combined_output
    );
}

/// §9.D.7 step 12 of `docs/design/bootnode-elimination.md`: a client output
/// comes only from `send_to_client`, delivered by the agreed admission's slot,
/// and the run still reaches `ProgramFinished` and returns its revealed value.
/// The returned share is not broadcast to output clients any more, so the
/// client receives exactly its admitted `output_count` of one value — a
/// second, broadcast share would make `obtain_outputs` ignore every node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn local_offchain_coordinator_delivers_send_to_client_outputs_by_admitted_slot() {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  MpcOutput.send_to_client(0, [share])
  var opened: int64 = share.open()
  return opened + 5
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-output-e2e>", &options)
        .expect("compile client output program");
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
        .expect("local coordinator client output run");

    assert_eq!(output.consistent_returned_values().unwrap(), vec!["47"]);
    let delivered: Vec<(u64, Vec<u64>)> = output
        .client_outputs
        .iter()
        .map(|record| (record.client_slot, record.values.clone()))
        .collect();
    assert_eq!(delivered, vec![(0, vec![42])]);
}

/// Decision 3 of `docs/design/bootnode-elimination.md` §9: a computation takes
/// clients whose identities are not known in advance. Under
/// `LocalAdmission::Open` the runner mints no client certificate and no party
/// is told one; two clients with certificates minted here, after the run
/// started, bind their slots at runtime — one by number, one as the first
/// free slot — and every party reveals `client[0] - client[1]` by the slot
/// each client bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and two unregistered clients"]
async fn local_offchain_coordinator_admits_unknown_clients_under_open_admission() {
    let source = r#"
def main() -> int64:
  var first = ClientStore.take_share(0, 0)
  var second = ClientStore.take_share(1, 0)
  var difference = first - second
  var opened: int64 = difference.open()
  return opened
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-open-e2e>", &options)
        .expect("compile open admission program");
    let binary = stoffellang::convert_to_binary(&compiled);
    let timeout = Duration::from_secs(180);

    let running = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(timeout)
        .admission(LocalAdmission::Open)
        .build()
        .expect("local runner config")
        .start()
        .await
        .expect("start the open-admission run");
    let endpoint = running.client_endpoint().clone();

    // Identities nobody configured: minted after the coordinator registered
    // the execution and every party started.
    let mint = || {
        let certified = self_signed_certs::client_cert();
        (
            certified.cert.der().to_vec(),
            certified.signing_key.serialize_der(),
        )
    };
    let (slot_one_cert, slot_one_key) = mint();
    let (first_free_cert, first_free_key) = mint();
    let slot_one_inputs = ["15".to_owned()];
    let first_free_inputs = ["25".to_owned()];

    let clients = async {
        tokio::join!(
            run_offchain_client(
                &endpoint,
                slot_one_cert,
                slot_one_key,
                AssociationRequest {
                    slot: Some(ClientIndex(1)),
                    invitation: None,
                },
                &slot_one_inputs,
                timeout,
            ),
            run_offchain_client(
                &endpoint,
                first_free_cert,
                first_free_key,
                AssociationRequest {
                    slot: None,
                    invitation: None,
                },
                &first_free_inputs,
                timeout,
            ),
        )
    };
    let (output, (slot_one, first_free)) = tokio::join!(running.finish(), clients);
    let output = output.expect("open-admission run");
    let slot_one = slot_one.expect("the client asking for slot 1 is admitted to it");
    let first_free = first_free.expect("the client asking for any slot is admitted");

    assert_eq!(slot_one.admission.client_index, ClientIndex(1));
    assert_eq!(first_free.admission.client_index, ClientIndex(0));
    assert!(slot_one.outputs.is_empty() && first_free.outputs.is_empty());
    // client[0] - client[1], by the slot each client bound: 25 - 15.
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["10"]);
    assert!(
        output
            .combined_output
            .contains("serves 5 nodes (n=5, t=1, digest="),
        "every party's allowlist is the coordinator's five-node roster under open admission; \
         output:\n{}",
        output.combined_output
    );
}

/// The required end-to-end test of `docs/design/bootnode-elimination.md` §9.H:
/// a client whose identity is not known in advance associates with an execution
/// under `Open` admission, provides its input and receives its output.
///
/// Its certificate is minted with `rcgen` only after the coordinator registered
/// the execution and every party started, so it cannot appear in any flag,
/// environment variable, file or registration of the run — and the
/// registration names no identity at all. No party's transport allowlist can
/// hold it either: a party installs the coordinator's node roster and nothing
/// else. Its participation is exactly the admission the coordinator records
/// when it associates, enforced by the nodes at the application layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and an unconfigured client"]
async fn local_offchain_coordinator_admits_an_unconfigured_client_under_open_admission() {
    // 1. One slot: one input, and the input's share sent back to the client.
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  MpcOutput.send_to_client(0, [share])
  var opened: int64 = share.open()
  return opened + 5
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-unconfigured-client-e2e>", &options)
        .expect("compile the one-slot client program");
    let binary = stoffellang::convert_to_binary(&compiled);
    let timeout = Duration::from_secs(180);

    // 2. An in-process coordinator registering one slot `1:1` under `Open`,
    //    and five real `stoffel-run` parties.
    let running = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(timeout)
        .admission(LocalAdmission::Open)
        .build()
        .expect("local runner config")
        .start()
        .await
        .expect("start the open-admission run");
    let endpoint = running.client_endpoint().clone();
    let coordinator_pin = SpkiDer::from_certificate_der(&endpoint.coordinator_cert_der)
        .expect("the run's coordinator certificate pins");

    // 3. Only now: the client's identity.
    let mint = || {
        let certified = rcgen::generate_simple_self_signed(vec!["unconfigured-client".to_owned()])
            .expect("mint a client certificate");
        (
            certified.cert.der().to_vec(),
            certified.signing_key.serialize_der(),
        )
    };
    let (cert_der, key_der) = mint();
    let request = AssociationRequest {
        slot: None,
        invitation: None,
    };
    let connect = |cert_der: Vec<u8>, key_der: Vec<u8>| {
        let endpoint = &endpoint;
        let coordinator_pin = &coordinator_pin;
        async move {
            OffChainCoordinatorClient::<Fr, RobustShare<Fr>>::start_rpc_client_for_execution(
                &endpoint.coordinator.ip().to_string(),
                endpoint.coordinator.port(),
                coordinator_pin,
                None,
                endpoint.execution_id,
                cert_der,
                key_der,
            )
            .await
            .expect("a pinned connection to the run's coordinator")
        }
    };

    // 4. Associate, pinned to the endpoint's coordinator certificate.
    let admission = {
        let mut client = connect(cert_der.clone(), key_der.clone()).await;
        let summary = client
            .get_execution_summary()
            .await
            .expect("the execution summary");
        assert_eq!(summary.admission, AdmissionPolicyKind::Open);
        assert!(
            summary.deadlines.is_some(),
            "an Open registration carries deadlines"
        );
        assert_eq!(
            summary.client_slots.slots(),
            &[ClientSlotSpec {
                input_count: 1,
                output_count: 1
            }]
        );
        let admission = client
            .associate_client(request.clone())
            .await
            .expect("an unconfigured client associates under Open");
        assert_eq!(admission.client_index, ClientIndex(0));
        assert_eq!(
            admission.input_range,
            Some(InputRange {
                start: 0,
                count: NonZeroU64::new(1).unwrap(),
            })
        );
        assert_eq!(
            admission.output_rights,
            OutputRights::Receive {
                output_count: NonZeroU64::new(1).unwrap(),
            }
        );
        admission
    };

    // 5. A second unconfigured client finds the one slot taken. Deterministic:
    //    the first client has not reserved, so no honest node can have proposed
    //    InputCollection, and association is still open.
    {
        let (other_cert, other_key) = mint();
        let mut other = connect(other_cert, other_key).await;
        let refusal = other
            .associate_client(request.clone())
            .await
            .expect_err("a second client past capacity is refused");
        assert!(
            matches!(
                refusal,
                CoordinatorError::Admission(AdmissionError::CapacityExhausted { capacity: 1, .. })
            ),
            "{refusal:?}"
        );
    }

    // 6. The identical request again is the idempotent association; one signed
    //    submission; the output from five signed per-node items.
    let inputs = ["42".to_owned()];
    let (output, client) = tokio::join!(
        running.finish(),
        run_offchain_client(&endpoint, cert_der, key_der, request, &inputs, timeout),
    );
    let client = client.expect("the unconfigured client provides its input and gets its output");
    assert_eq!(client.admission, admission);
    assert_eq!(client.outputs, vec![42]);
    let output = output.expect("open-admission run with an unconfigured client");
    assert_eq!(output.returned_values(), vec!["47", "47", "47", "47", "47"]);
    assert!(
        output
            .combined_output
            .contains("serves 5 nodes (n=5, t=1, digest="),
        "every party's allowlist is the coordinator's five-node roster; output:\n{}",
        output.combined_output
    );
}

/// §9.E.1 step 5, this repository's own cover for the client-leg pin
/// (docs/design/bootnode-elimination.md §9.H): a client's node RPC addresses
/// are hints, and every leg is pinned to a member of the roster the pinned
/// coordinator served. A node RPC listener presenting a certificate minted
/// here — no roster member — is refused as `ServerPinMismatch`, not believed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and an impostor node RPC listener"]
async fn a_local_client_refuses_a_node_rpc_listener_outside_the_served_roster() {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-impostor-leg-e2e>", &options)
        .expect("compile the one-slot client program");
    let binary = stoffellang::convert_to_binary(&compiled);
    let timeout = Duration::from_secs(120);

    let running = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(timeout)
        .admission(LocalAdmission::Open)
        .build()
        .expect("local runner config")
        .start()
        .await
        .expect("start the open-admission run");

    let impostor = rcgen::generate_simple_self_signed(vec!["impostor-node".to_owned()])
        .expect("mint an impostor certificate");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("reserve a port")
        .port();
    let _impostor = stoffel_mpc_coordinator_off_chain::node_rpc::NodeRPCServer::start(
        "127.0.0.1",
        port,
        impostor.cert.der().to_vec(),
        impostor.signing_key.serialize_der(),
    )
    .await
    .expect("start the impostor node RPC listener");

    let mut endpoint = running.client_endpoint().clone();
    endpoint.node_rpc_addresses[0] = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let client = rcgen::generate_simple_self_signed(vec!["client".to_owned()])
        .expect("mint a client certificate");
    let refused = run_offchain_client(
        &endpoint,
        client.cert.der().to_vec(),
        client.signing_key.serialize_der(),
        AssociationRequest {
            slot: None,
            invitation: None,
        },
        &["42".to_owned()],
        timeout,
    )
    .await
    .expect_err("a leg answered by a key outside the roster is refused");
    assert!(
        matches!(
            refused,
            LocalCoordinatorRunnerError::Client(CoordinatorClientError::NodeRpc(
                CoordinatorError::ServerPinMismatch { .. }
            ))
        ),
        "{refused:?}"
    );
    // The run is abandoned: dropping it kills every party.
    drop(running);
}

/// The same open-admission contract through the `stoffel-run` client, which is
/// what the Docker stacks run: each unregistered client names its slot with
/// `--client-slot` (`STOFFEL_CLIENT_SLOT`), pins the coordinator with
/// `--coord-cert`, and is admitted by the slot it asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and two stoffel-run clients"]
async fn stoffel_run_clients_bind_the_open_slots_they_name() {
    let source = r#"
def main() -> int64:
  var first = ClientStore.take_share(0, 0)
  var second = ClientStore.take_share(1, 0)
  var difference = first - second
  var opened: int64 = difference.open()
  return opened
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-open-cli-e2e>", &options)
        .expect("compile open admission program");
    let binary = stoffellang::convert_to_binary(&compiled);
    let timeout = Duration::from_secs(180);

    let running = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(timeout)
        .admission(LocalAdmission::Open)
        .build()
        .expect("local runner config")
        .start()
        .await
        .expect("start the open-admission run");
    let endpoint = running.client_endpoint().clone();

    let dir = std::env::temp_dir().join(format!("stoffel-open-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create client dir");
    let coord_cert = dir.join("coordinator.crt");
    std::fs::write(&coord_cert, &endpoint.coordinator_cert_der).expect("write coordinator.crt");
    let servers = endpoint
        .node_rpc_addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let client = |name: &str, slot: u32, input: &str| {
        let certified = self_signed_certs::client_cert();
        let cert = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.der"));
        std::fs::write(&cert, certified.cert.der()).expect("write client cert");
        std::fs::write(&key, certified.signing_key.serialize_der()).expect("write client key");
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_stoffel-run"));
        command
            .arg("--client")
            .arg("--inputs")
            .arg(input)
            .arg("--servers")
            .arg(&servers)
            .arg("--mpc-backend")
            .arg("honeybadger")
            .arg("--off-chain-coord")
            .arg(endpoint.coordinator.to_string())
            .arg("--coord-cert")
            .arg(&coord_cert)
            .arg("--execution-id")
            .arg(endpoint.execution_id.to_string())
            .arg("--cert")
            .arg(&cert)
            .arg("--key")
            .arg(&key)
            .arg("--client-slot")
            .arg(slot.to_string())
            .kill_on_drop(true);
        async move {
            tokio::time::timeout(timeout, command.output())
                .await
                .expect("stoffel-run client finishes")
                .expect("spawn stoffel-run client")
        }
    };

    let (output, first, second) = tokio::join!(
        running.finish(),
        client("slot0", 0, "15"),
        client("slot1", 1, "25"),
    );
    let _ = std::fs::remove_dir_all(&dir);
    for (name, client) in [("slot0", &first), ("slot1", &second)] {
        assert!(
            client.status.success(),
            "{name} client failed: {}",
            String::from_utf8_lossy(&client.stderr)
        );
    }
    let output = output.expect("open-admission run");
    // client[0] - client[1], by the slot each client named: 15 - 25.
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["-10"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and long-running MPC AES party mesh"]
async fn local_offchain_coordinator_runs_optimized_aes_circuit_without_docker_compose() {
    // Compiling the optimized AES circuit recurses deeply (the inlined S-box
    // network) and overflows the default test-thread stack, so do it on a
    // dedicated large-stack thread. `CompiledBinary` is `Send`, so the result
    // crosses back to this async context.
    let binary = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(|| {
            let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
            let options = stoffellang::CompilerOptions {
                optimize: true,
                mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
                ..Default::default()
            };
            let compiled = stoffellang::compile(source, "<local-runner-aes-e2e>", &options)
                .expect("compile AES");
            stoffellang::convert_to_binary(&compiled)
        })
        .expect("spawn AES compile thread")
        .join()
        .expect("AES compile thread panicked");

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(1800))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local AES coordinator run");

    assert_eq!(output.consistent_returned_values().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh"]
async fn local_offchain_coordinator_runs_honeybadger_batch_mul_40_without_docker_compose() {
    let source = r#"
def main() -> int64:
  var lefts: list[Share] = []
  var rights: list[Share] = []
  for i in 0..40:
    lefts.append(Share.from_clear_int(i % 2, 1))
    rights.append(Share.from_clear_int(1, 1))
  var products = Share.batch_mul(lefts, rights)
  return products[39].open()
"#;
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-batch-mul-40-e2e>", &options)
        .expect("compile batch mul 40");
    let binary = stoffellang::convert_to_binary(&compiled);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(900))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local batch mul coordinator run");

    assert_eq!(output.consistent_returned_values().unwrap(), vec!["true"]);
}

#[test]
fn local_run_output_reports_consistent_party_return_values() {
    let output = LocalCoordinatorRunOutput {
        combined_output: "Program returned: 5\nProgram returned: 5\n".to_owned(),
        party_outputs: vec![
            party_output("party0", "Program returned: 5\n"),
            party_output("party1", "Program returned: 5\n"),
        ],
        client_outputs: Vec::new(),
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
        client_outputs: Vec::new(),
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
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
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
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
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
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
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
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
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
