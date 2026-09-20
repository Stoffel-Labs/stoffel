//! `stoffel-run`'s coordinator pin (`--coord-cert`) and the node roster it
//! fetches, exercised through the binary.
//!
//! `docs/design/bootnode-elimination.md` §9.A and §9.D: a coordinator connection
//! exists only with a pin, a pin that cannot be loaded is a configuration error
//! (exit 2) naming its file, and a coordinator that presents another key is refused
//! before any RPC (exit 13). The coordinator is the only roster authority: a party
//! fetches the node roster from it once, before it binds anything, refuses to run
//! when its own certificate is not in it or when it is not the roster
//! `--expect-*` describe, and every flag that gave a node a roster, a party count,
//! a threshold or a client list of its own fails by name (§9.D.3). A client
//! reaches an execution only through the coordinator (§9.E.3).

use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use stoffel_mpc_coordinator_off_chain::{
    CoordinatorRPCServerSharedBase, ExecutionRegistration, OffChainCoordinatorClient,
    OffChainCoordinatorConnection, OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_shared::rpc::RpcServerLimits;
use stoffel_mpc_coordinator_shared::self_signed_certs;
use stoffel_mpc_coordinator_shared::{
    AdmissionPolicy, AssociationRequest, ClientIndex, ClientSlotSpec, ClientSlotTable,
    ExecutionDeadlines, ExecutionId, NodeCertificateDer, NodeRoster, SpkiDer, UnixSeconds,
};
use stoffel_vm_types::compiled_binary::utils::save_to_file;

const EXECUTION_ID: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn ids_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ids")
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stoffel-run-coordinator-pin-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Runs `stoffel-run` as a client with `extra` flags, bounded so a regression that
/// connects instead of refusing cannot hang the suite. `--execution-id` is passed
/// exactly when `extra` names a coordinator, since it is refused without one.
async fn run_client(extra: &[&str]) -> Output {
    let ids = ids_dir();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_stoffel-run"));
    command
        .arg("--client")
        .arg("--inputs")
        .arg("1")
        .arg("--cert")
        .arg(ids.join("clients/cert0.crt"))
        .arg("--key")
        .arg(ids.join("clients/key0.der"))
        .args(extra)
        .kill_on_drop(true);
    if extra.contains(&"--off-chain-coord") {
        command.arg("--execution-id").arg(EXECUTION_ID);
    }
    tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("stoffel-run must refuse promptly, not connect and wait")
        .expect("spawn stoffel-run")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn off_chain_coord_without_a_pin_is_refused() {
    let output = run_client(&["--off-chain-coord", "127.0.0.1:9"]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--off-chain-coord requires --coord-cert <path>"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_coord_cert_without_a_coordinator_is_refused() {
    let cert = ids_dir().join("server_cert.crt");
    let output = run_client(&["--coord-cert", cert.to_str().expect("utf-8 path")]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--coord-cert is only meaningful with --off-chain-coord"),
        "{stderr}"
    );
}

#[tokio::test]
async fn an_unreadable_coord_cert_names_its_path() {
    let missing = scratch_dir("unreadable").join("no-such-coordinator.crt");
    let missing = missing.to_str().expect("utf-8 path");
    let output = run_client(&["--off-chain-coord", "127.0.0.1:9", "--coord-cert", missing]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!("cannot read --coord-cert {missing}")),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_coord_cert_that_is_not_a_certificate_is_refused() {
    let dir = scratch_dir("garbage");
    // A private key is the likeliest wrong file to be named here.
    let not_a_cert = dir.join("server_key.der");
    std::fs::copy(ids_dir().join("server_key.der"), &not_a_cert).expect("copy key fixture");
    let not_a_cert = not_a_cert.to_str().expect("utf-8 path");
    let output = run_client(&[
        "--off-chain-coord",
        "127.0.0.1:9",
        "--coord-cert",
        not_a_cert,
    ])
    .await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "--coord-cert {not_a_cert} is not a usable DER X.509 certificate"
        )),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_coordinator_presenting_another_key_is_refused_with_exit_13() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ids = ids_dir();

    let roster = NodeRoster::new(
        1,
        (0..5)
            .map(|index| {
                NodeCertificateDer::from_der(
                    std::fs::read(ids.join(format!("nodes/cert{index}.crt")))
                        .expect("read node certificate fixture"),
                )
            })
            .collect(),
    )
    .expect("the five fixture nodes form a roster at t = 1");
    let client_identity = SpkiDer::from_certificate_der(
        &std::fs::read(ids.join("clients/cert0.crt")).expect("read client certificate fixture"),
    )
    .expect("fixture client certificate")
    .client_identity();

    // The coordinator actually listening: a fresh key, which the pinned
    // fixture certificate does not name.
    let served = self_signed_certs::server_cert();
    let served_der = served.cert.der().to_vec();
    let served_spki = SpkiDer::from_certificate_der(&served_der).expect("fresh certificate");
    let execution_id: ExecutionId = EXECUTION_ID.parse().expect("execution id");
    let state = CoordinatorRPCServerSharedBase::new_for_execution(
        roster,
        served_spki,
        ExecutionRegistration {
            execution_id,
            program_hash: [1; 32],
            client_slots: ClientSlotTable::new(vec![ClientSlotSpec {
                input_count: 1,
                output_count: 0,
            }]),
            admission: AdmissionPolicy::PreRegistered {
                clients: vec![client_identity],
            },
            deadlines: None,
        },
    )
    .expect("valid registration");
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("reserve a port")
        .port();
    let _coordinator = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
        state,
        "127.0.0.1",
        port,
        served_der,
        served.signing_key.serialize_der(),
        RpcServerLimits::default(),
    )
    .await
    .expect("start the coordinator");

    let pinned = ids.join("server_cert.crt");
    let pinned = pinned.to_str().expect("utf-8 path");
    let address = format!("127.0.0.1:{port}");
    let output = run_client(&[
        "--off-chain-coord",
        &address,
        "--coord-cert",
        pinned,
        "--servers",
        "127.0.0.1:9",
    ])
    .await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(13), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "Error: the coordinator at {address} presented a key that --coord-cert {pinned} does \
             not pin. Refusing to fetch a roster from it."
        )),
        "{stderr}"
    );
}

/// `--client-slot` names a coordinator client slot, so it is refused where there
/// is no coordinator to bind one, rather than ignored.
#[tokio::test]
async fn a_client_slot_without_a_coordinator_is_refused() {
    let output = run_client(&["--client-slot", "1"]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--client-slot is only meaningful for a coordinator client"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_client_slot_that_is_not_a_slot_number_is_refused() {
    let output = run_client(&["--client-slot", "first"]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--client-slot takes a slot number"),
        "{stderr}"
    );
}

/// Every flag design doc §9.D.3 removes, with the hint it fails with. The hints
/// are the contract: none of them names a flag of this table, so an operator
/// following one refusal is never sent to the next.
const REMOVED_FLAGS: [(&str, &str, &str); 12] = [
    (
        "--roster",
        "ids/nodes/cert0.crt",
        "Membership is the coordinator's node roster, fetched once at startup. Pass \
         --off-chain-coord, --coord-cert and --execution-id instead.",
    ),
    (
        "--expected-clients",
        "ids/clients/cert0.crt",
        "Client certificates no longer enter a node's transport allowlist. Clients associate \
         with an execution through the coordinator, and nodes read the admissions from it.",
    ),
    (
        "--wait-for-clients",
        "1",
        "Clients no longer connect to the node mesh. They associate through the coordinator and \
         fetch their masks from the nodes' --rpc-bind listeners.",
    ),
    (
        "--client-roster",
        "0",
        "The client slot layout is the coordinator's execution registration.",
    ),
    (
        "--client-input-slots",
        "0",
        "The client slot layout is the coordinator's execution registration.",
    ),
    (
        "--client-input-count",
        "1",
        "The client slot layout is the coordinator's execution registration.",
    ),
    (
        "--client-input-total",
        "1",
        "The client slot layout is the coordinator's execution registration.",
    ),
    (
        "--n-parties",
        "5",
        "n and t come from the coordinator's node roster. To refuse a roster of another size, \
         pass --expect-n-parties and --expect-threshold.",
    ),
    (
        "--threshold",
        "1",
        "n and t come from the coordinator's node roster. To refuse a roster of another size, \
         pass --expect-n-parties and --expect-threshold.",
    ),
    (
        "--timestamp",
        "0",
        "No coordinator takes a timestamp; an execution's deadlines are part of its \
         registration. Remove the flag.",
    ),
    // §9.E.2: a client's input range and output count are its admission's.
    (
        "--client-index",
        "0",
        "The coordinator assigns each client's input range when it associates. Pass \
         --client-slot <index> to ask for a specific slot.",
    ),
    (
        "--outputs",
        "1",
        "A client's output count comes from its admission.",
    ),
];

/// Retargets `a_coordinated_party_refuses_every_client_describing_flag`: those
/// four flags (and every other flag §9.D.3 removes) no longer depend on the mode
/// they appear in. Each fails by name, with its hint, in party mode with a
/// coordinator, in party mode without one, and in client mode — before anything
/// is read or dialed.
#[tokio::test]
async fn removed_flags_fail_by_name_with_hints_that_name_no_removed_flag() {
    let ids = ids_dir();
    for (flag, value, hint) in REMOVED_FLAGS {
        for (removed, _, _) in REMOVED_FLAGS {
            assert!(
                !hint.split_whitespace().any(|word| word
                    .trim_end_matches(['.', ',', ';', ')'])
                    .trim_start_matches('(')
                    == removed),
                "the hint for {flag} names the removed {removed}"
            );
        }
        let party_with_coordinator: Vec<String> = vec![
            "program-that-is-never-read.stflb".to_owned(),
            "main".to_owned(),
            "--off-chain-coord".to_owned(),
            "127.0.0.1:9".to_owned(),
            "--coord-cert".to_owned(),
            ids.join("server_cert.crt").display().to_string(),
            "--execution-id".to_owned(),
            EXECUTION_ID.to_owned(),
            "--peers".to_owned(),
            "127.0.0.1:9".to_owned(),
        ];
        let party_without: Vec<String> = vec![
            "program-that-is-never-read.stflb".to_owned(),
            "main".to_owned(),
            "--peers".to_owned(),
            "127.0.0.1:9".to_owned(),
        ];
        let client: Vec<String> =
            vec!["--client".to_owned(), "--inputs".to_owned(), "1".to_owned()];
        for (mode, base) in [
            ("a coordinated party", party_with_coordinator),
            ("a party without a coordinator", party_without),
            ("a client", client),
        ] {
            let output = run_stoffel(&base, &[flag, value]).await;
            let stderr = stderr(&output);
            assert_eq!(output.status.code(), Some(2), "{flag} as {mode}: {stderr}");
            assert!(
                stderr.contains(&format!("Error: `{flag}` was removed. {hint}")),
                "{flag} as {mode}: {stderr}"
            );
        }
    }
}

/// Runs `stoffel-run` with `base` then `extra`, bounded so a regression that
/// connects instead of refusing cannot hang the suite.
async fn run_stoffel(base: &[String], extra: &[&str]) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_stoffel-run"));
    command.args(base).args(extra).kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("stoffel-run must refuse promptly, not connect and wait")
        .expect("spawn stoffel-run")
}

/// §9.E.3: a client reaches an execution only through the coordinator. Without
/// `--off-chain-coord` it is refused by name, before any QUIC endpoint exists.
#[tokio::test]
async fn direct_client_mode_is_refused_by_name() {
    let output = run_client(&["--servers", "127.0.0.1:9"]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(
            "Error: direct client mode was removed. A client associates with an execution \
             through the coordinator: pass --off-chain-coord <host:port>, --coord-cert <path>, \
             --execution-id <64-hex> and --servers <node RPC addresses>."
        ),
        "{stderr}"
    );
}

/// §9.D.3: a mesh's membership has one source, so `--peers` without a
/// coordinator is refused before a program is read or a socket bound.
#[tokio::test]
async fn peers_without_a_coordinator_are_refused() {
    let ids = ids_dir();
    let base: Vec<String> = vec![
        "program-that-is-never-read.stflb".to_owned(),
        "main".to_owned(),
        "--cert".to_owned(),
        ids.join("nodes/cert0.crt").display().to_string(),
        "--key".to_owned(),
        ids.join("nodes/key0.der").display().to_string(),
    ];
    let output = run_stoffel(&base, &["--peers", "127.0.0.1:9"]).await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(
            "Error: --peers forms a mesh whose membership only the coordinator defines. Pass \
             --off-chain-coord <host:port>, --coord-cert <path> and --execution-id <64-hex>."
        ),
        "{stderr}"
    );
}

/// An in-process coordinator serving the five fixture node certificates at
/// `t = 1` (§9.B's golden roster), and the files a party pins it with.
struct RosterCoordinator {
    _server: OffChainCoordinatorServer<OffChainCoordinatorConnection>,
    address: String,
    cert_path: PathBuf,
    roster: NodeRoster,
    program_path: PathBuf,
}

impl RosterCoordinator {
    async fn start(name: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ids = ids_dir();
        let roster = NodeRoster::new(
            1,
            (0..5)
                .map(|index| {
                    NodeCertificateDer::from_der(
                        std::fs::read(ids.join(format!("nodes/cert{index}.crt")))
                            .expect("read node certificate fixture"),
                    )
                })
                .collect(),
        )
        .expect("the five fixture nodes form a roster at t = 1");

        let coordinator = self_signed_certs::server_cert();
        let coordinator_der = coordinator.cert.der().to_vec();
        let spki = SpkiDer::from_certificate_der(&coordinator_der).expect("fresh certificate");
        let dir = scratch_dir(name);
        let cert_path = dir.join("coordinator.crt");
        std::fs::write(&cert_path, &coordinator_der).expect("write the coordinator certificate");

        // A program the party can load: the roster is fetched after the program
        // is read, and before anything is bound.
        let compiled = stoffellang::compile(
            "def main() -> int64:\n  return 7",
            "<coordinator-pin>",
            &stoffellang::CompilerOptions::default(),
        )
        .expect("compile a trivial program");
        let program_path = dir.join("program.stflb");
        save_to_file(&stoffellang::convert_to_binary(&compiled), &program_path)
            .expect("write the program");

        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .expect("reserve a port")
            .port();
        let server = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
            CoordinatorRPCServerSharedBase::new(roster.clone(), spki),
            "127.0.0.1",
            port,
            coordinator_der,
            coordinator.signing_key.serialize_der(),
            RpcServerLimits::default(),
        )
        .await
        .expect("start the coordinator");
        Self {
            _server: server,
            address: format!("127.0.0.1:{port}"),
            cert_path,
            roster,
            program_path,
        }
    }

    /// A party pinned to this coordinator, presenting `cert`/`key`, with
    /// `extra` flags, run to completion.
    async fn run_party(&self, cert: &Path, key: &Path, extra: &[&str]) -> Output {
        run_stoffel(&self.party_args(cert, key), extra).await
    }

    /// The flags of a party pinned to this coordinator. `--bind` names a port
    /// nothing else holds, and the one peer hint is an address nobody answers
    /// at, so a party that gets past the roster binds and then waits.
    fn party_args(&self, cert: &Path, key: &Path) -> Vec<String> {
        let bind = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .expect("reserve a port")
            .to_string();
        let epochs = scratch_dir("epochs").join(format!("{}", std::process::id()));
        let base: Vec<String> = vec![
            self.program_path.display().to_string(),
            "main".to_owned(),
            "--off-chain-coord".to_owned(),
            self.address.clone(),
            "--coord-cert".to_owned(),
            self.cert_path.display().to_string(),
            "--execution-id".to_owned(),
            EXECUTION_ID.to_owned(),
            "--cert".to_owned(),
            cert.display().to_string(),
            "--key".to_owned(),
            key.display().to_string(),
            "--bind".to_owned(),
            bind,
            "--peers".to_owned(),
            "127.0.0.1:9".to_owned(),
            "--epoch-store".to_owned(),
            epochs.display().to_string(),
        ];
        base
    }
}

/// Runs `stoffel-run` until its stderr has shown every line of `needles`, then
/// kills it and returns what it printed. For a party that gets past every
/// refusal and would otherwise wait out its discovery budget.
async fn run_until_logged(base: &[String], extra: &[&str], needles: &[&str]) -> String {
    use tokio::io::AsyncBufReadExt;

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_stoffel-run"))
        .args(base)
        .args(extra)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn stoffel-run");
    let mut lines = tokio::io::BufReader::new(child.stderr.take().expect("piped stderr")).lines();
    let mut seen = String::new();
    let complete = tokio::time::timeout(Duration::from_secs(60), async {
        while let Ok(Some(line)) = lines.next_line().await {
            seen.push_str(&line);
            seen.push('\n');
            if needles.iter().all(|needle| seen.contains(needle)) {
                return true;
            }
        }
        false
    })
    .await;
    let _ = child.kill().await;
    assert!(
        matches!(complete, Ok(true)),
        "stoffel-run never logged {needles:?}: {seen}"
    );
    seen
}

/// Nothing was bound: the transport's first log line never appeared.
fn assert_bound_nothing(stderr: &str) {
    assert!(
        !stderr.contains("Listening on"),
        "a refused party must not bind a socket: {stderr}"
    );
}

/// §9.D.1 step 4: membership is checked against the coordinator's roster before
/// a socket is bound, so the refusal names that roster rather than surfacing as
/// the transport's "local certificate is absent" from inside the join.
#[tokio::test]
async fn a_node_absent_from_the_coordinator_roster_exits_before_binding() {
    let coordinator = RosterCoordinator::start("non-member").await;
    let ids = ids_dir();
    let outsider = ids.join("clients/cert0.crt");

    let output = coordinator
        .run_party(&outsider, &ids.join("clients/key0.der"), &[])
        .await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let digest_prefix = &coordinator.roster.digest().to_string()[..16];
    assert!(
        stderr.contains(&format!(
            "Error: this node's certificate (--cert {}) is not one of the 5 nodes in the \
             coordinator's roster (digest {digest_prefix}). A node cannot join a session it is \
             not a member of.",
            outsider.display()
        )),
        "{stderr}"
    );
    assert_bound_nothing(&stderr);
}

/// §9.D.1 step 3: `--expect-n-parties`, `--expect-threshold` and
/// `--expect-roster-digest` refuse a roster other than the one they describe,
/// before anything is bound; a malformed digest is refused as it is parsed.
#[tokio::test]
async fn an_unexpected_roster_size_or_digest_is_refused_before_binding() {
    let coordinator = RosterCoordinator::start("expectations").await;
    let ids = ids_dir();
    let (cert, key) = (ids.join("nodes/cert0.crt"), ids.join("nodes/key0.der"));
    let served = coordinator.roster.digest().to_string();
    let wrong = "ab".repeat(32);

    for (flags, message) in [
        (
            vec!["--expect-n-parties", "7"],
            "Error: the coordinator serves a roster of n = 5, t = 1, not the expected \
             --expect-n-parties 7; refusing to install it."
                .to_owned(),
        ),
        (
            vec!["--expect-threshold", "2"],
            "Error: the coordinator serves a roster of n = 5, t = 1, not the expected \
             --expect-threshold 2; refusing to install it."
                .to_owned(),
        ),
        (
            vec!["--expect-roster-digest", wrong.as_str()],
            format!(
                "Error: the coordinator serves roster digest {served}, not the \
                 --expect-roster-digest {wrong}; refusing to install it."
            ),
        ),
        (
            vec!["--expect-roster-digest", "abc"],
            "Error: --expect-roster-digest: expected 64 hexadecimal characters, got 3".to_owned(),
        ),
    ] {
        let output = coordinator.run_party(&cert, &key, &flags).await;
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{flags:?}: {stderr}");
        assert!(stderr.contains(&message), "{flags:?}: {stderr}");
        assert_bound_nothing(&stderr);
    }

    // The roster they do describe is accepted: the party gets past the fetch and
    // binds (and would then wait for peers nobody runs, which is not under test).
    let fetched = format!("n=5, t=1, digest={served}); fetched once");
    run_until_logged(
        &coordinator.party_args(&cert, &key),
        &[
            "--expect-n-parties",
            "5",
            "--expect-threshold",
            "1",
            "--expect-roster-digest",
            &served.to_uppercase(),
        ],
        &[fetched.as_str(), "Listening on"],
    )
    .await;
}

/// `--invitation` and `--expect-program-hash` shape a coordinator client's
/// association (§9.E.2), so they are refused where no association happens, and
/// a value that cannot be used is refused before anything is dialed.
#[tokio::test]
async fn association_flags_are_refused_without_a_coordinator_or_a_usable_value() {
    let hash = "01".repeat(32);
    for (flag, value) in [
        ("--invitation", "invitation.json"),
        ("--expect-program-hash", hash.as_str()),
    ] {
        let output = run_client(&[flag, value]).await;
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{flag}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "Error: {flag} is only meaningful for a coordinator client (--client with \
                 --off-chain-coord)"
            )),
            "{flag}: {stderr}"
        );
    }

    let output = run_client(&["--expect-program-hash", "abc"]).await;
    let malformed = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{malformed}");
    assert!(
        malformed
            .contains("Error: --expect-program-hash: expected 64 hexadecimal characters, got 3"),
        "{malformed}"
    );

    let pinned = ids_dir().join("server_cert.crt");
    let missing = scratch_dir("invitation").join("missing-invitation.json");
    let output = run_client(&[
        "--off-chain-coord",
        "127.0.0.1:9",
        "--coord-cert",
        pinned.to_str().expect("utf-8 path"),
        "--invitation",
        missing.to_str().expect("utf-8 path"),
        "--servers",
        "127.0.0.1:9",
    ])
    .await;
    let unreadable = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{unreadable}");
    assert!(
        unreadable.contains(&format!(
            "Error: cannot read --invitation {}",
            missing.display()
        )),
        "{unreadable}"
    );
}

/// An in-process coordinator under `Open` admission, serving `nodes` fixture
/// node certificates at `t = 1`, for one execution of `slots`, registered for
/// program `[1; 32]`. No client identity appears anywhere in it.
struct OpenCoordinator {
    _server: OffChainCoordinatorServer<OffChainCoordinatorConnection>,
    address: String,
    port: u16,
    cert_der: Vec<u8>,
    cert_path: PathBuf,
}

impl OpenCoordinator {
    async fn start(name: &str, nodes: usize, slots: Vec<ClientSlotSpec>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ids = ids_dir();
        let roster = NodeRoster::new(
            1,
            (0..nodes)
                .map(|index| {
                    NodeCertificateDer::from_der(
                        std::fs::read(ids.join(format!("nodes/cert{index}.crt")))
                            .expect("read node certificate fixture"),
                    )
                })
                .collect(),
        )
        .expect("fixture nodes form a roster at t = 1");
        let coordinator = self_signed_certs::server_cert();
        let cert_der = coordinator.cert.der().to_vec();
        let spki = SpkiDer::from_certificate_der(&cert_der).expect("fresh certificate");
        let cert_path = scratch_dir(name).join("coordinator.crt");
        std::fs::write(&cert_path, &cert_der).expect("write the coordinator certificate");
        let deadline = UnixSeconds(UnixSeconds::now().0 + 600);
        let state = CoordinatorRPCServerSharedBase::new_for_execution(
            roster,
            spki,
            ExecutionRegistration {
                execution_id: EXECUTION_ID.parse().expect("execution id"),
                program_hash: [1; 32],
                client_slots: ClientSlotTable::new(slots),
                admission: AdmissionPolicy::Open,
                deadlines: Some(ExecutionDeadlines {
                    association: deadline,
                    input: deadline,
                }),
            },
        )
        .expect("valid registration");
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .expect("reserve a port")
            .port();
        let server = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
            state,
            "127.0.0.1",
            port,
            cert_der.clone(),
            coordinator.signing_key.serialize_der(),
            RpcServerLimits::default(),
        )
        .await
        .expect("start the coordinator");
        Self {
            _server: server,
            address: format!("127.0.0.1:{port}"),
            port,
            cert_der,
            cert_path,
        }
    }

    /// A `stoffel-run` client of this coordinator with `extra` flags. Its node
    /// RPC address is one nobody answers at: every case here stops before a
    /// node leg is opened.
    async fn run_client(&self, extra: &[&str]) -> Output {
        let mut flags = vec![
            "--off-chain-coord",
            self.address.as_str(),
            "--coord-cert",
            self.cert_path.to_str().expect("utf-8 path"),
            "--servers",
            "127.0.0.1:9",
        ];
        flags.extend_from_slice(extra);
        run_client(&flags).await
    }

    /// Whether slot 0 is still free: a client minted now associates, and is
    /// admitted to it. It is an AVSS client, whose `2t + 1` minimum every
    /// roster here meets.
    async fn slot_zero_is_free(&self) -> bool {
        let identity = self_signed_certs::client_cert();
        let mut client = OffChainCoordinatorClient::<
            ark_bls12_381::Fr,
            stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<
                ark_bls12_381::Fr,
                ark_bls12_381::G1Projective,
            >,
        >::start_rpc_client_for_execution(
            "127.0.0.1",
            self.port,
            &SpkiDer::from_certificate_der(&self.cert_der).expect("pin"),
            None,
            EXECUTION_ID.parse().expect("execution id"),
            identity.cert.der().to_vec(),
            identity.signing_key.serialize_der(),
        )
        .await
        .expect("a pinned connection");
        client
            .associate_client(AssociationRequest {
                slot: None,
                invitation: None,
            })
            .await
            .is_ok_and(|admission| admission.client_index == ClientIndex(0))
    }
}

/// §9.E.1 step 2: an association is irrevocable, so a client refuses, before it
/// associates, an execution of another program, a slot that does not take its
/// inputs, a slot that does not exist and a roster its backend cannot
/// reconstruct at — each exit 2, and each leaving the slot free.
#[tokio::test]
async fn a_client_refuses_what_it_was_not_asked_to_join_before_associating() {
    let one_input = || {
        vec![ClientSlotSpec {
            input_count: 1,
            output_count: 0,
        }]
    };
    let coordinator = OpenCoordinator::start("refusals", 5, one_input()).await;
    let wrong_program = "02".repeat(32);
    for (flags, message) in [
        (
            vec!["--expect-program-hash", wrong_program.as_str()],
            format!(
                "Error: execution {EXECUTION_ID} runs program {}, not the --expect-program-hash \
                 {wrong_program}; refusing to associate.",
                "01".repeat(32)
            ),
        ),
        (
            vec!["--client-slot", "3"],
            format!(
                "Error: execution {EXECUTION_ID} has 1 client slot(s), so it has no client slot \
                 3; refusing to associate."
            ),
        ),
    ] {
        let output = coordinator.run_client(&flags).await;
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{flags:?}: {stderr}");
        assert!(stderr.contains(&message), "{flags:?}: {stderr}");
    }
    // `run_client` passes `--inputs 1`; a second value does not fit the slot.
    let output = {
        let ids = ids_dir();
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_stoffel-run"));
        command
            .args(["--client", "--inputs", "1,2", "--cert"])
            .arg(ids.join("clients/cert0.crt"))
            .arg("--key")
            .arg(ids.join("clients/key0.der"))
            .args(["--off-chain-coord", &coordinator.address, "--coord-cert"])
            .arg(&coordinator.cert_path)
            .args(["--servers", "127.0.0.1:9", "--execution-id", EXECUTION_ID])
            .kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(60), command.output())
            .await
            .expect("stoffel-run must refuse promptly")
            .expect("spawn stoffel-run")
    };
    let stderr_text = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr_text}");
    assert!(
        stderr_text.contains("Error: client slot 0 takes 1 inputs, but --inputs has 2."),
        "{stderr_text}"
    );
    assert!(
        coordinator.slot_zero_is_free().await,
        "a refused client must not have associated"
    );

    let undersized = OpenCoordinator::start("undersized", 3, one_input()).await;
    let output = undersized.run_client(&[]).await;
    let stderr_text = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr_text}");
    assert!(
        stderr_text.contains(
            "Error: honeybadger needs at least 4 nodes for threshold 1, and the coordinator's \
             roster has 3; refusing to associate."
        ),
        "{stderr_text}"
    );
    assert!(
        undersized.slot_zero_is_free().await,
        "a refused client must not have associated"
    );
}

/// §9.E.2: `--servers` is required of a coordinator client, and refused before
/// anything is dialed — a client that associated and could then reach no node
/// would hold its slot until the coordinator's deadline aborted the execution.
#[tokio::test]
async fn a_coordinator_client_without_node_rpc_addresses_is_refused_before_dialing() {
    let pinned = ids_dir().join("server_cert.crt");
    let output = run_client(&[
        "--off-chain-coord",
        "127.0.0.1:9",
        "--coord-cert",
        pinned.to_str().expect("utf-8 path"),
    ])
    .await;
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("Error: a coordinator client needs --servers <node RPC addresses>"),
        "{stderr}"
    );
}
