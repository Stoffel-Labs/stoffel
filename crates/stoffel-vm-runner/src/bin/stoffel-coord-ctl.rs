//! The operator's side of the coordinator's execution control plane.
//!
//! A standing deployment's executions used to be driven by writing JSON command
//! files into a directory every node had mounted, which made the mount the
//! authorization boundary: whoever could write it could admit an execution on
//! every party and name its clients. The coordinator is the trusted party now.
//! This is how an operator asks it to run something — over the same mutually
//! authenticated link everything else uses, authorized by the operator
//! certificate the coordinator was started with and by nothing else.
//!
//! It prints what the coordinator minted. A node is never told an execution
//! identity by an operator: it learns every execution from the coordinator's own
//! stream. The printed identity is for the operator, and for the MPC clients it
//! hands inputs to, which are not on the node roster and so are not published
//! anything.

use std::fs;
use std::process::exit;

use stoffel_mpc_coordinator_off_chain::{CoordinatorLink, ExecutionRequest};
use stoffel_mpc_coordinator_shared::{
    AdmissionPolicy, ClientIndex, ClientSlotSpec, ClientSlotTable, ExecutionDeadlines, ExecutionId,
    PreRegisteredClient, SpkiDer, UnixSeconds,
};
use stoffel_vm::net::program_id_from_bytes;

const USAGE: &str = r#"stoffel-coord-ctl — tell an off-chain coordinator what to run

Usage:
  stoffel-coord-ctl submit --coordinator <host:port> --coord-cert <path>
                           --cert <path> --key <path>
                           (--program <64-hex> | --program-file <path>)
                           [--entry <name>] [--client-slots <in:out,...>]
                           [--client <slot>=<cert path> ...]
                           [--association-timeout-secs <n>] [--input-timeout-secs <n>]

  stoffel-coord-ctl abort  --coordinator <host:port> --coord-cert <path>
                           --cert <path> --key <path> --execution <64-hex>

The coordinator mints every execution identity itself and publishes it to the
roster, so this tool never names one: `submit` prints
`<execution id> <registration nonce>` on one line.

  --coord-cert    The coordinator's certificate (DER). Its key is pinned, so no
                  other server can answer for it.
  --cert/--key    The operator identity (DER certificate, PKCS#8 DER key). The
                  coordinator admits it only if it was started with this
                  certificate in --operator-certs.
  --program-file  A compiled artifact whose content address is computed here, so
                  an operator need not hash it separately.
  --client-slots  <inputs>:<outputs> per client slot, in slot order.
  --client        One pre-registered client per flag, in the execution-local
                  ordinal order the MPC backend numbers clients by. That ordinal
                  and the program slot are different index spaces and need not
                  agree, so the order matters.
  --open-admission
                  Let any certificate holder bind a free slot, first come first
                  served, instead of pre-registering the clients. A standing
                  node refuses such an execution — it runs only pre-registered
                  admissions — so this is for one-shot deployments whose clients
                  are not known when the execution is submitted.
"#;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("Error: {}", message.as_ref());
    exit(2);
}

fn usage() -> ! {
    eprint!("{USAGE}");
    exit(2);
}

#[derive(Default)]
struct Flags {
    coordinator: Option<String>,
    coord_cert: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    program: Option<String>,
    program_file: Option<String>,
    entry: Option<String>,
    client_slots: Vec<String>,
    clients: Vec<String>,
    execution: Option<String>,
    open_admission: bool,
    association_timeout_secs: u64,
    input_timeout_secs: u64,
}

fn parse_flags(arguments: &[String]) -> Flags {
    let mut flags = Flags {
        association_timeout_secs: 3600,
        input_timeout_secs: 7200,
        ..Flags::default()
    };
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .cloned()
                .unwrap_or_else(|| fail(format!("{argument} requires a value")))
        };
        match argument.as_str() {
            "--coordinator" => flags.coordinator = Some(value()),
            "--coord-cert" => flags.coord_cert = Some(value()),
            "--cert" => flags.cert = Some(value()),
            "--key" => flags.key = Some(value()),
            "--program" => flags.program = Some(value()),
            "--program-file" => flags.program_file = Some(value()),
            "--entry" => flags.entry = Some(value()),
            "--execution" => flags.execution = Some(value()),
            "--client-slots" => flags.client_slots.extend(split_list(&value())),
            "--client" => flags.clients.extend(split_list(&value())),
            "--association-timeout-secs" => {
                flags.association_timeout_secs =
                    parse_seconds("--association-timeout-secs", &value())
            }
            "--input-timeout-secs" => {
                flags.input_timeout_secs = parse_seconds("--input-timeout-secs", &value())
            }
            "--open-admission" => flags.open_admission = true,
            "-h" | "--help" => usage(),
            other => fail(format!("unknown argument {other}")),
        }
    }
    flags
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_seconds(flag: &str, value: &str) -> u64 {
    value
        .parse()
        .unwrap_or_else(|error| fail(format!("{flag}: {error}")))
}

fn required(flag: &str, value: Option<String>) -> String {
    value.unwrap_or_else(|| fail(format!("{flag} is required")))
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let Some((command, rest)) = arguments.split_first() else {
        usage();
    };
    if command == "-h" || command == "--help" {
        usage();
    }
    let flags = parse_flags(rest);

    let coordinator = required("--coordinator", flags.coordinator.clone());
    let (host, port) = coordinator.rsplit_once(':').unwrap_or_else(|| {
        fail(format!(
            "--coordinator must be host:port, got {coordinator:?}"
        ))
    });
    let port = port
        .parse::<u16>()
        .unwrap_or_else(|error| fail(format!("--coordinator port {port:?}: {error}")));

    let coord_cert_path = required("--coord-cert", flags.coord_cert.clone());
    let coord_cert = read_file(&coord_cert_path);
    let coordinator_key = SpkiDer::from_certificate_der(&coord_cert)
        .unwrap_or_else(|error| fail(format!("--coord-cert {coord_cert_path}: {error}")));
    let cert_path = required("--cert", flags.cert.clone());
    let cert = read_file(&cert_path);
    let key = read_file(&required("--key", flags.key.clone()));

    let link = CoordinatorLink::connect(host, port, &coordinator_key, None, cert, key)
        .await
        .unwrap_or_else(|error| {
            fail(format!(
                "connect to the coordinator at {host}:{port}: {error}"
            ))
        });

    match command.as_str() {
        "submit" => submit(&link, &flags).await,
        "abort" => abort(&link, &flags).await,
        other => fail(format!("unknown command {other}")),
    }
}

async fn submit(link: &CoordinatorLink, flags: &Flags) {
    let program_hash = match (&flags.program, &flags.program_file) {
        (Some(_), Some(_)) => fail("--program and --program-file name the same thing; pass one"),
        (Some(hex), None) => parse_digest("--program", hex),
        (None, Some(path)) => program_id_from_bytes(&read_file(path)),
        (None, None) => fail("submit requires --program or --program-file"),
    };
    let now = UnixSeconds::now();
    let request = ExecutionRequest {
        program_hash,
        entry: flags.entry.clone().unwrap_or_else(|| "main".to_owned()),
        client_slots: ClientSlotTable::new(
            flags
                .client_slots
                .iter()
                .map(|slot| parse_slot(slot))
                .collect(),
        ),
        // Pre-registration is the default because it is the fail-closed one and
        // the only one a standing node admits: under an open policy any
        // certificate holder that can reach the coordinator may bind a slot of
        // a program the deployment holds. A program with no client slots is
        // pre-registered with no clients, which is not the same as open.
        admission: if flags.open_admission {
            if !flags.clients.is_empty() {
                fail("--open-admission and --client are different policies; pass one");
            }
            AdmissionPolicy::Open
        } else {
            AdmissionPolicy::PreRegistered {
                clients: flags
                    .clients
                    .iter()
                    .map(|entry| parse_client(entry))
                    .collect(),
            }
        },
        deadlines: Some(ExecutionDeadlines {
            association: UnixSeconds(now.0.saturating_add(flags.association_timeout_secs)),
            input: UnixSeconds(now.0.saturating_add(flags.input_timeout_secs)),
        }),
    };
    let submitted = link
        .submit_execution(request)
        .await
        .unwrap_or_else(|error| fail(format!("the coordinator refused the submission: {error}")));
    println!(
        "{} {}",
        submitted.execution_id, submitted.registration_nonce
    );
}

async fn abort(link: &CoordinatorLink, flags: &Flags) {
    let execution = required("--execution", flags.execution.clone());
    let execution_id = ExecutionId::from_bytes(parse_digest("--execution", &execution));
    link.abort_execution(execution_id)
        .await
        .unwrap_or_else(|error| fail(format!("the coordinator refused the abort: {error}")));
    println!("{execution_id} aborted");
}

fn read_file(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| fail(format!("read {path}: {error}")))
}

fn parse_digest(flag: &str, value: &str) -> [u8; 32] {
    hex::decode(value)
        .unwrap_or_else(|error| fail(format!("{flag} is not hexadecimal: {error}")))
        .try_into()
        .unwrap_or_else(|_| fail(format!("{flag} must be 64 hexadecimal characters")))
}

fn parse_slot(value: &str) -> ClientSlotSpec {
    let (inputs, outputs) = value.split_once(':').unwrap_or_else(|| {
        fail(format!(
            "--client-slots entry {value:?} must be <inputs>:<outputs>"
        ))
    });
    ClientSlotSpec {
        input_count: inputs.trim().parse().unwrap_or_else(|error| {
            fail(format!("--client-slots input count in {value:?}: {error}"))
        }),
        output_count: outputs.trim().parse().unwrap_or_else(|error| {
            fail(format!("--client-slots output count in {value:?}: {error}"))
        }),
    }
}

/// `<slot>=<certificate path>`. The identity published to the nodes is the
/// certificate's `subject_public_key`; the certificate itself never travels, so
/// a node admits only clients it already holds a certificate for.
fn parse_client(value: &str) -> PreRegisteredClient {
    let (slot, path) = value.split_once('=').unwrap_or_else(|| {
        fail(format!(
            "--client entry {value:?} must be <slot>=<cert path>"
        ))
    });
    let slot = slot
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|error| fail(format!("--client slot in {value:?}: {error}")));
    let identity = SpkiDer::from_certificate_der(&read_file(path.trim()))
        .unwrap_or_else(|error| fail(format!("client certificate {path:?}: {error}")))
        .client_identity();
    PreRegisteredClient {
        identity,
        client_slot: ClientIndex(slot),
    }
}
