//! The off-chain coordinator the shipped Docker stacks run.
//!
//! It exists to give `stoffel-mpc-coordinator-off-chain` a `main`: the crate
//! ships the RPC server, the shared state and the connection type
//! (`OffChainCoordinatorConnection`), and this binary registers one execution
//! and serves it.
//!
//! Coordinator `0.3.0` (docs/design/bootnode-elimination.md §9) makes the
//! coordinator the roster authority. The node roster is built here from the
//! node certificates as DER — never from a key form this binary derives — and
//! served to every node and client that pins this coordinator's certificate.
//! The connection type serves the whole `CoordinatorRPCBase` interface, so the
//! roster (`get_node_roster`), the execution summary and client association
//! (`associate_client`) are all reachable here; this binary implements none of
//! them itself.
//!
//! Every execution registers an immutable client slot table and an admission
//! policy (`--admission`, §9.F.3):
//!
//! - `pre-registered` (the default) binds `--client-certs` to the slots in
//!   order; each slot's client is named up front.
//! - `open` names no client anywhere: any certificate holder that pins this
//!   coordinator may bind a free slot, first come, first served. This is how a
//!   computation takes clients whose identities are not known in advance.
//! - `invitation` admits only the invitee named by an invitation that
//!   `--invitation-issuer-cert`'s key signed.
//!
//! `open` and `invitation` require `--association-deadline-secs` and
//! `--input-deadline-secs`, so an execution whose slots are never bound is
//! aborted instead of holding its nodes forever. A flag the chosen admission
//! does not read is refused, never ignored. An empty flag value is the same as
//! an absent flag, so a compose file can pass `--flag "${VARIABLE-}"`
//! unconditionally.

use std::fs;
use std::io;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{Parser, ValueEnum};
use stoffel_mpc_coordinator_off_chain::{
    CoordinatorRPCServerSharedBase, ExecutionRegistration, OffChainCoordinatorConnection,
    OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_shared::rpc::RpcServerLimits;
use stoffel_mpc_coordinator_shared::{
    program_hash_of, AdmissionPolicy, ClientIdentity, ClientSlotSpec, ClientSlotTable,
    CoordinatorError, ExecutionDeadlines, ExecutionId, InvitationIssuer, NodeCertificateDer,
    NodeRoster, PinError, RosterDigest, RosterError, SpkiDer, UnixSeconds,
};

/// How clients come to hold the execution's slots (§9.C.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Admission {
    /// `--client-certs` names one client per slot, bound at registration.
    #[default]
    PreRegistered,
    /// Any certificate holder may bind a free slot. Requires deadlines.
    Open,
    /// Only holders of an invitation signed by `--invitation-issuer-cert` may
    /// bind a slot. Requires deadlines.
    Invitation,
}

/// A flag value in which the empty string means the flag is absent
/// (docs/design/bootnode-elimination.md §9.F.3), so a compose file can pass
/// `--flag "${VARIABLE-}"` whether or not the variable is set.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Blankable<T>(Option<T>);

fn blankable<T: FromStr>(value: &str) -> Result<Blankable<T>, T::Err> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Blankable(None));
    }
    value.parse().map(|parsed| Blankable(Some(parsed)))
}

/// The value of a blankable flag, if it was given and not empty.
fn given<T>(flag: Option<Blankable<T>>) -> Option<T> {
    flag.and_then(|Blankable(value)| value)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(group(clap::ArgGroup::new("program_identity").required(true).args(["program", "hash"])))]
struct Args {
    /// The compiled program this execution runs; registers its program hash.
    #[arg(long)]
    program: Option<PathBuf>,

    /// The program hash this execution runs, as 64 hexadecimal characters, for
    /// an operator registering without the program bytes. The all-zero value is
    /// reserved.
    #[arg(long)]
    hash: Option<String>,

    /// The program invocation this coordinator serves, as 64 hexadecimal
    /// characters. Every party and client must pass the same value as
    /// `--execution-id`, and a later invocation must pass a different one.
    #[arg(long)]
    execution_id: String,

    /// The node certificates (DER X.509) that are the node roster. `n` is their
    /// number.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    node_certs: Vec<PathBuf>,

    /// The roster threshold; the roster requires `n >= 2t + 1` and `t >= 1`.
    #[arg(long)]
    t: u64,

    /// One client slot per entry, in slot order, as `<inputs>:<outputs>`. An
    /// empty value registers no client slots.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    client_io: Vec<String>,

    /// How clients are admitted to the client slots. Never defaults to `open`:
    /// client slots without `--client-certs` under the default fail with
    /// `PreRegisteredCountMismatch` rather than admitting anyone.
    #[arg(long, value_enum, default_value_t = Admission::PreRegistered)]
    admission: Admission,

    /// `pre-registered` only: one client certificate (DER X.509) per client
    /// slot, in slot order. Each is pre-registered to its slot. An empty value
    /// names no client.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    client_certs: Vec<String>,

    /// `invitation` only: the certificate (DER X.509) whose key signs
    /// invitations. It may be neither a roster node's nor this coordinator's.
    /// An empty value is no issuer.
    #[arg(long, value_parser = blankable::<PathBuf>)]
    invitation_issuer_cert: Option<Blankable<PathBuf>>,

    /// Seconds after startup by which every client slot must be bound, or the
    /// execution is aborted. Required under `open` and `invitation`; optional
    /// under `pre-registered`; given together with `--input-deadline-secs`. An
    /// empty value is no deadline.
    #[arg(long, value_parser = blankable::<u64>)]
    association_deadline_secs: Option<Blankable<u64>>,

    /// Seconds after startup by which every masked input must be submitted,
    /// or the execution is aborted. Paired with `--association-deadline-secs`.
    /// An empty value is no deadline.
    #[arg(long, value_parser = blankable::<u64>)]
    input_deadline_secs: Option<Blankable<u64>>,

    #[arg(long)]
    server_cert: PathBuf,

    #[arg(long)]
    server_key: PathBuf,

    /// Established connections of identities that are neither roster nodes
    /// nor bound clients.
    #[arg(long, default_value_t = RpcServerLimits::default().max_connections)]
    max_connections: usize,

    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    #[arg(long, default_value_t = 31415)]
    port: u16,
}

#[derive(Debug, thiserror::Error)]
enum ClientSlotSpecParseError {
    #[error("expected <inputs>:<outputs>, got {0:?}")]
    Shape(String),
    #[error("invalid count in {entry:?}: {source}")]
    Count {
        entry: String,
        source: ParseIntError,
    },
}

#[derive(Debug, thiserror::Error)]
enum ProgramHashParseError {
    #[error("not hexadecimal: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("expected 32 bytes (64 hexadecimal characters), got {0} bytes")]
    Length(usize),
}

/// A combination of admission flags this wrapper refuses before it builds a
/// registration. Every one exits 2.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum AdmissionFlagError {
    #[error("--client-certs is read only under --admission pre-registered, not {admission}")]
    ClientCertsUnread { admission: &'static str },
    #[error("--invitation-issuer-cert is read only under --admission invitation, not {admission}")]
    IssuerCertUnread { admission: &'static str },
    #[error("--admission invitation requires --invitation-issuer-cert")]
    IssuerCertRequired,
    #[error(
        "--association-deadline-secs and --input-deadline-secs are given together or not at all"
    )]
    DeadlinePairIncomplete,
    #[error(
        "--admission {admission} requires --association-deadline-secs and --input-deadline-secs"
    )]
    DeadlinesRequired { admission: &'static str },
    #[error("the deadline of {secs} seconds after startup overflows the coordinator clock")]
    DeadlineOverflow { secs: u64 },
}

/// Why this wrapper refuses to start. Every variant exits 2 with its message,
/// before anything listens.
#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("cannot read {flag} {}: {source}", path.display())]
    Unreadable {
        flag: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{flag} {} is not a usable DER X.509 certificate: {source}", path.display())]
    NotACertificate {
        flag: &'static str,
        path: PathBuf,
        source: PinError,
    },
    #[error("invalid --execution-id: {0}")]
    ExecutionId(String),
    #[error("invalid --hash: {0}")]
    ProgramHash(#[from] ProgramHashParseError),
    #[error("invalid node roster: {0}")]
    Roster(#[from] RosterError),
    #[error("--client-io: {0}")]
    ClientIo(#[from] ClientSlotSpecParseError),
    #[error(transparent)]
    Admission(#[from] AdmissionFlagError),
    #[error("invalid coordinator configuration: {0}")]
    Registration(#[source] CoordinatorError),
}

impl Admission {
    fn flag_value(self) -> &'static str {
        match self {
            Self::PreRegistered => "pre-registered",
            Self::Open => "open",
            Self::Invitation => "invitation",
        }
    }

    fn requires_deadlines(self) -> bool {
        matches!(self, Self::Open | Self::Invitation)
    }
}

/// The admission-related flags, already read from disk and derived into the
/// forms the coordinator takes.
struct AdmissionFlags {
    admission: Admission,
    clients: Vec<ClientIdentity>,
    invitation_issuer: Option<InvitationIssuer>,
    association_deadline_secs: Option<u64>,
    input_deadline_secs: Option<u64>,
}

/// The registration's admission policy and deadlines, from the admission flags
/// and the time of startup. The coordinator validates the result again
/// (`RegistrationError`); this refuses the flag combinations it cannot see,
/// such as a flag that the chosen admission would otherwise silently ignore.
fn admission_policy(
    flags: AdmissionFlags,
    startup: UnixSeconds,
) -> Result<(AdmissionPolicy, Option<ExecutionDeadlines>), AdmissionFlagError> {
    let admission = flags.admission;
    let name = admission.flag_value();
    if admission != Admission::PreRegistered && !flags.clients.is_empty() {
        return Err(AdmissionFlagError::ClientCertsUnread { admission: name });
    }
    if admission != Admission::Invitation && flags.invitation_issuer.is_some() {
        return Err(AdmissionFlagError::IssuerCertUnread { admission: name });
    }

    let deadlines = match (flags.association_deadline_secs, flags.input_deadline_secs) {
        (None, None) if admission.requires_deadlines() => {
            return Err(AdmissionFlagError::DeadlinesRequired { admission: name })
        }
        (None, None) => None,
        (Some(association), Some(input)) => {
            let after_startup = |secs: u64| {
                startup
                    .0
                    .checked_add(secs)
                    .map(UnixSeconds)
                    .ok_or(AdmissionFlagError::DeadlineOverflow { secs })
            };
            Some(ExecutionDeadlines {
                association: after_startup(association)?,
                input: after_startup(input)?,
            })
        }
        _ => return Err(AdmissionFlagError::DeadlinePairIncomplete),
    };

    let policy = match admission {
        Admission::PreRegistered => AdmissionPolicy::PreRegistered {
            clients: flags.clients,
        },
        Admission::Open => AdmissionPolicy::Open,
        Admission::Invitation => AdmissionPolicy::Invitation {
            issuer: flags
                .invitation_issuer
                .ok_or(AdmissionFlagError::IssuerCertRequired)?,
        },
    };
    Ok((policy, deadlines))
}

/// Parses one `--client-io` entry, `<inputs>:<outputs>`.
fn parse_client_slot_spec(entry: &str) -> Result<ClientSlotSpec, ClientSlotSpecParseError> {
    let (inputs, outputs) = entry
        .split_once(':')
        .ok_or_else(|| ClientSlotSpecParseError::Shape(entry.to_owned()))?;
    let count = |value: &str| {
        u64::from_str(value.trim()).map_err(|source| ClientSlotSpecParseError::Count {
            entry: entry.to_owned(),
            source,
        })
    };
    Ok(ClientSlotSpec {
        input_count: count(inputs)?,
        output_count: count(outputs)?,
    })
}

fn parse_program_hash(hash: &str) -> Result<[u8; 32], ProgramHashParseError> {
    let bytes = hex::decode(hash.trim())?;
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_| ProgramHashParseError::Length(length))
}

fn read_file(flag: &'static str, path: &Path) -> Result<Vec<u8>, ConfigError> {
    fs::read(path).map_err(|source| ConfigError::Unreadable {
        flag,
        path: path.to_owned(),
        source,
    })
}

fn read_certificate_spki(flag: &'static str, path: &Path) -> Result<SpkiDer, ConfigError> {
    SpkiDer::from_certificate_der(&read_file(flag, path)?).map_err(|source| {
        ConfigError::NotACertificate {
            flag,
            path: path.to_owned(),
            source,
        }
    })
}

/// What an operator needs to know about the roster this coordinator serves:
/// every node and client may pass `digest` as `--expect-roster-digest`
/// (`STOFFEL_EXPECT_ROSTER_DIGEST`) to refuse any other roster.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ServedRoster {
    n: u64,
    t: u64,
    digest: RosterDigest,
}

/// One execution, registered and ready to serve.
struct Configured {
    state: CoordinatorRPCServerSharedBase,
    execution_id: ExecutionId,
    served_roster: ServedRoster,
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
    limits: RpcServerLimits,
}

/// Reads every file the flags name and registers the one execution, refusing
/// anything the coordinator would refuse before a listener exists.
fn configure(args: &Args, startup: UnixSeconds) -> Result<Configured, ConfigError> {
    let program_hash = match (&args.program, &args.hash) {
        (Some(program), None) => program_hash_of(&read_file("--program", program)?),
        (None, Some(hash)) => parse_program_hash(hash)?,
        _ => unreachable!("clap requires exactly one of --program and --hash"),
    };
    let execution_id: ExecutionId = args
        .execution_id
        .trim()
        .parse()
        .map_err(ConfigError::ExecutionId)?;

    let node_certificates = args
        .node_certs
        .iter()
        .map(|path| read_file("--node-certs", path).map(NodeCertificateDer::from_der))
        .collect::<Result<Vec<_>, _>>()?;
    let node_roster = NodeRoster::new(args.t, node_certificates)?;
    let served_roster = ServedRoster {
        n: node_roster.n(),
        t: node_roster.t(),
        digest: node_roster.digest(),
    };

    // An empty flag value arrives as no entries, so a compose file can pass
    // `--client-io "${STOFFEL_CLIENT_IO-}"` unconditionally.
    let client_slots = ClientSlotTable::new(
        args.client_io
            .iter()
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
            .map(parse_client_slot_spec)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let clients = args
        .client_certs
        .iter()
        .map(|path| path.trim())
        .filter(|path| !path.is_empty())
        .map(|path| read_certificate_spki("--client-certs", Path::new(path)))
        .map(|spki| spki.map(|spki| spki.client_identity()))
        .collect::<Result<Vec<_>, _>>()?;
    let invitation_issuer = given(args.invitation_issuer_cert.clone())
        .map(|path| read_certificate_spki("--invitation-issuer-cert", &path))
        .transpose()?
        .map(InvitationIssuer::new);
    let (admission, deadlines) = admission_policy(
        AdmissionFlags {
            admission: args.admission,
            clients,
            invitation_issuer,
            association_deadline_secs: given(args.association_deadline_secs.clone()),
            input_deadline_secs: given(args.input_deadline_secs.clone()),
        },
        startup,
    )?;

    let server_cert_der = read_file("--server-cert", &args.server_cert)?;
    let server_key_der = read_file("--server-key", &args.server_key)?;
    let server_spki = SpkiDer::from_certificate_der(&server_cert_der).map_err(|source| {
        ConfigError::NotACertificate {
            flag: "--server-cert",
            path: args.server_cert.clone(),
            source,
        }
    })?;

    // One execution, registered before the listener accepts anything, so no
    // party can propose a round for an invocation the coordinator has not heard
    // of. The coordinator refuses an invitation issuer that is a roster node or
    // this coordinator's own key here.
    let registration = ExecutionRegistration {
        execution_id,
        program_hash,
        client_slots,
        admission,
        deadlines,
    };
    let state =
        CoordinatorRPCServerSharedBase::new_for_execution(node_roster, server_spki, registration)
            .map_err(ConfigError::Registration)?;

    Ok(Configured {
        state,
        execution_id,
        served_roster,
        server_cert_der,
        server_key_der,
        limits: RpcServerLimits {
            max_connections: args.max_connections,
            ..RpcServerLimits::default()
        },
    })
}

/// Starts the listener. It serves the roster, the summary, association and
/// every other `CoordinatorRPCBase` method until the process exits.
async fn serve(
    configured: Configured,
    bind_addr: &str,
    port: u16,
) -> Result<OffChainCoordinatorServer<OffChainCoordinatorConnection>, CoordinatorError> {
    OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
        configured.state,
        bind_addr,
        port,
        configured.server_cert_der,
        configured.server_key_der,
        configured.limits,
    )
    .await
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let args = Args::parse();
    let configured = configure(&args, UnixSeconds::now()).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let execution_id = configured.execution_id;
    let served_roster = configured.served_roster.clone();

    let _coord = serve(configured, &args.bind_addr, args.port)
        .await
        .expect("failed to start coordinator");

    println!(
        "Listening on {}:{} for execution {} ({} admission)",
        args.bind_addr,
        args.port,
        execution_id,
        args.admission.flag_value()
    );
    println!(
        "Serving node roster n={}, t={}, digest={} (pass it as STOFFEL_EXPECT_ROSTER_DIGEST to refuse any other)",
        served_roster.n, served_roster.t, served_roster.digest
    );

    tokio::time::sleep(tokio::time::Duration::MAX).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_mpc_coordinator_off_chain::{CoordinatorLink, CoordinatorRPCBaseClient};
    use stoffel_mpc_coordinator_shared::self_signed_certs::setup_client;
    use stoffel_mpc_coordinator_shared::{
        AdmissionPolicyKind, AssociationRequest, ClientIndex, InputRange, OutputRights,
        RegistrationError, ServerPin,
    };

    const STARTUP: UnixSeconds = UnixSeconds(1_000);
    const EXECUTION_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const PROGRAM_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn fixture_path(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../ids")
            .join(path)
    }

    fn fixture_certificate(path: &str) -> Vec<u8> {
        fs::read(fixture_path(path)).expect("fixture certificate")
    }

    fn fixture_spki(path: &str) -> SpkiDer {
        SpkiDer::from_certificate_der(&fixture_certificate(path)).expect("fixture certificate")
    }

    fn fixture_client() -> ClientIdentity {
        fixture_spki("clients/cert0.crt").client_identity()
    }

    fn fixture_issuer() -> InvitationIssuer {
        InvitationIssuer::new(fixture_spki("clients/cert1.crt"))
    }

    fn node_certs_flag() -> String {
        (0..5)
            .map(|index| {
                fixture_path(&format!("nodes/cert{index}.crt"))
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The flags every shipped stack passes, over the committed `ids/`
    /// fixtures, followed by `extra`.
    fn stack_args(extra: &[&str]) -> Args {
        let node_certs = node_certs_flag();
        let server_cert = fixture_path("server_cert.crt").display().to_string();
        let server_key = fixture_path("server_key.der").display().to_string();
        let mut argv = vec![
            "wrapper",
            "--hash",
            PROGRAM_HASH,
            "--execution-id",
            EXECUTION_ID,
            "--node-certs",
            &node_certs,
            "--t",
            "1",
            "--server-cert",
            &server_cert,
            "--server-key",
            &server_key,
        ];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).expect("stack flags parse")
    }

    fn flags(admission: Admission) -> AdmissionFlags {
        AdmissionFlags {
            admission,
            clients: Vec::new(),
            invitation_issuer: None,
            association_deadline_secs: None,
            input_deadline_secs: None,
        }
    }

    fn free_local_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free local port")
            .port()
    }

    #[test]
    fn admission_defaults_to_pre_registered_never_open() {
        let args = Args::try_parse_from([
            "wrapper",
            "--hash",
            "11",
            "--execution-id",
            "22",
            "--node-certs",
            "a.crt",
            "--t",
            "1",
            "--server-cert",
            "s.crt",
            "--server-key",
            "s.der",
        ])
        .expect("minimal flags parse");
        assert_eq!(args.admission, Admission::PreRegistered);
        assert_eq!(Admission::default(), Admission::PreRegistered);
    }

    #[test]
    fn admission_flag_takes_the_three_policy_names() {
        for (value, expected) in [
            ("pre-registered", Admission::PreRegistered),
            ("open", Admission::Open),
            ("invitation", Admission::Invitation),
        ] {
            assert_eq!(Admission::from_str(value, false), Ok(expected));
            assert_eq!(expected.flag_value(), value);
        }
        assert!(Admission::from_str("anyone", false).is_err());
    }

    #[test]
    fn an_empty_optional_flag_is_the_same_as_an_absent_one() {
        let blank = stack_args(&[
            "--client-io",
            "",
            "--client-certs",
            "",
            "--invitation-issuer-cert",
            "",
            "--association-deadline-secs",
            "",
            "--input-deadline-secs",
            " ",
        ]);
        assert_eq!(given(blank.invitation_issuer_cert.clone()), None);
        assert_eq!(given(blank.association_deadline_secs.clone()), None);
        assert_eq!(given(blank.input_deadline_secs.clone()), None);
        let configured = configure(&blank, STARTUP).expect("the empty registration");
        assert_eq!(configured.served_roster.n, 5);

        let given_values = stack_args(&[
            "--association-deadline-secs",
            "600",
            "--input-deadline-secs",
            "900",
        ]);
        assert_eq!(given(given_values.association_deadline_secs), Some(600));
        assert_eq!(given(given_values.input_deadline_secs), Some(900));

        assert!(
            Args::try_parse_from(["wrapper", "--association-deadline-secs", "soon"]).is_err(),
            "a non-empty value still has to parse"
        );
    }

    #[test]
    fn open_admission_names_no_client_and_carries_deadlines_after_startup() {
        let (policy, deadlines) = admission_policy(
            AdmissionFlags {
                association_deadline_secs: Some(600),
                input_deadline_secs: Some(900),
                ..flags(Admission::Open)
            },
            STARTUP,
        )
        .expect("open with deadlines");
        assert_eq!(policy, AdmissionPolicy::Open);
        assert_eq!(
            deadlines,
            Some(ExecutionDeadlines {
                association: UnixSeconds(1_600),
                input: UnixSeconds(1_900),
            })
        );
    }

    #[test]
    fn open_and_invitation_require_deadlines() {
        assert_eq!(
            admission_policy(flags(Admission::Open), STARTUP),
            Err(AdmissionFlagError::DeadlinesRequired { admission: "open" })
        );
        assert_eq!(
            admission_policy(
                AdmissionFlags {
                    invitation_issuer: Some(fixture_issuer()),
                    ..flags(Admission::Invitation)
                },
                STARTUP
            ),
            Err(AdmissionFlagError::DeadlinesRequired {
                admission: "invitation"
            })
        );
    }

    #[test]
    fn deadlines_are_given_together_or_not_at_all() {
        for (association, input) in [(Some(600), None), (None, Some(900))] {
            assert_eq!(
                admission_policy(
                    AdmissionFlags {
                        association_deadline_secs: association,
                        input_deadline_secs: input,
                        ..flags(Admission::PreRegistered)
                    },
                    STARTUP
                ),
                Err(AdmissionFlagError::DeadlinePairIncomplete)
            );
        }
        assert_eq!(
            admission_policy(
                AdmissionFlags {
                    association_deadline_secs: Some(u64::MAX),
                    input_deadline_secs: Some(u64::MAX),
                    ..flags(Admission::PreRegistered)
                },
                STARTUP
            ),
            Err(AdmissionFlagError::DeadlineOverflow { secs: u64::MAX })
        );
    }

    #[test]
    fn pre_registered_keeps_its_clients_and_optional_deadlines() {
        let client = fixture_client();
        let (policy, deadlines) = admission_policy(
            AdmissionFlags {
                clients: vec![client.clone()],
                ..flags(Admission::PreRegistered)
            },
            STARTUP,
        )
        .expect("pre-registered without deadlines");
        assert_eq!(
            policy,
            AdmissionPolicy::PreRegistered {
                clients: vec![client]
            }
        );
        assert_eq!(deadlines, None);
    }

    #[test]
    fn a_flag_the_admission_does_not_read_is_refused() {
        let with_deadlines = |admission| AdmissionFlags {
            association_deadline_secs: Some(600),
            input_deadline_secs: Some(900),
            ..flags(admission)
        };
        assert_eq!(
            admission_policy(
                AdmissionFlags {
                    clients: vec![fixture_client()],
                    ..with_deadlines(Admission::Open)
                },
                STARTUP
            ),
            Err(AdmissionFlagError::ClientCertsUnread { admission: "open" })
        );
        assert_eq!(
            admission_policy(
                AdmissionFlags {
                    invitation_issuer: Some(fixture_issuer()),
                    ..with_deadlines(Admission::Open)
                },
                STARTUP
            ),
            Err(AdmissionFlagError::IssuerCertUnread { admission: "open" })
        );
        assert_eq!(
            admission_policy(with_deadlines(Admission::Invitation), STARTUP),
            Err(AdmissionFlagError::IssuerCertRequired)
        );
    }

    #[test]
    fn invitation_admission_carries_its_issuer() {
        let (policy, _) = admission_policy(
            AdmissionFlags {
                invitation_issuer: Some(fixture_issuer()),
                association_deadline_secs: Some(600),
                input_deadline_secs: Some(900),
                ..flags(Admission::Invitation)
            },
            STARTUP,
        )
        .expect("invitation with issuer and deadlines");
        assert_eq!(
            policy,
            AdmissionPolicy::Invitation {
                issuer: fixture_issuer()
            }
        );
    }

    #[test]
    fn an_invitation_issuer_that_is_a_roster_node_or_the_coordinator_is_refused() {
        let with_issuer = |issuer: PathBuf| {
            let issuer = issuer.display().to_string();
            configure(
                &stack_args(&[
                    "--client-io",
                    "1:0",
                    "--admission",
                    "invitation",
                    "--invitation-issuer-cert",
                    &issuer,
                    "--association-deadline-secs",
                    "600",
                    "--input-deadline-secs",
                    "900",
                ]),
                UnixSeconds::now(),
            )
        };
        assert!(matches!(
            with_issuer(fixture_path("nodes/cert2.crt")),
            Err(ConfigError::Registration(CoordinatorError::Registration(
                RegistrationError::IssuerIsRosterNode { .. }
            )))
        ));
        assert!(matches!(
            with_issuer(fixture_path("server_cert.crt")),
            Err(ConfigError::Registration(CoordinatorError::Registration(
                RegistrationError::IssuerIsCoordinatorKey
            )))
        ));
        let accepted = with_issuer(fixture_path("clients/cert1.crt"));
        assert!(accepted.is_ok(), "{:?}", accepted.err());
    }

    #[test]
    fn client_slots_under_the_default_admission_need_their_certificates() {
        assert!(matches!(
            configure(&stack_args(&["--client-io", "1:0,1:0"]), STARTUP),
            Err(ConfigError::Registration(CoordinatorError::Registration(
                RegistrationError::PreRegisteredCountMismatch {
                    slots: 2,
                    clients: 0
                }
            )))
        ));
    }

    /// The listener this binary starts serves the roster and association RPCs
    /// of `CoordinatorRPCBase`: a roster node fetches the roster the operator
    /// configured, and a client whose certificate appears in no configuration
    /// associates under open admission (§9, decision 3). Both pin this
    /// coordinator's certificate; a pin to any other key is refused.
    #[tokio::test]
    async fn the_listener_serves_the_roster_and_admits_an_unconfigured_client() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let args = stack_args(&[
            "--client-io",
            "1:0",
            "--admission",
            "open",
            "--association-deadline-secs",
            "600",
            "--input-deadline-secs",
            "900",
        ]);
        let configured = configure(&args, UnixSeconds::now()).expect("open stack configuration");
        let execution_id = configured.execution_id;
        let served = configured.served_roster.clone();
        let expected_roster = NodeRoster::new(
            1,
            (0..5)
                .map(|index| {
                    NodeCertificateDer::from_der(fixture_certificate(&format!(
                        "nodes/cert{index}.crt"
                    )))
                })
                .collect(),
        )
        .expect("fixture roster");
        assert_eq!(served.digest, expected_roster.digest());

        let port = free_local_port();
        let _coordinator = serve(configured, "127.0.0.1", port)
            .await
            .expect("the coordinator listens");
        let coordinator_pin = fixture_spki("server_cert.crt");

        let node = CoordinatorLink::connect(
            "127.0.0.1",
            port,
            &coordinator_pin,
            Some(served.digest),
            fixture_certificate("nodes/cert3.crt"),
            fs::read(fixture_path("nodes/key3.der")).expect("fixture node key"),
        )
        .await
        .expect("a roster node fetches the roster");
        assert_eq!(node.node_roster().n(), 5);
        assert_eq!(node.node_roster().t(), 1);
        assert_eq!(node.node_roster().digest(), expected_roster.digest());

        let client = setup_client(
            "127.0.0.1",
            port,
            fixture_certificate("clients/cert1.crt"),
            fs::read(fixture_path("clients/key1.der")).expect("fixture client key"),
            &ServerPin::Exact(coordinator_pin),
        )
        .await
        .expect("a client pins the coordinator");
        let wire = CoordinatorRPCBaseClient::get_node_roster(&client.client)
            .await
            .expect("the roster is served to a client");
        assert_eq!(
            NodeRoster::try_from(wire)
                .expect("the served roster verifies")
                .digest(),
            expected_roster.digest()
        );
        let summary = CoordinatorRPCBaseClient::get_execution_summary(&client.client, execution_id)
            .await
            .expect("the summary is served");
        assert_eq!(summary.admission, AdmissionPolicyKind::Open);
        assert_eq!(
            summary.client_slots.slots(),
            &[ClientSlotSpec {
                input_count: 1,
                output_count: 0
            }]
        );
        let admission = CoordinatorRPCBaseClient::associate_client(
            &client.client,
            execution_id,
            AssociationRequest {
                slot: None,
                invitation: None,
            },
        )
        .await
        .expect("an unconfigured client associates under open admission");
        assert_eq!(admission.execution_id, execution_id);
        assert_eq!(admission.client_index, ClientIndex(0));
        assert_eq!(
            admission.input_range,
            Some(InputRange {
                start: 0,
                count: std::num::NonZeroU64::new(1).expect("nonzero"),
            })
        );
        assert_eq!(admission.output_rights, OutputRights::None);

        let impostor_pin = setup_client(
            "127.0.0.1",
            port,
            fixture_certificate("clients/cert0.crt"),
            fs::read(fixture_path("clients/key0.der")).expect("fixture client key"),
            &ServerPin::Exact(fixture_spki("nodes/cert0.crt")),
        )
        .await;
        assert!(matches!(
            impostor_pin,
            Err(CoordinatorError::ServerPinMismatch { .. })
        ));
    }
}
