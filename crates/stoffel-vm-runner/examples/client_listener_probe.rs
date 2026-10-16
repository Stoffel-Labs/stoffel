//! Adversarial probe for a standing node's client-facing listener.
//!
//! `docs/design/bootnode-elimination.md` §9 rule 3 gives a node a second socket
//! that carries no certificate allowlist, because the coordinator's
//! per-execution admission is what authorizes a client. Everything else in the
//! campaign reaches a node *through* the coordinator, so nothing in it ever
//! spoke to that socket as an adversary would. This does, and it is deliberately
//! not a client: it never associates with the coordinator, so the only thing
//! that can refuse it is the node.
//!
//! Two probes, matching the two properties that socket has to hold:
//!
//! * `route` — dial each listener with a well-formed certificate the execution's
//!   published admission does not name and send
//!   `EXECUTION_CLIENT_ROUTE_HELLO_V1` for a live execution. The node must
//!   refuse the route and the execution must be unaffected.
//! * `flood` — open more connections than one certificate is allowed to hold.
//!   The node must refuse the surplus and keep serving.
//!
//! The probe asserts only what it can see from outside: that the handshakes it
//! expected did or did not complete. Whether the node *refused* is asserted by
//! the campaign against the node's own log and snapshot, because a refusal that
//! the node does not report is a refusal an operator cannot audit.
//!
//! ```text
//! client_listener_probe route --servers A,B --cert C --key K --execution-id HEX
//! client_listener_probe flood --servers A --cert C --key K --connections 20
//! ```

use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::{
    encode_execution_frame, ExecutionMessageKind, EXECUTION_CLIENT_ROUTE_HELLO_V1,
};
use stoffelnet::transports::quic::{PeerConnection, QuicNetworkManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Announce an execution the prober is not admitted to.
    Route,
    /// Occupy more connection slots than one certificate may hold.
    Flood,
}

struct Options {
    probe: Probe,
    servers: Vec<SocketAddr>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    execution_id: Option<ExecutionId>,
    connections: usize,
    hold: Duration,
    connect_timeout: Duration,
}

fn usage() -> ! {
    eprintln!(
        "usage: client_listener_probe <route|flood> --servers <addr[,addr...]> \\\n\
         \x20   --cert <path> --key <path> [--execution-id <64 hex chars>] \\\n\
         \x20   [--connections <n>] [--hold-ms <n>] [--connect-timeout-ms <n>]"
    );
    exit(2)
}

fn parse_options() -> Options {
    let mut args = std::env::args().skip(1);
    let probe = match args.next().as_deref() {
        Some("route") => Probe::Route,
        Some("flood") => Probe::Flood,
        _ => usage(),
    };
    let mut servers: Vec<SocketAddr> = Vec::new();
    let mut cert_path = None;
    let mut key_path = None;
    let mut execution_id = None;
    let mut connections = 20usize;
    let mut hold = Duration::from_secs(3);
    // A dial at an address nothing is listening on otherwise blocks for
    // quinn's whole handshake timeout, which would turn a misconfigured
    // campaign into a stall rather than a failure.
    let mut connect_timeout = Duration::from_secs(10);

    while let Some(flag) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--servers" => {
                servers = value()
                    .split(',')
                    .map(|address| {
                        address
                            .trim()
                            .parse::<SocketAddr>()
                            .unwrap_or_else(|error| {
                                eprintln!("probe: bad --servers address {address:?}: {error}");
                                exit(2)
                            })
                    })
                    .collect();
            }
            "--cert" => cert_path = Some(value()),
            "--key" => key_path = Some(value()),
            "--execution-id" => {
                let hex_id = value();
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(hex_id.trim(), &mut bytes).unwrap_or_else(|error| {
                    eprintln!("probe: --execution-id must be 64 hex characters: {error}");
                    exit(2)
                });
                execution_id = Some(ExecutionId::from_bytes(bytes));
            }
            "--connections" => {
                connections = value().parse().unwrap_or_else(|error| {
                    eprintln!("probe: bad --connections: {error}");
                    exit(2)
                })
            }
            "--hold-ms" => {
                hold = Duration::from_millis(value().parse().unwrap_or_else(|error| {
                    eprintln!("probe: bad --hold-ms: {error}");
                    exit(2)
                }))
            }
            "--connect-timeout-ms" => {
                connect_timeout = Duration::from_millis(value().parse().unwrap_or_else(|error| {
                    eprintln!("probe: bad --connect-timeout-ms: {error}");
                    exit(2)
                }))
            }
            other => {
                eprintln!("probe: unknown flag {other}");
                usage()
            }
        }
    }

    if servers.is_empty() {
        eprintln!("probe: --servers is required");
        usage()
    }
    let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
        eprintln!("probe: --cert and --key are required");
        usage()
    };
    if probe == Probe::Route && execution_id.is_none() {
        eprintln!("probe: the route probe requires --execution-id");
        usage()
    }
    let read = |path: &str| {
        std::fs::read(path).unwrap_or_else(|error| {
            eprintln!("probe: failed to read {path}: {error}");
            exit(2)
        })
    };
    Options {
        probe,
        servers,
        cert_der: read(&cert_path),
        key_der: read(&key_path),
        execution_id,
        connections,
        hold,
        connect_timeout,
    }
}

/// Dial one client connection, bounding the wait so an unreachable listener
/// fails the probe instead of stalling it.
async fn dial(
    network: &mut QuicNetworkManager,
    address: SocketAddr,
    connect_timeout: Duration,
) -> Result<Arc<dyn PeerConnection>, String> {
    match tokio::time::timeout(connect_timeout, network.connect_as_client(address)).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "no handshake within {}ms",
            connect_timeout.as_millis()
        )),
    }
}

/// One client-role manager carrying the probe's certificate.
///
/// Returned rather than stored in a struct because stoffelnet drives a
/// connection from its manager's endpoint: dropping the manager closes
/// everything it dialled.
fn manager(cert_der: &[u8], key_der: &[u8]) -> QuicNetworkManager {
    let mut network = QuicNetworkManager::new();
    network
        .set_local_certificate_der(cert_der.to_vec(), key_der.to_vec())
        .unwrap_or_else(|error| {
            eprintln!("probe: failed to install the probe certificate: {error}");
            exit(2)
        });
    network
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");
    let options = parse_options();

    match options.probe {
        Probe::Route => route_probe(&options).await,
        Probe::Flood => flood_probe(&options).await,
    }
}

/// Dial every listener and announce an execution this certificate is not
/// admitted to.
async fn route_probe(options: &Options) {
    let execution_id = options
        .execution_id
        .expect("the route probe validated --execution-id");
    let hello = encode_execution_frame(
        execution_id,
        ExecutionMessageKind::Control,
        EXECUTION_CLIENT_ROUTE_HELLO_V1,
    )
    .unwrap_or_else(|error| {
        eprintln!("probe: failed to encode the route hello: {error}");
        exit(2)
    });

    let mut network = manager(&options.cert_der, &options.key_der);
    let mut held: Vec<Arc<dyn PeerConnection>> = Vec::new();
    let mut announced = 0usize;
    for &address in &options.servers {
        match dial(&mut network, address, options.connect_timeout).await {
            Ok(connection) => {
                // The transport authorizes nothing here, so a completed
                // handshake is the expected outcome and proves only that the
                // socket is reachable.
                println!("probe: handshake completed with {address}");
                match connection.send(&hello).await {
                    Ok(()) => {
                        announced += 1;
                        println!("probe: route hello sent to {address}");
                    }
                    Err(error) => println!("probe: route hello to {address} failed: {error}"),
                }
                held.push(connection);
            }
            Err(error) => println!("probe: handshake with {address} failed: {error}"),
        }
    }

    if announced == 0 {
        eprintln!(
            "probe: no route hello reached any listener, so the refusal boundary was never tested"
        );
        exit(1);
    }
    // Hold the connections open long enough for the node to decide and report.
    tokio::time::sleep(options.hold).await;
    println!("probe: route probe announced {announced} unadmitted routes");
}

/// Occupy more connections from one certificate than the node permits.
async fn flood_probe(options: &Options) {
    let address = options.servers[0];
    let mut network = manager(&options.cert_der, &options.key_der);
    let mut held: Vec<Arc<dyn PeerConnection>> = Vec::new();
    let mut failed = 0usize;
    for attempt in 0..options.connections {
        match dial(&mut network, address, options.connect_timeout).await {
            Ok(connection) => held.push(connection),
            Err(error) => {
                failed += 1;
                println!("probe: connection {attempt} to {address} failed: {error}");
            }
        }
    }
    println!(
        "probe: flood completed {}/{} handshakes against {address}",
        held.len(),
        options.connections
    );
    if held.is_empty() {
        eprintln!("probe: no connection reached the listener, so no bound was tested");
        exit(1);
    }
    // Hold them so the node's occupancy bound is tested against concurrent
    // connections rather than a sequence of short-lived ones.
    tokio::time::sleep(options.hold).await;
    println!(
        "probe: flood held {} connections, {failed} refused",
        held.len()
    );
}
