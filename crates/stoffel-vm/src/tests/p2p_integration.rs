// crates/stoffel-vm/src/tests/p2p_integration.rs
//! Transport coverage for the QUIC stack the VM actually runs on.
//!
//! Until Stage 10 of `docs/design/bootnode-elimination.md` this module imported
//! `crate::net::{NetworkManager, QuicNetworkManager}`, which resolved to the
//! **legacy in-VM** QUIC stack in `net/p2p.rs` — a second implementation that
//! shadowed stoffelnet's identically-spelled types. Nothing in production had
//! used it since Stage 8, yet this was the only module still exercising it, so
//! the suite's one piece of transport cover was aimed at dead code. The legacy
//! stack is gone; these tests now run against `stoffelnet`'s
//! [`QuicNetworkManager`], the transport every MPC backend and the mesh join
//! already use.
//!
//! The retarget is not a rename. stoffelnet's manager differs from the deleted
//! one in three ways this module has to respect:
//!
//! * Connections come back as `Arc<dyn PeerConnection>` with `&self` methods,
//!   not an owned `mut` handle.
//! * There is no public `local_addr()`, so a bound address is obtained by
//!   probing for a free loopback port and retrying a lost race (see
//!   [`listen_on_free_local_port`]).
//! * The role is negotiated over ALPN and the accept path authorizes the peer's
//!   certificate *before* it branches on that role. An inbound **server** peer
//!   that is neither a known node nor on the certificate allowlist is refused —
//!   which is the exact behavior the bootnode existed to work around, and is
//!   pinned here by
//!   [`a_node_refuses_an_unknown_server_peer_when_no_allowlist_is_installed`].
//!
//! Every test here terminates on its own: server tasks accept a known number of
//! connections and service a known number of exchanges rather than looping
//! until an accept timeout expires.

use crate::tests::test_utils::init_crypto_provider;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use stoffelnet::network_utils::ClientType;
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::time::{timeout, Duration};

const SERVER_COUNT: usize = 3;
const CLIENT_COUNT: usize = 3;
const PINGS_PER_SERVER: usize = 3;

/// Attempts to bind a probed-free loopback port before giving up.
const BIND_ATTEMPTS: usize = 8;

/// Budget for any single accept/connect in this module. Everything is loopback
/// in one process, so this is a failure bound, not a latency expectation.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Message sent from client to server
#[derive(Debug, Serialize, Deserialize)]
struct PingMessage {
    /// Timestamp when the ping was sent (milliseconds since epoch)
    sent_at: u128,
    /// Sequence number to identify this ping
    seq_num: u32,
}

/// Message sent from server back to client
#[derive(Debug, Serialize, Deserialize)]
struct PongMessage {
    /// Timestamp when the ping was received (milliseconds since epoch)
    received_at: u128,
    /// Timestamp when the pong was sent (milliseconds since epoch)
    sent_at: u128,
    /// Sequence number from the original ping
    seq_num: u32,
}

/// Get current time in milliseconds since epoch
fn current_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
}

/// Calculate latency from ping and pong timestamps
fn calculate_latency(ping_sent: u128, pong_received: u128, server_processing_time: u128) -> u128 {
    // Total round trip time minus the time the server took to process
    let rtt = pong_received - ping_sent;
    rtt - server_processing_time
}

/// Ask the OS for a loopback UDP port that is free *right now*.
///
/// The probe socket is released before the caller binds for real, so the
/// address is advisory: another test in this binary can take it in the window
/// between this call and the real bind. Callers must be prepared to lose that
/// race and ask again.
fn free_local_addr() -> SocketAddr {
    let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind probe UDP socket on localhost");
    probe.local_addr().expect("read probe socket address")
}

/// Bind `net` to a free loopback port, retrying when the port is lost.
///
/// Returns the address actually bound. stoffelnet's manager exposes no
/// `local_addr()`, so the address has to be chosen by the caller rather than
/// read back after a `:0` bind.
async fn listen_on_free_local_port(net: &mut QuicNetworkManager) -> SocketAddr {
    let mut last_error = String::from("no attempt was made");
    for attempt in 1..=BIND_ATTEMPTS {
        let addr = free_local_addr();
        match net.listen(addr).await {
            Ok(()) => return addr,
            Err(reason) => {
                last_error = format!("listen on {addr}: {reason}");
                if attempt < BIND_ATTEMPTS {
                    tokio::task::yield_now().await;
                }
            }
        }
    }
    panic!("no loopback port could be bound in {BIND_ATTEMPTS} attempts (last: {last_error})");
}

async fn accept_within_budget(net: &mut QuicNetworkManager) -> Arc<dyn PeerConnection> {
    timeout(STEP_TIMEOUT, net.accept())
        .await
        .expect("accept should not exceed its budget")
        .expect("accept should succeed")
}

/// A client dials a listening node and exchanges a request and a response.
///
/// Neither side sleeps. The client owns the teardown: it closes only after it
/// has read the response, and the acceptor parks on a trailing `receive` that
/// resolves (as an error) exactly when that close lands. `close()` tears the
/// QUIC connection down without flushing, so the party that closes must be the
/// party with nothing left to deliver.
#[tokio::test]
async fn a_client_exchanges_a_request_and_a_response_with_a_listening_node() {
    init_crypto_provider();

    let mut server = QuicNetworkManager::new();
    let server_addr = listen_on_free_local_port(&mut server).await;

    let server_handle = tokio::spawn(async move {
        let connection = accept_within_budget(&mut server).await;

        let data = connection.receive().await.expect("server should receive");
        assert_eq!(String::from_utf8_lossy(&data), "test message");

        connection
            .send(b"response")
            .await
            .expect("server should send response");

        // Resolves when the client closes, which it does only after reading the
        // response. The error is the signal.
        let _ = connection.receive().await;
    });

    let mut client = QuicNetworkManager::new();
    let connection = timeout(STEP_TIMEOUT, client.connect_as_client(server_addr))
        .await
        .expect("connect should not exceed its budget")
        .expect("client should connect");

    connection
        .send(b"test message")
        .await
        .expect("client should send message");

    let response = connection
        .receive()
        .await
        .expect("client should receive response");
    assert_eq!(response, b"response");

    connection.close().await.expect("client should close");

    server_handle.await.expect("server task should complete");
}

/// ALPN carries the dialer's role, and both ends agree on it.
///
/// The legacy stack signalled the role with a plaintext `ROLE:SERVER:<id>` line
/// on the wire. stoffelnet negotiates it in the TLS handshake instead, so a
/// role can no longer be asserted by an unauthenticated peer after the fact --
/// this test is the cover for that difference.
#[tokio::test]
async fn alpn_negotiation_agrees_on_the_dialer_role() {
    init_crypto_provider();

    let mut server = QuicNetworkManager::new();
    let server_addr = listen_on_free_local_port(&mut server).await;

    let server_handle = tokio::spawn(async move {
        let connection = accept_within_budget(&mut server).await;
        assert_eq!(
            connection.get_connection_role(),
            ClientType::Client,
            "acceptor should see a client-protocol dialer as a client"
        );
        connection
            .send(b"role-observed")
            .await
            .expect("server should report its observation");
        // Held open until the client closes; see the teardown note above.
        let _ = connection.receive().await;
    });

    let mut client = QuicNetworkManager::new();
    let connection = timeout(STEP_TIMEOUT, client.connect_as_client(server_addr))
        .await
        .expect("connect should not exceed its budget")
        .expect("client should connect");

    assert_eq!(
        connection.get_connection_role(),
        ClientType::Client,
        "dialer should negotiate the client protocol"
    );

    let observed = connection
        .receive()
        .await
        .expect("client should read the acceptor's observation");
    assert_eq!(observed, b"role-observed");

    connection.close().await.expect("client should close");
    server_handle.await.expect("server task should complete");
}

/// An unknown *server* peer is refused when no certificate allowlist is installed.
///
/// This is the single technical reason the bootnode existed (design doc §1):
/// the accept path rejects an inbound server peer that is neither an
/// already-known node nor on the certificate allowlist, so something had to
/// pre-seed peer identity. `install_expected_server_public_keys` -- exercised
/// by `tests::mesh_join_harness` -- is what replaced it. Pinned here because
/// the rejection is what makes the roster load-bearing: were this ever to
/// become permissive, a roster-parse bug would degrade silently instead of
/// failing.
#[tokio::test]
async fn a_node_refuses_an_unknown_server_peer_when_no_allowlist_is_installed() {
    init_crypto_provider();

    let mut acceptor = QuicNetworkManager::new();
    let acceptor_addr = listen_on_free_local_port(&mut acceptor).await;
    assert!(
        !acceptor.has_certificate_public_key_allowlist(),
        "this test is only meaningful without an allowlist"
    );

    // The dialer's own handshake completes -- the rejection is the acceptor's --
    // so the dialer is held open until the verdict is in. A dialer that returned
    // immediately would close the connection out from under the acceptor's
    // stream sync and the refusal would be masked by a transport error.
    let (release_dialer, dialer_released) = tokio::sync::oneshot::channel::<()>();
    let dialer_handle = tokio::spawn(async move {
        let mut dialer = QuicNetworkManager::new();
        let _ = timeout(STEP_TIMEOUT, dialer.connect_as_server(acceptor_addr)).await;
        let _ = dialer_released.await;
    });

    let rejection = timeout(STEP_TIMEOUT, acceptor.accept())
        .await
        .expect("accept should not exceed its budget")
        .expect_err("an unknown server peer must be refused");
    let _ = release_dialer.send(());
    assert!(
        rejection.contains("Unauthorized peer ID"),
        "expected an authorization refusal, got: {rejection}"
    );

    dialer_handle.await.expect("dialer task should complete");
}

/// Three listening nodes, three clients, a full ping-pong matrix.
#[tokio::test]
async fn three_nodes_serve_three_clients_with_ping_pong() {
    init_crypto_provider();

    let (server_handles, server_addrs) = start_ping_pong_servers().await;

    let latency_results = perform_ping_pong_exchanges(&server_addrs).await;

    for (client_id, server_results) in latency_results.iter().enumerate() {
        for (server_id, latencies) in server_results.iter().enumerate() {
            println!("Client {client_id} to Server {server_id} latencies: {latencies:?}");

            assert_eq!(
                latencies.len(),
                PINGS_PER_SERVER,
                "Should have {PINGS_PER_SERVER} latency measurements"
            );
        }
    }

    for handle in server_handles {
        handle.await.expect("Server task should complete");
    }
}

/// Start [`SERVER_COUNT`] ping-pong servers.
///
/// Each one accepts exactly [`CLIENT_COUNT`] connections and services exactly
/// [`PINGS_PER_SERVER`] exchanges on each, then returns. The counts are known,
/// so nothing here waits on an accept timeout to discover that the test is over.
async fn start_ping_pong_servers() -> (Vec<tokio::task::JoinHandle<()>>, Vec<SocketAddr>) {
    let mut server_handles = Vec::new();
    let mut server_addrs = Vec::new();

    for _ in 0..SERVER_COUNT {
        let mut server = QuicNetworkManager::new();
        let addr = listen_on_free_local_port(&mut server).await;
        server_addrs.push(addr);

        let server_handle = tokio::spawn(async move {
            for _ in 0..CLIENT_COUNT {
                let connection = accept_within_budget(&mut server).await;

                for _ in 0..PINGS_PER_SERVER {
                    let data = connection
                        .receive()
                        .await
                        .expect("server should receive ping");
                    let ping: PingMessage =
                        bincode::deserialize(&data).expect("server should decode ping");

                    let received_at = current_time_ms();
                    let pong = PongMessage {
                        received_at,
                        sent_at: current_time_ms(),
                        seq_num: ping.seq_num,
                    };
                    let pong_data = bincode::serialize(&pong).expect("server should encode pong");

                    connection
                        .send(&pong_data)
                        .await
                        .expect("server should send pong");
                }

                // The client closes once it has read the last pong; wait for
                // that rather than dropping the stream underneath it.
                let _ = connection.receive().await;
            }
        });

        server_handles.push(server_handle);
    }

    (server_handles, server_addrs)
}

/// Perform ping-pong exchanges between clients and servers
async fn perform_ping_pong_exchanges(server_addrs: &[SocketAddr]) -> Vec<Vec<Vec<u128>>> {
    let mut clients = Vec::new();
    for _ in 0..CLIENT_COUNT {
        clients.push(QuicNetworkManager::new());
    }

    // Track latency results: [client_id][server_id][ping_sequence]
    let mut latency_results: Vec<Vec<Vec<u128>>> =
        vec![vec![Vec::new(); server_addrs.len()]; CLIENT_COUNT];

    for (client_id, client) in clients.iter_mut().enumerate() {
        for (server_id, &server_addr) in server_addrs.iter().enumerate() {
            let connection = timeout(STEP_TIMEOUT, client.connect_as_client(server_addr))
                .await
                .unwrap_or_else(|_| {
                    panic!("client {client_id} connect to server {server_id} exceeded its budget")
                })
                .unwrap_or_else(|err| {
                    panic!("Client {client_id} should connect to server {server_id}: {err}")
                });

            for seq in 0..PINGS_PER_SERVER {
                let ping = PingMessage {
                    sent_at: current_time_ms(),
                    seq_num: u32::try_from(seq).expect("ping sequence fits u32"),
                };
                let ping_data = bincode::serialize(&ping).expect("Should serialize ping message");

                connection
                    .send(&ping_data)
                    .await
                    .expect("Should send ping message");

                let pong_data = connection
                    .receive()
                    .await
                    .expect("Should receive pong message");
                let pong_received_time = current_time_ms();

                let pong: PongMessage =
                    bincode::deserialize(&pong_data).expect("Should deserialize pong message");

                // Time between the server receiving the ping and sending the pong.
                let server_processing_time = pong.sent_at - pong.received_at;

                let latency =
                    calculate_latency(ping.sent_at, pong_received_time, server_processing_time);

                latency_results[client_id][server_id].push(latency);
            }

            connection.close().await.expect("Should close connection");
        }
    }

    latency_results
}
