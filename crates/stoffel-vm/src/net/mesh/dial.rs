//! One peer dial, one retry schedule, for the whole mesh.
//!
//! Stage 2 of `docs/design/bootnode-elimination.md` (§2, row "Peer dial +
//! backoff (2 near-duplicates)"). `net/discovery.rs` carried two copies of this
//! loop — `add_node_and_connect` and `add_node_and_connect_direct` — with the
//! same three attempts, the same 10s/20s/40s timeouts and the same
//! 500ms-per-attempt settle delay. They differed in exactly two ways: their log
//! strings, and whether the peer was pushed into the manager's node list before
//! the first attempt. The second difference is real, so it survives as
//! [`NodeInstall`]; the first was an accident, so it does not.
//!
//! # Why there is no "already connected?" short-circuit
//!
//! The obvious refinement is to skip a dial whose peer is already connected.
//! `QuicNetworkManager::is_party_connected` (stoffelnet `quic.rs:1605`) is an
//! `async fn` — it awaits the connection's own liveness probe — so it is not
//! available as a synchronous predicate, and a caller that wants it must
//! `.await` it at a point where yielding is acceptable (design doc §6). Stage 2
//! also has no business changing how many dials happen: it is a deduplication
//! plus a barrier, and a skipped dial is a behavior change.
//!
//! # Stage 4: pinned dials and the reconnect supervisor
//!
//! [`ExpectedIdentity::Pinned`] routes the dial through
//! `connect_as_server_with_expected_public_key` (`quic.rs:2162`), which closes
//! the connection when the certificate the far end presents is not the SPKI the
//! caller named. That is what makes a gossiped address safe to dial (see
//! [`crate::net::mesh::pex`]): the address selects *where* to knock, the pinned
//! SPKI decides *who* is allowed to answer, so a forged address fails closed at
//! the TLS handshake rather than becoming a peer.
//!
//! [`ReconnectSupervisor`] is the `is_party_connected` check Stage 2 deferred,
//! and it closes a real gap: **there is no reconnection logic anywhere in the
//! VM** today. A party whose QUIC connection drops mid-run stays dropped, and
//! the failure surfaces as an MPC round that never completes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stoffelnet::network_utils::{NodePublicKey, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

/// Attempts a mesh dial makes before it gives up.
pub const DEFAULT_DIAL_ATTEMPTS: u32 = 3;

/// Timeout of the first attempt; each later attempt doubles it.
pub const DEFAULT_DIAL_BASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay added per elapsed attempt before retrying, to let peers settle.
pub const DEFAULT_DIAL_RETRY_STEP: Duration = Duration::from_millis(500);

/// How long a dial waits, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialPolicy {
    pub attempts: u32,
    /// Timeout of attempt 0. Attempt `k` waits `base_timeout << k`.
    pub base_timeout: Duration,
    /// Multiplied by the 1-based attempt number to get the settle delay.
    pub retry_step: Duration,
}

impl Default for DialPolicy {
    /// The schedule both pre-Stage-2 copies used: 3 attempts at 10s, 20s, 40s.
    fn default() -> Self {
        Self {
            attempts: DEFAULT_DIAL_ATTEMPTS,
            base_timeout: DEFAULT_DIAL_BASE_TIMEOUT,
            retry_step: DEFAULT_DIAL_RETRY_STEP,
        }
    }
}

impl DialPolicy {
    /// Timeout for a zero-based `attempt`.
    ///
    /// Saturates rather than overflowing: the shift is bounded so an absurd
    /// `attempts` cannot panic in release *or* debug.
    pub fn attempt_timeout(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        self.base_timeout.saturating_mul(factor)
    }

    /// Settle delay after a failed zero-based `attempt`.
    pub fn retry_delay(&self, attempt: u32) -> Duration {
        self.retry_step.saturating_mul(attempt.saturating_add(1))
    }
}

/// Whether the dial registers the peer in the manager's node list first.
///
/// `QuicNetworkManager::add_node_with_party_id` is what makes `accept()`
/// recognise an inbound peer while the certificate allowlist is still empty
/// (stoffelnet `quic.rs:3385`), so it is not optional bookkeeping — it is the
/// difference between the two loops this module replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeInstall {
    /// Push the peer into the node list before dialing.
    Register,
    /// The peer is already in the node list; do not push it again.
    Skip,
}

/// How a dial ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// Connected on the given 1-based attempt.
    Connected { attempt: u32 },
    /// Every attempt failed or timed out.
    Unreachable { attempts: u32 },
}

impl DialOutcome {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

/// Who the dialer will accept an answer from.
///
/// `Any` is the pre-Stage-4 behavior: whoever answers the address becomes the
/// peer, and authorization happens later against the certificate allowlist (and
/// is fail-open when that allowlist is empty, `quic.rs:1791-1796`). `Pinned`
/// names the exact SPKI up front, which is what makes an *unsigned* gossiped
/// address sound — the address is a hint, the key is the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedIdentity {
    /// Accept whoever answers.
    Any,
    /// Accept only a peer presenting this exact `SubjectPublicKeyInfo`.
    Pinned(NodePublicKey),
}

impl ExpectedIdentity {
    pub fn is_pinned(&self) -> bool {
        matches!(self, Self::Pinned(_))
    }
}

/// Dial `addr`, retrying on the schedule in `policy`, accepting any answerer.
///
/// Never fails the caller. A peer that cannot be reached is a liveness fact,
/// not an error in the dialer: the mesh decides what an unreachable peer means
/// at its connectivity barrier, where *all* of the failures are visible at once
/// rather than one at a time.
pub async fn dial_peer(
    net: &mut QuicNetworkManager,
    party_id: PartyId,
    addr: SocketAddr,
    install: NodeInstall,
    policy: DialPolicy,
) -> DialOutcome {
    dial_peer_expecting(net, party_id, addr, &ExpectedIdentity::Any, install, policy).await
}

/// [`dial_peer`], with the identity the far end must present.
///
/// A pinned dial goes through `connect_as_server_with_expected_public_key`,
/// which closes the connection and returns an error on a mismatch, so a wrong
/// answerer is an ordinary failed attempt here — it retries, and then reports
/// [`DialOutcome::Unreachable`] like any other peer that never answered.
pub async fn dial_peer_expecting(
    net: &mut QuicNetworkManager,
    party_id: PartyId,
    addr: SocketAddr,
    expected: &ExpectedIdentity,
    install: NodeInstall,
    policy: DialPolicy,
) -> DialOutcome {
    if install == NodeInstall::Register {
        net.add_node_with_party_id(party_id, addr);
    }

    for attempt in 0..policy.attempts {
        let timeout_duration = policy.attempt_timeout(attempt);

        eprintln!(
            "[peer-connect] Attempting to connect to party {} at {} (attempt {}/{}, timeout {:?}{})",
            party_id,
            addr,
            attempt + 1,
            policy.attempts,
            timeout_duration,
            if expected.is_pinned() {
                ", pinned certificate"
            } else {
                ""
            }
        );

        let dial = async {
            match expected {
                ExpectedIdentity::Any => net.connect(addr).await,
                ExpectedIdentity::Pinned(key) => {
                    net.connect_as_server_with_expected_public_key(addr, key)
                        .await
                }
            }
        };

        match tokio::time::timeout(timeout_duration, dial).await {
            Ok(Ok(_conn)) => {
                eprintln!(
                    "[peer-connect] Successfully connected to party {} at {} (attempt {})",
                    party_id,
                    addr,
                    attempt + 1
                );
                return DialOutcome::Connected {
                    attempt: attempt + 1,
                };
            }
            Ok(Err(e)) => {
                eprintln!(
                    "[peer-connect] Connection error to party {} at {}: {} (attempt {}/{})",
                    party_id,
                    addr,
                    e,
                    attempt + 1,
                    policy.attempts
                );
            }
            Err(_) => {
                eprintln!(
                    "[peer-connect] Timeout connecting to party {} at {} after {:?} (attempt {}/{})",
                    party_id,
                    addr,
                    timeout_duration,
                    attempt + 1,
                    policy.attempts
                );
            }
        }

        // Longer delay before retry to allow other parties to settle.
        if attempt + 1 < policy.attempts {
            let delay = policy.retry_delay(attempt);
            eprintln!("[peer-connect] Waiting {:?} before retry...", delay);
            sleep(delay).await;
        }
    }

    eprintln!(
        "[peer-connect] WARNING: Could not connect to party {} at {} after {} attempts",
        party_id, addr, policy.attempts
    );
    DialOutcome::Unreachable {
        attempts: policy.attempts,
    }
}

/// Dial an address, once, admitting only the peer that presents `expected`.
///
/// The seed path, and the reason a discovery loop can keep dialing an address
/// it has not identified yet **without** endangering the connections it already
/// holds.
///
/// `--peers` and PEX carry *addresses*, and an address carries no identity — but
/// a roster-pinned mesh always knows which *identity* it is still missing, so
/// the dial names the certificate rather than trusting whoever answers. Nothing
/// is pre-registered in the node list: `connect_as_server_with_expected_public_key`
/// keys the connection under the peer's own `derive_id()` and pushes the node
/// itself (`quic.rs:2231-2255`), so registering here would only add a second
/// `nodes` entry under an invented id and inflate `parties()`.
///
/// `connect_as_server_with_expected_public_key` compares the presented
/// `SubjectPublicKeyInfo` against `expected` *before* it opens the persistent
/// stream and before the simultaneous-connect deduplication
/// (`quic.rs:2203-2219` runs ahead of `:2221` `open_bi` and `:2266` the
/// tie-breaker). A wrong answerer therefore costs one closed QUIC connection
/// and an `Err` here — it never reaches `server_connections`, so it can neither
/// replace nor close the connection this node already holds to that peer. The
/// far end sees the same: its `accept()` fails at `accept_bi` with the
/// connection already closed (`quic.rs:3303-3312`), which is *before* its own
/// deduplication branch closes anything (`:3411-3441`).
///
/// That asymmetry is the whole point. An **unpinned** re-dial of an address
/// whose peer is already connected is destructive: whichever side loses the
/// tie-breaker closes a live connection, and if the peer has moved on to the
/// join handshake, that is a handshake dying mid-frame. A pinned probe that
/// reaches the *wrong* party cannot do that.
///
/// It is worth being exact about the limit, because the natural
/// over-generalisation is what shipped a bug once already: a pinned dial that
/// reaches the party it names is **not** protected. The comparison passes, and
/// the connect then continues to `open_bi` and to the tie-breaker like any
/// other dial. Pinning makes it safe to act on an address hint whose owner is
/// unknown; it does not make it safe to dial a peer this node already holds.
/// Only not issuing that dial does — see
/// `join::missing_ranks`, and
/// `a_correctly_aimed_pinned_redial_is_just_as_destructive` for the
/// demonstration.
///
/// One attempt, because the caller is a discovery loop that re-probes what did
/// not answer on its own schedule; retrying here as well would multiply the two
/// budgets together.
///
/// Returns the connection rather than a [`DialOutcome`] because the caller's
/// next question is always "is this really who I aimed at?" — the answer is
/// `authenticated_peer_public_key()` on the value handed back, and it is what
/// lets a discovery loop attribute an address to a roster member.
pub async fn dial_address_expecting(
    net: &mut QuicNetworkManager,
    addr: SocketAddr,
    expected: &NodePublicKey,
    timeout: Duration,
) -> Result<Arc<dyn PeerConnection>, String> {
    let dial = net.connect_as_server_with_expected_public_key(addr, expected);
    match tokio::time::timeout(timeout, dial).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(reason)) => {
            eprintln!(
                "[mesh-dial] {addr} did not answer as compact ID {}: {reason}",
                expected.derive_id()
            );
            Err(reason)
        }
        Err(_) => {
            eprintln!("[mesh-dial] {addr} did not answer within {timeout:?}");
            Err(format!("no answer from {addr} within {timeout:?}"))
        }
    }
}

/// How often the supervisor probes, and how it redials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    /// Delay between sweeps.
    pub probe_interval: Duration,
    /// Schedule one redial runs on.
    ///
    /// Deliberately shorter than [`DialPolicy::default`]: a redial is a
    /// best-effort repair inside a running session, and a 70-second attempt
    /// chain would hold the sweep open long past the next probe.
    pub dial: DialPolicy,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            dial: DialPolicy {
                attempts: 1,
                base_timeout: Duration::from_secs(5),
                retry_step: DEFAULT_DIAL_RETRY_STEP,
            },
        }
    }
}

/// One peer the supervisor keeps connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectTarget {
    pub party_id: PartyId,
    pub addr: SocketAddr,
    pub expected: ExpectedIdentity,
}

/// What one sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconnectSweep {
    /// Targets probed.
    pub probed: usize,
    /// Targets `is_party_connected` reported as live.
    pub healthy: usize,
    /// Dropped targets this sweep brought back.
    pub reconnected: usize,
    /// Dropped targets that did not answer.
    pub still_down: usize,
}

/// Probe every target once and redial the ones that are down.
///
/// Split out of [`ReconnectSupervisor::run`] so the decision — probe, then
/// redial only what failed — is testable without a running task.
///
/// `is_party_connected` is `async` because it awaits the connection's own
/// liveness probe (`quic.rs:1605`), which is exactly why Stage 2's dial path
/// could not short-circuit on it; here the await is free, because the sweep has
/// nothing else to do.
pub async fn reconnect_sweep(
    net: &mut QuicNetworkManager,
    targets: &[ReconnectTarget],
    policy: ReconnectPolicy,
) -> ReconnectSweep {
    let mut sweep = ReconnectSweep {
        probed: targets.len(),
        ..ReconnectSweep::default()
    };

    for target in targets {
        if net.is_party_connected(target.party_id).await {
            sweep.healthy += 1;
            continue;
        }

        eprintln!(
            "[reconnect] party {} is not connected; redialing {}",
            target.party_id, target.addr
        );
        // `NodeInstall::Skip`: the peer is in the node list already — this is a
        // *re*-dial — and re-registering it would append a duplicate entry to
        // `nodes` (`quic.rs:1470`), inflating `parties()` and with it every
        // count derived from it.
        let outcome = dial_peer_expecting(
            net,
            target.party_id,
            target.addr,
            &target.expected,
            NodeInstall::Skip,
            policy.dial,
        )
        .await;
        if outcome.is_connected() {
            sweep.reconnected += 1;
        } else {
            sweep.still_down += 1;
        }
    }

    sweep
}

/// Keeps a set of peers connected for as long as it runs.
///
/// Holds its own clone of the manager. `QuicNetworkManager` shares its
/// connection and public-key maps across clones, so a connection this
/// supervisor re-establishes is visible to every other holder — the same
/// property mesh formation's accept task relies on.
#[derive(Debug)]
pub struct ReconnectSupervisor {
    net: QuicNetworkManager,
    targets: Vec<ReconnectTarget>,
    policy: ReconnectPolicy,
}

impl ReconnectSupervisor {
    pub fn new(
        net: QuicNetworkManager,
        targets: Vec<ReconnectTarget>,
        policy: ReconnectPolicy,
    ) -> Self {
        Self {
            net,
            targets,
            policy,
        }
    }

    /// Sweep until `shutdown` is cancelled.
    pub async fn run(mut self, shutdown: CancellationToken) {
        if self.targets.is_empty() {
            return;
        }

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = sleep(self.policy.probe_interval) => {}
            }

            let sweep = reconnect_sweep(&mut self.net, &self.targets, self.policy).await;
            if sweep.reconnected > 0 || sweep.still_down > 0 {
                eprintln!(
                    "[reconnect] sweep: {} probed, {} healthy, {} reconnected, {} still down",
                    sweep.probed, sweep.healthy, sweep.reconnected, sweep.still_down
                );
            }
        }
    }

    /// Run the supervisor on its own task.
    pub fn spawn(self, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run(shutdown))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two loops Stage 2 merged both waited 10s, then 20s, then 40s. The
    /// merge is only a dedupe if that is still the schedule.
    #[test]
    fn the_default_policy_is_three_attempts_at_ten_twenty_forty_seconds() {
        let policy = DialPolicy::default();

        assert_eq!(policy.attempts, 3);
        assert_eq!(policy.attempt_timeout(0), Duration::from_secs(10));
        assert_eq!(policy.attempt_timeout(1), Duration::from_secs(20));
        assert_eq!(policy.attempt_timeout(2), Duration::from_secs(40));
    }

    #[test]
    fn the_settle_delay_grows_by_one_step_per_attempt() {
        let policy = DialPolicy::default();

        assert_eq!(policy.retry_delay(0), Duration::from_millis(500));
        assert_eq!(policy.retry_delay(1), Duration::from_millis(1000));
    }

    /// `attempt_timeout` is handed an attempt index, and an index big enough to
    /// overflow the shift must saturate rather than panic in a debug build.
    #[test]
    fn an_absurd_attempt_index_saturates_instead_of_overflowing() {
        let policy = DialPolicy::default();

        assert!(policy.attempt_timeout(u32::MAX) >= policy.attempt_timeout(2));
    }

    #[test]
    fn only_a_connected_outcome_reports_connected() {
        assert!(DialOutcome::Connected { attempt: 1 }.is_connected());
        assert!(!DialOutcome::Unreachable { attempts: 3 }.is_connected());
    }

    mod stage_four {
        use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

        use stoffelnet::network_utils::NodePublicKey;

        use super::*;
        use crate::tests::test_utils::init_crypto_provider;

        struct Identity {
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
            public_key: NodePublicKey,
        }

        fn generate_identity() -> Identity {
            let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate self-signed certificate");
            let cert_der = generated.cert.der().to_vec();
            let key_der = generated.signing_key.serialize_der();
            let public_key = QuicNetworkManager::public_key_from_certificate_der(&cert_der)
                .expect("derive SPKI from generated certificate");
            Identity {
                cert_der,
                key_der,
                public_key,
            }
        }

        fn reserve_local_addr() -> SocketAddr {
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .expect("bind UDP socket on localhost");
            socket.local_addr().expect("get local socket address")
        }

        async fn manager_for(identity: &Identity) -> QuicNetworkManager {
            init_crypto_provider();
            let mut net = QuicNetworkManager::new();
            net.set_local_certificate_der(identity.cert_der.clone(), identity.key_der.clone())
                .expect("install local certificate");
            net
        }

        async fn listening_manager(identity: &Identity, addr: SocketAddr) -> QuicNetworkManager {
            let mut net = manager_for(identity).await;
            net.listen(addr).await.expect("listen on loopback");
            net
        }

        /// A QUIC handshake only completes when somebody is accepting, so every
        /// dial in these tests needs a live acceptor opposite it.
        fn accept_once(net: &QuicNetworkManager) -> tokio::task::JoinHandle<()> {
            let mut acceptor = net.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(10), acceptor.accept()).await;
            })
        }

        /// A quick schedule: these tests assert *which* outcome happens, not
        /// how patiently the dialer waits for it.
        fn brisk_policy() -> DialPolicy {
            DialPolicy {
                attempts: 1,
                base_timeout: Duration::from_secs(5),
                retry_step: Duration::from_millis(1),
            }
        }

        /// The property that makes an unsigned gossiped address safe: the
        /// address says where to knock, the pinned SPKI decides who may answer.
        #[tokio::test]
        async fn a_pinned_dial_refuses_the_wrong_certificate_at_the_right_address() {
            let server = generate_identity();
            let impostor = generate_identity();
            let client = generate_identity();

            let addr = reserve_local_addr();
            let listener = listening_manager(&server, addr).await;
            let mut dialer = manager_for(&client).await;

            let accepting = accept_once(&listener);
            let wrong = dial_peer_expecting(
                &mut dialer,
                7,
                addr,
                &ExpectedIdentity::Pinned(impostor.public_key.clone()),
                NodeInstall::Register,
                brisk_policy(),
            )
            .await;
            assert_eq!(
                wrong,
                DialOutcome::Unreachable { attempts: 1 },
                "a peer presenting the wrong certificate must not become a peer"
            );
            accepting.abort();

            let accepting = accept_once(&listener);
            let right = dial_peer_expecting(
                &mut dialer,
                7,
                addr,
                &ExpectedIdentity::Pinned(server.public_key.clone()),
                NodeInstall::Skip,
                brisk_policy(),
            )
            .await;
            assert!(
                right.is_connected(),
                "the same address answers when the pinned key is the one it presents"
            );
            accepting.abort();
        }

        /// A sweep must probe every target and redial only what is down —
        /// nothing in the VM reconnects today, so this is the whole behavior.
        #[tokio::test]
        async fn a_sweep_reconnects_a_peer_that_was_never_connected() {
            let server = generate_identity();
            let client = generate_identity();

            let addr = reserve_local_addr();
            let listener = listening_manager(&server, addr).await;
            let mut net = manager_for(&client).await;
            let party_id = server.public_key.derive_id();
            net.add_node_with_party_id(party_id, addr);
            let accepting = accept_once(&listener);

            let targets = vec![ReconnectTarget {
                party_id,
                addr,
                expected: ExpectedIdentity::Pinned(server.public_key.clone()),
            }];
            let policy = ReconnectPolicy {
                probe_interval: Duration::from_millis(10),
                dial: brisk_policy(),
            };

            let first = reconnect_sweep(&mut net, &targets, policy).await;
            assert_eq!(
                first,
                ReconnectSweep {
                    probed: 1,
                    healthy: 0,
                    reconnected: 1,
                    still_down: 0,
                }
            );

            // Now that it is connected, the next sweep must not redial it.
            let second = reconnect_sweep(&mut net, &targets, policy).await;
            assert_eq!(second.probed, 1);
            assert_eq!(second.healthy, 1);
            assert_eq!(second.reconnected, 0);
            accepting.abort();
        }

        #[tokio::test]
        async fn a_sweep_reports_a_peer_that_does_not_answer() {
            let client = generate_identity();
            let mut net = manager_for(&client).await;
            let dead = reserve_local_addr();
            net.add_node_with_party_id(11, dead);

            let targets = vec![ReconnectTarget {
                party_id: 11,
                addr: dead,
                expected: ExpectedIdentity::Any,
            }];
            let sweep = reconnect_sweep(
                &mut net,
                &targets,
                ReconnectPolicy {
                    probe_interval: Duration::from_millis(10),
                    dial: DialPolicy {
                        attempts: 1,
                        base_timeout: Duration::from_millis(250),
                        retry_step: Duration::from_millis(1),
                    },
                },
            )
            .await;

            assert_eq!(sweep.probed, 1);
            assert_eq!(sweep.still_down, 1);
            assert_eq!(sweep.reconnected, 0);
        }

        /// A supervisor with nothing to watch must exit rather than spin.
        #[tokio::test]
        async fn a_supervisor_with_no_targets_returns_immediately() {
            let identity = generate_identity();
            let net = manager_for(&identity).await;
            let shutdown = CancellationToken::new();

            let handle = ReconnectSupervisor::new(net, Vec::new(), ReconnectPolicy::default())
                .spawn(shutdown);
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("the supervisor returns without being cancelled")
                .expect("the supervisor task did not panic");
        }

        #[tokio::test]
        async fn a_supervisor_stops_when_its_token_is_cancelled() {
            let identity = generate_identity();
            let net = manager_for(&identity).await;
            let shutdown = CancellationToken::new();
            let targets = vec![ReconnectTarget {
                party_id: 1,
                addr: reserve_local_addr(),
                expected: ExpectedIdentity::Any,
            }];

            let handle = ReconnectSupervisor::new(
                net,
                targets,
                ReconnectPolicy {
                    probe_interval: Duration::from_secs(30),
                    dial: brisk_policy(),
                },
            )
            .spawn(shutdown.clone());
            shutdown.cancel();

            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("cancellation is observed inside the sleep")
                .expect("the supervisor task did not panic");
        }

        #[test]
        fn the_reconnect_schedule_is_shorter_than_a_formation_dial() {
            let reconnect = ReconnectPolicy::default();

            assert_eq!(reconnect.dial.attempts, 1);
            assert!(
                reconnect.dial.attempt_timeout(0) < DialPolicy::default().attempt_timeout(0),
                "a repair inside a live session must not outlast its own probe interval"
            );
        }
    }
}
