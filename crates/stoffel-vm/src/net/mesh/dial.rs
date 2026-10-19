//! One peer dial, one retry schedule, for the whole mesh.
//!
//! `docs/design/bootnode-elimination.md` §2, row "Peer dial + backoff (2
//! near-duplicates)". There were three near-copies of this loop across
//! discovery and the standing node's repair sweep; they differed in their log
//! strings and in nothing else that mattered, so there is one of each here.
//!
//! # Every dial is pinned
//!
//! There is no unpinned form. A dial names the exact SPKI it will accept an
//! answer from and goes through `connect_as_server_with_expected_public_key`
//! (stoffelnet `quic.rs:2162`), which closes the connection when the far end
//! presents anything else. That is what makes an *unsigned* address sound (see
//! [`crate::net::mesh::pex`]): the address selects *where* to knock, the pinned
//! SPKI decides *who* is allowed to answer, so a forged address fails closed at
//! the TLS handshake rather than becoming a peer.
//!
//! An unpinned `connect` would also be the one call that can take a live
//! connection down — see [`dial_address_expecting`] for the exact asymmetry —
//! so not offering one is a property, not an omission.
//!
//! # The supervisor is the reconnection the VM did not have
//!
//! [`ReconnectSupervisor`] closes a real gap: outside the standing node's own
//! loop there was no reconnection logic anywhere in the VM. A party whose QUIC
//! connection dropped mid-run stayed dropped, and the failure surfaced as an
//! MPC round that never completed.
//!
//! It repairs the mesh by *dialing*, and puts no control frame on the wire, so
//! it is safe to run for the whole life of a node — including while the
//! execution transport owns the read side of every connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use stoffelnet::network_utils::{NodePublicKey, PartyId};
use stoffelnet::transports::quic::{PeerConnection, QuicNetworkManager};
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
    /// The schedule the deleted discovery path used: 3 attempts at 10s, 20s,
    /// 40s.
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

/// Dial `addr` on the schedule in `policy`, admitting only `expected`.
///
/// Never fails the caller. A peer that cannot be reached is a liveness fact,
/// not an error in the dialer: the mesh decides what an unreachable peer means
/// at its connectivity barrier, where *all* of the failures are visible at once
/// rather than one at a time.
pub async fn dial_peer_expecting(
    net: &mut QuicNetworkManager,
    party_id: PartyId,
    addr: SocketAddr,
    expected: &NodePublicKey,
    policy: DialPolicy,
) -> DialOutcome {
    for attempt in 0..policy.attempts {
        let timeout_duration = policy.attempt_timeout(attempt);

        eprintln!(
            "[peer-connect] Pinned connect to party {} at {} (attempt {}/{}, timeout {:?})",
            party_id,
            addr,
            attempt + 1,
            policy.attempts,
            timeout_duration
        );

        match tokio::time::timeout(
            timeout_duration,
            net.connect_as_server_with_expected_public_key(addr, expected),
        )
        .await
        {
            Ok(Ok(_conn)) => {
                eprintln!(
                    "[peer-connect] Connected to party {} at {} (attempt {})",
                    party_id,
                    addr,
                    attempt + 1
                );
                return DialOutcome::Connected {
                    attempt: attempt + 1,
                };
            }
            Ok(Err(reason)) => {
                eprintln!(
                    "[peer-connect] Connection error to party {} at {}: {} (attempt {}/{})",
                    party_id,
                    addr,
                    reason,
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
/// The discovery path, and the reason a loop can keep dialing an address it has
/// not identified yet **without** endangering the connections it already holds.
///
/// `--peers` and a relayed peer book carry *addresses*, and an address carries
/// no identity — but a roster-pinned mesh always knows which *identity* it is
/// still missing, so the dial names the certificate rather than trusting
/// whoever answers. Nothing is pre-registered in the node list:
/// `connect_as_server_with_expected_public_key` keys the connection under the
/// peer's own `derive_id()` and pushes the node itself
/// (`quic.rs:2231-2255`), so registering here would only add a second `nodes`
/// entry under an invented id and inflate `parties()`.
///
/// `connect_as_server_with_expected_public_key` compares the presented
/// `SubjectPublicKeyInfo` against `expected` *before* it opens the persistent
/// stream and before the simultaneous-connect deduplication
/// (`quic.rs:2203-2219` runs ahead of `:2221` `open_bi` and `:2266` the
/// tie-breaker). A wrong answerer therefore costs one closed QUIC connection
/// and an `Err` here — it never reaches `server_connections`, so it can neither
/// replace nor close the connection this node already holds to that peer.
///
/// That asymmetry is the whole point, and it is worth being exact about its
/// limit, because the natural over-generalisation is what shipped a bug once
/// already: a pinned dial that reaches the party it names is **not** protected.
/// The comparison passes, and the connect then continues to `open_bi` and to
/// the tie-breaker like any other dial. Pinning makes it safe to act on an
/// address hint whose owner is unknown; it does not make it safe to dial a peer
/// this node already holds. Only not issuing that dial does — see
/// `crate::net::mesh::join::missing_ranks` and `dials_towards`.
///
/// One attempt, because the caller is a discovery loop that re-probes what did
/// not answer on its own schedule; retrying here as well would multiply the two
/// budgets together.
///
/// Returns the connection rather than a [`DialOutcome`] because the caller's
/// next question is always "is this really who I aimed at?" — the answer is
/// `authenticated_peer_public_key()` on the value handed back.
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
    /// best-effort repair inside a running mesh, and a 70-second attempt chain
    /// would hold the sweep open long past the next probe.
    pub dial: DialPolicy,
}

impl Default for ReconnectPolicy {
    /// The schedule the standing node's own repair loop ran on before this type
    /// absorbed it: a sweep twice a second, and one 3-second dial attempt per
    /// peer that is down.
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_millis(500),
            dial: DialPolicy {
                attempts: 1,
                base_timeout: Duration::from_secs(3),
                retry_step: DEFAULT_DIAL_RETRY_STEP,
            },
        }
    }
}

/// One peer the supervisor keeps connected.
///
/// `party_id` is the peer's **transport-derived** id, which is what
/// `is_party_connected` and the connection map are keyed by — not its roster
/// rank. The two are unrelated orders (one is a BLAKE3 digest, the other a
/// lexicographic SPKI sort), and probing the rank would ask about a different
/// peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectTarget {
    pub party_id: PartyId,
    pub addr: SocketAddr,
    /// The certificate this peer must present. A repair dial is pinned for the
    /// same reason a discovery dial is.
    pub expected: NodePublicKey,
}

impl ReconnectTarget {
    /// A target for the peer `expected` is, at `addr`, keyed the way the
    /// transport keys it.
    pub fn new(expected: NodePublicKey, addr: SocketAddr) -> Self {
        Self {
            party_id: expected.derive_id(),
            addr,
            expected,
        }
    }
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
/// Split out of [`ReconnectSupervisor::run`] so the decision — reap, probe,
/// then redial only what failed, then renumber — is testable without a running
/// task.
///
/// Three things happen around the dial, and each one is load-bearing:
///
/// * `cleanup_dead_connections` first, so that a connection whose socket is
///   gone but whose map entry is not cannot report healthy and leave a peer
///   unrepaired for the life of the process.
/// * `is_party_connected` is `async` because it awaits the connection's own
///   liveness probe (`quic.rs:1605`), which is why a dial path cannot
///   short-circuit on it; here the await is free, because the sweep has nothing
///   else to do.
/// * `assign_party_ids` after a reconnect, because a replacement connection
///   has to be renumbered into the certificate-sorted order before the
///   execution transport can attribute its frames to the right sender.
///
/// Every target is dialed, so the caller is responsible for passing only the
/// half of the mesh this node is the dialer for — see
/// `crate::net::mesh::join::dials_towards`, which is the one place that
/// decision is made. A supervisor that dialed both ends of a pair would
/// recreate the duplicate connection the tournament exists to prevent.
pub async fn reconnect_sweep(
    net: &mut QuicNetworkManager,
    targets: &[ReconnectTarget],
    policy: ReconnectPolicy,
) -> ReconnectSweep {
    let mut sweep = ReconnectSweep {
        probed: targets.len(),
        ..ReconnectSweep::default()
    };
    if targets.is_empty() {
        return sweep;
    }

    net.cleanup_dead_connections().await;

    for target in targets {
        if net.is_party_connected(target.party_id).await {
            sweep.healthy += 1;
            continue;
        }

        eprintln!(
            "[reconnect] transport peer {} is not connected; redialing {}",
            target.party_id, target.addr
        );
        let outcome = dial_peer_expecting(
            net,
            target.party_id,
            target.addr,
            &target.expected,
            policy.dial,
        )
        .await;
        if outcome.is_connected() {
            let assigned = net.assign_party_ids();
            eprintln!(
                "[reconnect] reconnected transport peer {} (assigned_party_connections={assigned})",
                target.party_id
            );
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

    /// The schedule the two deleted copies shared, preserved exactly: three
    /// attempts at 10s, 20s and 40s, with a 500ms-per-attempt settle.
    #[test]
    fn the_default_schedule_is_the_one_the_deleted_loops_used() {
        let policy = DialPolicy::default();

        assert_eq!(policy.attempts, 3);
        assert_eq!(policy.attempt_timeout(0), Duration::from_secs(10));
        assert_eq!(policy.attempt_timeout(1), Duration::from_secs(20));
        assert_eq!(policy.attempt_timeout(2), Duration::from_secs(40));
        assert_eq!(policy.retry_delay(0), Duration::from_millis(500));
        assert_eq!(policy.retry_delay(1), Duration::from_millis(1000));
    }

    /// An absurd attempt count must not panic in debug through an overflowing
    /// shift, because the policy is operator-reachable.
    #[test]
    fn an_absurd_attempt_count_saturates_instead_of_overflowing() {
        let policy = DialPolicy::default();

        assert!(policy.attempt_timeout(u32::MAX) >= policy.attempt_timeout(16));
        assert!(policy.retry_delay(u32::MAX) > Duration::ZERO);
    }

    /// A repair dial runs once with a short timeout: a sweep that held open for
    /// the full discovery chain would not finish before the next probe.
    #[test]
    fn a_repair_dial_is_shorter_than_a_discovery_dial() {
        let repair = ReconnectPolicy::default();

        assert_eq!(repair.dial.attempts, 1);
        assert!(repair.dial.attempt_timeout(0) < DialPolicy::default().attempt_timeout(0));
    }

    /// A target is keyed by the peer's transport-derived id, not by its roster
    /// rank: `is_party_connected` and the connection map are keyed that way,
    /// and the two orders are unrelated.
    #[test]
    fn a_target_is_keyed_by_the_transport_derived_id() {
        let expected = NodePublicKey(vec![7u8; 32]);
        let target = ReconnectTarget::new(
            expected.clone(),
            "127.0.0.1:9001".parse().expect("parse loopback address"),
        );

        assert_eq!(target.party_id, expected.derive_id());
    }

    /// A supervisor with nothing to keep connected returns rather than spinning
    /// a task that sweeps an empty list forever.
    #[tokio::test]
    async fn a_supervisor_with_no_targets_returns_immediately() {
        let supervisor = ReconnectSupervisor::new(
            QuicNetworkManager::with_node_id(0),
            Vec::new(),
            ReconnectPolicy::default(),
        );

        supervisor.run(CancellationToken::new()).await;
    }

    /// An empty sweep reports an empty sweep, so a caller logging "0 probed"
    /// is not reading a silently skipped one.
    #[tokio::test]
    async fn an_empty_sweep_probes_nothing() {
        let mut net = QuicNetworkManager::with_node_id(0);
        let sweep = reconnect_sweep(&mut net, &[], ReconnectPolicy::default()).await;

        assert_eq!(sweep, ReconnectSweep::default());
    }
}
