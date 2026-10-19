//! One preprocessing volume belongs to one standing pool — across OS processes.
//!
//! The in-process suite already covers the owner record with two threads. That
//! leaves the case the deployment actually has: five containers, each its own
//! process, and an operator who bind-mounts one volume into two of them. What
//! keeps them apart there is not a `Mutex` this crate holds but LMDB's own
//! writer lock, since `admit_preproc_volume` does its check and its claim
//! inside one write transaction. That argument was read and believed; this
//! runs it.
//!
//! A `harness = false` target that re-execs itself, because the alternatives
//! do not fit: `fork()` in a `#[test]` would fork a process holding an mmap and
//! a worker thread, and `CARGO_BIN_EXE_*` needs a `[[bin]]`, which this library
//! crate does not have. Nothing here touches a `#[cfg(test)]` item — the owner
//! API is public — so the child is an ordinary consumer of the crate.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stoffel_vm::net::mpc_engine::DurableIdentityDigest;
use stoffel_vm::storage::preproc::{LmdbPreprocStore, PreprocStoreError};

/// Set in a child process to the role it should play.
const ROLE_VAR: &str = "STOFFEL_PREPROC_VOLUME_PROBE_ROLE";

/// How many fresh volumes the two racing children contend over.
///
/// Modest on purpose: each round is one LMDB open in each child, and the
/// property under test does not get truer with more rounds — a single round in
/// which both children are admitted would already be a failure.
const RACE_ROUNDS: usize = 8;

/// How long the children are given to reach the first round's barrier.
const RACE_START_DELAY: Duration = Duration::from_millis(400);

/// Spacing between rounds, so a child that finishes a round early waits for the
/// other rather than running ahead into the next volume alone.
const RACE_ROUND_SPACING: Duration = Duration::from_millis(60);

fn node(seed: u8) -> DurableIdentityDigest {
    DurableIdentityDigest::from_public_key_bytes(&[seed; 32])
}

fn pool(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// What one open of a volume did, as a line of child stdout.
fn describe_open(result: Result<LmdbPreprocStore, PreprocStoreError>) -> String {
    match result {
        // Dropped immediately: holding the handle open across rounds would
        // leave this process's cached LMDB environment in play, and the point
        // is what a *fresh* open of the volume does.
        Ok(_store) => "CLAIMED".to_owned(),
        Err(PreprocStoreError::VolumeOwnerMismatch { .. }) => {
            "REFUSED VolumeOwnerMismatch".to_owned()
        }
        Err(other) => format!("REFUSED {other:?}"),
    }
}

fn open_as(path: &Path, owner: Option<(u8, u8)>) -> String {
    describe_open(match owner {
        Some((pool_seed, node_seed)) => {
            LmdbPreprocStore::open_for_standing_pool(path, pool(pool_seed), node(node_seed))
        }
        None => LmdbPreprocStore::open(path),
    })
}

fn sleep_until_epoch_millis(deadline_millis: u128) {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_millis();
        if now >= deadline_millis {
            return;
        }
        let remaining = u64::try_from(deadline_millis - now).unwrap_or(u64::MAX);
        std::thread::sleep(Duration::from_millis(remaining.min(20)));
    }
}

// ---------------------------------------------------------------------------
// Child roles
// ---------------------------------------------------------------------------

/// `open <path> <pool-seed|oneshot> <node-seed>` — one open, one line.
fn child_open(args: &[String]) {
    let path = PathBuf::from(&args[0]);
    let owner = match args[1].as_str() {
        "oneshot" => None,
        pool_seed => Some((
            pool_seed.parse::<u8>().expect("pool seed"),
            args[2].parse::<u8>().expect("node seed"),
        )),
    };
    println!("{}", open_as(&path, owner));
}

/// `race <base> <pool-seed> <node-seed> <start-epoch-millis>` — one open per
/// round, each at the round's barrier, so both children are inside
/// `admit_preproc_volume` for the same fresh volume at the same time.
fn child_race(args: &[String]) {
    let base = PathBuf::from(&args[0]);
    let pool_seed = args[1].parse::<u8>().expect("pool seed");
    let node_seed = args[2].parse::<u8>().expect("node seed");
    let start_millis = args[3].parse::<u128>().expect("start instant");

    for round in 0..RACE_ROUNDS {
        let barrier = start_millis
            + u128::try_from(round).expect("round fits u128")
                * u128::from(
                    u64::try_from(RACE_ROUND_SPACING.as_millis()).expect("spacing fits u64"),
                );
        sleep_until_epoch_millis(barrier);
        let path = base.join(format!("round-{round}"));
        let entered = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_millis();
        println!(
            "ROUND {round} {} at={entered}",
            open_as(&path, Some((pool_seed, node_seed)))
        );
    }
}

// ---------------------------------------------------------------------------
// Parent
// ---------------------------------------------------------------------------

fn spawn(role: &str, args: &[String]) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test binary path"));
    command
        .env(ROLE_VAR, role)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Run one child to completion and return its single line of stdout.
fn run_child(role: &str, args: &[String]) -> String {
    let output = spawn(role, args)
        .output()
        .expect("spawning the child test binary");
    assert!(
        output.status.success(),
        "child {role} {args:?} failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("child stdout is utf-8")
        .trim()
        .to_owned()
}

/// A volume claimed by one process is refused to every other opener — where
/// "other process" means a different OS process, not a different thread.
fn deterministic_cases() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("volume");
    let path_arg = path.display().to_string();

    let claim_a = vec![path_arg.clone(), "1".to_owned(), "9".to_owned()];
    let claim_b = vec![path_arg.clone(), "2".to_owned(), "9".to_owned()];
    let claim_other_node = vec![path_arg.clone(), "1".to_owned(), "8".to_owned()];
    let one_shot = vec![path_arg, "oneshot".to_owned(), "0".to_owned()];

    assert_eq!(
        run_child("open", &claim_a),
        "CLAIMED",
        "a fresh volume must be claimable"
    );
    assert_eq!(
        run_child("open", &claim_b),
        "REFUSED VolumeOwnerMismatch",
        "a second standing pool must be refused a volume another pool claimed"
    );
    assert_eq!(
        run_child("open", &claim_other_node),
        "REFUSED VolumeOwnerMismatch",
        "the same pool on a different node must be refused: the material is \
         party-specific"
    );
    assert_eq!(
        run_child("open", &one_shot),
        "REFUSED VolumeOwnerMismatch",
        "a one-shot run must be refused a volume a standing pool claimed"
    );
    assert_eq!(
        run_child("open", &claim_a),
        "CLAIMED",
        "the owning pool must be able to restart, or a standing volume is \
         useless and this test proves nothing about the refusals above"
    );
}

/// Two processes opening the same fresh volume at the same instant: exactly one
/// is admitted, every round.
///
/// Two spawns, not two per round, so the cost is the barrier rather than
/// process creation. A child that arrives late still yields exactly one
/// `CLAIMED`, so the assertion cannot be made flaky by a loaded machine — a
/// slow child weakens how *racy* the round was, never the property.
fn race_cases() {
    let dir = tempfile::tempdir().expect("temp dir");
    let base = dir.path().display().to_string();
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        + RACE_START_DELAY;
    let start_arg = start.as_millis().to_string();

    let children = [("3", "7"), ("4", "7")].map(|(pool_seed, node_seed)| {
        spawn(
            "race",
            &[
                base.clone(),
                pool_seed.to_owned(),
                node_seed.to_owned(),
                start_arg.clone(),
            ],
        )
        .spawn()
        .expect("spawning a racing child")
    });

    // Reap both before asserting anything, so a failure cannot leave a child
    // running on a shared CI machine.
    let outputs = children.map(|child| child.wait_with_output());

    let mut lines: Vec<Vec<String>> = Vec::new();
    for output in outputs {
        let output = output.expect("waiting for a racing child");
        assert!(
            output.status.success(),
            "a racing child failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        lines.push(
            String::from_utf8(output.stdout)
                .expect("child stdout is utf-8")
                .lines()
                .map(str::to_owned)
                .collect(),
        );
    }

    for (index, child) in lines.iter().enumerate() {
        assert_eq!(
            child.len(),
            RACE_ROUNDS,
            "racing child {index} reported {} rounds, expected {RACE_ROUNDS}: {child:?}",
            child.len()
        );
    }

    // Reported, not asserted. Whether the two opens really overlapped is a
    // property of the machine, and the outcome under test is correct either
    // way — a child that arrives late is simply refused. Printing the window
    // is what lets a reader see that the rounds were contended rather than
    // take it on trust.
    let mut tightest = u128::MAX;
    for round in 0..RACE_ROUNDS {
        let verdicts: Vec<&str> = lines
            .iter()
            .map(|child| {
                child[round]
                    .split(" at=")
                    .next()
                    .expect("a round line always has a verdict")
            })
            .collect();
        let entered: Vec<u128> = lines
            .iter()
            .map(|child| {
                child[round]
                    .rsplit_once(" at=")
                    .and_then(|(_, millis)| millis.parse().ok())
                    .expect("a round line always carries its entry instant")
            })
            .collect();
        tightest = tightest.min(entered[0].abs_diff(entered[1]));

        let claimed = verdicts
            .iter()
            .filter(|verdict| **verdict == format!("ROUND {round} CLAIMED"))
            .count();
        let refused = verdicts
            .iter()
            .filter(|verdict| **verdict == format!("ROUND {round} REFUSED VolumeOwnerMismatch"))
            .count();
        assert_eq!(
            (claimed, refused),
            (1, 1),
            "round {round}: exactly one process must claim the volume and the \
             other must be refused as a mismatched owner, got {:?} and {:?}",
            lines[0][round],
            lines[1][round],
        );
    }
    println!("tightest observed two-process open window: {tightest}ms");
}

fn main() {
    match std::env::var(ROLE_VAR).ok().as_deref() {
        Some("open") => {
            let args: Vec<String> = std::env::args().skip(1).collect();
            child_open(&args);
        }
        Some("race") => {
            let args: Vec<String> = std::env::args().skip(1).collect();
            child_race(&args);
        }
        Some(other) => panic!("unknown child role {other}"),
        None => {
            deterministic_cases();
            race_cases();
            println!("preproc_volume_two_processes: ok");
        }
    }
}
