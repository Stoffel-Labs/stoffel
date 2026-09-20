//! `instance_id` freshness: a monotone, bounded, LMDB-backed epoch.
//!
//! Stage 5 of `docs/design/bootnode-elimination.md`, blocker **B5**.
//!
//! # Why an epoch exists at all
//!
//! `instance_id` is the MPC session namespace (`net/mpc/protocol_ids.rs:5-14`).
//! Under the bootnode it came from a 64-bit random nonce, so it was fresh per
//! run by construction. A roster-pinned mesh has no such nonce, and the obvious
//! substitute is wrong: roster, program and entry are *constant* across runs in
//! every shipped deployment — `ids/` never changes and the program is baked into
//! the image — so an `instance_id` derived from them alone would be a constant,
//! and every run would reuse the previous run's protocol namespace.
//!
//! The replacement is a counter that each node keeps on disk, keyed by the
//! digest of the coordinator's node roster it belongs to, proposed in the
//! `JoinProposal` and agreed all-to-all.
//! [`crate::net::session::derive_instance_id`] then mixes it with that same
//! roster digest and the program id (design doc §9.D.5): a session id is
//! `blake3::derive_key("stoffel-session-instance-v2", roster_digest ||
//! program_id || epoch)` truncated to 64 bits. The digest is in the derivation
//! because the counter is only monotone *within* one digest: a new roster, or a
//! new digest layout, starts its counter at 1 again, and without the digest in
//! the namespace it would re-issue ids an earlier roster already used.
//!
//! # The bound is the whole point
//!
//! "Agreed epoch = `max(proposals)`" alone is a denial-of-service primitive. One
//! Byzantine roster member proposing `u64::MAX` makes every honest node commit
//! `u64::MAX`, after which `last + 1` overflows and *no* later proposal can ever
//! exceed it: the honest stores are permanently bricked and the roster can never
//! form another session, with no way back short of deleting the store by hand.
//!
//! [`agree_epoch`] therefore bounds the agreed value by `last + `[`MAX_EPOCH_JUMP`]
//! and returns [`EpochError::JumpTooLarge`] beyond it. Aborting the join is the
//! correct outcome: a proposal that far ahead is either an attack or a node
//! whose store came from a different history, and running the session would mean
//! accepting a namespace this node cannot later beat.
//!
//! The cost is a liveness bound, stated plainly: a node that has been offline
//! for more than [`MAX_EPOCH_JUMP`] runs must be resynchronised, which is one
//! [`EpochStore::bump_to`] call, not a rebuild.
//!
//! # Where the store lives
//!
//! The store is a directory, not a file (LMDB keeps a data and a lock file in
//! it). Resolution order, in [`epoch_store_path`]:
//!
//! 1. `--epoch-store <dir>` on `stoffel-run`;
//! 2. the `STOFFEL_EPOCH_STORE` environment variable (what `docker/entrypoint.sh`
//!    turns into the flag);
//! 3. `$HOME/.stoffel/epochs`, matching
//!    [`crate::storage::preproc::LmdbPreprocStore::default_path`]'s shape.
//!
//! In the compose stacks it goes on the **existing** `stoffel-local-store`
//! volume — `STOFFEL_EPOCH_STORE: /app/local-store/epochs-party-N` — beside the
//! party-index-keyed redb file (`STOFFEL_LOCAL_STORE:
//! /app/local-store/party-N.redb`). Sharing that volume is not laziness: it is
//! the volume the `docker compose down` / `up` cycle in
//! `docker/test-coordinator-preproc-store.sh` deliberately preserves, and an
//! epoch store on an unnamed path inside the container would be destroyed by
//! that cycle — at which point `last` resets to 0, the epoch stops being
//! monotone, and B5's reuse comes back through the back door. One store per
//! *node*, keyed by roster digest inside; nodes must not share a directory, the
//! same way they do not share `party-N.redb`.
//!
//! # Why this is synchronous
//!
//! [`crate::storage::preproc::LmdbPreprocStore`] hands its `heed::Env` to a
//! dedicated thread because it is on the preprocessing hot path and must never
//! block a tokio worker. This store is touched exactly twice per run — one read
//! at [`EpochStore::propose`], one write at [`EpochStore::commit`] — with a
//! single 40-byte record, so the actor machinery would be more moving parts than
//! the thing it protects. Callers that care run it under
//! `tokio::task::spawn_blocking`; [`crate::net::mesh::join_mesh`] does not,
//! because at that point it is the only thing the task is doing.

use std::path::{Path, PathBuf};

/// Environment variable naming the epoch store directory.
pub const EPOCH_STORE_ENV: &str = "STOFFEL_EPOCH_STORE";

/// Furthest ahead of this node's own `last` an agreed epoch may be.
///
/// Sized so that a node can miss a long weekend of runs and still rejoin, while
/// a hostile proposal is rejected long before it can exhaust the counter. The
/// exact number is not load-bearing; its existence is (see the module docs).
pub const MAX_EPOCH_JUMP: u64 = 1024;

/// LMDB map size for the store. One record per roster, so this is generous by
/// four orders of magnitude and costs nothing but address space.
const EPOCH_STORE_MAP_SIZE: usize = 1024 * 1024;

/// Name of the single LMDB database inside the environment.
const EPOCH_DB_NAME: &str = "epochs";

/// Why an epoch could not be read, agreed, or committed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EpochError {
    #[error("cannot open the epoch store at {}: {reason}", path.display())]
    Unopenable { path: PathBuf, reason: String },
    #[error("cannot read the epoch store: {reason}")]
    Unreadable { reason: String },
    #[error("cannot write the epoch store: {reason}")]
    Unwritable { reason: String },
    /// The stored record is not an epoch this build can read.
    #[error("the epoch store holds a {len}-byte record where an 8-byte epoch was expected")]
    Corrupt { len: usize },
    /// Blocker B5: a proposal far enough ahead to brick the store is refused.
    #[error(
        "the mesh agreed epoch {agreed}, more than {max} beyond this node's last epoch {last}; \
         refusing to commit it (a member proposing an unbounded epoch would permanently exhaust \
         this store)"
    )]
    JumpTooLarge { last: u64, agreed: u64, max: u64 },
    /// An epoch may only move forward.
    #[error("refusing to move the epoch backwards from {last} to {agreed}")]
    NotMonotone { last: u64, agreed: u64 },
    /// No proposals to agree over. A session has at least this node's own.
    #[error("no epoch proposals to agree over")]
    NoProposals,
}

impl From<heed::Error> for EpochError {
    fn from(error: heed::Error) -> Self {
        Self::Unreadable {
            reason: error.to_string(),
        }
    }
}

/// Where the epoch store lives, given an explicit override.
///
/// See the module docs for the resolution order.
pub fn epoch_store_path(explicit: Option<&str>) -> PathBuf {
    if let Some(path) = explicit {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var(EPOCH_STORE_ENV) {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| ".".into())
        .join(".stoffel")
        .join("epochs")
}

/// Agree one epoch from every party's proposal, and check it is committable.
///
/// `last` is this node's own stored epoch. `proposals` must include this node's
/// own, so that a single-party session still advances.
///
/// The rule is `max(proposals)`, which makes the agreement trivially the same at
/// every honest node that saw the same set — and the bound is what stops it
/// from being a weapon (blocker B5).
pub fn agree_epoch(last: u64, proposals: &[u64]) -> Result<u64, EpochError> {
    let agreed = proposals
        .iter()
        .copied()
        .max()
        .ok_or(EpochError::NoProposals)?;
    if agreed <= last {
        return Err(EpochError::NotMonotone { last, agreed });
    }
    if agreed.saturating_sub(last) > MAX_EPOCH_JUMP {
        return Err(EpochError::JumpTooLarge {
            last,
            agreed,
            max: MAX_EPOCH_JUMP,
        });
    }
    Ok(agreed)
}

/// This node's monotone epoch counter, keyed by roster digest.
///
/// Keyed by roster rather than global because an epoch only has to be fresh
/// *within* the session namespace it feeds: two different rosters are two
/// different sets of parties, and interleaving their counters would make each
/// one jump unpredictably for no benefit.
#[derive(Debug)]
pub struct EpochStore {
    env: heed::Env,
    db: heed::Database<heed::types::Bytes, heed::types::Bytes>,
    path: PathBuf,
}

impl EpochStore {
    /// Open, creating the directory and the database if they are absent.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EpochError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path).map_err(|error| EpochError::Unopenable {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        // Safety: the same contract `LmdbPreprocStore::open` relies on — the
        // directory must not be mutated underneath a live environment by
        // anything but LMDB itself.
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(EPOCH_STORE_MAP_SIZE)
                .max_dbs(1)
                .open(&path)
        }
        .map_err(|error| EpochError::Unopenable {
            path: path.clone(),
            reason: error.to_string(),
        })?;

        let mut wtxn = env.write_txn()?;
        let db = env.create_database(&mut wtxn, Some(EPOCH_DB_NAME))?;
        wtxn.commit()?;

        Ok(Self { env, db, path })
    }

    /// The directory this store occupies.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The last epoch committed for `roster_digest`, or 0 if there is none.
    ///
    /// 0 is a real answer, not a sentinel: [`EpochStore::propose`] proposes
    /// `last + 1`, so a store that has never seen this roster proposes 1, and
    /// [`agree_epoch`] refuses anything at or below `last` — an agreed epoch is
    /// therefore always at least 1.
    pub fn last(&self, roster_digest: &[u8; 32]) -> Result<u64, EpochError> {
        let rtxn = self.env.read_txn()?;
        let stored = self
            .db
            .get(&rtxn, roster_digest)
            .map_err(|error| EpochError::Unreadable {
                reason: error.to_string(),
            })?;
        match stored {
            None => Ok(0),
            Some(bytes) => {
                let bytes: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| EpochError::Corrupt { len: bytes.len() })?;
                Ok(u64::from_le_bytes(bytes))
            }
        }
    }

    /// The epoch this node proposes for its next session on `roster_digest`.
    ///
    /// `last + 1`, and deliberately *not* persisted: a proposal that never
    /// becomes an agreement must not advance this node's counter, or a peer that
    /// crashes mid-join would drag every honest store forward with it. Only
    /// [`EpochStore::commit`] writes.
    pub fn propose(&self, roster_digest: &[u8; 32]) -> Result<u64, EpochError> {
        Ok(self.last(roster_digest)?.saturating_add(1))
    }

    /// Commit the agreed epoch, refusing a non-monotone or unbounded jump.
    ///
    /// Re-reads `last` inside the write transaction rather than trusting the
    /// value the caller proposed against, so two joins racing on one store
    /// cannot interleave a stale bound check with a newer write.
    pub fn commit(&self, roster_digest: &[u8; 32], agreed: u64) -> Result<(), EpochError> {
        let mut wtxn = self.env.write_txn()?;
        let last =
            match self
                .db
                .get(&wtxn, roster_digest)
                .map_err(|error| EpochError::Unreadable {
                    reason: error.to_string(),
                })? {
                None => 0,
                Some(bytes) => {
                    let bytes: [u8; 8] = bytes
                        .try_into()
                        .map_err(|_| EpochError::Corrupt { len: bytes.len() })?;
                    u64::from_le_bytes(bytes)
                }
            };
        if agreed <= last {
            return Err(EpochError::NotMonotone { last, agreed });
        }
        if agreed.saturating_sub(last) > MAX_EPOCH_JUMP {
            return Err(EpochError::JumpTooLarge {
                last,
                agreed,
                max: MAX_EPOCH_JUMP,
            });
        }
        self.db
            .put(&mut wtxn, roster_digest, &agreed.to_le_bytes())
            .map_err(|error| EpochError::Unwritable {
                reason: error.to_string(),
            })?;
        wtxn.commit().map_err(|error| EpochError::Unwritable {
            reason: error.to_string(),
        })
    }

    /// Fast-forward this node's counter past a bound it cannot otherwise clear.
    ///
    /// The documented recovery from [`EpochError::JumpTooLarge`] on a node that
    /// was simply offline for a long time. It is an operator action, it skips
    /// the jump bound, and it is still monotone — an epoch never moves back.
    pub fn bump_to(&self, roster_digest: &[u8; 32], epoch: u64) -> Result<(), EpochError> {
        let last = self.last(roster_digest)?;
        if epoch <= last {
            return Err(EpochError::NotMonotone {
                last,
                agreed: epoch,
            });
        }
        let mut wtxn = self.env.write_txn()?;
        self.db
            .put(&mut wtxn, roster_digest, &epoch.to_le_bytes())
            .map_err(|error| EpochError::Unwritable {
                reason: error.to_string(),
            })?;
        wtxn.commit().map_err(|error| EpochError::Unwritable {
            reason: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "stoffel-epoch-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after the unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create the temporary epoch store directory");
        dir
    }

    const ROSTER: [u8; 32] = [7u8; 32];
    const OTHER_ROSTER: [u8; 32] = [9u8; 32];

    #[test]
    fn a_fresh_store_proposes_one_and_remembers_what_it_commits() {
        let dir = temp_dir("fresh");
        let store = EpochStore::open(&dir).expect("open a fresh epoch store");

        assert_eq!(store.last(&ROSTER).expect("read an absent epoch"), 0);
        assert_eq!(store.propose(&ROSTER).expect("propose"), 1);

        store.commit(&ROSTER, 1).expect("commit the first epoch");
        assert_eq!(store.last(&ROSTER).expect("read"), 1);
        assert_eq!(store.propose(&ROSTER).expect("propose again"), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A proposal is not a commitment: a join that fails after proposing must
    /// leave the counter where it was, or a crashing peer would ratchet every
    /// honest store forward.
    #[test]
    fn proposing_does_not_advance_the_counter() {
        let dir = temp_dir("propose-only");
        let store = EpochStore::open(&dir).expect("open");

        assert_eq!(store.propose(&ROSTER).expect("propose"), 1);
        assert_eq!(store.propose(&ROSTER).expect("propose again"), 1);
        assert_eq!(store.last(&ROSTER).expect("read"), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn epochs_are_kept_per_roster() {
        let dir = temp_dir("per-roster");
        let store = EpochStore::open(&dir).expect("open");

        store.commit(&ROSTER, 5).expect("commit one roster");
        assert_eq!(store.last(&ROSTER).expect("read"), 5);
        assert_eq!(
            store.last(&OTHER_ROSTER).expect("read the other roster"),
            0,
            "a second roster must start its own counter"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Blocker B5, the attack itself: one member proposing `u64::MAX` must not
    /// be committable, because committing it would leave `last + 1` unable to
    /// exceed it ever again.
    #[test]
    fn an_unbounded_proposal_is_refused_rather_than_bricking_the_store() {
        let dir = temp_dir("unbounded");
        let store = EpochStore::open(&dir).expect("open");
        store.commit(&ROSTER, 1).expect("commit an honest epoch");

        let error = agree_epoch(1, &[2, u64::MAX]).expect_err("an unbounded proposal");
        assert_eq!(
            error,
            EpochError::JumpTooLarge {
                last: 1,
                agreed: u64::MAX,
                max: MAX_EPOCH_JUMP,
            }
        );

        // And the store refuses it even if a caller ignores `agree_epoch`.
        assert!(matches!(
            store.commit(&ROSTER, u64::MAX),
            Err(EpochError::JumpTooLarge { .. })
        ));
        assert_eq!(
            store.last(&ROSTER).expect("read"),
            1,
            "a refused commit must not move the counter"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_agreed_epoch_is_the_largest_proposal_within_the_bound() {
        assert_eq!(agree_epoch(0, &[1, 1, 1]).expect("unanimous"), 1);
        assert_eq!(agree_epoch(3, &[4, 9, 7]).expect("max wins"), 9);
        assert_eq!(
            agree_epoch(0, &[MAX_EPOCH_JUMP]).expect("exactly at the bound"),
            MAX_EPOCH_JUMP
        );
        assert_eq!(
            agree_epoch(0, &[MAX_EPOCH_JUMP + 1]).expect_err("one past the bound"),
            EpochError::JumpTooLarge {
                last: 0,
                agreed: MAX_EPOCH_JUMP + 1,
                max: MAX_EPOCH_JUMP,
            }
        );
    }

    #[test]
    fn an_epoch_never_moves_backwards() {
        assert_eq!(
            agree_epoch(5, &[5]).expect_err("re-agreeing the committed epoch"),
            EpochError::NotMonotone { last: 5, agreed: 5 }
        );
        assert_eq!(
            agree_epoch(5, &[3]).expect_err("a stale proposal"),
            EpochError::NotMonotone { last: 5, agreed: 3 }
        );
        assert_eq!(
            agree_epoch(0, &[]).expect_err("no proposals"),
            EpochError::NoProposals
        );
    }

    /// The documented recovery from a node that has been offline for longer
    /// than the bound allows.
    #[test]
    fn an_operator_can_fast_forward_past_the_bound() {
        let dir = temp_dir("bump");
        let store = EpochStore::open(&dir).expect("open");
        store.commit(&ROSTER, 1).expect("commit");

        let far = 1 + MAX_EPOCH_JUMP * 4;
        assert!(matches!(
            store.commit(&ROSTER, far),
            Err(EpochError::JumpTooLarge { .. })
        ));
        store.bump_to(&ROSTER, far).expect("fast-forward");
        assert_eq!(store.last(&ROSTER).expect("read"), far);
        assert!(matches!(
            store.bump_to(&ROSTER, far - 1),
            Err(EpochError::NotMonotone { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The epoch has to survive the process, or B5's reuse comes straight back:
    /// a store that resets to 0 on restart derives the same `instance_id` the
    /// previous run used.
    #[test]
    fn an_epoch_survives_reopening_the_store() {
        let dir = temp_dir("reopen");
        {
            let store = EpochStore::open(&dir).expect("open");
            store.commit(&ROSTER, 42).expect("commit");
        }
        let reopened = EpochStore::open(&dir).expect("reopen");
        assert_eq!(reopened.last(&ROSTER).expect("read"), 42);
        assert_eq!(reopened.propose(&ROSTER).expect("propose"), 43);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The environment variable is what `docker/entrypoint.sh` sets, and the
    /// explicit flag has to win over it.
    #[test]
    fn an_explicit_path_wins_over_the_environment_default() {
        assert_eq!(
            epoch_store_path(Some("/app/local-store/epochs-party-3")),
            PathBuf::from("/app/local-store/epochs-party-3")
        );
        assert!(epoch_store_path(None).ends_with("epochs"));
    }
}
