//! Durable, single-use index of the execution identities this node has admitted.
//!
//! An execution identity is single use. [`ExecutionTransportMux`] states the
//! invariant and deliberately keeps no unbounded tombstone of its own: it
//! delegates non-reuse to a durable index, which is this one. A node that has
//! admitted an identity refuses it forever, across restarts, so a republished
//! admission can never re-run work this node already performed and can never
//! make two runs share one execution's preprocessing material.
//!
//! The claim is taken at admission rather than at completion: a node that
//! crashed mid-execution must not re-admit the identity when it comes back,
//! because its peers have already consumed correlated material under it.
//!
//! [`ExecutionTransportMux`]: crate::net::ExecutionTransportMux

use std::path::Path;
use std::sync::Mutex;

use crate::net::session::ExecutionId;

/// Initial virtual map size: ~16 MiB holds on the order of a hundred thousand
/// 32-byte identities, and the map doubles when LMDB reports it full.
const INITIAL_MAP_SIZE: usize = 16 * 1024 * 1024;

type RetiredDatabase = heed::Database<heed::types::Bytes, heed::types::Unit>;

#[derive(Debug, thiserror::Error)]
pub enum RetiredExecutionIndexError {
    #[error("retired execution index IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("retired execution index LMDB error: {0}")]
    Lmdb(#[from] heed::Error),
    #[error("retired execution index cannot grow beyond {bytes} bytes")]
    MapExhausted { bytes: usize },
    #[error("retired execution index lock was poisoned by a panicking writer")]
    Poisoned,
    #[error("the zero execution identity is never admitted and is never recorded")]
    ZeroExecutionId,
}

/// LMDB-backed set of every execution identity this node has admitted.
///
/// Every transaction is created and completed while `serializer` is held, so a
/// map resize never runs beside a live transaction — the condition LMDB
/// requires. The records are 32 bytes with no value, so the transactions are
/// short enough to run inline on the caller's thread; the preprocessing store's
/// actor thread exists for multi-megabyte blobs, which this index never holds.
pub struct RetiredExecutionIndex {
    env: heed::Env,
    database: RetiredDatabase,
    serializer: Mutex<()>,
}

impl RetiredExecutionIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RetiredExecutionIndexError> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;
        let map_size = initial_map_size(path)?;
        // SAFETY: LMDB requires that no other process has this environment open
        // with a different configuration. One standing node owns its state
        // directory. The preprocessing volume beside it no longer rests on that
        // as an operator requirement: `LmdbPreprocStore::open_for_standing_pool`
        // records the owning pool and node inside the volume and refuses it to
        // any other opener.
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(map_size)
                .max_dbs(1)
                .open(path)
        }?;
        let mut transaction = env.write_txn()?;
        let database = env.create_database(&mut transaction, Some("retired_executions"))?;
        transaction.commit()?;
        Ok(Self {
            env,
            database,
            serializer: Mutex::new(()),
        })
    }

    /// Records `execution_id` as admitted, reporting whether this call is the
    /// one that recorded it.
    ///
    /// `false` means the identity was already admitted by this node, possibly
    /// in an earlier process, and must not be admitted again.
    pub fn claim(&self, execution_id: ExecutionId) -> Result<bool, RetiredExecutionIndexError> {
        if execution_id.is_zero() {
            return Err(RetiredExecutionIndexError::ZeroExecutionId);
        }
        let key = *execution_id.as_bytes();
        self.with_map_growth(|env, database| {
            let mut transaction = env.write_txn()?;
            if database.get(&transaction, &key)?.is_some() {
                transaction.abort();
                return Ok(false);
            }
            database.put(&mut transaction, &key, &())?;
            transaction.commit()?;
            Ok(true)
        })
    }

    /// Whether this node has already admitted `execution_id`.
    pub fn contains(&self, execution_id: ExecutionId) -> Result<bool, RetiredExecutionIndexError> {
        let key = *execution_id.as_bytes();
        let _serialized = self.lock()?;
        let transaction = self.env.read_txn()?;
        let found = self.database.get(&transaction, &key)?.is_some();
        drop(transaction);
        Ok(found)
    }

    /// How many identities this node has admitted over its whole life.
    pub fn len(&self) -> Result<u64, RetiredExecutionIndexError> {
        let _serialized = self.lock()?;
        let transaction = self.env.read_txn()?;
        let count = self.database.len(&transaction)?;
        drop(transaction);
        Ok(count)
    }

    pub fn is_empty(&self) -> Result<bool, RetiredExecutionIndexError> {
        Ok(self.len()? == 0)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, RetiredExecutionIndexError> {
        self.serializer
            .lock()
            .map_err(|_| RetiredExecutionIndexError::Poisoned)
    }

    fn with_map_growth<T>(
        &self,
        mut operation: impl FnMut(&heed::Env, &RetiredDatabase) -> Result<T, heed::Error>,
    ) -> Result<T, RetiredExecutionIndexError> {
        let _serialized = self.lock()?;
        loop {
            match operation(&self.env, &self.database) {
                Err(heed::Error::Mdb(heed::MdbError::MapFull)) => {
                    let current = self.env.info().map_size;
                    let grown = current
                        .checked_mul(2)
                        .ok_or(RetiredExecutionIndexError::MapExhausted { bytes: current })?;
                    // SAFETY: `serializer` is held for the whole call and every
                    // transaction on this environment is taken under it, so the
                    // failed transaction was dropped before `operation`
                    // returned and no other transaction is live.
                    unsafe { self.env.resize(grown) }?;
                    tracing::warn!(
                        old_map_size = current,
                        new_map_size = grown,
                        "grew the retired execution index LMDB map after MDB_MAP_FULL"
                    );
                }
                result => return result.map_err(RetiredExecutionIndexError::Lmdb),
            }
        }
    }
}

impl std::fmt::Debug for RetiredExecutionIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetiredExecutionIndex")
            .field("map_size", &self.env.info().map_size)
            .finish_non_exhaustive()
    }
}

/// An existing data file larger than the requested map cannot be opened, so the
/// request doubles until it covers what is already on disk.
fn initial_map_size(path: &Path) -> Result<usize, RetiredExecutionIndexError> {
    let existing = match std::fs::metadata(path.join("data.mdb")) {
        Ok(metadata) => usize::try_from(metadata.len())
            .map_err(|_| RetiredExecutionIndexError::MapExhausted { bytes: usize::MAX })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    let mut map_size = INITIAL_MAP_SIZE;
    while map_size <= existing {
        map_size = map_size
            .checked_mul(2)
            .ok_or(RetiredExecutionIndexError::MapExhausted { bytes: existing })?;
    }
    Ok(map_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_execution_identity_is_claimed_once_and_refused_forever() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let index = RetiredExecutionIndex::open(directory.path()).expect("open index");
        let execution = ExecutionId::from([7; 32]);

        assert!(index.claim(execution).expect("first claim"));
        assert!(!index.claim(execution).expect("second claim"));
        assert!(index.contains(execution).expect("membership"));
        assert_eq!(index.len().expect("length"), 1);
    }

    #[test]
    fn a_claim_survives_the_process_that_made_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let execution = ExecutionId::from([9; 32]);
        {
            let index = RetiredExecutionIndex::open(directory.path()).expect("open index");
            assert!(index.claim(execution).expect("first claim"));
        }

        let reopened = RetiredExecutionIndex::open(directory.path()).expect("reopen index");
        assert!(
            reopened.contains(execution).expect("membership"),
            "a restarted node must still refuse an identity it already admitted"
        );
        assert!(!reopened.claim(execution).expect("claim after restart"));
    }

    /// A restarted node reports the size of the index it reopened, and that
    /// number is the whole retained history rather than what the new process
    /// has admitted. It is the only difference an operator — or the standing
    /// campaign's restart arm — can observe between an index that survived the
    /// process that wrote it and one that did not.
    #[test]
    fn a_reopened_index_reports_every_identity_it_retained() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let admitted: Vec<ExecutionId> = (1..=9u8)
            .map(|byte| ExecutionId::from([byte; 32]))
            .collect();
        {
            let index = RetiredExecutionIndex::open(directory.path()).expect("open index");
            assert!(index.is_empty().expect("fresh index is empty"));
            for execution in &admitted {
                assert!(index.claim(*execution).expect("claim"));
            }
            assert_eq!(index.len().expect("length"), admitted.len() as u64);
        }

        let reopened = RetiredExecutionIndex::open(directory.path()).expect("reopen index");
        assert_eq!(
            reopened.len().expect("retained length"),
            admitted.len() as u64,
            "a reopened index must report the identities the dead process admitted"
        );
        assert!(!reopened.is_empty().expect("retained emptiness"));
        for execution in &admitted {
            assert!(
                reopened.contains(*execution).expect("membership"),
                "{execution} was admitted before the restart and must still be held"
            );
        }
    }

    #[test]
    fn distinct_identities_do_not_collide() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let index = RetiredExecutionIndex::open(directory.path()).expect("open index");
        for byte in 1..=32u8 {
            assert!(index.claim(ExecutionId::from([byte; 32])).expect("claim"));
        }
        assert_eq!(index.len().expect("length"), 32);
        assert!(!index
            .contains(ExecutionId::from([200; 32]))
            .expect("membership"));
    }

    #[test]
    fn the_zero_identity_is_never_recorded() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let index = RetiredExecutionIndex::open(directory.path()).expect("open index");
        assert!(matches!(
            index.claim(ExecutionId::from([0; 32])),
            Err(RetiredExecutionIndexError::ZeroExecutionId)
        ));
        assert!(index.is_empty().expect("length"));
    }
}
