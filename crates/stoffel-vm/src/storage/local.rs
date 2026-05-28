//! Interface for persistent storage local to a single server/peer using redb.

use super::value_codec::{
    decode_value, decode_value_with_context, encode_value, encode_value_with_context,
    PersistentValueContext, PersistentValueError,
};
use redb::{Database, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stoffel_vm_types::core_types::{TableMemory, Value};

pub type LocalStorageResult<T> = Result<T, LocalStorageError>;
pub type LocalStorageValueResult<T> = Result<T, LocalStorageValueError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalStorageError {
    #[error("failed to open redb database at {path}: {reason}")]
    Open { path: PathBuf, reason: String },
    #[error("redb transaction '{operation}' failed: {reason}")]
    Transaction {
        operation: &'static str,
        reason: String,
    },
    #[error("redb table '{operation}' failed: {reason}")]
    Table {
        operation: &'static str,
        reason: String,
    },
    #[error("redb operation '{operation}' failed: {reason}")]
    Operation {
        operation: &'static str,
        reason: String,
    },
}

impl From<LocalStorageError> for String {
    fn from(error: LocalStorageError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalStorageValueError {
    #[error(transparent)]
    Storage(#[from] LocalStorageError),
    #[error(transparent)]
    Codec(#[from] PersistentValueError),
}

impl From<LocalStorageValueError> for String {
    fn from(error: LocalStorageValueError) -> Self {
        error.to_string()
    }
}

/// Trait defining operations for local data persistence.
pub trait LocalStorage: Send + Sync {
    /// Stores data associated with a key. Overwrites if the key exists.
    fn store(&mut self, key: &[u8], value: &[u8]) -> LocalStorageResult<()>;

    /// Retrieves data associated with a key.
    fn retrieve(&self, key: &[u8]) -> LocalStorageResult<Option<Vec<u8>>>;

    /// Deletes data associated with a key.
    fn delete(&mut self, key: &[u8]) -> LocalStorageResult<bool>;

    /// Checks if a key exists.
    fn exists(&self, key: &[u8]) -> LocalStorageResult<bool>;
}

/// Value-oriented extension methods for [`LocalStorage`] implementations.
pub trait LocalStorageValues: LocalStorage {
    fn store_value(
        &mut self,
        key: &[u8],
        value: &Value,
        memory: &mut dyn TableMemory,
    ) -> LocalStorageValueResult<()> {
        self.store_value_with_context(key, value, memory, None)
    }

    fn store_value_with_context(
        &mut self,
        key: &[u8],
        value: &Value,
        memory: &mut dyn TableMemory,
        context: Option<&PersistentValueContext>,
    ) -> LocalStorageValueResult<()> {
        let encoded = match context {
            Some(context) => encode_value_with_context(value, memory, Some(context))?,
            None => encode_value(value, memory)?,
        };
        self.store(key, &encoded)?;
        Ok(())
    }

    fn retrieve_value(
        &self,
        key: &[u8],
        memory: &mut dyn TableMemory,
    ) -> LocalStorageValueResult<Option<Value>> {
        self.retrieve_value_with_context(key, memory, None)
    }

    fn retrieve_value_with_context(
        &self,
        key: &[u8],
        memory: &mut dyn TableMemory,
        context: Option<&PersistentValueContext>,
    ) -> LocalStorageValueResult<Option<Value>> {
        self.retrieve(key)?
            .map(|bytes| match context {
                Some(context) => decode_value_with_context(&bytes, memory, Some(context)),
                None => decode_value(&bytes, memory),
            })
            .transpose()
            .map_err(LocalStorageValueError::from)
    }
}

impl<T> LocalStorageValues for T where T: LocalStorage + ?Sized {}

// Define the table for storing key-value pairs
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("data_kv_store");

/// Implementation of LocalStorage using the redb library.
pub struct RedbLocalStorage {
    db: Arc<Database>,
}

impl RedbLocalStorage {
    /// Creates or opens a redb database at the specified path.
    pub fn new<P: AsRef<Path>>(path: P) -> LocalStorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path).map_err(|error| LocalStorageError::Open {
            path,
            reason: error.to_string(),
        })?;

        let write_txn = db
            .begin_write()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "begin initial write",
                reason: error.to_string(),
            })?;
        {
            let _ = write_txn
                .open_table(DATA_TABLE)
                .map_err(|error| LocalStorageError::Table {
                    operation: "open data table",
                    reason: error.to_string(),
                })?;
        }
        write_txn
            .commit()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "commit initial write",
                reason: error.to_string(),
            })?;

        Ok(RedbLocalStorage { db: Arc::new(db) })
    }

    fn with_write_txn<F, R>(&mut self, operation: F) -> LocalStorageResult<R>
    where
        F: FnOnce(&mut redb::Table<&[u8], &[u8]>) -> LocalStorageResult<R>,
    {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "begin write",
                reason: error.to_string(),
            })?;
        let result = {
            let mut table =
                write_txn
                    .open_table(DATA_TABLE)
                    .map_err(|error| LocalStorageError::Table {
                        operation: "open data table for write",
                        reason: error.to_string(),
                    })?;
            operation(&mut table)
        };

        if result.is_ok() {
            write_txn
                .commit()
                .map_err(|error| LocalStorageError::Transaction {
                    operation: "commit write",
                    reason: error.to_string(),
                })?;
        }
        result
    }
}

impl LocalStorage for RedbLocalStorage {
    fn store(&mut self, key: &[u8], value: &[u8]) -> LocalStorageResult<()> {
        self.with_write_txn(|table| {
            table
                .insert(key, value)
                .map_err(|error| LocalStorageError::Operation {
                    operation: "insert",
                    reason: error.to_string(),
                })?;
            Ok(())
        })
    }

    fn retrieve(&self, key: &[u8]) -> LocalStorageResult<Option<Vec<u8>>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "begin read",
                reason: error.to_string(),
            })?;
        let table = read_txn
            .open_table(DATA_TABLE)
            .map_err(|error| LocalStorageError::Table {
                operation: "open data table for read",
                reason: error.to_string(),
            })?;

        match table
            .get(key)
            .map_err(|error| LocalStorageError::Operation {
                operation: "get",
                reason: error.to_string(),
            })? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    fn delete(&mut self, key: &[u8]) -> LocalStorageResult<bool> {
        self.with_write_txn(|table| {
            let existed = table
                .remove(key)
                .map_err(|error| LocalStorageError::Operation {
                    operation: "remove",
                    reason: error.to_string(),
                })?
                .is_some();
            Ok(existed)
        })
    }

    fn exists(&self, key: &[u8]) -> LocalStorageResult<bool> {
        self.retrieve(key).map(|opt| opt.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalStorage, LocalStorageValues, RedbLocalStorage};
    use crate::storage::PersistentShareContext;
    use crate::storage::PersistentValueContext;
    use stoffel_vm_types::core_types::{
        ObjectStore, ShareData, ShareType, TableMemory, TableRef, Value,
    };

    #[test]
    fn redb_storage_round_trips_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut storage = RedbLocalStorage::new(&path).expect("open storage");

        assert!(!storage.exists(b"key").expect("exists"));
        assert_eq!(storage.retrieve(b"key").expect("retrieve"), None);

        storage.store(b"key", b"value").expect("store");

        assert!(storage.exists(b"key").expect("exists"));
        assert_eq!(
            storage.retrieve(b"key").expect("retrieve"),
            Some(b"value".to_vec())
        );

        storage.store(b"key", b"replacement").expect("replace");
        assert_eq!(
            storage.retrieve(b"key").expect("retrieve"),
            Some(b"replacement".to_vec())
        );

        assert!(storage.delete(b"key").expect("delete"));
        assert!(!storage.delete(b"key").expect("delete missing"));
        assert_eq!(storage.retrieve(b"key").expect("retrieve"), None);
    }

    #[test]
    fn redb_storage_reopens_existing_database() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");

        {
            let mut storage = RedbLocalStorage::new(&path).expect("open storage");
            storage.store(b"key", b"value").expect("store");
        }

        let storage = RedbLocalStorage::new(&path).expect("reopen storage");

        assert_eq!(
            storage.retrieve(b"key").expect("retrieve"),
            Some(b"value".to_vec())
        );
    }

    #[test]
    fn redb_storage_round_trips_vm_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut memory = ObjectStore::new();
        let object_ref = memory.create_object_ref().expect("object");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("secret".to_owned()),
                Value::Share(
                    ShareType::secret_int(64),
                    ShareData::Feldman {
                        data: vec![1, 2, 3],
                        commitments: vec![vec![4], vec![5, 6]],
                    },
                ),
            )
            .expect("object field");

        {
            let mut storage = RedbLocalStorage::new(&path).expect("open storage");
            let context = PersistentValueContext::with_share_context(PersistentShareContext::new(
                "avss-mpc",
                "bls12-381",
                "bls12-381-fr",
                0,
                5,
                1,
                b"state",
            ));
            storage
                .store_value_with_context(
                    b"state",
                    &Value::from(object_ref),
                    &mut memory,
                    Some(&context),
                )
                .expect("store value");
        }

        let storage = RedbLocalStorage::new(&path).expect("reopen storage");
        let context = PersistentValueContext::with_share_context(PersistentShareContext::new(
            "avss-mpc",
            "bls12-381",
            "bls12-381-fr",
            0,
            5,
            1,
            b"state",
        ));
        let stored_value = storage
            .retrieve_value_with_context(b"state", &mut memory, Some(&context))
            .expect("retrieve value")
            .expect("stored value");
        let stored_object_ref = match stored_value {
            Value::Object(object_ref) => object_ref,
            other => panic!("expected object, got {other:?}"),
        };

        assert_eq!(
            memory
                .read_table_field(
                    TableRef::from(stored_object_ref),
                    &Value::String("secret".to_owned())
                )
                .expect("read decoded field"),
            Some(Value::Share(
                ShareType::secret_int(64),
                ShareData::Feldman {
                    data: vec![1, 2, 3],
                    commitments: vec![vec![4], vec![5, 6]],
                },
            ))
        );
    }
}
