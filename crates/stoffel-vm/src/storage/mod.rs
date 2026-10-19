//! Storage interfaces for local and replicated data.

pub mod local;
pub mod preproc;
pub mod replicated;
pub mod retired_executions;
pub mod value_codec;

// Re-export key traits/structs
pub use local::{
    LocalStorage, LocalStorageError, LocalStorageResult, LocalStorageValueError,
    LocalStorageValueResult, LocalStorageValues, RedbLocalStorage,
};
#[cfg(test)]
pub use preproc::PreprocBlob;
pub use preproc::{
    BlobNamespace, LmdbPreprocStore, MaterialKind, PreprocKey, PreprocMeta, PreprocStore,
    PreprocStoreError,
};
pub use replicated::{
    BasicReplicatedStorage, ReplicatedStorage, ReplicatedStorageError, ReplicatedStorageFuture,
    ReplicatedStorageResult,
};
pub use retired_executions::{RetiredExecutionIndex, RetiredExecutionIndexError};
pub use value_codec::{
    decode_value, decode_value_with_context, encode_value, encode_value_with_context,
    PersistentShareContext, PersistentValueContext, PersistentValueError, PersistentValueResult,
};
