//! Storage interfaces for local and replicated data.

pub mod local;
pub mod preproc;
pub mod replicated;
pub mod value_codec;

// Re-export key traits/structs
pub use local::{
    LocalStorage, LocalStorageError, LocalStorageResult, LocalStorageValueError,
    LocalStorageValueResult, LocalStorageValues, RedbLocalStorage,
};
pub use preproc::{
    LmdbPreprocStore, MaterialKind, PreprocBlob, PreprocKey, PreprocMeta, PreprocStore,
    PreprocStoreError,
};
pub use replicated::{
    BasicReplicatedStorage, ReplicatedStorage, ReplicatedStorageError, ReplicatedStorageFuture,
    ReplicatedStorageResult,
};
pub use value_codec::{
    decode_value, decode_value_with_context, encode_value, encode_value_with_context,
    PersistentShareContext, PersistentValueContext, PersistentValueError, PersistentValueResult,
};
