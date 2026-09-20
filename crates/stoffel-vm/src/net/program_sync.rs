// crates/stoffel-vm/src/net/program_sync.rs
//! # Program identity and the content-addressed program cache
//!
//! A program is named by a domain-separated BLAKE3 hash of its bytes
//! ([`program_id_from_bytes`]), and a node keeps the programs it has fetched in
//! a cache directory keyed by that name ([`program_path`]).
//!
//! Stage 8 of `docs/design/bootnode-elimination.md` deleted the transfer
//! protocol that used to live here: `agree_and_sync_program`, the
//! `ProgramSyncMessage` enum, and the send/receive helpers that framed it. That
//! path only ever ran against a bootnode, and it could not succeed — the
//! bootnode validated uploads with a bare `blake3::hash` against this
//! domain-separated id, so every honest upload was silently dropped (design doc
//! §2). Program transfer between mesh members is [`crate::net::mesh::program`],
//! which is chunked, verified, and pulled from a peer rather than pushed
//! through a third party.
//!
//! What stays is the part both paths share: the identity, the verification, and
//! the cache.

use blake3::Hasher;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub type ProgramSyncResult<T> = Result<T, ProgramSyncError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProgramSyncError {
    #[error("failed to {operation} program cache path {path}: {reason}")]
    CacheIo {
        operation: &'static str,
        path: PathBuf,
        reason: String,
    },
    #[error("downloaded program hash mismatch: expected {expected}, got {actual}")]
    DownloadedProgramHashMismatch { expected: String, actual: String },
}

impl From<ProgramSyncError> for String {
    fn from(error: ProgramSyncError) -> Self {
        error.to_string()
    }
}

fn program_id_hex(program_id: &[u8; 32]) -> String {
    hex::encode(program_id)
}

fn cache_io_error(operation: &'static str, path: &Path, error: io::Error) -> ProgramSyncError {
    ProgramSyncError::CacheIo {
        operation,
        path: path.to_path_buf(),
        reason: error.to_string(),
    }
}

/// Returns the cache directory for storing synced programs
pub fn cache_dir() -> PathBuf {
    std::env::var("STOFFEL_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| ".".into())
                .join(".stoffel")
                .join("programs")
        })
}

/// Returns the path where a program with the given ID should be cached
pub fn program_path(program_id: &[u8; 32]) -> PathBuf {
    let hex = hex::encode(program_id);
    cache_dir().join(hex)
}

/// Computes a BLAKE3 hash of the program bytes to use as its ID
pub fn program_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-program-v1");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Ensures the cache directory exists
pub fn ensure_cache_dir() -> ProgramSyncResult<()> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|error| cache_io_error("create", &dir, error))
}

/// Check that `bytes` hash to `expected_id` under the domain-separated program id.
///
/// Crate-visible so the Stage 0 characterization harness can assert the
/// program↔session binding without re-implementing the hash.
pub(crate) fn verify_program_id(expected_id: &[u8; 32], bytes: &[u8]) -> ProgramSyncResult<()> {
    let actual_id = program_id_from_bytes(bytes);
    if actual_id == *expected_id {
        Ok(())
    } else {
        Err(ProgramSyncError::DownloadedProgramHashMismatch {
            expected: program_id_hex(expected_id),
            actual: program_id_hex(&actual_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloaded_program_hash_mismatch_is_typed() {
        let err = verify_program_id(&[9u8; 32], b"not the announced program").unwrap_err();

        assert!(matches!(
            err,
            ProgramSyncError::DownloadedProgramHashMismatch { .. }
        ));
    }

    /// The program id is the whole reason the bootnode's custody path was dead
    /// (design doc §2): the bootnode compared a bare `blake3::hash` against this
    /// domain-separated one, so it rejected every honest upload. The domain
    /// separation is load-bearing for the mesh too — it is what a peer verifies
    /// a pulled program against — so it is pinned here rather than assumed.
    #[test]
    fn the_program_id_is_domain_separated_from_a_bare_blake3_hash() {
        let bytes = b"a compiled program";

        assert_ne!(
            program_id_from_bytes(bytes),
            *blake3::hash(bytes).as_bytes()
        );
        verify_program_id(&program_id_from_bytes(bytes), bytes)
            .expect("a program verifies against its own domain-separated id");
    }

    #[test]
    fn the_cache_path_is_the_program_id_under_the_cache_directory() {
        let program_id = [4u8; 32];

        let path = program_path(&program_id);

        assert_eq!(path.parent(), Some(cache_dir().as_path()));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(hex::encode(program_id).as_str())
        );
    }
}
