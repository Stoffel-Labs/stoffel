//! Masked share reservation registry.
//!
//! Tracks which preprocessing indices are reserved by which clients. Mirrors
//! the coordinator's allocation model: sequential index allocation via an
//! advancing cursor.
//!
//! This registry is process-local and never reaches disk. It used to be able
//! to persist itself through `PreprocStore`, into the same LMDB environment as
//! the preprocessing material — a key prefix was the only separation — so a
//! payload field here would have put a client's masked input on disk beside
//! the mask share that unmasks it. There is nowhere for such a field to land
//! now: the persistence is gone, the `rsv:` namespace with it, and a record
//! under that prefix makes a node refuse its own volume
//! ([`crate::storage::preproc::PreprocStoreError::CondemnedRecordsInVolume`]).
//! `a_standing_engine_writes_nothing_into_the_volume_holding_its_preprocessing`
//! asserts the volume holds no such key.
//!
//! A client's masked input `x + r` does not enter this registry either: the
//! coordinator carries that value to every node, and a node subtracts its own
//! mask share from it in process memory.

use crate::net::mpc_engine::DurableIdentityDigest;
use crate::storage::preproc::PoolAvailability;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Per-index reservation state (only stored for non-Free indices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlotStatus {
    Reserved(DurableIdentityDigest),
    Consumed(DurableIdentityDigest),
}

/// Result of a successful reservation.
#[derive(Debug, Clone)]
pub struct ReservationGrant {
    pub start: u64,
    pub count: u64,
}

impl ReservationGrant {
    pub fn indices(&self) -> std::ops::Range<u64> {
        self.start..self.start + self.count
    }
}

/// Serializable snapshot of the full registry state.
///
/// Slots are stored sparsely: only Reserved/Consumed entries appear in `slots`.
/// Indices >= `next_index` are implicitly Free.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryState {
    pub program_hash: [u8; 32],
    pub node_identity: DurableIdentityDigest,
    #[serde(default)]
    pub run_id: u64,
    #[serde(default)]
    pub preproc_offset: PoolAvailability,
    pub capacity: u64,
    pub next_index: u64,
    pub slots: BTreeMap<u64, SlotStatus>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("insufficient material: need {need}, have {have}")]
    InsufficientMaterial { need: u64, have: u64 },
    #[error("reservation index range overflows u64: start {start}, count {count}")]
    IndexOverflow { start: u64, count: u64 },
    #[error("invalid reservation state: {0}")]
    InvalidState(String),
    #[error("index {0} not reserved")]
    NotReserved(u64),
    #[error("index {0} already consumed")]
    AlreadyConsumed(u64),
    #[error("index {0} out of bounds")]
    OutOfBounds(u64),
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Tracks masked share reservations for one (program, party) pair.
///
/// Slots are stored sparsely in a `BTreeMap`; indices below `next_index` that
/// are absent from the map were never individually reserved (impossible with
/// sequential allocation) or have been evicted.
pub struct ReservationRegistry {
    state: RwLock<RegistryState>,
}

impl ReservationRegistry {
    /// [`Self::new_for_run`] for run 0 with no offset.
    ///
    /// Test-only: production always has a run to name, so it calls
    /// `new_for_run`. Kept because spelling out two defaults at four fixture
    /// call sites says less than this does.
    #[cfg(test)]
    pub fn new(
        program_hash: [u8; 32],
        node_identity: DurableIdentityDigest,
        capacity: u64,
    ) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                program_hash,
                node_identity,
                run_id: 0,
                preproc_offset: PoolAvailability::default(),
                capacity,
                next_index: 0,
                slots: BTreeMap::new(),
            }),
        }
    }

    pub fn new_for_run(
        program_hash: [u8; 32],
        node_identity: DurableIdentityDigest,
        capacity: u64,
        run_id: u64,
        preproc_offset: PoolAvailability,
    ) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                program_hash,
                node_identity,
                run_id,
                preproc_offset,
                capacity,
                next_index: 0,
                slots: BTreeMap::new(),
            }),
        }
    }

    /// Build a registry around a state given on trust.
    ///
    /// Test-only: `new` and `new_for_run` cannot produce an inconsistent state,
    /// and nothing reads one back from anywhere, so the only caller left is the
    /// fixture that needs the inconsistent state `reserve` must survive.
    #[cfg(test)]
    pub fn from_state(state: RegistryState) -> Self {
        Self {
            state: RwLock::new(state),
        }
    }

    /// Reserve `n` consecutive preprocessing indices for `client_identity`.
    pub async fn reserve(
        &self,
        client_identity: DurableIdentityDigest,
        n: u64,
    ) -> Result<ReservationGrant, ReservationError> {
        let mut s = self.state.write().await;
        let avail = s.capacity.checked_sub(s.next_index).ok_or_else(|| {
            ReservationError::InvalidState(format!(
                "next_index {} exceeds capacity {}",
                s.next_index, s.capacity
            ))
        })?;
        if n > avail {
            return Err(ReservationError::InsufficientMaterial {
                need: n,
                have: avail,
            });
        }
        let start = s.next_index;
        let end = start
            .checked_add(n)
            .ok_or(ReservationError::IndexOverflow { start, count: n })?;
        for i in start..end {
            s.slots.insert(i, SlotStatus::Reserved(client_identity));
        }
        s.next_index = end;
        Ok(ReservationGrant { start, count: n })
    }

    /// Mark indices as consumed during MPC execution.
    pub async fn consume(&self, indices: &[u64]) -> Result<(), ReservationError> {
        let mut s = self.state.write().await;
        let mut consumed = Vec::with_capacity(indices.len());
        for &i in indices {
            if i >= s.capacity {
                return Err(ReservationError::OutOfBounds(i));
            }
            let client_id = match s.slots.get(&i) {
                Some(SlotStatus::Reserved(id)) => *id,
                Some(SlotStatus::Consumed(_)) => return Err(ReservationError::AlreadyConsumed(i)),
                None => return Err(ReservationError::NotReserved(i)),
            };
            consumed.push((i, client_id));
        }
        for (i, client_id) in consumed {
            s.slots.insert(i, SlotStatus::Consumed(client_id));
        }
        Ok(())
    }

    pub async fn available(&self) -> u64 {
        let s = self.state.read().await;
        s.capacity.saturating_sub(s.next_index)
    }

    /// Whether every slot handed out so far has been consumed.
    ///
    /// Test-only: it reads the effect `consume` has, which is what a test
    /// asserts and what no production caller asks about.
    #[cfg(test)]
    pub async fn all_reserved_slots_consumed(&self) -> bool {
        let s = self.state.read().await;
        !s.slots.is_empty()
            && s.slots
                .values()
                .all(|status| matches!(status, SlotStatus::Consumed(_)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> DurableIdentityDigest {
        DurableIdentityDigest::from_public_key_bytes(&[seed; 32])
    }

    fn client(seed: u8) -> DurableIdentityDigest {
        DurableIdentityDigest::from_public_key_bytes(&[seed; 16])
    }

    #[tokio::test]
    async fn reserve_basic() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 10);
        let grant = reg.reserve(client(1), 3).await.unwrap();
        assert_eq!(grant.start, 0);
        assert_eq!(grant.count, 3);
        assert_eq!(reg.available().await, 7);
    }

    #[tokio::test]
    async fn reserve_insufficient() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 5);
        let err = reg.reserve(client(1), 6).await.unwrap_err();
        assert!(matches!(
            err,
            ReservationError::InsufficientMaterial { need: 6, have: 5 }
        ));
    }

    #[tokio::test]
    async fn consume_marks_reserved_slots_and_refuses_a_second_pass() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 10);
        let grant = reg.reserve(client(1), 3).await.unwrap();

        let indices: Vec<u64> = grant.indices().collect();
        reg.consume(&indices).await.unwrap();
        assert!(reg.all_reserved_slots_consumed().await);
        assert_eq!(
            reg.available().await,
            7,
            "consuming does not return indices to the cursor"
        );

        let err = reg.consume(&indices).await.unwrap_err();
        assert!(matches!(err, ReservationError::AlreadyConsumed(_)));
    }

    #[tokio::test]
    async fn unreserved_index_errors() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 10);
        let err = reg.consume(&[0]).await.unwrap_err();
        assert!(matches!(err, ReservationError::NotReserved(0)));
    }

    #[tokio::test]
    async fn reserve_rejects_invalid_cursor_without_underflow() {
        let reg = ReservationRegistry::from_state(RegistryState {
            program_hash: [0; 32],
            node_identity: identity(0),
            run_id: 0,
            preproc_offset: PoolAvailability::default(),
            capacity: 1,
            next_index: 2,
            slots: BTreeMap::new(),
        });

        let err = reg.reserve(client(1), 1).await.unwrap_err();
        assert!(matches!(err, ReservationError::InvalidState(_)));
    }
}
