//! What is left of session formation once the bootnode is gone.
//!
//! Stage 8 of `docs/design/bootnode-elimination.md` deleted this module's
//! bootnode half: `agree_session_with_bootnode`, the `SessionMessage` control
//! enum it framed (including the `SessionRequest` and `SessionStart` variants
//! nothing ever constructed), the `CONTROL_STREAM_ID` / `PROGRAM_STREAM_ID`
//! stream numbers that only that exchange used, and `random_instance_id`.
//!
//! Session agreement now happens all-to-all in [`crate::net::mesh::join`], over
//! the mesh's own framed control prefix, and `instance_id` freshness comes from
//! the monotone epoch in [`crate::net::mesh::epoch`] rather than a 64-bit random
//! nonce.
//!
//! [`derive_instance_id`] mixes three things (design doc §9.D.5): the digest of
//! the coordinator's node roster, the program's content address and the agreed
//! epoch. The roster digest is there because the epoch counter is kept *per
//! roster digest* ([`crate::net::mesh::epoch::EpochStore`]): an epoch is only
//! fresh within one digest, so the namespace has to say which digest. Without
//! it, two rosters that share a node would reuse instance ids for the same
//! program and epoch, and a change of digest (a new roster, or a new digest
//! layout) would restart every store at epoch 1 and re-issue ids the old digest
//! already issued — blocker B5's reuse through the back door.
//!
//! [`SessionExecutionId`] is the coordinator's `ExecutionId` as the mesh agrees
//! on it: every party of one session proposes the execution it was started for,
//! and the join refuses a party proposing another one.

use serde::{Deserialize, Serialize};

/// BLAKE3 derive-key context for [`derive_instance_id`].
///
/// `v2` because the derivation changed shape: `v1` hashed
/// `b"stoffel-session-v1" || program_id || nonce` with no roster digest.
pub const INSTANCE_ID_CONTEXT: &str = "stoffel-session-instance-v2";

/// Derive the MPC session namespace every party of one session agrees on.
///
/// `blake3::Hasher::new_derive_key("stoffel-session-instance-v2")` over the
/// roster digest, the program id and the epoch (8 bytes little-endian), with the
/// first 8 bytes of the hash read little-endian. Every input is fixed-width, so
/// no length prefix is needed.
pub fn derive_instance_id(roster_digest: &[u8; 32], program_id: &[u8; 32], epoch: u64) -> u64 {
    let mut hasher = blake3::Hasher::new_derive_key(INSTANCE_ID_CONTEXT);
    hasher.update(roster_digest);
    hasher.update(program_id);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

/// The coordinator's `ExecutionId`, as the bytes the mesh agrees on.
///
/// `stoffel-vm` does not depend on the coordinator crates, so the join carries
/// the execution as its own newtype. `stoffel-vm-runner` converts with
/// `SessionExecutionId::from_bytes(*execution_id.as_bytes())`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionExecutionId([u8; 32]);

impl SessionExecutionId {
    /// All zeros. The coordinator reserves this value and refuses it, so no
    /// coordinated session can carry it.
    pub const UNUSED: Self = Self([0u8; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for SessionExecutionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROSTER: [u8; 32] = [5u8; 32];

    /// Retargets `derive_instance_id_is_deterministic_and_domain_separated`
    /// onto the v2 signature: deterministic, epoch-sensitive, and — the reason
    /// the signature changed — roster-sensitive.
    #[test]
    fn the_instance_id_depends_on_the_roster_digest() {
        let program_id = [7u8; 32];

        let first = derive_instance_id(&ROSTER, &program_id, 11);
        let second = derive_instance_id(&ROSTER, &program_id, 11);
        let different_epoch = derive_instance_id(&ROSTER, &program_id, 12);
        let different_roster = derive_instance_id(&[6u8; 32], &program_id, 11);
        let different_program = derive_instance_id(&ROSTER, &[8u8; 32], 11);

        assert_eq!(first, second);
        assert_ne!(first, different_epoch);
        assert_ne!(
            first, different_roster,
            "the epoch is kept per roster digest, so the namespace must name the digest"
        );
        assert_ne!(first, different_program);
    }

    /// The epoch is what makes one roster's successive runs different sessions
    /// (blocker B5). The bootnode's `random_instance_id` is gone, so this is the
    /// only remaining source of per-run freshness and it has to actually move.
    #[test]
    fn a_new_epoch_is_a_new_session_namespace_for_one_program() {
        let program_id = [3u8; 32];

        let epochs: std::collections::BTreeSet<u64> = (1..=64)
            .map(|epoch| derive_instance_id(&ROSTER, &program_id, epoch))
            .collect();

        assert_eq!(epochs.len(), 64);
    }

    #[test]
    fn a_session_execution_id_round_trips_its_bytes_and_displays_as_hex() {
        let bytes = [0xabu8; 32];
        let id = SessionExecutionId::from_bytes(bytes);

        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert_ne!(id, SessionExecutionId::UNUSED);
        assert_eq!(SessionExecutionId::UNUSED.as_bytes(), &[0u8; 32]);
    }
}
