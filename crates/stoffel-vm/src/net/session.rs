//! Execution identity.
//!
//! This module holds identity and nothing else. Agreement is
//! [`crate::net::mesh::join`]'s: it is reached all-to-all over the mesh's own
//! framed control prefix, and the mesh it agrees carries no session at all,
//! because many executions ride one.
//!
//! [`ExecutionId`] is the coordinator's 256-bit identity for one execution, and
//! [`derive_instance_id_for_execution`] reduces it to the compact `u64`
//! namespace the MPC protocols ask for. Freshness therefore comes from the
//! minted id: every party derives the same namespace from it without agreeing
//! anything, and an id nobody minted twice cannot be replayed.
//!
//! `docs/design/bootnode-elimination.md` §8 records what this module used to
//! carry and why none of it survived.

use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Coordinator-issued identity for one execution of a program.
///
/// A program may be executed more than once at the same time, so `program_id`
/// is not a session key. All 256 bits travel with every frame: they are the
/// execution field of
/// [`crate::net::execution_transport::ExecutionEnvelopeV1`], and they are the
/// key [`crate::net::node_supervisor::NodeSupervisor`] holds one running
/// execution under, so two concurrent executions of one program never share an
/// inbox or a supervisor entry.
///
/// [`derive_instance_id_for_execution`] reduces the same 256 bits to the `u64`
/// the MPC protocols ask for. That reduction is a protocol argument and nothing
/// else: no route, no registry key and no admission decision is made from it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionId(pub [u8; 32]);

impl ExecutionId {
    pub fn new() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let id = Self(bytes);
            if !id.is_zero() {
                return id;
            }
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl Default for ExecutionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; 32]> for ExecutionId {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<ExecutionId> for [u8; 32] {
    fn from(value: ExecutionId) -> Self {
        value.into_bytes()
    }
}

impl fmt::Debug for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExecutionId({})", hex::encode(self.0))
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for ExecutionId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(format!(
                "execution ID must contain exactly 64 hexadecimal characters, got {}",
                value.len()
            ));
        }
        let bytes = hex::decode(value).map_err(|error| format!("invalid execution ID: {error}"))?;
        Ok(Self(
            bytes.try_into().expect("validated execution ID length"),
        ))
    }
}

/// Derive the compact `u64` protocol routing ID for an execution.
///
/// The full [`ExecutionId`] stays the authoritative identity — it is what the
/// execution transport's envelope carries and what the node supervisor keys an
/// execution by — so a live collision in this shortened value must be refused
/// there rather than tolerated here.
pub fn derive_instance_id_for_execution(execution_id: &ExecutionId) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-execution-instance-v1");
    hasher.update(execution_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

/// Derive the transport identity for a coordinator-free one-shot session.
///
/// One-shot callers already coordinate on a unique protocol instance ID. Keep
/// that compact API while ensuring their traffic uses the same mandatory wire
/// envelope as coordinator-issued executions.
pub fn derive_execution_id_for_instance(instance_id: u64) -> ExecutionId {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-one-shot-execution-v1");
    hasher.update(&instance_id.to_le_bytes());
    ExecutionId::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_instance_id_is_deterministic_and_execution_scoped() {
        let first_execution = ExecutionId::from([1u8; 32]);
        let second_execution = ExecutionId::from([2u8; 32]);

        assert_eq!(
            derive_instance_id_for_execution(&first_execution),
            derive_instance_id_for_execution(&first_execution)
        );
        assert_ne!(
            derive_instance_id_for_execution(&first_execution),
            derive_instance_id_for_execution(&second_execution)
        );
    }

    #[test]
    fn execution_id_hex_round_trip_matches_coordinator_contract() {
        let id = ExecutionId::from_bytes([0xab; 32]);
        let encoded = id.to_string();

        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded.parse::<ExecutionId>().unwrap(), id);
        assert!("ab".parse::<ExecutionId>().is_err());
        assert!(format!("{}z", &encoded[..63])
            .parse::<ExecutionId>()
            .is_err());
    }
}
