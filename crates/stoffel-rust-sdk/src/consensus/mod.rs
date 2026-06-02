//! Consensus types are owned by `stoffel-networking`.
//!
//! The SDK re-exports them so applications can stay on the SDK-facing API
//! without duplicating the networking crate's ordering or gate semantics.

pub use stoffelnet::network_utils::{
    ConsensusError, ConsensusGate, NodePublicKey, VerifiedOrdering,
};
