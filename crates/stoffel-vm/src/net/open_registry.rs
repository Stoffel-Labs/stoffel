//! Per-instance accumulation registry for `open_share` and `batch_open_shares`.
//!
//! Each MPC engine/session owns an [`OpenMessageRouter`] that routes wire
//! messages to per-instance [`InstanceRegistry`] values owned by that runtime.
//! Registries are scoped per `instance_id` within one router, preventing
//! cross-session contamination inside the same process.

mod accumulators;
mod consensus;
mod instance;
mod router;
mod wire;

pub use accumulators::{
    ExpOpenAccumulator, ExpOpenProgress, ExpOpenRegistryKind, ExpOpenRequest, RbcState,
};
pub use instance::InstanceRegistry;
pub use router::OpenMessageRouter;
pub use wire::{
    encode_avss_g2_open_exp_wire_message, encode_avss_open_exp_wire_message,
    encode_batch_share_wire_message, encode_hb_open_exp_wire_message, encode_rbc_wire_message,
    encode_single_share_wire_message, UNKNOWN_SENDER_ID,
};
// The in-band tags this module owns on the shared framed stream. Public so that
// `net::mesh::wire` can state blocker B7's disjointness invariant over the real
// constants instead of over copies of their spellings.
pub use wire::{
    AVSS_EXP_WIRE_PREFIX, AVSS_G2_EXP_WIRE_PREFIX, HB_EXP_OPEN_WIRE_PREFIX,
    OPEN_REGISTRY_WIRE_PREFIX,
};

#[cfg(test)]
mod tests;
