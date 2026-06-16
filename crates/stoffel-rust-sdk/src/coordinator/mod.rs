//! Coordinator surfaces and re-exports.
//!
//! Off-chain and provider-backed on-chain coordinator behavior is owned by
//! `stoffel-mpc-coordinator`; the SDK re-exports those types and adds a small
//! no-provider on-chain handle for address-only wiring.

pub mod offchain;
pub mod onchain;

pub use offchain::{
    AssignedMaskReservation, AssignedMaskShare, AssignedMaskedInputEvent, ClientIdentity,
    InputAssignment, InputSlotAssignment, OffChainCoordinator, OffChainCoordinatorClient,
    OffChainCoordinatorServer,
};
pub use onchain::{
    node_rpc, setup_coord, ws_connect, BlsOnChainAvssCoordinator, CoordinatorEvent,
    CoordinatorEventStream, HoneyBadgerOnChainCoordinator, OnChainClientIdentity,
    OnChainCoordinator, OnChainCoordinatorConfig, OnChainCoordinatorConfigBuilder,
    OnChainCoordinatorConfigSummary, OnChainCoordinatorHandle, OnChainCoordinatorSummary,
};
pub use stoffel_mpc_coordinator::{Coordinator, CoordinatorError, Round, ShareBound};
