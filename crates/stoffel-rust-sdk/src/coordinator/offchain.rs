//! Off-chain coordinator re-exports from `stoffel-mpc-coordinator`.
//!
//! The SDK does not implement an off-chain coordinator facade. Users who need
//! coordinator RPC behavior should use the concrete coordinator crate types
//! re-exported here.

pub use stoffel_mpc_coordinator::off_chain::{
    BoundClientIoSchema, ClearShareValue, ClientIdentity, OffChainCoordinatorClient,
    OffChainCoordinatorServer, TypedClearOutput, TypedMaskReservation, TypedMaskShare,
    TypedMaskedInput, TypedMaskedInputEvent, TypedOutputShare, TypedOutputShareEnvelope,
};

pub type OffChainCoordinator<F, S> = OffChainCoordinatorClient<F, S>;
