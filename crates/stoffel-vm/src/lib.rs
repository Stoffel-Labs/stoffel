#![allow(
    clippy::blocks_in_conditions,
    clippy::len_without_is_empty,
    clippy::too_many_arguments,
    clippy::while_let_loop
)]

pub mod cffi;
pub mod core_vm;
mod error;
pub mod foreign_functions;
pub mod mpc_builtins;
mod mpc_values;
pub mod net;
pub mod output;
mod program;
mod reveal_destination;
pub mod runtime_hooks;
mod runtime_instruction;
mod runtime_value_ops;
mod standard_library;
pub mod storage;
#[cfg(test)]
mod tests;
mod value_conversions;
pub mod vm_function_helper;
mod vm_state;

// Re-export types from stoffel_vm_types for convenient API
pub use error::{VirtualMachineError, VirtualMachineErrorKind, VirtualMachineResult};
pub use net::client_store::{
    ClientInputHydrationCount, ClientInputIndex, ClientInputStore, ClientOutputShareCount,
    ClientOutputShareCountError, ClientShare, ClientShareIndex,
};
pub use net::mpc_engine::{
    DurableIdentityDigest, MpcEngineIdentity, MpcInstanceId, MpcPartyCount, MpcPartyId,
    MpcRuntimeInfo, MpcSessionTopology, MpcSessionTopologyError, MpcThreshold,
};
pub use output::{StdoutOutputSink, VmOutputError, VmOutputResult, VmOutputSink};
pub use stoffel_vm_types::{core_types, functions, instructions};
