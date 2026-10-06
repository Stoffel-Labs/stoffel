//! Running Stoffel nodes: the `stoffel run-node` process entry point and the
//! in-process local coordinator runner that spawns it.
//!
//! * [`run_node`] is what `stoffel run-node` executes: one party of a
//!   coordinator-pinned mesh, a coordinator client (`--client`), or a local
//!   no-MPC run. It is a **process entry point** and exits the process.
//! * [`LocalCoordinatorRunner`] starts an in-process off-chain coordinator and
//!   spawns `n` party subprocesses, each `<stoffel binary> run-node <argv>`.
//! * [`coordinator_client`] is the one coordinator-mediated client flow every
//!   client surface runs (`docs/design/bootnode-elimination.md` §9.E.1).
//! * [`admissions`] holds the node-side checks of what the coordinator serves.

pub mod admissions;
pub(crate) mod binary;
pub mod coordinator_client;
mod driver;
pub mod local_runner;

pub use driver::run_node;

pub use coordinator_client::{
    AdmittedClient, BindableSlots, CoordinatorClientConfig, CoordinatorClientError,
    CoordinatorClientRun, CoordinatorEndpoint, PendingAssociation,
};

pub use local_runner::{
    run_offchain_client, ClientOutputRecord, LocalAdmission, LocalClientEndpoint, LocalClientInput,
    LocalClientRun, LocalCoordinatorRunOutput, LocalCoordinatorRunner,
    LocalCoordinatorRunnerBuilder, LocalCoordinatorRunnerError, LocalCoordinatorRunnerResult,
    LocalPartyOutput, LocalTopology, RunningLocalCoordinator,
};
