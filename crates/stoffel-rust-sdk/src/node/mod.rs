//! The MPC node: the party driver behind `stoffel run-node`, the operator tool
//! behind `stoffel coord-ctl`, and the local coordinator runner that spawns
//! `stoffel run-node` parties for local execution.
//!
//! [`run_node`] and [`coord_ctl::run`] are process entry points: they parse their
//! own arguments and exit the process on error. Call them only as the body of a
//! dedicated process (the `stoffel` CLI does), never from embedding code.

mod binary;
pub mod coord_ctl;
mod driver;
pub mod execution_stream;
pub mod local_runner;
pub mod returned_share;

pub(crate) use binary::resolve_stoffel_binary;
pub use driver::run_node;
pub use execution_stream::{
    AdmittedClient, AdmittedExecution, CoordinatorExecutionStream, CoordinatorLinkSource,
    ExecutionStreamError, InstanceLedger, LinkFailure, NoticeOutcome, SnapshotCursor,
    StandingClientCatalog, StandingExecutionHandler, StandingProgram, StandingProgramCatalog,
};
pub use local_runner::{
    ClientOutputRecord, LocalClientInput, LocalCoordinatorRunOutput, LocalCoordinatorRunner,
    LocalCoordinatorRunnerBuilder, LocalCoordinatorRunnerError, LocalCoordinatorRunnerResult,
    LocalPartyOutput,
};
pub use returned_share::{ReturnedShare, ReturnedShareParseError, RETURNED_SHARE_PREFIX_V1};

/// The subcommand of the `stoffel` binary that runs one MPC party. Every party
/// process this crate spawns is `<stoffel binary> run-node <party argv>`.
pub const RUN_NODE_SUBCOMMAND: &str = "run-node";
