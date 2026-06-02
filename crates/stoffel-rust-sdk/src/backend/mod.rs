//! MPC backend selection and identity helpers.
//!
//! Backend types expose protocol identity for configuration and metadata. Actual
//! HoneyBadger and AVSS protocol execution stays in the VM and MPC protocol
//! crates.

pub mod avss;
pub mod honeybadger;

pub use crate::config::MpcBackend;

/// Common SDK view of protocol backends.
///
/// Protocol execution is still owned by `stoffel-vm` and `mpc-protocols`; this
/// trait only exposes the backend identity needed by SDK builders and
/// configuration code.
pub trait Backend: Send + Sync {
    fn kind(&self) -> MpcBackend;
    fn name(&self) -> &'static str;
}

impl Backend for MpcBackend {
    fn kind(&self) -> MpcBackend {
        *self
    }

    fn name(&self) -> &'static str {
        match self {
            MpcBackend::HoneyBadger => "honeybadger",
            MpcBackend::Avss { .. } => "avss",
        }
    }
}
