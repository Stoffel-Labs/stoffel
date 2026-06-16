//! HoneyBadger backend identity helpers.
//!
//! This module names the default general-purpose MPC backend without
//! reimplementing HoneyBadger protocol logic in the SDK.

use crate::backend::Backend;
use crate::config::MpcBackend;

#[derive(Debug, Clone, Default)]
pub struct HoneyBadgerBackend;

impl HoneyBadgerBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for HoneyBadgerBackend {
    fn kind(&self) -> MpcBackend {
        MpcBackend::HoneyBadger
    }

    fn name(&self) -> &'static str {
        "honeybadger"
    }
}
