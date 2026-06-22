//! Health status values for SDK servers and status APIs.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }

    pub fn is_degraded(&self) -> bool {
        matches!(self, HealthStatus::Degraded { .. })
    }

    pub fn is_unhealthy(&self) -> bool {
        matches!(self, HealthStatus::Unhealthy { .. })
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            HealthStatus::Healthy => None,
            HealthStatus::Degraded { reason } | HealthStatus::Unhealthy { reason } => Some(reason),
        }
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => f.write_str("healthy"),
            HealthStatus::Degraded { reason } => write!(f, "degraded: {reason}"),
            HealthStatus::Unhealthy { reason } => write!(f, "unhealthy: {reason}"),
        }
    }
}
