//! Observability helpers for tracing, health, and metrics.
//!
//! These types provide lightweight SDK-level instrumentation surfaces for
//! applications and tests without requiring an exporter to be configured.

pub mod health;
pub mod metrics;
pub mod tracing;

pub use health::HealthStatus;
pub use metrics::{ServerMetrics, ServerMetricsSnapshot};
pub use tracing::{
    init_tracing, OpenTelemetryGuard, TracingConfig, TracingConfigBuilder, TracingConfigSummary,
};
