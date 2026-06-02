//! Tracing and OpenTelemetry setup helpers.
//!
//! Applications that already install subscribers can ignore this module. The
//! helpers are for SDK users who want a quick structured tracing setup.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use serde::{Deserialize, Serialize};
use tracing::Level;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct TracingConfig {
    max_level: Level,
    ansi: bool,
    compact: bool,
    service_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracingConfigSummary {
    pub max_level: String,
    pub ansi: bool,
    pub compact: bool,
    pub service_name: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            max_level: Level::INFO,
            ansi: true,
            compact: true,
            service_name: "stoffel-rust-sdk".to_owned(),
        }
    }
}

impl TracingConfig {
    pub fn builder() -> TracingConfigBuilder {
        TracingConfigBuilder::default()
    }

    pub fn max_level(&self) -> Level {
        self.max_level
    }

    pub fn ansi(&self) -> bool {
        self.ansi
    }

    pub fn compact(&self) -> bool {
        self.compact
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn summary(&self) -> TracingConfigSummary {
        TracingConfigSummary {
            max_level: self.max_level.to_string(),
            ansi: self.ansi,
            compact: self.compact,
            service_name: self.service_name.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_name.trim().is_empty() {
            return Err(Error::Configuration(
                "tracing service_name must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn install(self) -> Result<()> {
        self.validate()?;
        if self.compact {
            fmt()
                .with_max_level(self.max_level)
                .with_ansi(self.ansi)
                .compact()
                .try_init()
        } else {
            fmt()
                .with_max_level(self.max_level)
                .with_ansi(self.ansi)
                .try_init()
        }
        .map_err(|error| Error::Configuration(format!("failed to initialize tracing: {error}")))
    }

    pub fn install_opentelemetry_stdout(self) -> Result<OpenTelemetryGuard> {
        self.validate()?;
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
            .with_resource(
                Resource::builder()
                    .with_service_name(self.service_name.clone())
                    .build(),
            )
            .build();
        let level_filter = LevelFilter::from_level(self.max_level);
        let init_result = if self.compact {
            let tracer = provider.tracer("stoffel-rust-sdk");
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .compact()
                        .with_ansi(self.ansi)
                        .with_filter(level_filter),
                )
                .with(telemetry)
                .try_init()
        } else {
            let tracer = provider.tracer("stoffel-rust-sdk");
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(fmt::layer().with_ansi(self.ansi).with_filter(level_filter))
                .with(telemetry)
                .try_init()
        };
        init_result.map_err(|error| {
            Error::Configuration(format!(
                "failed to initialize OpenTelemetry tracing: {error}"
            ))
        })?;

        Ok(OpenTelemetryGuard {
            provider: Some(provider),
        })
    }
}

#[derive(Debug)]
pub struct OpenTelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl OpenTelemetryGuard {
    pub fn shutdown(mut self) -> Result<()> {
        shutdown_provider(self.provider.take())
    }
}

impl Drop for OpenTelemetryGuard {
    fn drop(&mut self) {
        let _ = shutdown_provider(self.provider.take());
    }
}

fn shutdown_provider(provider: Option<SdkTracerProvider>) -> Result<()> {
    if let Some(provider) = provider {
        provider.shutdown().map_err(|error| {
            Error::Configuration(format!(
                "failed to shut down OpenTelemetry tracer provider: {error}"
            ))
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct TracingConfigBuilder {
    config: TracingConfig,
}

impl TracingConfigBuilder {
    pub fn max_level(mut self, level: Level) -> Self {
        self.config.max_level = level;
        self
    }

    pub fn ansi(mut self, ansi: bool) -> Self {
        self.config.ansi = ansi;
        self
    }

    pub fn compact(mut self, compact: bool) -> Self {
        self.config.compact = compact;
        self
    }

    pub fn service_name(mut self, service_name: impl Into<String>) -> Self {
        self.config.service_name = service_name.into();
        self
    }

    pub fn build(self) -> TracingConfig {
        self.config
    }

    pub fn install(self) -> Result<()> {
        self.build().install()
    }

    pub fn install_opentelemetry_stdout(self) -> Result<OpenTelemetryGuard> {
        self.build().install_opentelemetry_stdout()
    }
}

pub fn init_tracing() -> Result<()> {
    TracingConfig::default().install()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_provider_allows_absent_provider() {
        shutdown_provider(None).expect("empty OpenTelemetry guard shutdown is a no-op");
    }

    #[test]
    fn dropping_empty_guard_is_a_noop() {
        drop(OpenTelemetryGuard { provider: None });
    }
}
