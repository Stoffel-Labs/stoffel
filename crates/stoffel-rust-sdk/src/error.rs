//! SDK error types and recovery metadata.
//!
//! Errors keep lower-crate failures typed where possible while exposing stable
//! categories for application recovery logic, logging, and status APIs.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub use stoffel_mpc_coordinator_shared::CoordinatorError;
pub use stoffelnet::network_utils::{ConsensusError, NetworkError};

/// SDK result type.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Compilation,
    Configuration,
    Network,
    Consensus,
    Coordinator,
    Preprocessing,
    Computation,
    Runtime,
    Input,
    Unsupported,
    Io,
    Bytecode,
    ConfigParse,
    ConfigSerialize,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Compilation => "compilation",
            ErrorCategory::Configuration => "configuration",
            ErrorCategory::Network => "network",
            ErrorCategory::Consensus => "consensus",
            ErrorCategory::Coordinator => "coordinator",
            ErrorCategory::Preprocessing => "preprocessing",
            ErrorCategory::Computation => "computation",
            ErrorCategory::Runtime => "runtime",
            ErrorCategory::Input => "input",
            ErrorCategory::Unsupported => "unsupported",
            ErrorCategory::Io => "io",
            ErrorCategory::Bytecode => "bytecode",
            ErrorCategory::ConfigParse => "config_parse",
            ErrorCategory::ConfigSerialize => "config_serialize",
        }
    }

    pub fn is_recoverable(self) -> bool {
        matches!(
            self,
            ErrorCategory::Network
                | ErrorCategory::Consensus
                | ErrorCategory::Preprocessing
                | ErrorCategory::Io
        )
    }

    pub fn recovery_hint(self) -> Option<&'static str> {
        match self {
            ErrorCategory::Network => {
                Some("check connectivity and retry with the same program and inputs")
            }
            ErrorCategory::Consensus => Some(
                "verify all parties see the same node/client set and consider a longer timeout",
            ),
            ErrorCategory::Preprocessing => {
                Some("ensure each server has enough triples and random shares before retrying")
            }
            ErrorCategory::Io => Some("check the file path or filesystem permissions and retry"),
            ErrorCategory::Configuration => {
                Some("fix the invalid SDK configuration before retrying")
            }
            ErrorCategory::Input => {
                Some("fix the provided function or client inputs before retrying")
            }
            ErrorCategory::Unsupported => {
                Some("use a supported SDK execution mode or wire the required lower-level backend")
            }
            _ => None,
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ErrorCategory {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "compilation" => Ok(ErrorCategory::Compilation),
            "configuration" => Ok(ErrorCategory::Configuration),
            "network" => Ok(ErrorCategory::Network),
            "consensus" => Ok(ErrorCategory::Consensus),
            "coordinator" => Ok(ErrorCategory::Coordinator),
            "preprocessing" => Ok(ErrorCategory::Preprocessing),
            "computation" => Ok(ErrorCategory::Computation),
            "runtime" => Ok(ErrorCategory::Runtime),
            "input" => Ok(ErrorCategory::Input),
            "unsupported" => Ok(ErrorCategory::Unsupported),
            "io" => Ok(ErrorCategory::Io),
            "bytecode" => Ok(ErrorCategory::Bytecode),
            "config_parse" => Ok(ErrorCategory::ConfigParse),
            "config_serialize" => Ok(ErrorCategory::ConfigSerialize),
            category => Err(Error::Configuration(format!(
                "unsupported error category '{category}'"
            ))),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Compilation failed: {0}")]
    Compilation(String),
    #[error("Invalid configuration: {0}")]
    Configuration(String),
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    #[error("Network connection error: {0}")]
    NetworkConnection(String),
    #[error("Consensus failed: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("Coordinator error: {0}")]
    Coordinator(#[from] CoordinatorError),
    #[error("Preprocessing failed: {0}")]
    Preprocessing(String),
    #[error("Computation failed: {0}")]
    Computation(String),
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Unsupported SDK operation: {0}")]
    Unsupported(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bytecode error: {0}")]
    Bytecode(String),
    #[error("Config parse error: {0}")]
    ConfigParse(#[from] toml::de::Error),
    #[error("Config serialize error: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),
}

impl Error {
    pub fn category(&self) -> ErrorCategory {
        match self {
            Error::Compilation(_) => ErrorCategory::Compilation,
            Error::Configuration(_) => ErrorCategory::Configuration,
            Error::Network(_) => ErrorCategory::Network,
            Error::NetworkConnection(_) => ErrorCategory::Network,
            Error::Consensus(_) => ErrorCategory::Consensus,
            Error::Coordinator(_) => ErrorCategory::Coordinator,
            Error::Preprocessing(_) => ErrorCategory::Preprocessing,
            Error::Computation(_) => ErrorCategory::Computation,
            Error::FunctionNotFound(_) => ErrorCategory::Runtime,
            Error::InvalidInput(_) => ErrorCategory::Input,
            Error::Unsupported(_) => ErrorCategory::Unsupported,
            Error::Io(_) => ErrorCategory::Io,
            Error::Bytecode(_) => ErrorCategory::Bytecode,
            Error::ConfigParse(_) => ErrorCategory::ConfigParse,
            Error::ConfigSerialize(_) => ErrorCategory::ConfigSerialize,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        self.category().is_recoverable()
    }

    pub fn recovery_hint(&self) -> Option<&'static str> {
        self.category().recovery_hint()
    }
}

pub(crate) fn format_compiler_errors<E: fmt::Display>(errors: &[E]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}
