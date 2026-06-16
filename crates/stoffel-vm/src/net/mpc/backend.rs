//! MPC backend selection.
//!
//! Provides an enum for choosing between HoneyBadger and AVSS backends at runtime.

use super::engine::{MpcCapabilities, MpcCapability};
use std::fmt;
use stoffel_vm_types::compiled_binary;

pub type MpcBackendResult<T> = Result<T, MpcBackendError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcBackendError {
    UnknownBackend {
        name: String,
        available: Vec<&'static str>,
    },
}

impl fmt::Display for MpcBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcBackendError::UnknownBackend { name, available } => write!(
                f,
                "Unknown MPC backend '{}'. Available: {}",
                name,
                available.join(", ")
            ),
        }
    }
}

impl std::error::Error for MpcBackendError {}

impl From<MpcBackendError> for String {
    fn from(error: MpcBackendError) -> Self {
        error.to_string()
    }
}

/// Available MPC backend implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcBackendKind {
    HoneyBadger,
    Avss,
}

impl From<compiled_binary::MpcBackend> for MpcBackendKind {
    fn from(value: compiled_binary::MpcBackend) -> Self {
        match value {
            compiled_binary::MpcBackend::HoneyBadger => MpcBackendKind::HoneyBadger,
            compiled_binary::MpcBackend::Avss => MpcBackendKind::Avss,
        }
    }
}

impl std::str::FromStr for MpcBackendKind {
    type Err = MpcBackendError;

    /// Parse a backend name from a string.
    ///
    /// Accepted values:
    /// - `"honeybadger"` or `"hb"` -> `HoneyBadger`
    /// - `"avss"` or `"adkg"` -> `Avss`
    fn from_str(s: &str) -> MpcBackendResult<Self> {
        match s.trim().to_lowercase().as_str() {
            "honeybadger" | "hb" => Ok(MpcBackendKind::HoneyBadger),
            "avss" | "adkg" => Ok(MpcBackendKind::Avss),
            other => Err(MpcBackendError::UnknownBackend {
                name: other.to_string(),
                available: Self::available_names(),
            }),
        }
    }
}

impl MpcBackendKind {
    pub fn available_names() -> Vec<&'static str> {
        vec!["honeybadger", "avss"]
    }

    /// Returns the default backend.
    ///
    /// Legacy default for callers without a compiled program manifest.
    pub fn default_backend() -> Self {
        MpcBackendKind::HoneyBadger
    }

    /// Static capability metadata for this backend family.
    ///
    /// Concrete engine instances still advertise their runtime capabilities via
    /// [`crate::net::mpc_engine::MpcEngine::capabilities`]. This method is for
    /// early CLI/config validation before an engine has been constructed.
    pub fn capabilities(&self) -> MpcCapabilities {
        match self {
            MpcBackendKind::HoneyBadger => {
                MpcCapabilities::MULTIPLICATION
                    | MpcCapabilities::OPEN_IN_EXP
                    | MpcCapabilities::CLIENT_INPUT
                    | MpcCapabilities::CLIENT_OUTPUT
                    | MpcCapabilities::CONSENSUS
                    | MpcCapabilities::RESERVATION
                    | MpcCapabilities::RANDOMNESS
                    | MpcCapabilities::PREPROC_PERSISTENCE
            }
            MpcBackendKind::Avss => {
                MpcCapabilities::MULTIPLICATION
                    | MpcCapabilities::OPEN_IN_EXP
                    | MpcCapabilities::ELLIPTIC_CURVES
                    | MpcCapabilities::CLIENT_INPUT
                    | MpcCapabilities::CLIENT_OUTPUT
                    | MpcCapabilities::RANDOMNESS
                    | MpcCapabilities::FIELD_OPEN
                    | MpcCapabilities::PREPROC_PERSISTENCE
            }
        }
    }

    /// Whether this backend family advertises a capability before construction.
    pub fn has_capability(&self, capability: MpcCapability) -> bool {
        self.capabilities().contains(capability.flag())
    }

    /// Whether this backend supports secure multiplication (requires Beaver triples).
    pub fn supports_multiplication(&self) -> bool {
        self.has_capability(MpcCapability::Multiplication)
    }

    /// Whether this backend supports and is safe for elliptic curve operations.
    ///
    /// AVSS uses `FeldmanShamirShare<F, G>` whose commitments are EC points (`G`),
    /// enabling operations like `open_share_in_exp` and threshold signatures.
    /// HoneyBadger uses `RobustShare<F>` with field-only commitments and is not
    /// suitable for direct EC operations.
    pub fn supports_elliptic_curves(&self) -> bool {
        self.has_capability(MpcCapability::EllipticCurves)
    }

    /// Whether this backend supports standalone client input mode.
    ///
    /// Both HoneyBadger and AVSS support a separate client role
    /// (`stoffel-run --client`) where external clients submit secret inputs
    /// to the MPC parties.
    pub fn supports_client_input(&self) -> bool {
        self.has_capability(MpcCapability::ClientInput)
    }

    /// Whether this backend supports sending private output shares to clients.
    pub fn supports_client_output(&self) -> bool {
        self.has_capability(MpcCapability::ClientOutput)
    }

    /// Human-readable name for this backend.
    pub fn name(&self) -> &'static str {
        match self {
            MpcBackendKind::HoneyBadger => "honeybadger",
            MpcBackendKind::Avss => "avss",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_honeybadger() {
        assert_eq!(
            MpcBackendKind::from_str("honeybadger").unwrap(),
            MpcBackendKind::HoneyBadger
        );
        assert_eq!(
            MpcBackendKind::from_str("hb").unwrap(),
            MpcBackendKind::HoneyBadger
        );
        assert_eq!(
            MpcBackendKind::from_str("HoneyBadger").unwrap(),
            MpcBackendKind::HoneyBadger
        );
    }

    #[test]
    fn test_parse_avss() {
        assert_eq!(
            MpcBackendKind::from_str("avss").unwrap(),
            MpcBackendKind::Avss
        );
        assert_eq!(
            MpcBackendKind::from_str("AVSS").unwrap(),
            MpcBackendKind::Avss
        );
        // "adkg" is kept as a backward-compatible alias
        assert_eq!(
            MpcBackendKind::from_str("adkg").unwrap(),
            MpcBackendKind::Avss
        );
    }

    #[test]
    fn test_parse_unknown() {
        assert_eq!(
            MpcBackendKind::from_str("unknown").unwrap_err(),
            MpcBackendError::UnknownBackend {
                name: "unknown".to_string(),
                available: MpcBackendKind::available_names(),
            }
        );
    }

    #[test]
    fn test_default_is_honeybadger() {
        assert_eq!(
            MpcBackendKind::default_backend(),
            MpcBackendKind::HoneyBadger
        );
    }

    #[test]
    fn converts_compiled_binary_backend_metadata() {
        assert_eq!(
            MpcBackendKind::from(compiled_binary::MpcBackend::HoneyBadger),
            MpcBackendKind::HoneyBadger
        );
        assert_eq!(
            MpcBackendKind::from(compiled_binary::MpcBackend::Avss),
            MpcBackendKind::Avss
        );
    }

    #[test]
    fn test_honeybadger_capabilities() {
        let hb = MpcBackendKind::HoneyBadger;
        let capabilities = hb.capabilities();

        assert!(capabilities.contains(MpcCapabilities::MULTIPLICATION));
        assert!(capabilities.contains(MpcCapabilities::OPEN_IN_EXP));
        assert!(capabilities.contains(MpcCapabilities::CLIENT_INPUT));
        assert!(capabilities.contains(MpcCapabilities::CLIENT_OUTPUT));
        assert!(capabilities.contains(MpcCapabilities::CONSENSUS));
        assert!(capabilities.contains(MpcCapabilities::RESERVATION));
        assert!(capabilities.contains(MpcCapabilities::RANDOMNESS));
        assert!(capabilities.contains(MpcCapabilities::PREPROC_PERSISTENCE));
        assert!(!capabilities.contains(MpcCapabilities::ELLIPTIC_CURVES));
        assert!(!capabilities.contains(MpcCapabilities::FIELD_OPEN));

        assert!(hb.has_capability(MpcCapability::Multiplication));
        assert!(!hb.supports_elliptic_curves());
        assert!(hb.supports_client_input());
        assert!(hb.supports_client_output());
    }

    #[test]
    fn test_avss_capabilities() {
        let avss = MpcBackendKind::Avss;
        let capabilities = avss.capabilities();

        assert!(capabilities.contains(MpcCapabilities::MULTIPLICATION));
        assert!(capabilities.contains(MpcCapabilities::OPEN_IN_EXP));
        assert!(capabilities.contains(MpcCapabilities::ELLIPTIC_CURVES));
        assert!(capabilities.contains(MpcCapabilities::CLIENT_INPUT));
        assert!(capabilities.contains(MpcCapabilities::CLIENT_OUTPUT));
        assert!(capabilities.contains(MpcCapabilities::RANDOMNESS));
        assert!(capabilities.contains(MpcCapabilities::FIELD_OPEN));
        assert!(capabilities.contains(MpcCapabilities::PREPROC_PERSISTENCE));
        assert!(!capabilities.contains(MpcCapabilities::CONSENSUS));
        assert!(!capabilities.contains(MpcCapabilities::RESERVATION));

        assert!(avss.supports_multiplication());
        assert!(avss.supports_elliptic_curves());
        assert!(avss.supports_client_input());
        assert!(avss.supports_client_output());
    }

    #[test]
    fn test_honeybadger_supports_multiplication() {
        let hb = MpcBackendKind::HoneyBadger;
        assert!(hb.supports_multiplication());
    }
}
