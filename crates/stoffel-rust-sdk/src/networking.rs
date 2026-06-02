//! Networking re-exports from `stoffel-networking`.
//!
//! The SDK intentionally does not implement transport behavior. Applications
//! that need lower-level networking access can use these re-exports while still
//! depending on the SDK crate.

pub use stoffelnet::transports::quic::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
