use super::super::{MpcEngineResult, MpcPartyId, RbcSessionId};
use super::core::MpcEngine;

/// Extended MPC engine trait for consensus protocols (RBC).
///
/// RBC (Reliable Broadcast) ensures that:
/// - If the broadcaster is honest, all honest parties deliver the same message
/// - If any honest party delivers a message, all honest parties eventually
///   deliver it
pub trait MpcEngineConsensus: MpcEngine {
    /// Broadcast a message reliably to all parties using RBC.
    fn rbc_broadcast(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId>;

    /// Receive a reliable broadcast from a specific party.
    fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> MpcEngineResult<Vec<u8>>;

    /// Receive a reliable broadcast from any party.
    fn rbc_receive_any(&self, timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)>;
}

/// Async version of `MpcEngineConsensus`.
#[async_trait::async_trait]
pub trait AsyncMpcEngineConsensus: MpcEngineConsensus {
    /// Broadcast a message reliably to all parties asynchronously.
    async fn rbc_broadcast_async(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId>;

    /// Receive a reliable broadcast from a specific party asynchronously.
    async fn rbc_receive_async(
        &self,
        from_party: MpcPartyId,
        timeout_ms: u64,
    ) -> MpcEngineResult<Vec<u8>>;

    /// Receive a reliable broadcast from any party asynchronously.
    async fn rbc_receive_any_async(
        &self,
        timeout_ms: u64,
    ) -> MpcEngineResult<(MpcPartyId, Vec<u8>)>;
}
