use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{
    AsyncMpcEngineConsensus, MpcEngineConsensus, MpcEngineOperationResultExt, MpcEngineResult,
    MpcPartyId, RbcSessionId,
};
use ark_ec::{CurveGroup, PrimeGroup};
use stoffelnet::network_utils::Network;

// RBC uses the engine's session-local open registry for in-process coordination
// between parties. Multi-process deployments should route through the
// protocol/network implementations behind this adapter.
impl<F, G> MpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn rbc_broadcast(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        let session_id = self
            .open_registry
            .rbc_broadcast(self.topology.party_id(), message)
            .map_mpc_engine_operation("rbc_broadcast")?;
        let wire_message = crate::net::open_registry::encode_rbc_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            message,
        )
        .map_mpc_engine_operation("rbc_broadcast")?;
        if self.net.party_count() > 1 {
            self.broadcast_open_registry_payload_sync(wire_message)
                .map_mpc_engine_operation("rbc_broadcast")?;
        }
        Ok(RbcSessionId::new(session_id))
    }

    fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> MpcEngineResult<Vec<u8>> {
        self.open_registry
            .rbc_receive(self.topology.party_id(), from_party.id(), timeout_ms)
            .map_mpc_engine_operation("rbc_receive")
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        self.open_registry
            .rbc_receive_any(self.topology.party_id(), timeout_ms)
            .map(|(party_id, message)| (MpcPartyId::new(party_id), message))
            .map_mpc_engine_operation("rbc_receive_any")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn rbc_broadcast_async(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        let session_id = self
            .open_registry
            .rbc_broadcast_async(self.topology.party_id(), message)
            .await
            .map_mpc_engine_operation("async_rbc_broadcast")?;
        let wire_message = crate::net::open_registry::encode_rbc_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            message,
        )
        .map_mpc_engine_operation("async_rbc_broadcast")?;
        if self.net.party_count() > 1 {
            self.broadcast_open_registry_payload(wire_message)
                .await
                .map_mpc_engine_operation("async_rbc_broadcast")?;
        }
        Ok(RbcSessionId::new(session_id))
    }

    async fn rbc_receive_async(
        &self,
        from_party: MpcPartyId,
        timeout_ms: u64,
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_registry
            .rbc_receive_async(self.topology.party_id(), from_party.id(), timeout_ms)
            .await
            .map_mpc_engine_operation("async_rbc_receive")
    }

    async fn rbc_receive_any_async(
        &self,
        timeout_ms: u64,
    ) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        self.open_registry
            .rbc_receive_any_async(self.topology.party_id(), timeout_ms)
            .await
            .map(|(party_id, message)| (MpcPartyId::new(party_id), message))
            .map_mpc_engine_operation("async_rbc_receive_any")
    }
}
