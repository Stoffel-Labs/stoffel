use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{MpcEngineOperationResultExt, MpcEngineReservation, MpcEngineResult};
use crate::net::reservation::{ReservationGrant, ReservationRegistry};
use crate::storage::preproc::PoolAvailability;
use ark_ec::{CurveGroup, PrimeGroup};
use stoffelnet::network_utils::ClientId;

#[async_trait::async_trait]
impl<F, G> MpcEngineReservation for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn init_reservations(
        &self,
        program_hash: [u8; 32],
        capacity: u64,
    ) -> MpcEngineResult<()> {
        self.init_reservations_for_run(program_hash, capacity, 0, PoolAvailability::default())
            .await
    }

    /// Build this run's reservation state.
    ///
    /// Always fresh: nothing is restored, because nothing is persisted. A
    /// reserved mask is not a bookmark into the store — `reserve_masks` draws
    /// the share out of the live pool — so a cursor restored after a crash
    /// would point at material this node no longer holds.
    async fn init_reservations_for_run(
        &self,
        program_hash: [u8; 32],
        capacity: u64,
        run_id: u64,
        preproc_offset: PoolAvailability,
    ) -> MpcEngineResult<()> {
        *self.reservation.write().await = Some(ReservationRegistry::new_for_run(
            program_hash,
            self.persistent_identity(),
            capacity,
            run_id,
            preproc_offset,
        ));
        Ok(())
    }

    async fn reserve_masks(
        &self,
        client_id: ClientId,
        n: u64,
    ) -> MpcEngineResult<ReservationGrant> {
        async {
            // Serializes logical allocation with destructive LMDB removal so
            // concurrent requests cannot disagree about index-to-share mapping.
            let mut reserved_masks = self.reserved_mask_shares.lock().await;
            let guard = self.reservation.read().await;
            let reg = guard.as_ref().ok_or("reservations not initialized")?;
            let grant = reg
                .reserve(self.client_identity(client_id).await?, n)
                .await
                .map_err(|e| e.to_string())?;
            drop(guard);

            let count = usize::try_from(n)
                .map_err(|_| format!("reserved mask count {n} exceeds usize range"))?;
            let shares = self.reserve_random_shares(count).await?;
            if shares.len() != count {
                return Err(format!(
                    "reserved mask decode returned {} shares, expected {n}",
                    shares.len()
                ));
            }
            for (index, share) in grant.indices().zip(shares.iter()) {
                reserved_masks.insert(index, Self::encode_share(share)?);
            }
            Ok::<ReservationGrant, String>(grant)
        }
        .await
        .map_mpc_engine_operation("reserve_masks")
    }

    /// A reserved mask share is served from the shares `reserve_masks` drew out
    /// of the live pool, and from nowhere else.
    ///
    /// The store is not consulted. Drawing a mask out of a persisted blob would
    /// mean reading material the store still holds — material a later execution
    /// could be handed too — so the only mask a node can serve is one it has
    /// already removed from its pool.
    async fn get_mask_share(&self, index: u64) -> MpcEngineResult<Vec<u8>> {
        async {
            self.reserved_mask_shares
                .lock()
                .await
                .get(&index)
                .cloned()
                .ok_or_else(|| format!("mask index {index} was not reserved before retrieval"))
        }
        .await
        .map_mpc_engine_operation("get_mask_share")
    }

    /// The batch form of [`Self::get_mask_share`], under one lock.
    async fn get_mask_shares(&self, indices: &[u64]) -> MpcEngineResult<Vec<Vec<u8>>> {
        async {
            if indices.is_empty() {
                return Ok(Vec::new());
            }
            let cache = self.reserved_mask_shares.lock().await;
            indices
                .iter()
                .map(|index| {
                    cache.get(index).cloned().ok_or_else(|| {
                        format!("mask index {index} was not reserved before retrieval")
                    })
                })
                .collect()
        }
        .await
        .map_mpc_engine_operation("get_mask_shares")
    }

    async fn retire_masks(&self, indices: &[u64]) -> MpcEngineResult<()> {
        async {
            {
                let reg_guard = self.reservation.read().await;
                let reg = reg_guard.as_ref().ok_or("reservations not initialized")?;
                reg.consume(indices).await.map_err(|e| e.to_string())?;
            }
            let mut reserved_masks = self.reserved_mask_shares.lock().await;
            for index in indices {
                reserved_masks.remove(index);
            }
            Ok::<(), String>(())
        }
        .await
        .map_mpc_engine_operation("retire_masks")
    }

    async fn available_masks(&self) -> u64 {
        let guard = self.reservation.read().await;
        match guard.as_ref() {
            Some(reg) => reg.available().await,
            None => 0,
        }
    }
}
