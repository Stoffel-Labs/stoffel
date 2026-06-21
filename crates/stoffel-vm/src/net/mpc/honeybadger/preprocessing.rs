use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{self, PreprocBlob, PreprocKeyScope};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::SeedableRng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerError;

fn ensure_decoded_count(label: &str, actual: usize, expected: u32) -> Result<(), String> {
    let expected = usize::try_from(expected)
        .map_err(|_| format!("{label} expected count exceeds usize::MAX"))?;
    if actual != expected {
        return Err(format!(
            "{label} decoded {actual} items, expected {expected}"
        ));
    }
    Ok(())
}

fn preprocessing_progress_interval() -> Option<Duration> {
    std::env::var("STOFFEL_HB_PREPROCESSING_PROGRESS_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    /// Fully async startup + preprocessing.
    pub async fn start_async(&self) -> Result<(), String> {
        self.preprocess().await
    }

    pub async fn preprocess(&self) -> Result<(), String> {
        if self.try_load_preproc().await? {
            self.ready.store(true, Ordering::SeqCst);
            return Ok(());
        }

        {
            let mut node = self.clone_node().await;
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            let party_id = self.topology.party_id();
            let started = Instant::now();
            let progress_done = Arc::new(AtomicBool::new(false));
            let progress_handle = preprocessing_progress_interval().map(|interval| {
                let progress_done = Arc::clone(&progress_done);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(interval).await;
                        if progress_done.load(Ordering::SeqCst) {
                            break;
                        }
                        eprintln!(
                            "[hb preprocessing progress] party={} elapsed_ms={}",
                            party_id,
                            started.elapsed().as_millis()
                        );
                    }
                })
            });

            let result = node.run_preprocessing(self.net.clone(), &mut rng).await;
            progress_done.store(true, Ordering::SeqCst);
            if let Some(handle) = progress_handle {
                handle.abort();
            }
            result.map_err(|e| format!("Preprocessing failed: {:?}", e))?;
        }

        self.persist_preproc().await?;

        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Try to load preprocessing material from the persistent store.
    /// Returns `true` if material was loaded, `false` if nothing available.
    async fn try_load_preproc(&self) -> Result<bool, String> {
        let store = self.preproc_store.read().await.clone();
        let hash = *self.program_hash.read().await;
        let (store, hash) = match (store, hash) {
            (Some(s), Some(h)) => (s, h),
            _ => return Ok(false),
        };
        let persistent_identity = self.persistent_identity();

        let scope = PreprocKeyScope::new(
            hash,
            F::field_kind(),
            self.topology.n_parties(),
            self.topology.threshold(),
            persistent_identity,
        );
        let base = scope.beaver_triple();
        let k_rs = scope.random_share();
        let k_pb = scope.prand_bit();
        let k_pi = scope.prand_int();
        let (triples, randoms, prandbits, prandints) = tokio::try_join!(
            store.load(&base),
            store.load(&k_rs),
            store.load(&k_pb),
            store.load(&k_pi),
        )?;

        if triples.is_none() && randoms.is_none() && prandbits.is_none() && prandints.is_none() {
            let msg = format!(
                "No preprocessing material found in store for program {} (identity={}, n={}, t={})",
                hex::encode(hash),
                persistent_identity,
                self.topology.n_parties(),
                self.topology.threshold()
            );
            eprintln!("{msg}");
            tracing::info!("{msg}");
            return Ok(false);
        }

        let node = self.clone_node().await;
        let mut loaded_triples = 0;
        let mut loaded_randoms = 0;
        let mut loaded_prandbits = 0;
        let mut loaded_prandints = 0;

        if let Some(ref blob) = triples {
            let available = blob.meta.available();
            if available > 0 {
                let decoded = preproc::deserialize_beaver_triples::<F>(
                    blob.unconsumed_data()?,
                    blob.meta.item_size,
                    0,
                )?;
                ensure_decoded_count("beaver triples", decoded.len(), available)?;
                store
                    .reserve_at(&base, blob.meta.consumed, available)
                    .await?;
                store.delete(&base).await?;
                loaded_triples = available;
                node.preprocessing_material.lock().await.add(
                    Some(decoded),
                    None,
                    None,
                    None,
                    None,
                    None,
                );
            }
        }
        if let Some(ref blob) = randoms {
            let available = blob.meta.available();
            if available > 0 {
                let decoded = preproc::deserialize_robust_shares::<F>(
                    blob.unconsumed_data()?,
                    blob.meta.item_size,
                    0,
                )?;
                ensure_decoded_count("random shares", decoded.len(), available)?;
                store
                    .reserve_at(&k_rs, blob.meta.consumed, available)
                    .await?;
                store.delete(&k_rs).await?;
                loaded_randoms = available;
                node.preprocessing_material.lock().await.add(
                    None,
                    None,
                    Some(decoded),
                    None,
                    None,
                    None,
                );
            }
        }
        if let Some(ref blob) = prandbits {
            let available = blob.meta.available();
            if available > 0 {
                let decoded = preproc::deserialize_prandbit_shares::<F>(
                    blob.unconsumed_data()?,
                    blob.meta.item_size,
                    0,
                )?;
                ensure_decoded_count("PRandBit shares", decoded.len(), available)?;
                store
                    .reserve_at(&k_pb, blob.meta.consumed, available)
                    .await?;
                store.delete(&k_pb).await?;
                loaded_prandbits = available;
                node.preprocessing_material.lock().await.add(
                    None,
                    None,
                    None,
                    None,
                    Some(decoded),
                    None,
                );
            }
        }
        if let Some(ref blob) = prandints {
            let available = blob.meta.available();
            if available > 0 {
                let decoded = preproc::deserialize_robust_shares::<F>(
                    blob.unconsumed_data()?,
                    blob.meta.item_size,
                    0,
                )?;
                ensure_decoded_count("PRandInt shares", decoded.len(), available)?;
                store
                    .reserve_at(&k_pi, blob.meta.consumed, available)
                    .await?;
                store.delete(&k_pi).await?;
                loaded_prandints = available;
                node.preprocessing_material.lock().await.add(
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(decoded),
                );
            }
        }

        if loaded_triples == 0
            && loaded_randoms == 0
            && loaded_prandbits == 0
            && loaded_prandints == 0
        {
            let msg = format!(
                "No unconsumed preprocessing material found in store for program {} (identity={}, n={}, t={})",
                hex::encode(hash),
                persistent_identity,
                self.topology.n_parties(),
                self.topology.threshold()
            );
            eprintln!("{msg}");
            tracing::info!("{msg}");
            return Ok(false);
        }

        let msg = format!(
            "Loaded preprocessing material from store for program {} (identity={}, n={}, t={}, triples={}, randoms={}, prandbits={}, prandints={})",
            hex::encode(hash),
            persistent_identity,
            self.topology.n_parties(),
            self.topology.threshold(),
            loaded_triples,
            loaded_randoms,
            loaded_prandbits,
            loaded_prandints
        );
        eprintln!("{msg}");
        tracing::info!("{msg}");
        Ok(true)
    }

    /// Persist current preprocessing material to the store.
    ///
    /// Drains and serializes material inside the lock, then releases the lock
    /// before the async store writes to minimise lock hold time.
    async fn persist_preproc(&self) -> Result<(), String> {
        let store = self.preproc_store.read().await.clone();
        let hash = *self.program_hash.read().await;
        let (store, hash) = match (store, hash) {
            (Some(s), Some(h)) => (s, h),
            _ => return Ok(()),
        };
        let persistent_identity = self.persistent_identity();

        let scope = PreprocKeyScope::new(
            hash,
            F::field_kind(),
            self.topology.n_parties(),
            self.topology.threshold(),
            persistent_identity,
        );
        let base = scope.beaver_triple();

        let mut to_store = Vec::new();
        let mut restore_bt = None;
        let mut restore_rs = None;
        let mut restore_pb = None;
        let mut restore_pi = None;

        {
            let node = self.clone_node().await;
            let mut prep = node.preprocessing_material.lock().await;
            let _m = prep.length();
            let (n_bt, n_rs, n_pb, n_pi) =
                (_m.beaver_triples, _m.random_shr, _m.prandbit, _m.prandint);

            if n_bt > 0 {
                let items = prep
                    .take_beaver_triples(n_bt)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_beaver_triples::<F>(&items)?;
                to_store.push((
                    base.clone(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_bt = Some(items);
            }
            if n_rs > 0 {
                let items = prep
                    .take_random_shares(n_rs)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_robust_shares::<F>(&items)?;
                to_store.push((
                    scope.random_share(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_rs = Some(items);
            }
            if n_pb > 0 {
                let items = prep
                    .take_prandbit_shares(n_pb)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_prandbit_shares::<F>(&items)?;
                to_store.push((
                    scope.prand_bit(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_pb = Some(items);
            }
            if n_pi > 0 {
                let items = prep
                    .take_prandint_shares(n_pi)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_robust_shares::<F>(&items)?;
                to_store.push((
                    scope.prand_int(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_pi = Some(items);
            }

            prep.add(restore_bt, None, restore_rs, None, restore_pb, restore_pi);
        }

        for (key, blob) in &to_store {
            store.store(key, blob).await?;
        }

        let msg = format!(
            "Persisted preprocessing material to store for program {} (identity={}, n={}, t={}, blobs={})",
            hex::encode(hash),
            persistent_identity,
            self.topology.n_parties(),
            self.topology.threshold(),
            to_store.len()
        );
        eprintln!("{msg}");
        tracing::info!("{msg}");
        Ok(())
    }

    pub(super) async fn reserve_random_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, String> {
        loop {
            let attempt = {
                let node = self.clone_node().await;
                let mut prep_material = node.preprocessing_material.lock().await;
                prep_material.take_random_shares(num_shares)
            };

            match attempt {
                Ok(shares) => return Ok(shares),
                Err(HoneyBadgerError::NotEnoughPreprocessing) => {
                    self.regenerate_random_shares(num_shares).await?;
                    continue;
                }
                Err(other) => {
                    return Err(format!("Failed to take random shares: {:?}", other));
                }
            }
        }
    }

    pub(super) async fn reserve_prandint_shares(
        &self,
        num_shares: usize,
        ty: ShareType,
    ) -> Result<Vec<RobustShare<F>>, String> {
        loop {
            let attempt = {
                let node = self.clone_node().await;
                let mut prep_material = node.preprocessing_material.lock().await;
                prep_material.take_prandint_shares(num_shares)
            };

            match attempt {
                Ok(shares) => return Ok(shares),
                Err(HoneyBadgerError::NotEnoughPreprocessing) => {
                    self.regenerate_prandint_shares(num_shares, ty).await?;
                    continue;
                }
                Err(other) => {
                    return Err(format!("Failed to take PRandInt shares: {:?}", other));
                }
            }
        }
    }

    async fn regenerate_random_shares(&self, needed: usize) -> Result<(), String> {
        let mut node = self.clone_node().await;
        {
            let current = node.preprocessing_material.lock().await.length().random_shr;
            let target = current + needed;
            if node.params.n_random_shares < target {
                node.params.n_random_shares = target;
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.net.clone(), &mut rng)
            .await
            .map_err(|e| format!("Failed to regenerate preprocessing material: {:?}", e))
    }

    async fn regenerate_prandint_shares(&self, needed: usize, ty: ShareType) -> Result<(), String> {
        let mut node = self.clone_node().await;
        {
            let current = node.preprocessing_material.lock().await.length().prandint;
            let target = current + needed;
            if node.params.n_prandint < target {
                node.params.n_prandint = target;
            }
            if let ShareType::SecretInt { bit_length } | ShareType::SecretUInt { bit_length } = ty {
                let target_random_bits = bit_length.min(56);
                node.params.l = target_random_bits.saturating_sub(node.params.k);
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.net.clone(), &mut rng)
            .await
            .map_err(|e| {
                format!(
                    "Failed to regenerate PRandInt preprocessing material: {:?}",
                    e
                )
            })
    }

    /// Pull one pre-generated random share from the preprocessing pool.
    /// If the pool is empty, `reserve_random_shares` auto-regenerates via
    /// the RanSha protocol over the network.
    pub(super) async fn random_share_async_impl(
        &self,
        _ty: ShareType,
    ) -> Result<ShareData, String> {
        let shares = self.reserve_random_shares(1).await?;
        Self::encode_share(&shares[0]).map(|v| ShareData::Opaque(v.into()))
    }

    /// Pull one pre-generated PRandInt share from the preprocessing pool.
    pub(super) async fn random_integer_share_async_impl(
        &self,
        ty: ShareType,
    ) -> Result<ShareData, String> {
        let shares = self.reserve_prandint_shares(1, ty).await?;
        Self::encode_share(&shares[0]).map(|v| ShareData::Opaque(v.into()))
    }
}
