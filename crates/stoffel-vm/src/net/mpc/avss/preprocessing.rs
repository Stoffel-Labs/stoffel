use super::{AvssExecutionNetwork, AvssMpcEngine, AvssMpcNode, AvssSessionId};
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{
    self, agree_standing_preproc_plan_for_party, apply_standing_preproc_plan,
    standing_preproc_snapshot, OwnedPreprocBundle, PoolAvailability, PreprocKeyScope,
};
pub use crate::storage::preproc::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};
use ark_ec::CurveGroup;
use ark_std::rand::SeedableRng;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::avss::MAX_DEAL_BATCH;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;

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

impl<F, G> AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    /// Run cooperative preprocessing to generate random shares and Beaver triples.
    ///
    /// A persistent store uses a party-agreed inventory and destructively
    /// allocates fresh material before execution.
    ///
    /// This clones the inner node so that preprocessing can run concurrently
    /// with the message processing loop (which also needs the node lock for
    /// `process()`). Both clones share `Arc<Mutex<>>` internal state
    /// (preprocessing_material, shares) so results are visible to either.
    pub async fn preprocess(&self) -> Result<(), String> {
        if self.is_standing() {
            return self.preprocess_standing().await;
        }

        if self.preproc_store.read().await.is_some() {
            return self.preprocess_persistent_execution().await;
        }

        {
            let mut node_clone = self.clone_avss_node().await;
            self.run_bounded_preprocessing(&mut node_clone).await?;
        }

        Ok(())
    }

    /// Keep each dealing within stoffelcrypto's wire limit. Version 0.1.2
    /// appends a sacrifice candidate for every requested triple, so requesting
    /// MAX_DEAL_BATCH triples at once would send twice that many commitments.
    async fn run_bounded_preprocessing(
        &self,
        node: &mut AvssMpcNode<F, Avid<AvssSessionId>, G>,
    ) -> Result<(), String> {
        let requested_triples = node.params.n_triples;
        let mut generated_target = node.preprocessing_material.lock().await.len().0;
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        loop {
            generated_target = generated_target
                .saturating_add(MAX_DEAL_BATCH / 2)
                .min(requested_triples);
            node.params.n_triples = generated_target;
            let result = PreprocessingMPCProtocol::<
                F,
                FeldmanShamirShare<F, G>,
                AvssExecutionNetwork,
            >::run_preprocessing(node, self.protocol_net.clone(), &mut rng)
            .await;
            node.params.n_triples = requested_triples;
            result.map_err(|error| format!("AVSS preprocessing failed: {error:?}"))?;
            if generated_target == requested_triples {
                return Ok(());
            }
        }
    }

    async fn preproc_scope(
        &self,
    ) -> Result<
        (
            std::sync::Arc<dyn crate::storage::preproc::PreprocStore>,
            [u8; 32],
            PreprocKeyScope,
        ),
        String,
    > {
        let store = self.preproc_store.read().await.clone();
        let config = *self.preproc_config.read().await;
        let (store, (hash, field_kind)) = match (store, config) {
            (Some(s), Some(c)) => (s, c),
            _ => return Err(
                "standing AVSS preprocessing requires configured preproc store and program hash"
                    .to_owned(),
            ),
        };
        if self.is_standing()
            && !self
                .use_program_preproc_reservoir
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                "standing execution preprocessing is owned in memory, not persisted".to_owned(),
            );
        }
        let scope = PreprocKeyScope::new(
            hash,
            field_kind,
            self.topology.n_parties(),
            self.topology.threshold(),
            self.local_identity,
        );
        Ok((store, hash, scope))
    }

    /// Exact preprocessing counts configured for this standing engine.
    ///
    /// Callers include these targets in the authenticated party proposal so
    /// mismatched configurations are rejected before an interactive
    /// preprocessing protocol starts.
    pub async fn standing_preproc_targets(&self) -> Result<PoolAvailability, String> {
        let node = self.clone_avss_node().await;
        Ok(PoolAvailability {
            beaver: preproc::u32_index(node.params.n_triples as u64, "AVSS beaver target")?,
            random: preproc::u32_index(node.params.n_v_random_shares as u64, "AVSS random target")?,
            prand_bit: 0,
            prand_int: 0,
        })
    }

    /// Install a destructively allocated reservoir bundle into this
    /// execution's private in-memory preprocessing pool.
    pub async fn activate_preallocated_standing(
        &self,
        bundle: OwnedPreprocBundle,
    ) -> Result<(), String> {
        if !self.is_standing() {
            return Err("preallocated AVSS activation requires standing mode".to_owned());
        }
        if self
            .use_program_preproc_reservoir
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("an AVSS program reservoir cannot be activated as an execution".to_owned());
        }
        let targets = self.standing_preproc_targets().await?;
        let availability = bundle.availability();
        if availability != targets {
            return Err(format!(
                "preallocated AVSS bundle does not match target: available={availability:?}, target={targets:?}"
            ));
        }
        self.activate_preproc_bundle(bundle).await
    }

    async fn activate_preproc_bundle(&self, bundle: OwnedPreprocBundle) -> Result<(), String> {
        let triples = bundle
            .beaver
            .map(|item| {
                let mut decoded =
                    preproc::deserialize_avss_triples::<F, G>(&item.data, item.item_size, 0)?;
                ensure_decoded_count("preallocated AVSS triples", decoded.len(), item.count)?;
                Self::normalize_multiply_triples(&mut decoded);
                Ok::<_, String>(decoded)
            })
            .transpose()?;
        let random = bundle
            .random
            .map(|item| {
                let decoded =
                    preproc::deserialize_feldman_shares::<F, G>(&item.data, item.item_size, 0)?;
                ensure_decoded_count("preallocated AVSS random shares", decoded.len(), item.count)?;
                Ok::<_, String>(decoded)
            })
            .transpose()?;
        if bundle.prand_bit.is_some() || bundle.prand_int.is_some() {
            return Err("AVSS bundle contains HoneyBadger-only material".to_owned());
        }
        self.clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(triples, random);
        self.ready.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub async fn standing_preproc_snapshot(&self) -> Result<StandingPreprocSnapshot, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        standing_preproc_snapshot(store.as_ref(), scope)
            .await
            .map_err(String::from)
    }

    pub async fn install_standing_preproc_plan(
        &self,
        snapshots: Vec<StandingPreprocSnapshot>,
        fresh_generation_id: [u8; 32],
    ) -> Result<StandingPreprocPlan, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        let targets = self.standing_preproc_targets().await?;
        let plan = agree_standing_preproc_plan_for_party(
            store.as_ref(),
            scope,
            targets,
            &snapshots,
            self.topology.party_id(),
            self.topology.n_parties(),
            fresh_generation_id,
        )
        .await?;
        *self.standing_preproc_plan.lock().await = Some(plan);
        Ok(plan)
    }

    async fn preprocess_standing(&self) -> Result<(), String> {
        let targets = self.standing_preproc_targets().await?;
        let plan = if self.topology.n_parties() == 1 {
            agree_standing_preproc_plan(
                targets,
                &[self.standing_preproc_snapshot().await?],
                crate::net::session::ExecutionId::new().into_bytes(),
            )?
        } else {
            self.standing_preproc_plan.lock().await.take().ok_or_else(|| {
                "multi-party standing AVSS preprocessing requires a party-agreed inventory plan before protocol startup"
                    .to_owned()
            })?
        };
        let (store, _hash, scope) = self.preproc_scope().await?;
        apply_standing_preproc_plan(store.as_ref(), scope, targets, plan, |needed| {
            self.top_up_exact(needed)
        })
        .await?;
        Ok(())
    }

    async fn top_up_exact(&self, needed: PoolAvailability) -> Result<(), String> {
        if needed == PoolAvailability::default() {
            return Ok(());
        }
        let (store, _hash, scope) = self.preproc_scope().await?;

        let mut node_clone = self.clone_avss_node().await;
        node_clone.params.n_triples = needed.beaver as usize;
        node_clone.params.n_v_random_shares = needed.random as usize;
        self.run_bounded_preprocessing(&mut node_clone).await?;

        let mut to_append = Vec::new();
        {
            let mut prep = node_clone.preprocessing_material.lock().await;
            let (n_bt, n_rs) = prep.len();
            if n_bt > 0 {
                let items = prep.take_triples(n_bt).map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_avss_triples::<F, G>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated AVSS beaver")?;
                to_append.push((scope.beaver_triple(), item_size, added, data));
            }
            if n_rs > 0 {
                let items = prep
                    .take_v_random_shares(n_rs)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_feldman_shares::<F, G>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated AVSS random")?;
                to_append.push((scope.random_share(), item_size, added, data));
            }
        }

        for (key, item_size, added, data) in to_append {
            store.append_items(&key, item_size, added, &data).await?;
        }

        Ok(())
    }

    /// Agree and refill the persistent inventory, then remove this execution's
    /// entire allocation before making any correlated material available in RAM.
    /// A subsequent process must refill consumed material rather than reuse it.
    async fn preprocess_persistent_execution(&self) -> Result<(), String> {
        self.preprocess_standing().await?;
        let targets = self.standing_preproc_targets().await?;
        let (store, _, scope) = self.preproc_scope().await?;
        let bundle = store.take_bundle_from_reservoir(&scope, targets).await?;
        self.activate_preproc_bundle(bundle).await
    }

    pub(super) async fn reserve_random_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, String> {
        let node = self.clone_avss_node().await;
        let result = node
            .preprocessing_material
            .lock()
            .await
            .take_v_random_shares(num_shares)
            .map_err(|error| format!("not enough AVSS random shares: {error:?}"));
        result
    }

    /// Reserve the correlated masks distributed to one external input client.
    /// Standing executions remove these shares from LMDB atomically before
    /// handing them to the input server; one-shot executions consume the
    /// engine's in-memory preprocessing material.
    pub async fn reserve_client_input_masks(
        &self,
        num_shares: usize,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, String> {
        self.reserve_random_shares(num_shares).await
    }
}
