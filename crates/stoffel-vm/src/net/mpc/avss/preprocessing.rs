use super::{AvssExecutionNetwork, AvssMpcEngine, AvssNodeLease};
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{
    self, agree_standing_preproc_plan_for_party, apply_standing_preproc_plan,
    standing_preproc_snapshot, GeneratedMaterialCommit, MaterialKind, OwnedPreprocBundle,
    PoolAvailability, PreprocKey, PreprocKeyScope,
};
pub use crate::storage::preproc::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};
use ark_ec::CurveGroup;
use ark_std::rand::SeedableRng;
use stoffelmpc_mpc::avss_mpc::AvssMPCNodePreprocMaterial;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
use tracing::info;

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
    /// If a persistent store is configured, attempts to load from it first.
    /// After generation, persists the result for future runs.
    ///
    /// This clones the inner node so that preprocessing can run concurrently
    /// with the message processing loop (which also needs the node lock for
    /// `process()`). Both clones share `Arc<Mutex<>>` internal state
    /// (preprocessing_material, shares) so results are visible to either.
    pub async fn preprocess(&self) -> Result<(), String> {
        if self.is_standing() {
            return self.preprocess_standing().await;
        }

        // Draw whatever the store holds before deciding what to generate. A
        // commit writes only the surplus an execution did not keep
        // (`commit_generated_material`), so a stored bundle is normally less
        // than one execution's worth: it is a head start, not a substitute for
        // the protocol. Short-circuiting on any non-empty load left this
        // execution unable to serve even its own client input masks, since
        // AVSS has no regeneration path. Falling through costs only what the
        // load did not cover, because `run_preprocessing` generates the pool's
        // deficit against these same targets rather than the whole of them.
        let targets = self.preproc_targets().await?;
        if self.try_load_preproc().await? {
            let held = self.pool_availability().await?;
            if held.covers(targets) {
                return Ok(());
            }
            let msg = format!(
                "Stored AVSS preprocessing material {} (held={held:?}, target={targets:?}); generating the shortfall",
                preproc::PREPROC_PARTIAL_LOAD_LOG_MARKER
            );
            eprintln!("{msg}");
            info!("{msg}");
        }

        {
            let mut node_clone = self.clone_avss_node().await;
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            PreprocessingMPCProtocol::<
                F,
                FeldmanShamirShare<F, G>,
                AvssExecutionNetwork,
            >::run_preprocessing(&mut *node_clone, self.protocol_net.clone(), &mut rng)
            .await
            .map_err(|e| format!("AVSS preprocessing failed: {:?}", e))?;
        }

        self.persist_preproc().await?;
        Ok(())
    }

    /// The store and key scope this engine's preprocessing material lives
    /// under, or `None` when no store is attached.
    ///
    /// The single place a store handle and a [`PreprocKeyScope`] are paired,
    /// so the refusal below — a standing *execution* owns its material in
    /// memory and must never persist it — guards the commit path as well as
    /// the draw, which building the scope inline used to bypass.
    async fn preproc_home(
        &self,
    ) -> Result<
        Option<(
            std::sync::Arc<dyn crate::storage::preproc::PreprocStore>,
            [u8; 32],
            PreprocKeyScope,
        )>,
        String,
    > {
        let store = self.preproc_store.read().await.clone();
        let config = *self.preproc_config.read().await;
        let (Some(store), Some((hash, field_kind))) = (store, config) else {
            return Ok(None);
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
        Ok(Some((store, hash, scope)))
    }

    /// [`Self::preproc_home`] for the callers that cannot proceed without a
    /// store: the standing reservoir lifecycle.
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
        self.preproc_home().await?.ok_or_else(|| {
            "standing AVSS preprocessing requires configured preproc store and program hash"
                .to_owned()
        })
    }

    /// Exact preprocessing counts configured for this engine.
    ///
    /// The standing lifecycle includes these targets in the authenticated
    /// party proposal, so mismatched configurations are rejected before an
    /// interactive preprocessing protocol starts. A one-shot execution uses
    /// them as the amount it keeps out of a finished round, committing only
    /// what it does not keep.
    pub async fn preproc_targets(&self) -> Result<PoolAvailability, String> {
        let node = self.clone_avss_node().await;
        Ok(PoolAvailability {
            beaver: preproc::u32_index(node.params.n_triples as u64, "AVSS beaver target")?,
            random: preproc::u32_index(node.params.n_v_random_shares as u64, "AVSS random target")?,
            prand_bit: 0,
            prand_int: 0,
        })
    }

    /// What this engine's in-memory pool holds right now.
    ///
    /// Against [`Self::preproc_targets`] this is what decides whether a
    /// one-shot execution still needs a preprocessing round after consulting
    /// the store. The store holds only material no execution was served, which
    /// is the surplus of earlier runs, so covering a whole execution is the
    /// exception rather than the rule.
    async fn pool_availability(&self) -> Result<PoolAvailability, String> {
        let node = self.clone_avss_node().await;
        let (beaver, random) = node.preprocessing_material.lock().await.len();
        Ok(PoolAvailability {
            beaver: preproc::u32_index(beaver as u64, "pooled AVSS beaver")?,
            random: preproc::u32_index(random as u64, "pooled AVSS random")?,
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
        let targets = self.preproc_targets().await?;
        let availability = bundle.availability();
        if availability != targets {
            return Err(format!(
                "preallocated AVSS bundle does not match target: available={availability:?}, target={targets:?}"
            ));
        }
        self.activate_preproc_bundle(bundle).await?;
        // A preallocated bundle equals the targets, checked just above, so
        // activating it is this execution's whole preprocessing. A partial
        // bundle from the store is not, so loading one must not mark the
        // engine ready before `preprocess` has provisioned the targets.
        self.ready.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
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
        let targets = self.preproc_targets().await?;
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
        let targets = self.preproc_targets().await?;
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

        let mut node_clone = self.lease_node_with_emptied_pool_for_top_up().await;
        node_clone.params.n_triples = needed.beaver as usize;
        node_clone.params.n_v_random_shares = needed.random as usize;
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        PreprocessingMPCProtocol::<F, FeldmanShamirShare<F, G>, AvssExecutionNetwork>::run_preprocessing(
            &mut *node_clone,
            self.protocol_net.clone(),
            &mut rng,
        )
        .await
        .map_err(|e| format!("AVSS top-up preprocessing failed: {:?}", e))?;

        // Commit exactly the agreed chunk. Draining whatever the round
        // happened to leave would bank the protocol's over-production, and the
        // standing agreement is exact: unequal per-party reservoir snapshots
        // force a Rebuild on the next execution.
        self.commit_generated_material(
            store.as_ref(),
            &scope,
            GeneratedMaterialCommit::AgreedChunk(needed),
        )
        .await?;

        Ok(())
    }

    /// Lease this node for a standing top-up, emptying its live pool first.
    ///
    /// [`GeneratedMaterialCommit::AgreedChunk`] commits everything it drains,
    /// so a top-up that began with material already in the pool would bank that
    /// material — and material already in the pool is material this engine may
    /// have served. Until now nothing inside the top-up prevented that; facts
    /// outside it did. Emptying the pool here makes the guarantee local:
    /// whatever this engine held before the round is destroyed rather than
    /// persisted, so what the top-up banks is material the round it is about to
    /// run produced.
    ///
    /// Destroying preprocessing material is a liveness cost, never a privacy
    /// one, which is why this is the safe direction to fail in.
    async fn lease_node_with_emptied_pool_for_top_up(&self) -> AvssNodeLease<F, G> {
        let node = self.clone_avss_node().await;
        *node.preprocessing_material.lock().await = AvssMPCNodePreprocMaterial::empty();
        node
    }

    /// Divide the material a finished generation round left in the live pool
    /// between this engine and the store, and commit the store's share.
    ///
    /// The division is the privacy guard: an item is appended only if this
    /// engine keeps none of it, so the store never holds material an execution
    /// has been served. Both lifecycles meet here —
    /// [`GeneratedMaterialCommit::AgreedChunk`] for a standing reservoir
    /// top-up, [`GeneratedMaterialCommit::SurplusAbove`] for a one-shot
    /// execution's leftovers.
    ///
    /// Returns what was committed. Needs no network, so a test can seed the
    /// pool and check both halves of the division directly.
    async fn commit_generated_material(
        &self,
        store: &dyn preproc::PreprocStore,
        scope: &PreprocKeyScope,
        commit: GeneratedMaterialCommit,
    ) -> Result<PoolAvailability, String> {
        let mut to_append: Vec<(PreprocKey, u32, u32, Vec<u8>)> = Vec::new();
        let mut committed = PoolAvailability::default();
        {
            let node = self.clone_avss_node().await;
            let mut prep = node.preprocessing_material.lock().await;
            let (held_beaver, held_random) = prep.len();
            let mut retained_beaver = None;
            let mut retained_random = None;

            let split = commit.split(
                MaterialKind::BeaverTriple,
                preproc::u32_index(held_beaver as u64, "held AVSS beaver")?,
            );
            if split.drained > 0 {
                let mut items = prep
                    .take_triples(split.drained as usize)
                    .map_err(|e| format!("{e:?}"))?;
                let surplus = items.split_off(split.retained as usize);
                if !surplus.is_empty() {
                    let (data, item_size) = preproc::serialize_avss_triples::<F, G>(&surplus)?;
                    committed.beaver =
                        preproc::u32_index(surplus.len() as u64, "committed AVSS beaver")?;
                    to_append.push((scope.beaver_triple(), item_size, committed.beaver, data));
                }
                retained_beaver = (!items.is_empty()).then_some(items);
            }

            let split = commit.split(
                MaterialKind::RandomShare,
                preproc::u32_index(held_random as u64, "held AVSS random")?,
            );
            if split.drained > 0 {
                let mut items = prep
                    .take_v_random_shares(split.drained as usize)
                    .map_err(|e| format!("{e:?}"))?;
                let surplus = items.split_off(split.retained as usize);
                if !surplus.is_empty() {
                    let (data, item_size) = preproc::serialize_feldman_shares::<F, G>(&surplus)?;
                    committed.random =
                        preproc::u32_index(surplus.len() as u64, "committed AVSS random")?;
                    to_append.push((scope.random_share(), item_size, committed.random, data));
                }
                retained_random = (!items.is_empty()).then_some(items);
            }

            if commit.discards_undrained_material() {
                // AVSS batch sizes can overproduce. The persistent agreement
                // is exact, so those extras are neither carried forward nor
                // committed to the reservoir.
                *prep = AvssMPCNodePreprocMaterial::empty();
            }
            if retained_beaver.is_some() || retained_random.is_some() {
                prep.add(retained_beaver, retained_random);
            }
        }

        for (key, item_size, added, data) in to_append {
            store.append_items(&key, item_size, added, &data).await?;
        }

        Ok(committed)
    }

    /// Try to load AVSS preprocessing material from the persistent store.
    async fn try_load_preproc(&self) -> Result<bool, String> {
        let Some((store, hash, scope)) = self.preproc_home().await? else {
            return Ok(false);
        };
        let requested = store.scope_availability(&scope).await?;
        if requested == PoolAvailability::default() {
            return Ok(false);
        }

        let bundle = store.take_bundle_from_reservoir(&scope, requested).await?;
        self.activate_preproc_bundle(bundle).await?;
        // Emitted twice, exactly as HoneyBadger emits its own: a docker suite
        // that asserts the ABSENCE of a commit must not be silenced by an
        // operator's `RUST_LOG`, and the same goes for the load it pairs with.
        let msg = format!(
            "Loaded AVSS {} for program {}",
            preproc::PREPROC_LOAD_LOG_MARKER,
            hex::encode(hash)
        );
        eprintln!("{msg}");
        info!("{msg}");
        Ok(true)
    }

    /// Commit the surplus of a finished AVSS preprocessing round to the store.
    ///
    /// This execution keeps exactly the counts it declared
    /// ([`Self::preproc_targets`]) and the store gets everything above them.
    /// Nothing retained is written, so the client input masks this execution
    /// publishes can never be handed to a later one — which is what copying
    /// the whole pool and putting the identical shares back used to do (design
    /// doc §9.1 stage V-0, §C.9 part 4, finding S12).
    async fn persist_preproc(&self) -> Result<(), String> {
        let Some((store, hash, scope)) = self.preproc_home().await? else {
            return Ok(());
        };
        let targets = self.preproc_targets().await?;
        let committed = self
            .commit_generated_material(
                store.as_ref(),
                &scope,
                GeneratedMaterialCommit::SurplusAbove(targets),
            )
            .await?;

        let msg = format!(
            "Committed surplus AVSS {} for program {} (triples={}, randoms={})",
            preproc::PREPROC_COMMIT_LOG_MARKER,
            hex::encode(hash),
            committed.beaver,
            committed.random,
        );
        eprintln!("{msg}");
        info!("{msg}");
        Ok(())
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

/// Item-level evidence that V-0's open question has the same answer on the
/// AVSS engine as on HoneyBadger, and that the answer is adverse.
///
/// The HoneyBadger counterpart is
/// `net::mpc::honeybadger::preprocessing::persisted_item_identity_tests`. This
/// module exists because the two engines persist independently: AVSS has its
/// own `persist_preproc`/`try_load_preproc`, so "HB leaks" does not by itself
/// establish anything about AVSS. It is driven through the real engine, the
/// real store and the real `reserve_client_input_masks`.
///
/// Approximation, stated plainly: `run_preprocessing` needs a live network, so
/// the engine's pool is seeded with distinguishable shares instead of
/// generated. Everything downstream of that — persistence, the store, the load
/// and the draw — is production code in production order.
#[cfg(test)]
mod persisted_item_identity_tests {
    use super::*;
    use crate::net::mpc::avss::{AvssEngineConfig, AvssMpcEngine};
    use crate::net::mpc::session_config::MpcSessionConfig;
    use crate::net::mpc_engine::MpcEngine;
    use crate::storage::preproc::{LmdbPreprocStore, PreprocStore};
    use ark_bls12_381::{Fr, G1Projective as G1};
    use ark_ec::PrimeGroup;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Arc;
    use stoffelnet::transports::quic::QuicNetworkManager;

    const N: usize = 4;
    const T: usize = 1;
    const PARTY: usize = 0;

    fn next_instance_id() -> u64 {
        static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(7_200_000);
        NEXT_INSTANCE_ID.fetch_add(1, AtomicOrdering::Relaxed)
    }

    /// One engine is one execution. The instance id differs every time; the
    /// node identity and `(n, t)` that key the preprocessing store do not,
    /// because that is the configuration V-0 is about.
    ///
    /// `random_target` is what the engine declares it needs. A one-shot commit
    /// keeps exactly that back for this execution and writes only the surplus
    /// above it, so the target has to be the number of masks the execution
    /// actually draws. The default (`DEFAULT_N_RANDOM_SHARES` = 16) exceeds
    /// anything a unit test seeds, which would leave no surplus and nothing in
    /// the store.
    async fn one_shot_engine(random_target: usize) -> Arc<AvssMpcEngine<Fr, G1>> {
        let session = MpcSessionConfig::try_new(
            next_instance_id(),
            PARTY,
            N,
            T,
            Arc::new(QuicNetworkManager::new()),
        )
        .expect("valid topology");
        AvssMpcEngine::<Fr, G1>::from_config(
            AvssEngineConfig::new(session, Fr::from(9u64), Arc::new(vec![G1::generator(); N]))
                .with_preprocessing_counts(random_target, 0),
        )
        .await
        .expect("engine construction should succeed")
    }

    /// A mask share whose secret names its index, so an item is identified by
    /// CONTENT rather than by the cursor position it came from.
    fn labelled_mask(index: u64) -> FeldmanShamirShare<Fr, G1> {
        FeldmanShamirShare::new(
            Fr::from(2_000 + index),
            PARTY + 1,
            T,
            vec![G1::generator(); T + 1],
        )
        .expect("valid Feldman share")
    }

    /// Content identity by the exact bytes the store holds for this item.
    fn mask_content(share: &FeldmanShamirShare<Fr, G1>) -> Vec<u8> {
        preproc::serialize_feldman_shares::<Fr, G1>(std::slice::from_ref(share))
            .expect("serialize one mask")
            .0
    }

    /// A standing AVSS execution cannot persist, and cannot be made to by the
    /// commit path.
    ///
    /// This is the refusal in [`Self::preproc_home`]: a standing engine that
    /// has not opted into the program reservoir
    /// (`use_program_preproc_reservoir`) owns its material in memory, so
    /// pairing a store handle with a [`PreprocKeyScope`] for it is an error.
    ///
    /// It is pinned because the fix made it load-bearing on a second path.
    /// `persist_preproc` used to build its own `PreprocKeyScope` inline and so
    /// never consulted this refusal at all; it now goes through
    /// `preproc_home`, which is what makes "a standing execution's material is
    /// never committed" structural rather than a side effect of
    /// `preprocess()`'s early return. One edit to that early return used to
    /// turn this into a live defect. Deleting the refusal from both engines
    /// leaves every other test in the crate green.
    ///
    /// Both directions are asserted: refused while the engine owns its
    /// material in memory, permitted once it opts in, because the standing
    /// reservoir lifecycle depends on exactly that pairing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_execution_is_refused_the_store_until_it_opts_into_the_reservoir() {
        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));

        let session = MpcSessionConfig::try_new(
            next_instance_id(),
            PARTY,
            N,
            T,
            Arc::new(QuicNetworkManager::new()),
        )
        .expect("valid topology");
        let engine = AvssMpcEngine::<Fr, G1>::from_config(
            AvssEngineConfig::new(session, Fr::from(9u64), Arc::new(vec![G1::generator(); N]))
                .with_preprocessing_counts(4, 0)
                .with_deployment_mode(crate::net::engine_config::DeploymentMode::Standing),
        )
        .await
        .expect("engine construction should succeed");
        assert!(engine.is_standing());
        engine
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), [0x3e; 32])
            .expect("attach the store");

        // Seed the pool, so a commit that was wrongly allowed would have
        // material to write and the emptiness check below could not pass by
        // accident.
        let generated: Vec<_> = (0..4).map(labelled_mask).collect();
        engine
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some(generated));

        for (what, outcome) in [
            ("pairing a scope", engine.preproc_home().await.map(|_| ())),
            ("committing", engine.persist_preproc().await),
            ("loading", engine.try_load_preproc().await.map(|_| ())),
        ] {
            let error = outcome.expect_err(&format!(
                "{what} must be refused while this standing engine owns its material in memory"
            ));
            assert!(
                error.contains("owned in memory, not persisted"),
                "{what} was refused, but not by the in-memory ownership rule: {error}"
            );
        }

        // Opting in is what the standing reservoir lifecycle does, and it is
        // the only thing that may pair a store with a scope here. Taking the
        // scope from production code rather than rebuilding it keeps this
        // test honest about which keys the refused commit would have written.
        engine.use_program_preproc_reservoir();
        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the reservoir lifecycle may pair a store with a scope")
            .expect("the store is attached");
        assert_eq!(
            store
                .scope_availability(&scope)
                .await
                .expect("read the scope"),
            PoolAvailability::default(),
            "nothing a standing execution holds may reach the store"
        );
    }

    /// Both halves of a one-shot AVSS commit's division, asserted together.
    ///
    /// Checking only the store would pass for a commit that wrote the surplus
    /// and ALSO kept it, which is the defect this replaced. So the retained
    /// masks are drawn through `reserve_client_input_masks` and compared
    /// against what the store holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_one_shot_commit_writes_only_what_this_execution_does_not_keep() {
        const POOL: u64 = 6;
        const TARGET: u32 = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x82; 32];
        let engine = one_shot_engine(TARGET as usize).await;
        engine
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let generated: Vec<_> = (0..POOL).map(labelled_mask).collect();
        engine
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some(generated.clone()));

        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        let committed = engine
            .commit_generated_material(
                store.as_ref(),
                &scope,
                GeneratedMaterialCommit::SurplusAbove(PoolAvailability {
                    beaver: 0,
                    random: TARGET,
                    prand_bit: 0,
                    prand_int: 0,
                }),
            )
            .await
            .expect("commit the surplus");

        let surplus = POOL as u32 - TARGET;
        assert_eq!(committed.random, surplus);
        assert_eq!(
            store.scope_availability(&scope).await.unwrap().random,
            surplus,
            "what the commit reports is what the store holds"
        );

        let retained = engine
            .reserve_client_input_masks(TARGET as usize)
            .await
            .expect("the retained masks are this execution's to publish");
        assert_eq!(
            retained.iter().map(mask_content).collect::<Vec<_>>(),
            generated[..TARGET as usize]
                .iter()
                .map(mask_content)
                .collect::<Vec<_>>(),
            "this execution keeps the front of the pool it generated"
        );

        let blob = store
            .load(&scope.random_share())
            .await
            .unwrap()
            .expect("masks were committed");
        let stored =
            preproc::deserialize_feldman_shares::<Fr, G1>(&blob.data, blob.meta.item_size, 0)
                .expect("decode the committed masks");
        assert_eq!(
            stored.iter().map(mask_content).collect::<Vec<_>>(),
            generated[TARGET as usize..]
                .iter()
                .map(mask_content)
                .collect::<Vec<_>>(),
            "the store must hold the surplus, not the masks this execution published"
        );
        for mine in &retained {
            for theirs in &stored {
                assert_ne!(
                    mask_content(mine),
                    mask_content(theirs),
                    "a mask this execution published is also sitting in the store"
                );
            }
        }
    }

    /// The draw side of the same division: a stored bundle is a head start,
    /// not a substitute for the preprocessing protocol.
    ///
    /// Because a commit writes only the surplus an execution did not keep,
    /// what the store holds is normally *less* than one execution's worth.
    /// `preprocess` treated any non-empty load as full provisioning and
    /// returned without running the protocol, which on AVSS leaves the
    /// execution unable to serve even its own client input masks:
    /// `reserve_random_shares` has no regeneration path. It now compares the
    /// loaded pool against the declared targets and falls through to
    /// generation when the load does not cover them, which costs only the
    /// shortfall — `run_preprocessing` generates the pool's deficit against
    /// these same targets, not the whole of them.
    ///
    /// What is asserted is that decision, not the protocol round: there is no
    /// network here, so generation cannot finish. A load that covers the
    /// targets returns immediately and without a network, which is
    /// `avss::tests::preprocess_reserves_persistent_avss_random_shares_when_loaded`;
    /// a load that does not must not, however much of it succeeded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_load_that_does_not_cover_the_targets_is_not_full_provisioning() {
        const SLACK: u32 = 2;
        const TARGET: usize = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x86; 32];

        // What a finished one-shot run leaves in the store: its surplus. A
        // target of zero keeps nothing back, so every seeded mask is surplus.
        let donor = one_shot_engine(0).await;
        donor
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");
        donor
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(
                None,
                Some((0..u64::from(SLACK)).map(labelled_mask).collect()),
            );
        donor.persist_preproc().await.expect("commit the surplus");

        // The next execution of the same program needs more masks than the
        // surplus can serve.
        let second = one_shot_engine(TARGET).await;
        second
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");
        let (_store, _hash, scope) = second
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        assert_eq!(
            store
                .scope_availability(&scope)
                .await
                .expect("read the store"),
            PoolAvailability {
                beaver: 0,
                random: SLACK,
                prand_bit: 0,
                prand_int: 0,
            },
            "the premise: the store holds less than one execution's worth"
        );

        // No network, so generation cannot complete: it either fails for want
        // of peers or is still running when the timeout fires. Either outcome
        // is this execution still trying to provision itself. What it must
        // never do is report success.
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(5), second.preprocess()).await;
        if let Ok(reported) = &outcome {
            let error = reported.as_ref().err().unwrap_or_else(|| {
                panic!(
                    "preprocess() reported this execution provisioned by a bundle of \
                     {SLACK} masks against a target of {TARGET}: it could not \
                     publish the client input masks it just promised"
                )
            });
            assert!(
                error.contains("AVSS preprocessing failed"),
                "a short load must put this execution into the preprocessing \
                 protocol, not into a refusal: {error}"
            );
        }

        // The partial bundle was still drawn: the gate is about coverage, not
        // about refusing to use what the store has.
        assert_eq!(
            store
                .scope_availability(&scope)
                .await
                .expect("read the store"),
            PoolAvailability::default(),
            "the surplus must still have been taken: generating the shortfall \
             means generating what the load did not cover, not all of it"
        );
    }

    /// The standing half of the same division on AVSS.
    ///
    /// `top_up_exact` commits exactly the party-agreed chunk and clears the
    /// live pool. The clear is what keeps generated material from existing in
    /// two places at once, and the exact drain is what keeps the reservoir a
    /// deterministic function of the program: AVSS used to bank whatever the
    /// round happened to leave, so two parties whose batch sizes differed
    /// would hold different inventories and force a Rebuild.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_commit_keeps_nothing_and_banks_no_overproduction() {
        const PRODUCED: u64 = 5;
        const AGREED: u32 = 3;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x83; 32];
        let engine = one_shot_engine(AGREED as usize).await;
        engine
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        engine
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some((0..PRODUCED).map(labelled_mask).collect()));

        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        let agreed = PoolAvailability {
            beaver: 0,
            random: AGREED,
            prand_bit: 0,
            prand_int: 0,
        };
        let committed = engine
            .commit_generated_material(
                store.as_ref(),
                &scope,
                GeneratedMaterialCommit::AgreedChunk(agreed),
            )
            .await
            .expect("commit the agreed chunk");

        assert_eq!(
            committed, agreed,
            "a standing commit writes exactly what the parties agreed"
        );
        assert_eq!(
            store.scope_availability(&scope).await.unwrap(),
            agreed,
            "the reservoir holds the agreed chunk and not the {} masks of \
             over-production",
            PRODUCED - u64::from(AGREED)
        );
        assert_eq!(
            engine
                .clone_avss_node()
                .await
                .preprocessing_material
                .lock()
                .await
                .len(),
            (0, 0),
            "a standing commit must leave this engine holding nothing: every \
             mask it wrote belongs to a future execution's bundle, and the \
             over-production belongs to nobody"
        );
    }

    /// The AVSS twin of the standing top-up's pool clear.
    ///
    /// `AgreedChunk` commits everything it drains, so a top-up that began with
    /// material already in the pool — material a live engine may have served —
    /// would bank it for a later execution to draw. Nothing inside the top-up
    /// used to prevent that; facts outside it did.
    ///
    /// Two assertions, matching the HoneyBadger pair. The first drives the real
    /// `top_up_exact`, and the hazard is live rather than theoretical: deleting
    /// the clear makes the top-up return `Ok(())` immediately, because
    /// `run_preprocessing` finds the pool already holding what it was asked for
    /// and does nothing, and the commit then banks the inherited masks — the
    /// store assertion fails with `random: 2` present. With the clear, the
    /// round has an empty pool and no peers, so it never returns and the test
    /// abandons it at the timeout. The second composes the clear with a commit,
    /// standing in for the round, and asserts at mask-content level that the
    /// reservoir holds the round's own output and nothing the engine inherited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_top_up_destroys_the_pool_it_inherited_before_generating() {
        const INHERITED: u64 = 4;
        const AGREED: u32 = 2;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x9e; 32];
        let engine = one_shot_engine(AGREED as usize).await;
        engine
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let inherited: Vec<_> = (0..INHERITED).map(labelled_mask).collect();
        engine
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some(inherited.clone()));

        let needed = PoolAvailability {
            beaver: 0,
            random: AGREED,
            prand_bit: 0,
            prand_int: 0,
        };
        // Abandoned at the timeout once the pool is empty, because an
        // interactive round with no peers never returns. What the engine and
        // the store hold afterwards is the subject, not how this resolves.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(750),
            engine.top_up_exact(needed),
        )
        .await;

        assert_eq!(
            engine
                .clone_avss_node()
                .await
                .preprocessing_material
                .lock()
                .await
                .len(),
            (0, 0),
            "a top-up must not carry an inherited pool into the round it is \
             about to commit from"
        );
        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        assert_eq!(
            store.scope_availability(&scope).await.unwrap(),
            PoolAvailability::default(),
            "no mask this engine was holding before the top-up may reach the \
             reservoir, where a later execution would draw it"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_top_up_banks_the_round_it_ran_and_never_what_it_inherited() {
        const INHERITED: u64 = 4;
        const GENERATED: u64 = 4;
        const AGREED: u32 = 3;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x9f; 32];
        let engine = one_shot_engine(AGREED as usize).await;
        engine
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let inherited: Vec<_> = (0..INHERITED).map(labelled_mask).collect();
        engine
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some(inherited.clone()));

        // Step 1 of the real `top_up_exact`.
        drop(engine.lease_node_with_emptied_pool_for_top_up().await);

        // Step 2 stands in for `run_preprocessing`: labels disjoint from the
        // inherited ones, so the store's contents name their origin.
        let generated: Vec<_> = (100..100 + GENERATED).map(labelled_mask).collect();
        engine
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some(generated.clone()));

        // Step 3, unchanged production code.
        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        let agreed = PoolAvailability {
            beaver: 0,
            random: AGREED,
            prand_bit: 0,
            prand_int: 0,
        };
        engine
            .commit_generated_material(
                store.as_ref(),
                &scope,
                GeneratedMaterialCommit::AgreedChunk(agreed),
            )
            .await
            .expect("commit the agreed chunk");

        let blob = store
            .load(&scope.random_share())
            .await
            .unwrap()
            .expect("masks were banked");
        let banked =
            preproc::deserialize_feldman_shares::<Fr, G1>(&blob.data, blob.meta.item_size, 0)
                .expect("decode the banked masks");
        let banked_content = banked.iter().map(mask_content).collect::<Vec<_>>();
        for (index, mask) in inherited.iter().map(mask_content).enumerate() {
            assert!(
                !banked_content.contains(&mask),
                "the reservoir holds inherited mask {index}, which this engine \
                 was already able to serve"
            );
        }
        assert_eq!(
            banked_content,
            generated[..AGREED as usize]
                .iter()
                .map(mask_content)
                .collect::<Vec<_>>(),
            "the reservoir must hold the front of the round's own output"
        );
    }

    /// V-0's open question on the AVSS engine, answered by execution.
    ///
    /// Execution 1 commits with the real `persist_preproc`, then
    /// draws client input masks with the real `reserve_client_input_masks` —
    /// the shares that get published to input clients. Execution 2, a separate
    /// engine with the same node identity, program hash and `(n, t)`, loads
    /// with the real `try_load_preproc` and draws its own masks. No mask may
    /// appear in both.
    ///
    /// This test FAILED when it was written, and the failure was the finding:
    /// `persist_preproc` wrote a `consumed: 0` copy of the pool and put the
    /// identical shares straight back (`prep.add(None, Some(items))`), so
    /// execution 1 masked client inputs with material it had already published
    /// for the next execution to draw. It passes now because a commit is a
    /// division rather than a copy: this execution keeps the masks it declared
    /// it needs and only the surplus above them is written.
    ///
    /// Its sizing was corrected when the defect was fixed, and nothing else
    /// was: with POOL = 6 it asserted that two disjoint four-mask sets both
    /// came out of six seeded masks, which no sound fix could satisfy — AVSS
    /// has no regeneration path at all (`reserve_random_shares` errors), so
    /// both sets are subsets of what is seeded. The old constant encoded the
    /// broken behaviour, in which both executions received all six masks
    /// because they were copies. Every assertion below is unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_masks_one_execution_used_are_never_handed_to_a_later_execution() {
        // Two executions of USED masks each, which is what this test draws, so
        // disjointness is satisfiable at all.
        const POOL: u64 = 2 * USED as u64;
        const USED: usize = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x81; 32];

        let first = one_shot_engine(USED).await;
        assert!(
            !first.is_standing(),
            "this is the one-shot --preproc-store path, which is what persists"
        );
        first
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let generated: Vec<_> = (0..POOL).map(labelled_mask).collect();
        first
            .clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(None, Some(generated.clone()));

        first.persist_preproc().await.expect("persist");

        let used = first
            .reserve_client_input_masks(USED)
            .await
            .expect("execution 1 publishes masks to its clients");
        assert_eq!(used.len(), USED);

        let second = one_shot_engine(USED).await;
        second
            .preproc_persistence_ops()
            .expect("AVSS supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");
        assert!(
            second
                .try_load_preproc()
                .await
                .expect("execution 2 consults the store"),
            "execution 2 found nothing persisted, so this test exercised nothing"
        );

        let received = second
            .reserve_client_input_masks(USED)
            .await
            .expect("execution 2 publishes masks to its clients");

        // Non-vacuity: execution 2 drew real material that was really generated.
        assert_eq!(received.len(), USED);
        let generated_contents: Vec<_> = generated.iter().map(mask_content).collect();
        for mask in &received {
            assert!(
                generated_contents.contains(&mask_content(mask)),
                "execution 2 received a mask that was never generated"
            );
        }

        for (i, mine) in used.iter().enumerate() {
            for (j, theirs) in received.iter().enumerate() {
                assert_ne!(
                    mask_content(mine),
                    mask_content(theirs),
                    "execution 2's client input mask {j} is the SAME mask execution 1 \
                     already published as its mask {i}: secret share {:?}",
                    mine.feldmanshare
                );
            }
        }
    }
}
