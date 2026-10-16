use super::{HoneyBadgerMpcEngine, HoneyBadgerNodeLease};
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{
    self, agree_standing_preproc_plan_for_party, apply_standing_preproc_plan,
    standing_preproc_snapshot, GeneratedMaterialCommit, MaterialKind, OwnedPreprocBundle,
    PoolAvailability, PreprocKey, PreprocKeyScope, TakenPreproc,
};
pub use crate::storage::preproc::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::SeedableRng;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
use stoffelmpc_mpc::honeybadger::fpmul::f256::Gf256;
use stoffelmpc_mpc::honeybadger::preprocessing::HoneyBadgerMPCNodePreprocMaterial;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
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

// HoneyBadger turns each requested Beaver triple into two temporary random
// shares before constructing the triple.  Letting a large standing-reservoir
// deficit flow through one `run_preprocessing` call pipelines every RanSha
// batch at once. Keep each call small enough that TripleGen's serialized batch
// messages remain comfortably below the transport's 10 MiB decode limit.
const STANDING_TOP_UP_RANDOM_WORK_LIMIT: u64 = 32 * 1024;
// Keep derived-share top-ups bounded independently of the much larger RanSha
// workload. The MPC dependency performs finer-grained internal mask batches.
const STANDING_TOP_UP_DERIVED_SHARE_LIMIT: u64 = 256;

fn div_ceil_u64(value: u64, divisor: u64) -> u64 {
    if value == 0 {
        0
    } else {
        1 + (value - 1) / divisor
    }
}

fn split_u32(total: u32, parts: u64, index: u64) -> u32 {
    let total = u64::from(total);
    let value = total / parts + u64::from(index < total % parts);
    u32::try_from(value).expect("a partition of a u32 count always fits in u32")
}

fn split_u32_aligned(total: u32, parts: u64, index: u64, alignment: u64) -> u32 {
    let alignment = alignment.max(1);
    let total = u64::from(total);
    let full_units = total / alignment;
    let remainder = total % alignment;
    let value = full_units / parts + u64::from(index < full_units % parts);
    let value =
        value.saturating_mul(alignment) + u64::from(index + 1 == parts).saturating_mul(remainder);
    u32::try_from(value).expect("an aligned partition of a u32 count always fits in u32")
}

fn standing_top_up_random_work(chunk: PoolAvailability, threshold: usize) -> u64 {
    let group_size = u64::try_from(threshold)
        .unwrap_or(u64::MAX)
        .saturating_mul(2)
        .saturating_add(1);
    let beaver = u64::from(chunk.beaver);
    let rounded_beaver = div_ceil_u64(beaver, group_size).saturating_mul(group_size);
    rounded_beaver
        .saturating_mul(2)
        .saturating_add(u64::from(chunk.random))
}

/// Split one agreed standing-store deficit into deterministic protocol calls.
/// Every party computes the same chunks from the authenticated target, keeping
/// HoneyBadger session counters aligned while bounding the number of pipelined
/// RanSha and derived-share sessions in any one call.
fn standing_top_up_chunks(needed: PoolAvailability, threshold: usize) -> Vec<PoolAvailability> {
    if needed == PoolAvailability::default() {
        return Vec::new();
    }

    let group_size = u64::try_from(threshold)
        .unwrap_or(u64::MAX)
        .saturating_mul(2)
        .saturating_add(1);
    let mask_group_size = u64::try_from(threshold)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let random_work_limit = STANDING_TOP_UP_RANDOM_WORK_LIMIT.max(group_size.saturating_mul(2));
    let total_random_work = standing_top_up_random_work(needed, threshold);
    let mut part_count = div_ceil_u64(total_random_work, random_work_limit)
        .max(div_ceil_u64(
            u64::from(needed.prand_bit),
            STANDING_TOP_UP_DERIVED_SHARE_LIMIT,
        ))
        .max(div_ceil_u64(
            u64::from(needed.prand_int),
            STANDING_TOP_UP_DERIVED_SHARE_LIMIT,
        ))
        .max(1);

    loop {
        let chunks = (0..part_count)
            .map(|index| {
                // RandBit/PRandBit consume masks in threshold+1 groups. Keep
                // every partition aligned when the total is aligned so a
                // chunk never needs an unaccounted extra triple/random share.
                let prand_bit =
                    split_u32_aligned(needed.prand_bit, part_count, index, mask_group_size);
                let beaver = if needed.beaver >= needed.prand_bit {
                    prand_bit.saturating_add(split_u32(
                        needed.beaver - needed.prand_bit,
                        part_count,
                        index,
                    ))
                } else {
                    split_u32(needed.beaver, part_count, index)
                };
                let random = if needed.random >= needed.prand_bit {
                    prand_bit.saturating_add(split_u32(
                        needed.random - needed.prand_bit,
                        part_count,
                        index,
                    ))
                } else {
                    split_u32(needed.random, part_count, index)
                };
                PoolAvailability {
                    beaver,
                    random,
                    prand_bit,
                    prand_int: split_u32(needed.prand_int, part_count, index),
                }
            })
            .filter(|chunk| *chunk != PoolAvailability::default())
            .collect::<Vec<_>>();
        let within_limits = chunks.iter().all(|chunk| {
            standing_top_up_random_work(*chunk, threshold) <= random_work_limit
                && u64::from(chunk.prand_bit) <= STANDING_TOP_UP_DERIVED_SHARE_LIMIT
                && u64::from(chunk.prand_int) <= STANDING_TOP_UP_DERIVED_SHARE_LIMIT
        });
        if within_limits {
            return chunks;
        }
        part_count = part_count.saturating_add(1);
    }
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
        if self.is_standing() {
            return self.preprocess_standing().await;
        }

        // Draw whatever the store holds before deciding what to generate. A
        // commit writes only the surplus an execution did not keep
        // (`commit_generated_material`), so a stored bundle is normally less
        // than one execution's worth: it is a head start, not a substitute for
        // the protocol. Short-circuiting on any non-empty load left this
        // execution declaring itself ready while holding no triples, and it
        // then failed at its first multiplication with its clients' masked
        // inputs already published. Falling through costs only what the load
        // did not cover, because `run_preprocessing` generates the pool's
        // deficit against these same targets rather than the whole of them.
        let targets = self.preproc_targets().await?;
        if self.try_load_preproc().await? {
            let held = self.pool_availability().await?;
            if held.covers(targets) {
                self.ready.store(true, Ordering::SeqCst);
                return Ok(());
            }
            let msg = format!(
                "Stored preprocessing material {} (held={held:?}, target={targets:?}); generating the shortfall",
                preproc::PREPROC_PARTIAL_LOAD_LOG_MARKER
            );
            eprintln!("{msg}");
            tracing::info!("{msg}");
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

            let result = node
                .run_preprocessing(self.protocol_net.clone(), &mut rng)
                .await;
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

    /// The store and key scope this engine's preprocessing material lives
    /// under, or `None` when no store is attached.
    ///
    /// This is the only place a store handle and a [`PreprocKeyScope`] are
    /// paired, so every path that can reach the preprocessing store — the
    /// standing reservoir lifecycle, the one-shot commit and the one-shot
    /// draw alike — passes the refusal below. A standing *execution* owns its
    /// material in memory and must never persist it; building the scope
    /// inline, as the commit path used to, bypassed that.
    pub(super) async fn preproc_home(
        &self,
    ) -> Result<
        Option<(
            Arc<dyn crate::storage::preproc::PreprocStore>,
            [u8; 32],
            PreprocKeyScope,
        )>,
        String,
    > {
        let store = self.preproc_store.read().await.clone();
        let hash = *self.program_hash.read().await;
        let (Some(store), Some(hash)) = (store, hash) else {
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
            F::field_kind(),
            self.topology.n_parties(),
            self.topology.threshold(),
            self.persistent_identity(),
        );
        Ok(Some((store, hash, scope)))
    }

    /// [`Self::preproc_home`] for the callers that cannot proceed without a
    /// store: the standing reservoir lifecycle.
    pub(super) async fn preproc_scope(
        &self,
    ) -> Result<
        (
            Arc<dyn crate::storage::preproc::PreprocStore>,
            [u8; 32],
            PreprocKeyScope,
        ),
        String,
    > {
        self.preproc_home().await?.ok_or_else(|| {
            "standing preprocessing requires configured preproc store and program hash".to_owned()
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
        let node = self.clone_node().await;
        Ok(PoolAvailability {
            beaver: preproc::u32_index(node.params.n_triples as u64, "HB beaver target")?,
            random: preproc::u32_index(node.params.n_random_shares as u64, "HB random target")?,
            prand_bit: preproc::u32_index(node.params.n_prandbit as u64, "HB prandbit target")?,
            prand_int: preproc::u32_index(node.params.n_prandint as u64, "HB prandint target")?,
        })
    }

    /// What this engine's upstream in-memory pool holds right now.
    ///
    /// Against [`Self::preproc_targets`] this is what decides whether a
    /// one-shot execution still needs a preprocessing round after consulting
    /// the store. The store holds only material no execution was served, which
    /// is the surplus of earlier runs, so covering a whole execution is the
    /// exception rather than the rule.
    ///
    /// Both a load and a finished round leave their material in this pool;
    /// only a standing bundle and the execution-time draws touch
    /// `random_share_cache`, which is therefore empty where this is used.
    async fn pool_availability(&self) -> Result<PoolAvailability, String> {
        let node = self.clone_node().await;
        let held = node.preprocessing_material.lock().await.length();
        Ok(PoolAvailability {
            beaver: preproc::u32_index(held.beaver_triples as u64, "pooled beaver")?,
            random: preproc::u32_index(held.random_shr as u64, "pooled random")?,
            prand_bit: preproc::u32_index(held.prandbit as u64, "pooled prandbit")?,
            prand_int: preproc::u32_index(held.prandint as u64, "pooled prandint")?,
        })
    }

    /// Install a destructively allocated reservoir bundle into this execution's
    /// private in-memory preprocessing pool. The bundle has no persistent
    /// execution lane: dropping it before this call securely burns it.
    pub async fn activate_preallocated_standing(
        &self,
        bundle: OwnedPreprocBundle,
    ) -> Result<(), String> {
        if !self.is_standing() {
            return Err("preallocated activation requires standing deployment mode".to_owned());
        }
        if self
            .use_program_preproc_reservoir
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                "a program reservoir engine cannot be activated as an execution".to_owned(),
            );
        }
        let targets = self.preproc_targets().await?;
        let availability = bundle.availability();
        if availability != targets {
            return Err(format!(
                "preallocated HB bundle does not match target: available={availability:?}, target={targets:?}"
            ));
        }
        self.activate_preproc_bundle(bundle).await?;
        // A preallocated bundle equals the targets, checked just above, so
        // activating it is this execution's whole preprocessing. A partial
        // bundle from the store is not, and `is_ready` gates client input and
        // every share operation, so it must not be set until `preprocess` has
        // provisioned the declared targets.
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn activate_preproc_bundle(&self, bundle: OwnedPreprocBundle) -> Result<(), String> {
        fn decode<T>(
            item: Option<TakenPreproc>,
            label: &str,
            decode: impl FnOnce(&[u8], u32) -> Result<Vec<T>, String>,
        ) -> Result<Option<Vec<T>>, String> {
            item.map(|item| {
                let expected = item.count;
                let decoded = decode(&item.data, item.item_size)?;
                ensure_decoded_count(label, decoded.len(), expected)?;
                Ok(decoded)
            })
            .transpose()
        }

        let beaver = decode(
            bundle.beaver,
            "preallocated Beaver triples",
            |data, item_size| {
                preproc::deserialize_beaver_triples::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        let mut random = decode(
            bundle.random,
            "preallocated random shares",
            |data, item_size| {
                preproc::deserialize_robust_shares::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        let prand_bit = decode(
            bundle.prand_bit,
            "preallocated PRandBit shares",
            |data, item_size| {
                preproc::deserialize_prandbit_shares::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        let prand_int = decode(
            bundle.prand_int,
            "preallocated PRandInt shares",
            |data, item_size| {
                preproc::deserialize_robust_shares::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        // Standing executions never return their owned preprocessing bundle to
        // persistent storage. Install program-visible random shares directly
        // into the O(1) front-pop cache instead of the upstream Vec, whose
        // single-item front drain is quadratic over a large execution.
        if self.is_standing() {
            if let Some(shares) = random.take() {
                let mut cache = self.random_share_cache.lock().await;
                if cache.is_empty() {
                    *cache = shares.into();
                } else {
                    cache.extend(shares);
                }
            }
        }
        self.clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(beaver, None, random, None, prand_bit, prand_int);
        Ok(())
    }

    pub async fn standing_preproc_snapshot(&self) -> Result<StandingPreprocSnapshot, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        standing_preproc_snapshot(store.as_ref(), scope)
            .await
            .map_err(String::from)
    }

    /// Validate party-indexed snapshots and install the only plan that a
    /// multi-party standing execution may use. Callers exchange snapshots over
    /// the execution-scoped control route before calling [`Self::preprocess`].
    pub async fn install_standing_preproc_plan(
        &self,
        snapshots: Vec<StandingPreprocSnapshot>,
        fresh_generation_id: [u8; 32],
    ) -> Result<StandingPreprocPlan, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        let plan = agree_standing_preproc_plan_for_party(
            store.as_ref(),
            scope,
            self.preproc_targets().await?,
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
                "multi-party standing preprocessing requires a party-agreed inventory plan before protocol startup"
                    .to_owned()
            })?
        };
        let (store, _hash, scope) = self.preproc_scope().await?;
        apply_standing_preproc_plan(store.as_ref(), scope, targets, plan, |needed| {
            self.top_up_exact(needed)
        })
        .await?;

        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn top_up_exact(&self, needed: PoolAvailability) -> Result<(), String> {
        if needed == PoolAvailability::default() {
            return Ok(());
        }
        let (store, _hash, scope) = self.preproc_scope().await?;
        let mut node = self.lease_node_with_emptied_pool_for_top_up().await;
        let chunks = standing_top_up_chunks(needed, self.topology.threshold());
        for (chunk_index, chunk) in chunks.iter().copied().enumerate() {
            let mask_group_size = self.topology.threshold().saturating_add(1);
            let mask_cost = usize::try_from(
                div_ceil_u64(u64::from(chunk.prand_bit), mask_group_size as u64)
                    .saturating_mul(mask_group_size as u64),
            )
            .map_err(|_| "PRandBit top-up cost does not fit usize".to_owned())?;
            // Big-field RandBit consumes one ordinary triple and random share
            // per mask. These are generation costs, not part of the program's
            // declared final reservoir, so provision them in addition.
            node.params.n_triples = (chunk.beaver as usize).saturating_add(mask_cost);
            node.params.n_random_shares = (chunk.random as usize).saturating_add(mask_cost);
            node.params.n_prandbit = chunk.prand_bit as usize;
            node.params.n_prandint = chunk.prand_int as usize;

            eprintln!(
                "[party {}] standing preprocessing top-up chunk {}/{}: {:?}",
                self.topology.party_id(),
                chunk_index + 1,
                chunks.len(),
                chunk,
            );
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            node.run_preprocessing(self.protocol_net.clone(), &mut rng)
                .await
                .map_err(|e| {
                    format!(
                        "Failed to top up preprocessing material in chunk {}/{}: {:?}",
                        chunk_index + 1,
                        chunks.len(),
                        e
                    )
                })?;

            // Drain and commit each completed chunk before beginning the next
            // one. This bounds memory and leaves an inspectable partial store if
            // a later chunk fails, while the generation marker remains pending
            // until `apply_standing_preproc_plan` commits the complete plan.
            self.commit_generated_material(
                store.as_ref(),
                &scope,
                GeneratedMaterialCommit::AgreedChunk(chunk),
            )
            .await?;
        }

        Ok(())
    }

    /// Lease this node for a standing top-up, emptying its live pool first.
    ///
    /// [`GeneratedMaterialCommit::AgreedChunk`] commits everything it drains,
    /// so a top-up that began with material already in the pool would bank that
    /// material — and material already in the pool is material this engine may
    /// have served. Until now nothing inside the top-up prevented that; three
    /// facts outside it did (the `preprocess` ordering, `preproc_home`'s refusal
    /// to persist a standing *execution*'s pool, and the runner building a
    /// throwaway engine to warm a reservoir). Emptying the pool here makes the
    /// guarantee local: whatever this engine held before the round is destroyed
    /// rather than persisted, so what the top-up banks is material the round it
    /// is about to run produced.
    ///
    /// One clear before the chunk loop covers every chunk, because
    /// [`Self::commit_generated_material`] re-empties the pool at the end of
    /// each `AgreedChunk` commit, which re-establishes the precondition for the
    /// next chunk's round.
    ///
    /// Destroying preprocessing material is a liveness cost, never a privacy
    /// one: the worst case is a round that has to generate what it could have
    /// reused. That asymmetry is why this is the safe direction to fail in.
    async fn lease_node_with_emptied_pool_for_top_up(&self) -> HoneyBadgerNodeLease<F> {
        let node = self.clone_node().await;
        *node.preprocessing_material.lock().await = HoneyBadgerMPCNodePreprocMaterial::empty();
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
    /// execution's leftovers — which is why the guard exists once rather than
    /// twice with opposite signs.
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
            let node = self.clone_node().await;
            let mut prep = node.preprocessing_material.lock().await;
            let held = prep.length();
            let mut retained_beaver = None;
            let mut retained_random = None;
            let mut retained_prand_bit = None;
            let mut retained_prand_int = None;

            let split = commit.split(
                MaterialKind::BeaverTriple,
                preproc::u32_index(held.beaver_triples as u64, "held beaver")?,
            );
            if split.drained > 0 {
                let mut items = prep
                    .take_beaver_triples(split.drained as usize)
                    .map_err(|e| format!("{e:?}"))?;
                let surplus = items.split_off(split.retained as usize);
                if !surplus.is_empty() {
                    let (data, item_size) = preproc::serialize_beaver_triples::<F>(&surplus)?;
                    committed.beaver =
                        preproc::u32_index(surplus.len() as u64, "committed beaver")?;
                    to_append.push((scope.beaver_triple(), item_size, committed.beaver, data));
                }
                retained_beaver = (!items.is_empty()).then_some(items);
            }

            let split = commit.split(
                MaterialKind::RandomShare,
                preproc::u32_index(held.random_shr as u64, "held random")?,
            );
            if split.drained > 0 {
                let mut items = prep
                    .take_random_shares(split.drained as usize)
                    .map_err(|e| format!("{e:?}"))?;
                let surplus = items.split_off(split.retained as usize);
                if !surplus.is_empty() {
                    let (data, item_size) = preproc::serialize_robust_shares::<F>(&surplus)?;
                    committed.random =
                        preproc::u32_index(surplus.len() as u64, "committed random")?;
                    to_append.push((scope.random_share(), item_size, committed.random, data));
                }
                retained_random = (!items.is_empty()).then_some(items);
            }

            let split = commit.split(
                MaterialKind::PRandBit,
                preproc::u32_index(held.prandbit as u64, "held prandbit")?,
            );
            if split.drained > 0 {
                let mut items = prep
                    .take_prandbit_shares(split.drained as usize)
                    .map_err(|e| format!("{e:?}"))?;
                let surplus = items.split_off(split.retained as usize);
                if !surplus.is_empty() {
                    let (data, item_size) = preproc::serialize_prandbit_shares::<F>(&surplus)?;
                    committed.prand_bit =
                        preproc::u32_index(surplus.len() as u64, "committed prandbit")?;
                    to_append.push((scope.prand_bit(), item_size, committed.prand_bit, data));
                }
                retained_prand_bit = (!items.is_empty()).then_some(items);
            }

            let split = commit.split(
                MaterialKind::PRandInt,
                preproc::u32_index(held.prandint as u64, "held prandint")?,
            );
            if split.drained > 0 {
                let mut items = prep
                    .take_prandint_shares(split.drained as usize)
                    .map_err(|e| format!("{e:?}"))?;
                let surplus = items.split_off(split.retained as usize);
                if !surplus.is_empty() {
                    let (data, item_size) = preproc::serialize_robust_shares::<F>(&surplus)?;
                    committed.prand_int =
                        preproc::u32_index(surplus.len() as u64, "committed prandint")?;
                    to_append.push((scope.prand_int(), item_size, committed.prand_int, data));
                }
                retained_prand_int = (!items.is_empty()).then_some(items);
            }

            if commit.discards_undrained_material() {
                // Protocol batch sizes can overproduce a few items. The
                // persistent agreement is exact, so do not carry those extras
                // into the next chunk or commit them to the reservoir.
                *prep = HoneyBadgerMPCNodePreprocMaterial::empty();
            }
            if retained_beaver.is_some()
                || retained_random.is_some()
                || retained_prand_bit.is_some()
                || retained_prand_int.is_some()
            {
                prep.add(
                    retained_beaver,
                    None,
                    retained_random,
                    None,
                    retained_prand_bit,
                    retained_prand_int,
                );
            }
        }

        for (key, item_size, added, data) in to_append {
            store.append_items(&key, item_size, added, &data).await?;
        }

        Ok(committed)
    }

    /// Try to load preprocessing material from the persistent store.
    /// Returns `true` if material was loaded, `false` if nothing available.
    async fn try_load_preproc(&self) -> Result<bool, String> {
        let Some((store, hash, scope)) = self.preproc_home().await? else {
            return Ok(false);
        };
        let identity = self.persistent_identity();
        let requested = store.scope_availability(&scope).await?;
        if requested == PoolAvailability::default() {
            return Ok(false);
        }

        // One transaction removes the complete bundle before it reaches RAM.
        // Concurrent engines therefore cannot observe or consume the same
        // correlated material.
        let bundle = store.take_bundle_from_reservoir(&scope, requested).await?;
        let loaded = bundle.availability();
        self.activate_preproc_bundle(bundle).await?;
        let msg = format!(
            "Loaded {} for program {} (identity={}, n={}, t={}, triples={}, randoms={}, prandbits={}, prandints={})",
            preproc::PREPROC_LOAD_LOG_MARKER,
            hex::encode(hash),
            identity,
            self.topology.n_parties(),
            self.topology.threshold(),
            loaded.beaver,
            loaded.random,
            loaded.prand_bit,
            loaded.prand_int,
        );
        eprintln!("{msg}");
        tracing::info!("{msg}");
        Ok(true)
    }

    /// Commit the surplus of a finished preprocessing round to the store.
    ///
    /// This execution keeps exactly the counts it declared
    /// ([`Self::preproc_targets`]) and the store gets everything above them.
    /// Nothing retained is written, so what the store holds — and what it
    /// hands to a later execution — is material no execution has been served.
    /// Until this split existed the whole pool was copied to the store and the
    /// identical items handed back, so execution 1 went on to use exactly the
    /// material execution 2 would later draw (design doc §9.1 stage V-0,
    /// §C.9 part 4, finding S12).
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
            "Committed surplus {} for program {} (identity={}, n={}, t={}, triples={}, randoms={}, prandbits={}, prandints={})",
            preproc::PREPROC_COMMIT_LOG_MARKER,
            hex::encode(hash),
            self.persistent_identity(),
            self.topology.n_parties(),
            self.topology.threshold(),
            committed.beaver,
            committed.random,
            committed.prand_bit,
            committed.prand_int,
        );
        eprintln!("{msg}");
        tracing::info!("{msg}");
        Ok(())
    }

    async fn fill_random_share_cache(
        &self,
        cache: &mut VecDeque<RobustShare<F>>,
    ) -> Result<(), String> {
        let node = self.clone_node().await;
        let mut prep_material = node.preprocessing_material.lock().await;
        let upstream = prep_material.length().random_shr;
        if upstream == 0 {
            return Ok(());
        }
        let shares = prep_material
            .take_random_shares(upstream)
            .map_err(|error| format!("Failed to refill random-share cache: {error:?}"))?;
        if cache.is_empty() {
            *cache = shares.into();
        } else {
            cache.extend(shares);
        }
        Ok(())
    }

    pub(super) async fn reserve_random_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, String> {
        if num_shares == 0 {
            return Ok(Vec::new());
        }
        loop {
            let available = {
                let mut cache = self.random_share_cache.lock().await;
                if cache.len() < num_shares {
                    // Move the whole remaining upstream Vec in one drain. Its
                    // front-drain cost is then paid once, with no tail left to
                    // shift, rather than once per random builtin invocation.
                    self.fill_random_share_cache(&mut cache).await?;
                }
                if cache.len() >= num_shares {
                    return Ok(cache.drain(..num_shares).collect());
                }
                cache.len()
            };

            if self.is_standing() {
                return Err(format!(
                    "standing execution exhausted its owned random-share bundle (need {num_shares}, have {available})"
                ));
            }
            self.regenerate_random_shares(num_shares.saturating_sub(available))
                .await?;
        }
    }

    /// Reserve one random share without allocating a temporary one-element
    /// vector. This is the hot path for `Share.random_field()`.
    pub(super) fn try_reserve_random_share(&self) -> Option<RobustShare<F>> {
        self.random_share_cache.try_lock().ok()?.pop_front()
    }

    pub(super) async fn reserve_random_share(&self) -> Result<RobustShare<F>, String> {
        // The VM normally consumes random shares sequentially. Avoid building
        // and polling a mutex future on that overwhelmingly common path while
        // retaining the async fallback for concurrent callers.
        if let Some(share) = self.try_reserve_random_share() {
            return Ok(share);
        }

        loop {
            let available = {
                let mut cache = self.random_share_cache.lock().await;
                if let Some(share) = cache.pop_front() {
                    return Ok(share);
                }
                self.fill_random_share_cache(&mut cache).await?;
                if let Some(share) = cache.pop_front() {
                    return Ok(share);
                }
                cache.len()
            };

            if self.is_standing() {
                return Err(format!(
                    "standing execution exhausted its owned random-share bundle (need 1, have {available})"
                ));
            }
            self.regenerate_random_shares(1).await?;
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
                Err(HoneyBadgerError::NotEnoughPreprocessing) if self.is_standing() => {
                    return Err(format!(
                        "standing execution exhausted its owned PRandInt bundle (need {num_shares})"
                    ));
                }
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

    pub(super) async fn reserve_beaver_triples(
        &self,
        num_triples: usize,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, String> {
        let node = self.clone_node().await;
        let result = node
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(num_triples)
            .map_err(|e| format!("Failed to take Beaver triples: {:?}", e));
        result
    }

    pub(super) async fn reserve_prandbit_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<(RobustShare<F>, Gf256)>, String> {
        let node = self.clone_node().await;
        let result = node
            .preprocessing_material
            .lock()
            .await
            .take_prandbit_shares(num_shares)
            .map_err(|e| format!("Failed to take PRandBit shares: {:?}", e));
        result
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
        node.run_preprocessing(self.protocol_net.clone(), &mut rng)
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
        node.run_preprocessing(self.protocol_net.clone(), &mut rng)
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
        let share = self.reserve_random_share().await?;
        Self::encode_share(&share).map(|v| ShareData::Opaque(v.into()))
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

#[cfg(test)]
mod standing_agreement_tests {
    use super::*;

    fn retained_snapshot() -> StandingPreprocSnapshot {
        StandingPreprocSnapshot {
            generation_id: Some([4; 32]),
            beaver: preproc::PreprocMeta {
                count: 16,
                consumed: 3,
                item_size: 96,
            },
            random: preproc::PreprocMeta {
                count: 20,
                consumed: 4,
                item_size: 48,
            },
            prand_bit: preproc::PreprocMeta {
                count: 8,
                consumed: 1,
                item_size: 49,
            },
            prand_int: preproc::PreprocMeta {
                count: 6,
                consumed: 2,
                item_size: 48,
            },
        }
    }

    fn sum_chunks(chunks: &[PoolAvailability]) -> PoolAvailability {
        chunks
            .iter()
            .fold(PoolAvailability::default(), |sum, chunk| PoolAvailability {
                beaver: sum.beaver + chunk.beaver,
                random: sum.random + chunk.random,
                prand_bit: sum.prand_bit + chunk.prand_bit,
                prand_int: sum.prand_int + chunk.prand_int,
            })
    }

    #[test]
    fn small_standing_top_up_stays_in_one_protocol_call() {
        let needed = PoolAvailability {
            beaver: 2_048,
            random: 128,
            prand_bit: 64,
            prand_int: 32,
        };
        assert_eq!(standing_top_up_chunks(needed, 1), vec![needed]);
    }

    #[test]
    fn aes_standing_reservoir_top_up_is_split_at_safe_ransha_workload() {
        let needed = PoolAvailability {
            beaver: 131_072,
            random: 1_152,
            prand_bit: 0,
            prand_int: 0,
        };
        let chunks = standing_top_up_chunks(needed, 1);
        assert_eq!(chunks.len(), 9);
        assert_eq!(sum_chunks(&chunks), needed);
        assert_eq!(chunks[0].beaver, 14_564);
        assert_eq!(chunks[0].random, 128);
        assert!(chunks.iter().all(|chunk| {
            standing_top_up_random_work(*chunk, 1) <= STANDING_TOP_UP_RANDOM_WORK_LIMIT
        }));
    }

    #[test]
    fn standing_top_up_chunking_preserves_all_material_counts() {
        let needed = PoolAvailability {
            beaver: 262_145,
            random: 200_003,
            prand_bit: 131_073,
            prand_int: 65_537,
        };
        let chunks = standing_top_up_chunks(needed, 2);
        assert_eq!(sum_chunks(&chunks), needed);
        assert!(chunks.iter().all(|chunk| {
            standing_top_up_random_work(*chunk, 2) <= STANDING_TOP_UP_RANDOM_WORK_LIMIT
                && u64::from(chunk.prand_bit) <= STANDING_TOP_UP_DERIVED_SHARE_LIMIT
                && u64::from(chunk.prand_int) <= STANDING_TOP_UP_DERIVED_SHARE_LIMIT
        }));
    }

    #[test]
    fn fixed_division_stress_top_up_splits_single_shot_prandbit_work() {
        let needed = PoolAvailability {
            beaver: 1_664,
            random: 1_792,
            prand_bit: 1_664,
            prand_int: 104,
        };
        let chunks = standing_top_up_chunks(needed, 1);
        assert_eq!(chunks.len(), 7);
        assert_eq!(sum_chunks(&chunks), needed);
        assert!(chunks.iter().all(|chunk| {
            chunk.prand_bit <= STANDING_TOP_UP_DERIVED_SHARE_LIMIT as u32
                && chunk.prand_int <= STANDING_TOP_UP_DERIVED_SHARE_LIMIT as u32
                && chunk.prand_bit % 2 == 0
                && chunk.beaver >= chunk.prand_bit
                && chunk.random >= chunk.prand_bit
        }));
    }

    #[test]
    fn party_agreement_rebuilds_empty_store_against_retained_peers() {
        let retained = retained_snapshot();
        let empty = StandingPreprocSnapshot::default();
        let plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 16,
                random: 16,
                prand_bit: 8,
                prand_int: 4,
            },
            &[retained, retained, empty, retained],
            [9; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Rebuild);
        assert_eq!(
            plan.needed,
            PoolAvailability {
                beaver: 16,
                random: 16,
                prand_bit: 8,
                prand_int: 4,
            }
        );
        assert_eq!(plan.generation_id, [9; 32]);
    }

    #[test]
    fn party_agreement_rebuilds_stale_cursor_before_top_up() {
        let retained = retained_snapshot();
        let mut stale = retained;
        stale.random.consumed += 1;
        let plan = agree_standing_preproc_plan(
            PoolAvailability::default(),
            &[retained, stale, retained],
            [7; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Rebuild);
        assert_eq!(plan.generation_id, [7; 32]);
    }

    #[test]
    fn same_shape_from_different_generations_rebuilds() {
        let first = retained_snapshot();
        let mut second = first;
        second.generation_id = Some([99; 32]);
        let plan =
            agree_standing_preproc_plan(first.availability(), &[first, second], [8; 32]).unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Rebuild);
        assert_eq!(plan.generation_id, [8; 32]);
    }

    #[test]
    fn retained_matching_generation_is_reused_without_changing_nonce() {
        let retained = retained_snapshot();
        let plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 13,
                random: 16,
                prand_bit: 7,
                prand_int: 4,
            },
            &[retained, retained],
            [88; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Reuse);
        assert_eq!(plan.needed, PoolAvailability::default());
        assert_eq!(plan.generation_id, [4; 32]);
    }

    #[test]
    fn matching_inventories_choose_one_identical_deficit_and_generation() {
        let retained = retained_snapshot();
        let plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 20,
                random: 20,
                prand_bit: 10,
                prand_int: 8,
            },
            &[retained, retained, retained],
            [5; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::TopUp);
        assert_eq!(
            plan.needed,
            PoolAvailability {
                beaver: 7,
                random: 4,
                prand_bit: 3,
                prand_int: 4,
            }
        );
        assert_eq!(plan.generation_id, [5; 32]);
        let peer_plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 20,
                random: 20,
                prand_bit: 10,
                prand_int: 8,
            },
            &[retained, retained, retained],
            [5; 32],
        )
        .unwrap();
        assert_eq!(peer_plan, plan, "all parties must install the same plan");
    }
}

/// Item-level evidence for "no preprocessing item ever serves two executions"
/// (design doc §9.1 stage V-0, §C.9 part 4, finding S12), driven through the
/// engine rather than through the store alone.
///
/// The store-level tests in `storage/preproc.rs` can only show that a STORED
/// item is not served twice. The open question V-0 names is upstream of that:
/// whether material one execution has already USED can reach the store and be
/// drawn later by a different execution. Answering it needs the real
/// `persist_preproc`, the real `try_load_preproc` and the real draw calls, so
/// these tests live beside them, where those private methods are visible.
///
/// Approximation, stated plainly: `run_preprocessing` is a protocol round that
/// needs a live network, so each test seeds the engine's in-memory pool with
/// distinguishable material instead of generating it. Everything after that
/// point — persistence, the store, the load, the draws — is production code,
/// called in production order. The seeding stands in for the protocol's
/// output, not for any part of the mechanism under test.
#[cfg(test)]
mod persisted_item_identity_tests {
    use super::*;
    use crate::net::mpc::honeybadger::{HoneyBadgerEngineConfig, HoneyBadgerPreprocessingConfig};
    use crate::net::mpc::session_config::{DeploymentMode, MpcSessionConfig};
    use crate::net::mpc_engine::MpcEngine;
    use crate::net::open_registry::OpenMessageRouter;
    use crate::storage::preproc::{LmdbPreprocStore, PreprocBlob, PreprocStore};
    use ark_bls12_381::{Fr, G1Projective};
    use std::sync::atomic::AtomicU64;
    use stoffelnet::transports::quic::QuicNetworkManager;

    type TestEngine = HoneyBadgerMpcEngine<Fr, G1Projective>;

    fn next_instance_id() -> u64 {
        static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(7_100_000);
        NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed)
    }

    /// One engine is one execution: a fresh instance id each time, with the
    /// node identity and topology that key the preprocessing store held fixed,
    /// because that is the configuration V-0 is about.
    fn engine(
        party_id: usize,
        n: usize,
        t: usize,
        mode: DeploymentMode,
        targets: (usize, usize),
    ) -> Arc<TestEngine> {
        let session = MpcSessionConfig::try_new(
            next_instance_id(),
            party_id,
            n,
            t,
            Arc::new(QuicNetworkManager::new()),
        )
        .expect("test topology should be valid")
        .with_open_message_router(Arc::new(OpenMessageRouter::new()));
        let config = HoneyBadgerEngineConfig::new(
            session,
            HoneyBadgerPreprocessingConfig::new(targets.0, targets.1),
        )
        .with_deployment_mode(mode);
        TestEngine::from_config(config).expect("engine construction should succeed")
    }

    fn labelled_triple(index: u64) -> ShamirBeaverTriple<Fr> {
        ShamirBeaverTriple::new(
            RobustShare::new(Fr::from(3 * index + 1), 1, 2),
            RobustShare::new(Fr::from(3 * index + 2), 1, 2),
            RobustShare::new(Fr::from(3 * index + 3), 1, 2),
        )
    }

    fn labelled_share(index: u64) -> RobustShare<Fr> {
        RobustShare::new(Fr::from(1_000 + index), 1, 2)
    }

    fn share_content(share: &RobustShare<Fr>) -> (Fr, usize, usize) {
        (share.share[0], share.id, share.degree)
    }

    type TripleContent = ((Fr, usize, usize), (Fr, usize, usize), (Fr, usize, usize));

    fn triple_content(triple: &ShamirBeaverTriple<Fr>) -> TripleContent {
        (
            share_content(&triple.a),
            share_content(&triple.b),
            share_content(&triple.mult),
        )
    }

    /// The item size the store recorded for one key, so a committed blob can
    /// be decoded back into items.
    async fn scope_item_size(store: &LmdbPreprocStore, key: &preproc::PreprocKey) -> u32 {
        store
            .meta(key)
            .await
            .expect("read the committed metadata")
            .expect("the key was committed")
            .item_size
    }

    async fn seed_pool(
        engine: &Arc<TestEngine>,
        triples: Vec<ShamirBeaverTriple<Fr>>,
        shares: Vec<RobustShare<Fr>>,
    ) {
        engine
            .clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(Some(triples), None, Some(shares), None, None, None);
    }

    /// `assert_ne!` over every pair, reporting the colliding secret rather than
    /// an index, so a failure names the material that served two executions.
    fn assert_no_shared_share(used: &[RobustShare<Fr>], received: &[RobustShare<Fr>]) {
        for (i, mine) in used.iter().enumerate() {
            for (j, theirs) in received.iter().enumerate() {
                assert_ne!(
                    share_content(mine),
                    share_content(theirs),
                    "execution 2's random share {j} is the SAME material execution 1 \
                     already used as its share {i}: {:?}",
                    share_content(mine)
                );
            }
        }
    }

    fn assert_no_shared_triple(
        used: &[ShamirBeaverTriple<Fr>],
        received: &[ShamirBeaverTriple<Fr>],
    ) {
        for (i, mine) in used.iter().enumerate() {
            for (j, theirs) in received.iter().enumerate() {
                assert_ne!(
                    triple_content(mine),
                    triple_content(theirs),
                    "execution 2's Beaver triple {j} is the SAME material execution 1 \
                     already used as its triple {i}: {:?}",
                    triple_content(mine)
                );
            }
        }
    }

    /// V-0's open question, answered by execution rather than by reading.
    ///
    /// Sequence, in production order and through production code:
    /// execution 1 commits with `persist_preproc`, then draws and uses
    /// material through the same calls the runner and the VM use
    /// (`reserve_random_shares` for client input masks,
    /// `reserve_beaver_triples` for multiplication); execution 2 — a different
    /// engine, so a different execution, on the same program hash, node
    /// identity and `(n, t)`, which is what `PreprocKeyScope` keys on — then
    /// loads with `try_load_preproc` and draws.
    ///
    /// The assertion is the property itself: no item execution 2 receives may
    /// be one execution 1 used. Content, not cursor ranges — a reused Beaver
    /// triple is the privacy break whatever index it was served from.
    ///
    /// This test FAILED when it was written, and that failure was the finding:
    /// `persist_preproc` wrote a `consumed: 0` copy of the pool to LMDB and
    /// returned the identical items to the live pool
    /// (`prep.add(restore_bt, …)`), so execution 1 went on to use exactly the
    /// material it had just published. It passes now because a commit is a
    /// division rather than a copy: this execution keeps the counts it
    /// declared and only the surplus above them is written, so nothing the
    /// store can hand execution 2 was ever available to execution 1.
    ///
    /// Its sizing was corrected when the defect was fixed, and nothing else
    /// was: with POOL = 6 the test asserted that two disjoint four-item sets
    /// both came out of six seeded items, which no sound fix could satisfy —
    /// `reserve_beaver_triples` never regenerates and there is no network
    /// here, so both sets are subsets of what is seeded. The old constant
    /// encoded the broken behaviour, in which both executions received all six
    /// items because they were copies. POOL is now 8 = 2 × USED and the engine
    /// declares the demand the test actually draws. Every assertion below is
    /// unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn material_one_execution_used_is_never_handed_to_a_later_execution() {
        // Two executions of USED items each, which is what this test draws, so
        // disjointness is satisfiable at all.
        const POOL: u64 = 2 * USED as u64;
        const USED: usize = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x7e; 32];
        let (party_id, n, t) = (0usize, 5usize, 1usize);

        // ---- execution 1 ----
        // The engine declares the demand this execution goes on to draw. That
        // is what a one-shot commit keeps back for it; the surplus above it is
        // what reaches the store.
        let first = engine(party_id, n, t, DeploymentMode::OneShot, (USED, USED));
        assert!(
            !first.is_standing(),
            "this is the one-shot --preproc-store path, which is what persists"
        );
        first
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let generated_triples: Vec<_> = (0..POOL).map(labelled_triple).collect();
        let generated_shares: Vec<_> = (0..POOL).map(labelled_share).collect();
        seed_pool(&first, generated_triples.clone(), generated_shares.clone()).await;

        // Production: what a finished preprocessing round persists.
        first.persist_preproc().await.expect("persist");

        // Production: what the execution then draws and uses.
        let used_shares = first
            .reserve_random_shares(USED)
            .await
            .expect("execution 1 draws its masks");
        let used_triples = first
            .reserve_beaver_triples(USED)
            .await
            .expect("execution 1 draws its triples");
        assert_eq!(used_shares.len(), USED);
        assert_eq!(used_triples.len(), USED);

        // ---- execution 2: same program, same node, a different execution ----
        let second = engine(party_id, n, t, DeploymentMode::OneShot, (USED, USED));
        second
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let inherited = second
            .try_load_preproc()
            .await
            .expect("execution 2 consults the store");
        assert!(
            inherited,
            "execution 2 found nothing persisted, so this test exercised nothing"
        );

        let received_shares = second
            .reserve_random_shares(USED)
            .await
            .expect("execution 2 draws its masks");
        let received_triples = second
            .reserve_beaver_triples(USED)
            .await
            .expect("execution 2 draws its triples");

        // Non-vacuity: execution 2 received real material from the store, so
        // the comparison below is between two non-empty sets of secrets.
        assert_eq!(received_shares.len(), USED);
        assert_eq!(received_triples.len(), USED);
        let generated_share_contents: Vec<_> = generated_shares.iter().map(share_content).collect();
        for share in &received_shares {
            assert!(
                generated_share_contents.contains(&share_content(share)),
                "execution 2 received a share that was never generated: {:?}",
                share_content(share)
            );
        }

        assert_no_shared_share(&used_shares, &received_shares);
        assert_no_shared_triple(&used_triples, &received_triples);
    }

    /// The control for the test above: the same engines, the same store, the
    /// same assertions, differing only in WHICH material execution 1 used.
    ///
    /// Here execution 1 persists one pool, is then handed a second, disjoint
    /// pool, and uses only that. Execution 2 inherits the persisted pool, which
    /// execution 1 never touched, so the property holds and the test passes.
    ///
    /// Its job is to show that the reproduction above is not a tautology: the
    /// assertions pass whenever the inherited material really is untouched, so
    /// what they detect is specifically that execution 1 used what it
    /// published — not merely that two executions drew from one store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inherited_material_an_execution_never_touched_is_not_a_reuse() {
        const POOL: u64 = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x7f; 32];
        let (party_id, n, t) = (0usize, 5usize, 1usize);

        // Targets (0, 0): this execution declares it needs nothing, so the
        // commit keeps nothing and the whole of pool A reaches the store.
        let first = engine(party_id, n, t, DeploymentMode::OneShot, (0, 0));
        first
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        // Pool A, indices 0..POOL: persisted, and never drawn by execution 1.
        seed_pool(
            &first,
            (0..POOL).map(labelled_triple).collect(),
            (0..POOL).map(labelled_share).collect(),
        )
        .await;
        first.persist_preproc().await.expect("persist");

        // What this execution goes on to use is therefore pool B alone, and it
        // is production code that makes that true. Before the commit became a
        // division this had to be arranged by hand here, by undoing
        // `persist_preproc`'s re-add — the one step in this test that was not
        // production code. Now the pool is empty because the commit kept
        // nothing, which is worth asserting rather than assuming.
        {
            let node = first.clone_node().await;
            let held = node.preprocessing_material.lock().await.length();
            assert_eq!(
                (held.beaver_triples, held.random_shr),
                (0, 0),
                "an execution that declared it needs nothing must be left \
                 holding nothing: everything it published is in the store"
            );
        }

        // Pool B, indices 100..100+POOL: disjoint from pool A by construction.
        let b_triples: Vec<_> = (100..100 + POOL).map(labelled_triple).collect();
        let b_shares: Vec<_> = (100..100 + POOL).map(labelled_share).collect();
        seed_pool(&first, b_triples.clone(), b_shares.clone()).await;

        let used_shares = first
            .reserve_random_shares(POOL as usize)
            .await
            .expect("execution 1 draws from pool B");
        let used_triples = first
            .reserve_beaver_triples(POOL as usize)
            .await
            .expect("execution 1 draws from pool B");
        assert_eq!(
            used_shares.iter().map(share_content).collect::<Vec<_>>(),
            b_shares.iter().map(share_content).collect::<Vec<_>>(),
            "execution 1 must have used pool B, or this control proves nothing"
        );

        let second = engine(party_id, n, t, DeploymentMode::OneShot, (1, 1));
        second
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");
        assert!(
            second
                .try_load_preproc()
                .await
                .expect("execution 2 consults the store"),
            "execution 2 must inherit pool A for this control to be meaningful"
        );

        let received_shares = second
            .reserve_random_shares(POOL as usize)
            .await
            .expect("execution 2 draws its masks");
        let received_triples = second
            .reserve_beaver_triples(POOL as usize)
            .await
            .expect("execution 2 draws its triples");
        assert_eq!(received_shares.len(), POOL as usize);
        assert_eq!(received_triples.len(), POOL as usize);

        assert_no_shared_share(&used_shares, &received_shares);
        assert_no_shared_triple(&used_triples, &received_triples);
    }

    /// The property's other variant: two executions of one program on one
    /// node, concurrent, with no restart between them.
    ///
    /// [`PreprocKeyScope`] deliberately carries no execution component (design
    /// doc §9.1 V-0 item 3), so two concurrent one-shot executions of one
    /// program on one node address exactly one key. Before the fix that was
    /// sufficient for reuse on its own, and it was worse than the sequential
    /// case: each execution's commit was an unconditional two-key put that
    /// reset `consumed` to 0 and read no existing metadata, so the two
    /// clobbered each other and the survivor's already-used material was then
    /// drawn by whoever loaded next.
    ///
    /// Two things make it safe now, and this asserts both. Commits accumulate
    /// — the only write primitive is `append_items`, which read-modify-writes
    /// inside one transaction — so the store ends up holding both surpluses
    /// rather than one of them. And neither surplus contains anything its own
    /// execution kept, so the third execution, which receives all of it,
    /// receives nothing either of the first two used.
    ///
    /// Two store handles on one directory stand in for two processes, which is
    /// the deployment this variant describes: one node, one `--preproc-store`
    /// directory, two one-shot runs in flight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_executions_commit_surpluses_that_overlap_neither_of_them() {
        const PER_EXECUTION: usize = 2;

        let dir = tempfile::tempdir().expect("temp store dir");
        let program_hash = [0x7c; 32];
        let (party_id, n, t) = (0usize, 5usize, 1usize);

        // Disjoint pools, so a mix-up names which execution leaked.
        let pools = [0u64, 100];
        let mut engines = Vec::new();
        for base in pools {
            let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
            let engine = engine(
                party_id,
                n,
                t,
                DeploymentMode::OneShot,
                (PER_EXECUTION, PER_EXECUTION),
            );
            engine
                .preproc_persistence_ops()
                .expect("HB supports preprocessing persistence")
                .set_preproc_store(store, program_hash)
                .expect("attach the store");
            let triples: Vec<_> = (base..base + 2 * PER_EXECUTION as u64)
                .map(labelled_triple)
                .collect();
            let shares: Vec<_> = (base..base + 2 * PER_EXECUTION as u64)
                .map(labelled_share)
                .collect();
            seed_pool(&engine, triples, shares).await;
            engines.push(engine);
        }

        // Both commits in flight at once, against one store directory.
        let (first, second) =
            tokio::join!(engines[0].persist_preproc(), engines[1].persist_preproc());
        first.expect("execution 1 commits");
        second.expect("execution 2 commits");

        // Each execution then uses what its own commit kept back.
        let mut used_shares = Vec::new();
        let mut used_triples = Vec::new();
        for engine in &engines {
            used_shares.extend(
                engine
                    .reserve_random_shares(PER_EXECUTION)
                    .await
                    .expect("draw this execution's masks"),
            );
            used_triples.extend(
                engine
                    .reserve_beaver_triples(PER_EXECUTION)
                    .await
                    .expect("draw this execution's triples"),
            );
        }
        assert_eq!(used_shares.len(), 2 * PER_EXECUTION);
        assert_eq!(used_triples.len(), 2 * PER_EXECUTION);

        // Accumulation, not clobber: the store holds BOTH surpluses. A
        // clobbering write would leave one execution's surplus only.
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("reopen store"));
        let third = engine(
            party_id,
            n,
            t,
            DeploymentMode::OneShot,
            (PER_EXECUTION, PER_EXECUTION),
        );
        third
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store, program_hash)
            .expect("attach the store");
        let (_store, _hash, scope) = third
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        let surplus = PoolAvailability {
            beaver: PER_EXECUTION as u32 * 2,
            random: PER_EXECUTION as u32 * 2,
            prand_bit: 0,
            prand_int: 0,
        };
        assert_eq!(
            _store.scope_availability(&scope).await.unwrap(),
            surplus,
            "both concurrent commits must survive: one clobbering the other \
             would leave half of this"
        );

        assert!(
            third
                .try_load_preproc()
                .await
                .expect("execution 3 consults the store"),
            "execution 3 found nothing persisted, so this test exercised nothing"
        );
        let received_shares = third
            .reserve_random_shares(2 * PER_EXECUTION)
            .await
            .expect("execution 3 draws its masks");
        let received_triples = third
            .reserve_beaver_triples(2 * PER_EXECUTION)
            .await
            .expect("execution 3 draws its triples");
        assert_eq!(received_shares.len(), 2 * PER_EXECUTION);
        assert_eq!(received_triples.len(), 2 * PER_EXECUTION);

        assert_no_shared_share(&used_shares, &received_shares);
        assert_no_shared_triple(&used_triples, &received_triples);
    }

    /// A standing execution cannot persist, and cannot be made to by the
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
        let engine = engine(0, 5, 1, DeploymentMode::Standing, (4, 4));
        assert!(engine.is_standing());
        engine
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), [0x3d; 32])
            .expect("attach the store");

        // Seed the pool, so a commit that was wrongly allowed would have
        // material to write and the emptiness check below could not pass by
        // accident.
        let triples: Vec<_> = (0..4).map(labelled_triple).collect();
        let shares: Vec<_> = (0..4).map(labelled_share).collect();
        seed_pool(&engine, triples, shares).await;

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

    /// Both halves of a one-shot commit's division, asserted together.
    ///
    /// The privacy argument rests on a conjunction, not on either half alone:
    /// the store must hold the surplus AND the live pool must hold the
    /// retained items, with no item in both. Checking only the store would
    /// pass for a commit that wrote the surplus and ALSO kept it — which is
    /// exactly the defect this replaced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_one_shot_commit_writes_only_what_this_execution_does_not_keep() {
        const POOL: u64 = 6;
        const TARGET: u32 = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x7a; 32];
        let engine = engine(
            0,
            5,
            1,
            DeploymentMode::OneShot,
            (TARGET as usize, TARGET as usize),
        );
        engine
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let generated_triples: Vec<_> = (0..POOL).map(labelled_triple).collect();
        let generated_shares: Vec<_> = (0..POOL).map(labelled_share).collect();
        seed_pool(&engine, generated_triples.clone(), generated_shares.clone()).await;

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
                    beaver: TARGET,
                    random: TARGET,
                    prand_bit: 0,
                    prand_int: 0,
                }),
            )
            .await
            .expect("commit the surplus");

        let surplus = POOL as u32 - TARGET;
        assert_eq!(
            committed,
            PoolAvailability {
                beaver: surplus,
                random: surplus,
                prand_bit: 0,
                prand_int: 0,
            },
            "a commit writes the pool minus the declared targets"
        );
        assert_eq!(
            store.scope_availability(&scope).await.unwrap(),
            committed,
            "what the commit reports is what the store holds"
        );

        // The retained half: still in the pool, and it is the FRONT of the
        // generated material, because the draw order is the pool order.
        let retained_triples = engine
            .reserve_beaver_triples(TARGET as usize)
            .await
            .expect("the retained triples are this execution's to draw");
        let retained_shares = engine
            .reserve_random_shares(TARGET as usize)
            .await
            .expect("the retained shares are this execution's to draw");
        assert_eq!(
            retained_triples
                .iter()
                .map(triple_content)
                .collect::<Vec<_>>(),
            generated_triples[..TARGET as usize]
                .iter()
                .map(triple_content)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            retained_shares
                .iter()
                .map(share_content)
                .collect::<Vec<_>>(),
            generated_shares[..TARGET as usize]
                .iter()
                .map(share_content)
                .collect::<Vec<_>>()
        );

        // The committed half: in the store, disjoint from the half above.
        let stored_triples = preproc::deserialize_beaver_triples::<Fr>(
            &store
                .load(&scope.beaver_triple())
                .await
                .unwrap()
                .expect("triples were committed")
                .data,
            scope_item_size(&store, &scope.beaver_triple()).await,
            0,
        )
        .expect("decode the committed triples");
        let stored_shares = preproc::deserialize_robust_shares::<Fr>(
            &store
                .load(&scope.random_share())
                .await
                .unwrap()
                .expect("shares were committed")
                .data,
            scope_item_size(&store, &scope.random_share()).await,
            0,
        )
        .expect("decode the committed shares");
        assert_eq!(
            stored_triples
                .iter()
                .map(triple_content)
                .collect::<Vec<_>>(),
            generated_triples[TARGET as usize..]
                .iter()
                .map(triple_content)
                .collect::<Vec<_>>(),
            "the store must hold the surplus, not the retained front"
        );
        assert_no_shared_triple(&retained_triples, &stored_triples);
        assert_no_shared_share(&retained_shares, &stored_shares);
    }

    /// The draw side of the same division: a stored bundle is a head start,
    /// not a substitute for the preprocessing protocol.
    ///
    /// Because a commit writes only the surplus an execution did not keep,
    /// what the store holds is normally *less* than one execution's worth —
    /// live, a finished five-party run banked two random shares and no
    /// triples. `preprocess` treated any non-empty load as full provisioning:
    /// it set `ready` and returned without running the protocol, so the
    /// execution went on to fail at its first multiplication, after its
    /// clients had already published masked inputs. It now compares the loaded
    /// pool against the declared targets and falls through to generation when
    /// the load does not cover them, which costs only the shortfall —
    /// `run_preprocessing` generates the pool's deficit against these same
    /// targets, not the whole of them.
    ///
    /// What is asserted is that decision, not the protocol round: there is no
    /// network here, so generation cannot finish. A load that covers the
    /// targets reports success immediately and without a network, which is
    /// `tests::preprocess_reserves_persistent_random_shares_when_loaded`; a
    /// load that does not must not, however much of it succeeded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_load_that_does_not_cover_the_targets_is_not_full_provisioning() {
        const SLACK: u32 = 2;
        const TARGET: usize = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x7b; 32];
        let (party_id, n, t) = (0usize, 5usize, 1usize);

        // What a finished one-shot run leaves in the store: its banding slack.
        // Targets (0, 0) keep nothing back, so every seeded item is surplus.
        let donor = engine(party_id, n, t, DeploymentMode::OneShot, (0, 0));
        donor
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");
        seed_pool(
            &donor,
            Vec::new(),
            (0..u64::from(SLACK)).map(labelled_share).collect(),
        )
        .await;
        donor.persist_preproc().await.expect("commit the slack");

        // The next execution of the same program needs triples as well, and
        // more masks than the slack can serve.
        let second = engine(party_id, n, t, DeploymentMode::OneShot, (TARGET, TARGET));
        second
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
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
        let outcome = tokio::time::timeout(Duration::from_secs(5), second.preprocess()).await;
        if let Ok(reported) = &outcome {
            let error = reported.as_ref().err().unwrap_or_else(|| {
                panic!(
                    "preprocess() reported this execution provisioned by a bundle of \
                     {SLACK} random shares and no triples against targets of {TARGET} \
                     each: it would fail at its first multiplication, with its \
                     clients' masked inputs already published"
                )
            });
            assert!(
                error.contains("Preprocessing failed"),
                "a short load must put this execution into the preprocessing \
                 protocol, not into a refusal: {error}"
            );
        }
        assert!(
            !second.ready.load(Ordering::SeqCst),
            "an execution that could not be provisioned must not be marked ready"
        );

        // The partial bundle was still drawn: the gate is about coverage, not
        // about refusing to use what the store has.
        assert_eq!(
            store
                .scope_availability(&scope)
                .await
                .expect("read the store"),
            PoolAvailability::default(),
            "the slack must still have been taken: generating the shortfall \
             means generating what the load did not cover, not all of it"
        );
    }

    /// A round that produced less than this execution declared writes nothing.
    ///
    /// `SurplusAbove` clamps the retained amount to what the pool actually
    /// holds. Without that clamp the commit would try to split the drained
    /// items past their end and panic; with it, a short round simply leaves
    /// every item with the execution that generated it and the store empty,
    /// which is the direction that has to be safe — a deficit must never be
    /// resolved by writing material this execution still needs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_round_that_produced_less_than_declared_commits_nothing() {
        const PRODUCED: u64 = 2;
        const TARGET: u32 = 5;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let engine = engine(
            0,
            5,
            1,
            DeploymentMode::OneShot,
            (TARGET as usize, TARGET as usize),
        );
        engine
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), [0x7d; 32])
            .expect("attach the store");

        let generated_shares: Vec<_> = (0..PRODUCED).map(labelled_share).collect();
        seed_pool(
            &engine,
            (0..PRODUCED).map(labelled_triple).collect(),
            generated_shares.clone(),
        )
        .await;

        engine.persist_preproc().await.expect("commit the surplus");

        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        assert_eq!(
            store.scope_availability(&scope).await.unwrap(),
            PoolAvailability::default(),
            "a short round has no surplus, so the store must stay empty"
        );
        assert_eq!(
            engine
                .reserve_random_shares(PRODUCED as usize)
                .await
                .expect("the execution still holds everything it generated")
                .iter()
                .map(share_content)
                .collect::<Vec<_>>(),
            generated_shares
                .iter()
                .map(share_content)
                .collect::<Vec<_>>()
        );
    }

    /// The standing half of the same division, and the only coverage of the
    /// guard that keeps generated material from existing in two places at
    /// once.
    ///
    /// `top_up_exact` commits exactly the party-agreed chunk and then clears
    /// the live pool, discarding the protocol's over-production: the agreement
    /// is exact, so extras must reach neither the reservoir (where unequal
    /// per-party snapshots force a Rebuild) nor the next chunk. That clear
    /// used to be unreachable from a unit test, because `top_up_exact` runs an
    /// interactive round first; the commit is now a separate function, so both
    /// its halves can be asserted with no network.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_commit_keeps_nothing_and_banks_no_overproduction() {
        const PRODUCED: u64 = 5;
        const AGREED: u32 = 3;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x7b; 32];
        let engine = engine(0, 5, 1, DeploymentMode::OneShot, (1, 1));
        engine
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        let generated_triples: Vec<_> = (0..PRODUCED).map(labelled_triple).collect();
        let generated_shares: Vec<_> = (0..PRODUCED).map(labelled_share).collect();
        seed_pool(&engine, generated_triples, generated_shares).await;

        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        let agreed = PoolAvailability {
            beaver: AGREED,
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
            "the reservoir holds the agreed chunk and not the {} items of \
             over-production",
            PRODUCED - u64::from(AGREED)
        );

        let held = engine
            .clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .length();
        assert_eq!(
            (
                held.beaver_triples,
                held.random_shr,
                held.prandbit,
                held.prandint
            ),
            (0, 0, 0, 0),
            "a standing commit must leave this engine holding nothing: every \
             item it wrote belongs to a future execution's bundle, and the \
             over-production belongs to nobody"
        );
    }

    /// A standing top-up destroys what it inherited before it generates
    /// anything, so a round that never finishes cannot bank it.
    ///
    /// `AgreedChunk` commits everything it drains. If a top-up began with
    /// material already in the pool — and material in a live engine's pool is
    /// material it may have served — that material would be written to the
    /// reservoir for a later execution to draw. Nothing inside the top-up used
    /// to prevent it; three facts outside it did, and inherited safety is the
    /// kind that breaks when one of those three moves.
    ///
    /// This drives the real `top_up_exact`, and the hazard it pins is live
    /// rather than theoretical. Measured by deleting the clear: the top-up then
    /// returns `Ok(())` *immediately*, because `run_preprocessing` finds the
    /// pool already holding the counts it was asked for and does nothing, and
    /// the commit that follows drains the inherited items from the front of
    /// that pool and banks them in the reservoir — the store assertion below
    /// fails with the inherited counts present. With the clear, the round has
    /// an empty pool and no peers, so it never returns and the test abandons it
    /// at the timeout. Either way the two assertions are the subject: nothing
    /// this engine was holding is in the pool or the store afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_top_up_destroys_the_pool_it_inherited_before_generating() {
        const INHERITED: u64 = 4;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x9c; 32];
        let engine = engine(0, 5, 1, DeploymentMode::OneShot, (1, 1));
        engine
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        // Stand-in for a pool this engine was still holding: labelled, so a
        // leak into the store would be reported as the colliding secrets.
        let inherited_triples: Vec<_> = (0..INHERITED).map(labelled_triple).collect();
        let inherited_shares: Vec<_> = (0..INHERITED).map(labelled_share).collect();
        seed_pool(&engine, inherited_triples, inherited_shares).await;

        let needed = PoolAvailability {
            beaver: 2,
            random: 2,
            prand_bit: 0,
            prand_int: 0,
        };
        // Abandoned at the timeout once the pool is empty, because an
        // interactive round with no peers never returns. What the engine and
        // the store hold afterwards is the subject, not how this resolves.
        let _ = tokio::time::timeout(Duration::from_millis(750), engine.top_up_exact(needed)).await;

        let held = engine
            .clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .length();
        assert_eq!(
            (
                held.beaver_triples,
                held.random_shr,
                held.prandbit,
                held.prandint
            ),
            (0, 0, 0, 0),
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
            "no material this engine was holding before the top-up may reach \
             the reservoir, where a later execution would draw it"
        );
    }

    /// The consequence of that clear, at item-content level in the store.
    ///
    /// The test above pins the ORDER: the pool is emptied before the round
    /// runs. This one pins what the order buys, through the two production
    /// functions a top-up is made of, with the interactive round stood in for
    /// because it needs a network. An engine holding material, a clear, a round
    /// that produces different material, a commit — and the assertion is that
    /// every item the reservoir now holds came from the round, and that no item
    /// the engine was holding beforehand is in it. Without the clear the commit
    /// drains the inherited items first, because `AgreedChunk` takes from the
    /// front of the pool, and banks them for a later execution to draw.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_top_up_banks_the_round_it_ran_and_never_what_it_inherited() {
        const INHERITED: u64 = 4;
        const GENERATED: u64 = 4;
        const AGREED: u32 = 3;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x9d; 32];
        let engine = engine(0, 5, 1, DeploymentMode::OneShot, (1, 1));
        engine
            .preproc_persistence_ops()
            .expect("HB supports preprocessing persistence")
            .set_preproc_store(store.clone(), program_hash)
            .expect("attach the store");

        // What this engine was holding when the top-up began.
        let inherited_triples: Vec<_> = (0..INHERITED).map(labelled_triple).collect();
        let inherited_shares: Vec<_> = (0..INHERITED).map(labelled_share).collect();
        seed_pool(&engine, inherited_triples.clone(), inherited_shares.clone()).await;

        // Step 1 of the real `top_up_exact`.
        drop(engine.lease_node_with_emptied_pool_for_top_up().await);

        // Step 2 stands in for `run_preprocessing`: labels disjoint from the
        // inherited ones, so the store's contents name their origin.
        let generated_triples: Vec<_> = (100..100 + GENERATED).map(labelled_triple).collect();
        let generated_shares: Vec<_> = (100..100 + GENERATED).map(labelled_share).collect();
        seed_pool(&engine, generated_triples.clone(), generated_shares.clone()).await;

        // Step 3, unchanged production code.
        let (_store, _hash, scope) = engine
            .preproc_home()
            .await
            .expect("the store is attached")
            .expect("the store is attached");
        let agreed = PoolAvailability {
            beaver: AGREED,
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

        let banked_triples = preproc::deserialize_beaver_triples::<Fr>(
            &store
                .load(&scope.beaver_triple())
                .await
                .unwrap()
                .expect("triples were banked")
                .data,
            scope_item_size(&store, &scope.beaver_triple()).await,
            0,
        )
        .expect("decode the banked triples");
        let banked_shares = preproc::deserialize_robust_shares::<Fr>(
            &store
                .load(&scope.random_share())
                .await
                .unwrap()
                .expect("shares were banked")
                .data,
            scope_item_size(&store, &scope.random_share()).await,
            0,
        )
        .expect("decode the banked shares");

        assert_no_shared_triple(&inherited_triples, &banked_triples);
        assert_no_shared_share(&inherited_shares, &banked_shares);
        assert_eq!(
            banked_triples
                .iter()
                .map(triple_content)
                .collect::<Vec<_>>(),
            generated_triples[..AGREED as usize]
                .iter()
                .map(triple_content)
                .collect::<Vec<_>>(),
            "the reservoir must hold the front of the round's own output"
        );
        assert_eq!(
            banked_shares.iter().map(share_content).collect::<Vec<_>>(),
            generated_shares[..AGREED as usize]
                .iter()
                .map(share_content)
                .collect::<Vec<_>>(),
            "the reservoir must hold the front of the round's own output"
        );
    }

    /// The standing path's item-level property, through the production draw.
    ///
    /// A standing node keeps one reservoir per (program, node) and every
    /// execution allocates out of it with `take_bundle_from_reservoir` followed
    /// by `activate_preallocated_standing`. This drives both, twice, against
    /// one reservoir, and compares the secrets the two executions go on to use
    /// rather than the cursor ranges they were given.
    ///
    /// Covers at engine level what no test covered before: the standing draw is
    /// the only route by which a stored item reaches a running execution, so it
    /// is the draw whose disjointness carries the property.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_reservoir_never_hands_two_executions_the_same_item() {
        const PER_EXECUTION: u32 = 3;
        const RESERVOIR: u64 = 6;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = Arc::new(LmdbPreprocStore::open(dir.path()).expect("open store"));
        let program_hash = [0x80; 32];
        let (party_id, n, t) = (0usize, 5usize, 1usize);
        let scope = PreprocKeyScope::new(
            program_hash,
            <Fr as SupportedMpcField>::field_kind(),
            n,
            t,
            crate::net::mpc_engine::DurableIdentityDigest::from_legacy_party_id(party_id),
        );

        // The reservoir as a standing top-up leaves it: material in the store
        // and in nobody's live pool.
        let triples: Vec<_> = (0..RESERVOIR).map(labelled_triple).collect();
        let shares: Vec<_> = (0..RESERVOIR).map(labelled_share).collect();
        let (triple_data, triple_item_size) =
            preproc::serialize_beaver_triples::<Fr>(&triples).unwrap();
        store
            .seed_items(
                &scope.beaver_triple(),
                &PreprocBlob::try_new(triple_data, triple_item_size, triples.len()).unwrap(),
            )
            .await
            .expect("seed the reservoir's triples");
        let (share_data, share_item_size) =
            preproc::serialize_robust_shares::<Fr>(&shares).unwrap();
        store
            .seed_items(
                &scope.random_share(),
                &PreprocBlob::try_new(share_data, share_item_size, shares.len()).unwrap(),
            )
            .await
            .expect("seed the reservoir's random shares");

        let request = PoolAvailability {
            beaver: PER_EXECUTION,
            random: PER_EXECUTION,
            prand_bit: 0,
            prand_int: 0,
        };

        async fn allocate_and_draw(
            engine: &Arc<TestEngine>,
            store: &Arc<LmdbPreprocStore>,
            scope: &PreprocKeyScope,
            request: PoolAvailability,
        ) -> (Vec<RobustShare<Fr>>, Vec<ShamirBeaverTriple<Fr>>) {
            let bundle = store
                .take_bundle_from_reservoir(scope, request)
                .await
                .expect("the execution allocates its bundle");
            engine
                .activate_preallocated_standing(bundle)
                .await
                .expect("the execution installs its bundle");
            let shares = engine
                .reserve_random_shares(request.random as usize)
                .await
                .expect("the execution draws its masks");
            let triples = engine
                .reserve_beaver_triples(request.beaver as usize)
                .await
                .expect("the execution draws its triples");
            (shares, triples)
        }

        let targets = (PER_EXECUTION as usize, PER_EXECUTION as usize);
        let first = engine(party_id, n, t, DeploymentMode::Standing, targets);
        let second = engine(party_id, n, t, DeploymentMode::Standing, targets);
        assert!(first.is_standing() && second.is_standing());

        let (first_shares, first_triples) =
            allocate_and_draw(&first, &store, &scope, request).await;
        let (second_shares, second_triples) =
            allocate_and_draw(&second, &store, &scope, request).await;

        // Non-vacuity: both executions drew the full width, from the material
        // that was actually in the reservoir.
        assert_eq!(first_shares.len() as u32, PER_EXECUTION);
        assert_eq!(second_shares.len() as u32, PER_EXECUTION);
        assert_eq!(first_triples.len() as u32, PER_EXECUTION);
        assert_eq!(second_triples.len() as u32, PER_EXECUTION);
        let seeded: Vec<_> = shares.iter().map(share_content).collect();
        for share in first_shares.iter().chain(second_shares.iter()) {
            assert!(
                seeded.contains(&share_content(share)),
                "an execution drew a share that was never in the reservoir: {:?}",
                share_content(share)
            );
        }

        assert_no_shared_share(&first_shares, &second_shares);
        assert_no_shared_triple(&first_triples, &second_triples);

        // The reservoir held exactly two executions' worth, and both were
        // served by physical removal, so nothing is left to serve a third.
        assert_eq!(
            store.scope_availability(&scope).await.unwrap(),
            PoolAvailability::default(),
            "a standing draw must remove what it serves"
        );
    }
}
