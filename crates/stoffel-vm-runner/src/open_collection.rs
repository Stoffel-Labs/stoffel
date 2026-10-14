//! Native open-window data-plane adapter. This does not start an MPC engine or
//! execute a program: collection must finish before the selected VM is hydrated.
//! The caller supplies destructively allocated, execution-local one-time masks.
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, kem::Kem,
    single_shot_seal, Deserializable, OpModeS, Serializable};
use jsonrpsee::async_client::Client;
use p256::ecdsa::VerifyingKey;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, path::PathBuf, time::Duration};
use stoffel_mpc_coordinator_off_chain::{node_rpc::NodeRPCServer, AssignedMaskReservation,
    AssignedMaskedInputEvent, CoordinatorRPCBaseClient, FrozenCollection, OpenCollectionPolicy};
use stoffel_mpc_coordinator_shared::{ExecutionId, ShareBound};

use stoffel_vm_types::compiled_binary::{ClientIoManifest, CompiledBinary, MpcBackend, MpcCurve, PreprocessingDemand};

pub type OpenResult<T> = Result<T, String>;

fn artifact_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Local, trusted program approval configuration; never obtained from a browser.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenProgramFile {
    pub path: PathBuf,
    /// The manifest output slot bound to the policy owner, not an identity roster slot.
    pub owner_output_slot: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCollectionConfig {
    pub policy: OpenCollectionPolicy,
    pub programs: BTreeMap<u32, OpenProgramFile>,
}

pub struct ApprovedOpenProgram {
    bytes: Vec<u8>,
    pub manifest: ClientIoManifest,
    pub owner_output_slot: u64,
}
impl ApprovedOpenProgram {
    pub fn bytes(&self) -> &[u8] { &self.bytes }
}

/// Artifacts are read and checked *before* policy registration, then kept in
/// memory: replacing a file during collection cannot change the selected VM.
pub struct ApprovedOpenCollection {
    policy: OpenCollectionPolicy,
    programs: BTreeMap<u32, ApprovedOpenProgram>,
    demand: PreprocessingDemand,
}
impl ApprovedOpenCollection {
    pub fn load(config: OpenCollectionConfig, n: u64, t: u64) -> OpenResult<Self> {
        validate_policy(&config.policy, n, t)?;
        if config.programs.keys().ne(config.policy.approved_programs.keys()) {
            return Err("artifact counts differ from approved policy counts".into());
        }
        let mut programs = BTreeMap::new();
        let mut demand = PreprocessingDemand::default();
        for (count, file) in config.programs {
            let bytes = std::fs::read(file.path).map_err(|e| format!("read approved artifact: {e}"))?;
            // Opening-policy programSha256 commits to the artifact bytes, not
            // the VM transport's separately domain-separated BLAKE3 program ID.
            if artifact_sha256(&bytes) != config.policy.approved_programs[&count] {
                return Err("artifact hash does not match preapproved program".into());
            }
            let binary = CompiledBinary::deserialize(&mut bytes.as_slice())
                .map_err(|e| format!("invalid approved binary: {e:?}"))?;
            validate_manifest(&binary.client_io_manifest, count, config.policy.inputs_per_client, file.owner_output_slot)?;
            // Never admit an artifact that explicitly opens aggregate shares or
            // bypasses captured owner-only MpcOutput delivery.
            for function in &binary.functions {
                for instruction in &function.instructions {
                    if let stoffel_vm_types::compiled_binary::CompiledInstruction::CALL(name) = instruction {
                        if name.starts_with("Share.open") || name.starts_with("Share.batch_open")
                            || name == "Share.interpolate_local" || name == "Share.send_to_client" {
                            return Err("approved program contains a plaintext opening or direct output route".into());
                        }
                    }
                }
            }
            let d = binary.client_io_manifest.preprocessing_demand;
            demand.triples = demand.triples.max(d.triples);
            demand.randoms = demand.randoms.max(d.randoms);
            demand.prandbits = demand.prandbits.max(d.prandbits);
            demand.prandints = demand.prandints.max(d.prandints);
            demand.dynamic |= d.dynamic;
            programs.insert(count, ApprovedOpenProgram { bytes,
                manifest: binary.client_io_manifest, owner_output_slot: file.owner_output_slot });
        }
        Ok(Self { policy: config.policy, programs, demand })
    }
    pub fn policy(&self) -> &OpenCollectionPolicy { &self.policy }
    /// Program demand only; the caller must additionally allocate `mask_count()`
    /// randoms with its existing preprocessing planner (do not double-count them).
    pub fn preprocessing_demand(&self) -> PreprocessingDemand { self.demand }
    pub fn mask_count(&self) -> usize {
        self.policy.reservation_mask_count().expect("validated reservation budget") as usize
    }
}

fn valid_identity(id: &[u8]) -> bool {
    VerifyingKey::from_sec1_bytes(id).is_ok_and(|key| key.to_encoded_point(false).as_bytes() == id)
}
pub fn validate_policy(policy: &OpenCollectionPolicy, n: u64, t: u64) -> OpenResult<()> {
    if n != 5 || t != 1 { return Err("open runner requires n=5, t=1".into()); }
    let total = policy.reservation_mask_count();
    if policy.execution_id.is_zero() || !valid_identity(&policy.owner)
        || policy.min_clients < 2 || policy.max_clients < policy.min_clients
        || policy.max_clients > 4096 || policy.inputs_per_client == 0
        || total.is_none_or(|v| v > 1_000_000)
        || policy.min_output_shares != n
        || policy.approved_programs.len() != (policy.max_clients-policy.min_clients+1) as usize
        || (policy.min_clients..=policy.max_clients).any(|c|
            policy.approved_programs.get(&c).is_none_or(|h| *h == [0;32])) {
        return Err("invalid open policy identity, bounds, programs or output quorum".into());
    }
    Ok(())
}

pub fn validate_manifest(manifest: &ClientIoManifest, count: u32, width: u64, owner_slot: u64) -> OpenResult<()> {
    // Restrict this initial adapter to exact static count-specific BLS/HB layouts.
    // Dynamic templates are not proof of a count-specific input contract.
    if manifest.clients.len() != count as usize + 1 || owner_slot != u64::from(count)
        || manifest.mpc_backend != MpcBackend::HoneyBadger || manifest.mpc_curve != MpcCurve::Bls12_381
        || !manifest.dynamic_client_inputs.is_empty() || manifest.preprocessing_demand.dynamic {
        return Err("open runner requires static HoneyBadger/BLS12-381 manifest".into());
    }
    let mut seen = BTreeSet::new();
    let mut input_slots = BTreeSet::new();
    let mut output_slots = Vec::new();
    for schema in &manifest.clients {
        if !seen.insert(schema.client_slot) { return Err("duplicate manifest client slot".into()); }
        if !schema.inputs.is_empty() {
            if schema.client_slot >= u64::from(count) || schema.inputs.len() as u64 != width {
                return Err("manifest input count/width does not match policy".into());
            }
            input_slots.insert(schema.client_slot);
        }
        if schema.client_slot > owner_slot { return Err("manifest contains an unapproved client slot".into()); }
        if !schema.outputs.is_empty() {
            if schema.outputs.len() != 1 { return Err("manifest must contain exactly one owner output".into()); }
            output_slots.push(schema.client_slot);
        }
    }
    if input_slots != (0..u64::from(count)).collect() || output_slots != vec![owner_slot] {
        return Err("manifest must have exact dense inputs and one precommitted owner output slot".into());
    }
    Ok(())
}

/// Validate an immutable party-only reservation snapshot. Full vectors and
/// reservation order remain original; a snapshot must never rebind an old mask.
fn validate_reservations(policy: &OpenCollectionPolicy, reservations: &[AssignedMaskReservation]) -> OpenResult<()> {
    let width = policy.inputs_per_client;
    if reservations.len() as u64 > policy.reservation_mask_count().ok_or("reservation budget overflow")?
        || reservations.len() as u64 % width != 0 {
        return Err("reservation snapshot exceeds bounds or contains a partial vector".into());
    }
    let mut identities = BTreeSet::new();
    for group in reservations.chunks(width as usize) {
        if !valid_identity(&group[0].client) || !identities.insert(group[0].client.clone()) {
            return Err("invalid or duplicate reservation identity".into());
        }
        for (ordinal, r) in group.iter().enumerate() {
            if r.client != group[0].client || r.input_ordinal != ordinal as u64
                || r.reserved_index != (identities.len() as u64 - 1)*width + ordinal as u64 {
                return Err("reservation original index/identity/ordinal mismatch".into());
            }
        }
    }
    Ok(())
}

pub fn validate_frozen(policy: &OpenCollectionPolicy, frozen: &FrozenCollection,
    reservations: &[AssignedMaskReservation], events: &[AssignedMaskedInputEvent]) -> OpenResult<()> {
    validate_policy(policy, 5, 1)?;
    validate_reservations(policy, reservations)?;
    let reg = &frozen.registration;
    let count = u32::try_from(reg.input_assignment.clients.len()).map_err(|_| "client count overflow")?;
    let width = policy.inputs_per_client;
    if count < policy.min_clients || count > policy.max_clients
        || reg.execution_id != policy.execution_id || reg.output_clients != vec![policy.owner.clone()]
        || policy.approved_programs.get(&count) != Some(&reg.program_hash)
        || reg.min_output_shares != policy.min_output_shares || reg.n_inputs != u64::from(count)*width
        || reg.input_assignment.ranges.len() != count as usize
        || frozen.input_mapping.len() as u64 != reg.n_inputs || events.len() as u64 != reg.n_inputs {
        return Err("frozen execution/program/owner/count/policy mismatch (no padding allowed)".into());
    }
    let mut clients = BTreeSet::new();
    for (slot, client) in reg.input_assignment.clients.iter().enumerate() {
        let range = &reg.input_assignment.ranges[slot];
        if !valid_identity(client) || !clients.insert(client.clone())
            || range.client_index != slot as u32 || range.count != width {
            return Err("frozen identities/ranges are not unique dense full vectors".into());
        }
    }
    let mut by_index = BTreeMap::new();
    for event in events {
        if event.masked_input.is_empty() || event.masked_input.len() > 1024
            || by_index.insert(event.reserved_index, event).is_some() {
            return Err("missing, duplicate or malformed masked input".into());
        }
    }
    let mut seen = BTreeSet::new();
    let mut previous_original_slot = None;
    for (position, mapping) in frozen.input_mapping.iter().enumerate() {
        let slot = position as u64 / width;
        let ordinal = position as u64 % width;
        if mapping.client_slot as u64 != slot || mapping.input_ordinal != ordinal
            || mapping.original_index % width != ordinal || !seen.insert(mapping.original_index) {
            return Err("frozen mapping is not dense/unique or changed an original ordinal".into());
        }
        let original_slot = mapping.original_index / width;
        if ordinal == 0 {
            if previous_original_slot.is_some_and(|p| p >= original_slot) {
                return Err("frozen original slots must preserve reservation order".into());
            }
            previous_original_slot = Some(original_slot);
        } else if previous_original_slot != Some(original_slot) {
            return Err("frozen vector mixes original reservation slots".into());
        }
        let reservation = reservations.get(mapping.original_index as usize).ok_or("original mask index absent")?;
        let event = by_index.get(&mapping.original_index).ok_or("accepted input missing")?;
        let client = &reg.input_assignment.clients[slot as usize];
        if &reservation.client != client || &event.client != client
            || reservation.reserved_index != mapping.original_index
            || reservation.input_ordinal != ordinal || event.input_ordinal != ordinal {
            return Err("input identity/ordinal differs from original reservation".into());
        }
    }
    Ok(())
}

/// Consumes the whole execution-local mask pool, including unused reservations.
/// Every accepted original mask is read exactly once. Trailing serialized bytes
/// are rejected rather than interpreted as a valid contribution.
pub fn reconstruct_frozen<F: FftField, S: ShareBound<F>>(policy: &OpenCollectionPolicy,
    frozen: &FrozenCollection, reservations: &[AssignedMaskReservation],
    events: &[AssignedMaskedInputEvent], masks: Vec<S>) -> OpenResult<BTreeMap<u64, Vec<S>>> {
    validate_frozen(policy, frozen, reservations, events)?;
    if masks.len() as u64 != policy.reservation_mask_count().ok_or("reservation budget overflow")? {
        return Err("one-time mask pool must match reservation budget exactly".into());
    }
    let by_index = events.iter().map(|e| (e.reserved_index,e)).collect::<BTreeMap<_,_>>();
    let mut shares = BTreeMap::<u64,Vec<S>>::new();
    for mapping in &frozen.input_mapping {
        let mut bytes = by_index[&mapping.original_index].masked_input.as_slice();
        let value = S::ValueType::deserialize_compressed(&mut bytes).map_err(|_| "malformed canonical masked input")?;
        if !bytes.is_empty() { return Err("trailing bytes in masked input".into()); }
        let input = S::compute_masked_input(value, &masks[mapping.original_index as usize])
            .map_err(|_| "masked input share reconstruction failed")?;
        shares.entry(u64::from(mapping.client_slot)).or_default().push(input);
    }
    Ok(shares)
}

pub struct CollectedOpenInputs<S> {
    pub frozen: FrozenCollection,
    pub program: ApprovedOpenProgram,
    pub shares: BTreeMap<u64, Vec<S>>,
}

/// One-shot native connection. No legacy registration or round transitions are
/// issued; native mTLS identity must be one of the configured coordinator parties.
/// Collection consumes this adapter so it cannot be rebound to another execution.
pub struct NativeOpenCollectionParty {
    rpc: Client,
    approved: ApprovedOpenCollection,
}
impl NativeOpenCollectionParty {
    pub async fn connect(addr: &str, port: u16, cert_der: Vec<u8>, key_der: Vec<u8>,
        approved: ApprovedOpenCollection, expected_coordinator_public_key: &[u8]) -> OpenResult<Self> {
        let rpc = stoffel_mpc_coordinator_shared::self_signed_certs::setup_client_pinned(addr,port,cert_der,key_der,expected_coordinator_public_key)
            .await.map_err(|e| format!("native coordinator TLS connection: {e}"))?;
        rpc.open_register_policy(approved.policy.clone()).await.map_err(|e| format!("register open policy: {e}"))?;
        Ok(Self { rpc, approved })
    }
    /// RPC listener must have been started with this execution and its existing
    /// `with_browser_rpc` protected-envelope path. Poll/publish overlaps browser
    /// submissions; never waits for a full roster before releasing masks.
    pub async fn collect<F: FftField, S: ShareBound<F>>(self, node: &NodeRPCServer, masks: Vec<S>,
        timeout: Duration) -> OpenResult<(CollectedOpenInputs<S>, NativeOpenOutput)> {
        if masks.len() != self.approved.mask_count() { return Err("reservation-budget one-time masks not preprocessed".into()); }
        let id = self.approved.policy.execution_id;
        let collect = async {
            let mut mirrored = Vec::<AssignedMaskReservation>::new();
            loop {
                let snapshot = self.rpc.open_reservations(id).await.map_err(|e| format!("party reservations: {e}"))?;
                validate_reservations(&self.approved.policy, &snapshot)?;
                if snapshot.len() < mirrored.len() || snapshot[..mirrored.len()] != mirrored {
                    return Err("original one-time reservation was rebound".into());
                }
                let delta = &snapshot[mirrored.len()..];
                if !delta.is_empty() {
                    node.add_assigned_reserved_indices_for_execution(id,delta.to_vec()).await
                        .map_err(|e| format!("publish original reservations: {e:?}"))?;
                    let pairs = delta.iter().map(|r| (r.reserved_index,&masks[r.reserved_index as usize])).collect::<Vec<_>>();
                    node.add_mask_shares_for_execution(id,&pairs).await
                        .map_err(|e| format!("publish protected mask shares: {e:?}"))?;
                    mirrored = snapshot;
                }
                // The coordinator exercises only a persisted owner-signed permit.
                // Not eligible (including below-minimum) is a normal poll result;
                // open_status remains authoritative and transport failures there abort.
                let _ = self.rpc.open_freeze_eligible(id).await;
                let status = self.rpc.open_status(id).await.map_err(|e| format!("open status: {e}"))?;
                if status.execution_id != id || status.min_clients != self.approved.policy.min_clients
                    || status.max_clients != self.approved.policy.max_clients
                    || status.deadline_unix_ms != self.approved.policy.deadline_unix_ms {
                    return Err("open status policy binding mismatch".into());
                }
                if status.termination.is_some() {
                    return Err("open execution was retired before computation".into());
                }
                if let Some(frozen) = status.frozen {
                    // A freeze can race the snapshot: loop once more to mirror all
                    // accepted identities before constructing any VM inputs.
                    let events = self.rpc.open_frozen_inputs(id).await.map_err(|e| format!("party frozen inputs: {e}"))?;
                    if frozen.input_mapping.iter().any(|m| m.original_index as usize >= mirrored.len()) { continue; }
                    let shares = reconstruct_frozen::<F,S>(&self.approved.policy,&frozen,&mirrored,&events,masks)?;
                    let count = frozen.registration.input_assignment.clients.len() as u32;
                    let mut programs = self.approved.programs;
                    let program = programs.remove(&count).ok_or("unapproved frozen program count")?;
                    return Ok((CollectedOpenInputs { frozen, program, shares }, NativeOpenOutput {
                        rpc: self.rpc, execution_id: id, owner: self.approved.policy.owner }));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(timeout,collect).await.map_err(|_| "open collection deadline expired".to_owned())?
    }
}

/// Created only after authenticated freeze. Consuming send prevents local replay
/// and accepts no caller-selected recipient or execution destination.
pub struct NativeOpenOutput {
    rpc: Client,
    execution_id: ExecutionId,
    owner: Vec<u8>,
}
impl NativeOpenOutput {
    pub async fn send<S: CanonicalSerialize>(self, shares: &[S]) -> OpenResult<()> {
        if shares.is_empty() { return Err("missing owner output shares".into()); }
        let ciphertext = seal_output(self.execution_id,&self.owner,shares)?;
        self.rpc.open_send_output(self.execution_id,ciphertext).await
            .map_err(|e| format!("native open_send_output: {e}"))
    }
}
fn seal_output<S: CanonicalSerialize>(execution: ExecutionId, owner: &[u8], shares: &[S]) -> OpenResult<(Vec<u8>,Vec<u8>)> {
    let pk = <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(owner).map_err(|_| "invalid owner HPKE key")?;
    let mut plaintext = Vec::new();
    shares.serialize_compressed(&mut plaintext).map_err(|_| "serialize owner output shares")?;
    let mut info = b"StoffelOutputShareEncryption".to_vec();
    info.extend_from_slice(execution.as_bytes());
    let result = single_shot_seal::<AesGcm256,HkdfSha256,DhP256HkdfSha256,_>(
        &OpModeS::Base,&pk,&info,&plaintext,b"",&mut StdRng::from_os_rng());
    // Secret share serialization is never printed, returned or persisted.
    plaintext.fill(0);
    let (enc,ciphertext) = result.map_err(|_| "encrypt owner output shares")?;
    Ok((enc.to_bytes().to_vec(),ciphertext))
}

#[cfg(test)]
mod tests;
