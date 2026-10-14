//! Explicit variable-roster lifecycle. This is not a legacy registration resize API.
//!
//! Parties must preprocess `policy.reservation_mask_count()` one-time masks for this
//! execution, relay `open_reservations` to their node RPC, and use the original mask
//! indices when constructing input shares. After owner freeze they must verify/load
//! the selected program hash and apply `input_mapping` before running the VM. The
//! fixed-roster runner does not do this automatically. No state is exported into a
//! second execution, and no app-facing response contains masked values.
use crate::*;
use p256::ecdsa::VerifyingKey;
use std::collections::BTreeMap;

pub const MAX_OPEN_CLIENTS: u32 = 4096;
pub const MAX_OPEN_INPUTS: u64 = 1_000_000;
/// Protocol-v1 deterministic one-time reservation budget, implicitly committed
/// by the immutable max_clients/width policy and approved runtime revision.
/// Abandoned reservations burn masks forever; exhaustion is a resource queue,
/// not accepted capacity. This is bounded churn tolerance, not unlimited joins.
pub const OPEN_RESERVATION_MULTIPLIER: u32 = 16;
pub const MAX_OPEN_RESERVATIONS: u32 = MAX_OPEN_CLIENTS * OPEN_RESERVATION_MULTIPLIER;
/// Automatic collection windows are bounded to 24 hours.
pub const MAX_OPEN_CLOSURE_DELAY_MS: u64 = 24 * 60 * 60 * 1000;

pub(crate) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

fn valid_deadline(deadline: u64, now: u64) -> bool {
    deadline > now
        && deadline
            .checked_sub(now)
            .is_some_and(|d| d <= MAX_OPEN_CLOSURE_DELAY_MS)
}

/// Structural validation of an already masked field element, not input opening.
fn canonical_masked_fr(bytes: &[u8]) -> bool {
    let mut remaining = bytes;
    ark_bls12_381::Fr::deserialize_compressed(&mut remaining).is_ok() && remaining.is_empty()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenClosureAuthorization {
    pub deadline_unix_ms: u64,
    pub freeze_at_capacity: bool,
}

/// Value-free identity receipt; excludes all protected input bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAcceptedMetadata {
    pub execution_id: ExecutionId,
    pub client: ClientIdentity,
    pub reserved_indices: Vec<u64>,
}

/// Terminal tombstone. Retirement burns this execution identifier for the
/// lifetime of this coordinator; no protected input or output bytes survive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenTerminationReceipt {
    pub execution_id: ExecutionId,
    pub accepted_clients: u32,
    /// Value-free historical acceptance, captured atomically before protected bytes clear.
    pub accepted_metadata: Vec<OpenAcceptedMetadata>,
    pub program_hash: Option<[u8; 32]>,
    pub encrypted_output_shares: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEncryptedOutput {
    pub party: ClientIdentity,
    pub ciphertext: (Vec<u8>, Vec<u8>),
}

/// Registered by a configured MPC party before admitting identities or inputs.
/// Every supported accepted count must have a nonzero approved hash. The runner
/// must check that each artifact's manifest has this width and owner-only output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenCollectionPolicy {
    pub execution_id: ExecutionId,
    pub owner: ClientIdentity,
    pub min_clients: u32,
    pub max_clients: u32,
    pub inputs_per_client: u64,
    pub approved_programs: BTreeMap<u32, [u8; 32]>,
    pub min_output_shares: u64,
    /// None is reserved for explicit owner/manual closure compatibility.
    #[serde(default)]
    pub deadline_unix_ms: Option<u64>,
}

impl OpenCollectionPolicy {
    /// No caller-selected budget: every valid policy reserves exactly 16x its
    /// accepted capacity, capped by protocol policy validation at 65,536 clients.
    pub fn reservation_clients(&self) -> u32 {
        self.max_clients.saturating_mul(OPEN_RESERVATION_MULTIPLIER)
    }
    pub fn reservation_mask_count(&self) -> Option<u64> {
        self.inputs_per_client.checked_mul(u64::from(self.reservation_clients()))
    }
}

/// Value-free mapping: masks remain at their original indices, while the frozen
/// program's ClientStore layout uses dense accepted-client slots. Reserved but
/// unsubmitted identities are excluded, never replaced with synthetic inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenInputMapping {
    pub original_index: u64,
    pub client_slot: u32,
    pub input_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenCollection {
    pub registration: ExecutionRegistration,
    pub input_mapping: Vec<FrozenInputMapping>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenCollectionStatus {
    pub execution_id: ExecutionId,
    pub reserved_clients: u32,
    pub accepted_clients: u32,
    pub min_clients: u32,
    pub max_clients: u32,
    pub deadline_unix_ms: Option<u64>,
    pub closure_authorization: Option<OpenClosureAuthorization>,
    pub termination: Option<OpenTerminationReceipt>,
    pub own_indices: Vec<u64>,
    pub own_input_accepted: bool,
    pub frozen: Option<FrozenCollection>,
}

pub(crate) struct OpenCollectionState {
    policy: OpenCollectionPolicy,
    reservations: Vec<AssignedMaskReservation>,
    clients: Vec<ClientIdentity>,
    // Indexed by reservation slot, not by eventual accepted-client slot.
    inputs: BTreeMap<u32, Vec<Vec<u8>>>,
    closure_authorization: Option<OpenClosureAuthorization>,
    termination: Option<OpenTerminationReceipt>,
    frozen: Option<FrozenCollection>,
    output_shares: BTreeMap<ClientIdentity, (Vec<u8>, Vec<u8>)>,
}

fn error(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32060, message.into(), None::<()>)
}

fn valid_identity(identity: &[u8]) -> bool {
    // Canonical uncompressed SEC1 prevents one key occupying several identities.
    VerifyingKey::from_sec1_bytes(identity)
        .is_ok_and(|key| key.to_encoded_point(false).as_bytes() == identity)
}

impl OpenCollectionState {
    fn ensure_live(&self) -> RpcResult<()> {
        if self.termination.is_some() {
            return Err(error("execution is retired"));
        }
        Ok(())
    }

    fn ensure_admitting(&self) -> RpcResult<()> {
        self.ensure_live()?;
        if self.policy.deadline_unix_ms.is_some_and(|d| unix_ms() >= d) {
            return Err(error("collection deadline reached"));
        }
        Ok(())
    }

    fn freeze(
        &mut self,
        execution_id: ExecutionId,
        expected_program_hash: [u8; 32],
    ) -> RpcResult<FrozenCollection> {
        if let Some(frozen) = &self.frozen {
            return if frozen.registration.program_hash == expected_program_hash {
                Ok(frozen.clone())
            } else {
                Err(error("frozen program is immutable"))
            };
        }
        let count = self.inputs.len() as u32;
        if !(self.policy.min_clients..=self.policy.max_clients).contains(&count) {
            return Err(error("accepted contributions are outside privacy bounds"));
        }
        let hash = self
            .policy
            .approved_programs
            .get(&count)
            .ok_or_else(|| error("accepted count has no approved program"))?;
        if *hash != expected_program_hash {
            return Err(error("program does not match preapproved accepted count"));
        }
        let mut clients = Vec::new();
        let mut mapping = Vec::new();
        for (dense_slot, original_slot) in self.inputs.keys().enumerate() {
            clients.push(self.clients[*original_slot as usize].clone());
            for ordinal in 0..self.policy.inputs_per_client {
                mapping.push(FrozenInputMapping {
                    original_index: u64::from(*original_slot) * self.policy.inputs_per_client
                        + ordinal,
                    client_slot: dense_slot as u32,
                    input_ordinal: ordinal,
                });
            }
        }
        let frozen = FrozenCollection {
            registration: ExecutionRegistration {
                execution_id,
                program_hash: *hash,
                n_inputs: mapping.len() as u64,
                output_clients: vec![self.policy.owner.clone()],
                input_assignment: InputAssignment {
                    clients,
                    ranges: (0..count)
                        .map(|client_index| InputClientRange {
                            client_index,
                            count: self.policy.inputs_per_client,
                        })
                        .collect(),
                },
                min_output_shares: self.policy.min_output_shares,
            },
            input_mapping: mapping,
        };
        self.frozen = Some(frozen.clone());
        Ok(frozen)
    }
}

impl CoordinatorRPCServerSharedBase {
    /// Trusted in-process bootstrap, analogous to `register_execution`. Network
    /// registration goes through `open_register_policy`'s configured-party check.
    pub fn register_open_collection(&mut self, policy: OpenCollectionPolicy) -> RpcResult<()> {
        if self.executions.contains_key(&policy.execution_id) {
            return Err(error(
                "execution already has an immutable legacy registration",
            ));
        }
        if let Some(existing) = self.open_collections.get(&policy.execution_id) {
            return if existing.termination.is_none() && existing.policy == policy {
                Ok(())
            } else {
                Err(error("open policy is immutable"))
            };
        }
        if self.executions.len() + self.open_collections.len() >= DEFAULT_MAX_CONCURRENT_EXECUTIONS
        {
            return Err(error("execution capacity reached"));
        }
        let total = policy.reservation_mask_count();
        if policy.execution_id.is_zero()
            || policy
                .deadline_unix_ms
                .is_some_and(|d| !valid_deadline(d, unix_ms()))
            || !valid_identity(&policy.owner)
            || policy.min_clients < 2
            || policy.max_clients < policy.min_clients
            || policy.max_clients > MAX_OPEN_CLIENTS
            || policy.reservation_clients() > MAX_OPEN_RESERVATIONS
            || policy.inputs_per_client == 0
            || total.is_none_or(|n| n > MAX_OPEN_INPUTS)
            || policy.min_output_shares < 2 * self.t + 1
            || policy.min_output_shares > self.n
            || policy.approved_programs.len()
                != (policy.max_clients - policy.min_clients + 1) as usize
            || (policy.min_clients..=policy.max_clients).any(|count| {
                policy
                    .approved_programs
                    .get(&count)
                    .is_none_or(|hash| *hash == [0; 32])
            })
        {
            return Err(error(
                "invalid open collection policy, identity, bounds, programs or output quorum",
            ));
        }
        self.open_collections.insert(
            policy.execution_id,
            OpenCollectionState {
                policy,
                reservations: vec![],
                clients: vec![],
                inputs: BTreeMap::new(),
                closure_authorization: None,
                termination: None,
                frozen: None,
                output_shares: BTreeMap::new(),
            },
        );
        Ok(())
    }
}

impl CoordinatorRPCServerConnectionBase {
    /// Owner identity is from mTLS or the signed browser envelope. Exact retries
    /// use a fresh authentication nonce, and cannot extend the committed window.
    pub async fn open_authorize_closure(
        &self,
        execution_id: ExecutionId,
        authorization: OpenClosureAuthorization,
    ) -> RpcResult<OpenClosureAuthorization> {
        self.open_authorize_closure_with_clock(execution_id, authorization, unix_ms)
            .await
    }

    #[cfg(test)]
    async fn open_authorize_closure_at(
        &self,
        execution_id: ExecutionId,
        authorization: OpenClosureAuthorization,
        now: u64,
    ) -> RpcResult<OpenClosureAuthorization> {
        self.open_authorize_closure_with_clock(execution_id, authorization, || now)
            .await
    }

    async fn open_authorize_closure_with_clock(
        &self,
        execution_id: ExecutionId,
        authorization: OpenClosureAuthorization,
        clock: impl FnOnce() -> u64,
    ) -> RpcResult<OpenClosureAuthorization> {
        let mut shared = self.d.lock().await;
        // Sample time at the state transition, not before waiting for the lock.
        let now = clock();
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        if self.id != state.policy.owner {
            return Err(error("only the policy owner can authorize closure"));
        }
        if let Some(existing) = &state.closure_authorization {
            return if existing == &authorization {
                Ok(existing.clone())
            } else {
                Err(error("closure authorization is immutable"))
            };
        }
        if state.frozen.is_some()
            || !authorization.freeze_at_capacity
            || state.policy.deadline_unix_ms != Some(authorization.deadline_unix_ms)
            || !valid_deadline(authorization.deadline_unix_ms, now)
        {
            return Err(error("closure requires a bounded future deadline matching the committed policy and capacity freeze"));
        }
        state.closure_authorization = Some(authorization.clone());
        Ok(authorization)
    }

    /// Configured mTLS parties may only exercise a saved owner permit. Selection
    /// and freeze share one lock: no caller-controlled roster, count or program.
    pub async fn open_freeze_eligible(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<FrozenCollection> {
        self.open_freeze_eligible_with_clock(execution_id, unix_ms)
            .await
    }

    #[cfg(test)]
    async fn open_freeze_eligible_at(
        &self,
        execution_id: ExecutionId,
        now: u64,
    ) -> RpcResult<FrozenCollection> {
        self.open_freeze_eligible_with_clock(execution_id, || now)
            .await
    }

    async fn open_freeze_eligible_with_clock(
        &self,
        execution_id: ExecutionId,
        clock: impl FnOnce() -> u64,
    ) -> RpcResult<FrozenCollection> {
        let mut shared = self.d.lock().await;
        let now = clock();
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error(
                "only configured MPC parties exercise automatic closure",
            ));
        }
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        let permit = state
            .closure_authorization
            .as_ref()
            .ok_or_else(|| error("owner has not authorized automatic closure"))?;
        if let Some(frozen) = &state.frozen {
            return Ok(frozen.clone());
        }
        let count = state.inputs.len() as u32;
        if count != state.policy.max_clients && now < permit.deadline_unix_ms {
            return Err(error("collection is not eligible for closure"));
        }
        let hash = *state
            .policy
            .approved_programs
            .get(&count)
            .ok_or_else(|| error("accepted contributions are below privacy minimum"))?;
        state.freeze(execution_id, hash)
    }

    pub async fn open_accepted_metadata(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<Vec<OpenAcceptedMetadata>> {
        let shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error(
                "only configured MPC parties read accepted identities",
            ));
        }
        let state = shared
            .open_collections
            .get(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        if let Some(t) = &state.termination { return Ok(t.accepted_metadata.clone()); }
        Ok(state
            .inputs
            .keys()
            .map(|slot| OpenAcceptedMetadata {
                execution_id,
                client: state.clients[*slot as usize].clone(),
                reserved_indices: (u64::from(*slot) * state.policy.inputs_per_client
                    ..(u64::from(*slot) + 1) * state.policy.inputs_per_client)
                    .collect(),
            })
            .collect())
    }

    /// Already-encrypted owner-bound shares only, with public party provenance.
    /// The controller can archive these without holding any owner private key.
    pub async fn open_encrypted_archive(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<Option<Vec<OpenEncryptedOutput>>> {
        let shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error(
                "only configured MPC parties archive encrypted outputs",
            ));
        }
        let state = shared
            .open_collections
            .get(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        if state.output_shares.len() < state.policy.min_output_shares as usize {
            return Ok(None);
        }
        Ok(Some(
            state
                .output_shares
                .iter()
                .map(|(party, ciphertext)| OpenEncryptedOutput {
                    party: party.clone(),
                    ciphertext: ciphertext.clone(),
                })
                .collect(),
        ))
    }

    /// Configured parties may abort an unfrozen collection or retire one after
    /// encrypted output quorum, never abort frozen computation/partial output.
    /// The immutable tombstone blocks data plane activity/reuse and is retryable.
    /// Archive ciphertext before stopping; retirement drops protected bytes.
    pub async fn open_stop(&self, execution_id: ExecutionId) -> RpcResult<OpenTerminationReceipt> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error("only configured MPC parties retire executions"));
        }
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        if let Some(receipt) = &state.termination {
            return Ok(receipt.clone());
        }
        // Freeze starts computation: no party may turn a computation or partial
        // output into an abort. Completed owner-bound ciphertext can be archived
        // and then retired; an unsealed collection may still be aborted.
        if state.frozen.is_some()
            && state.output_shares.len() < state.policy.min_output_shares as usize
        {
            return Err(error(
                "frozen computation cannot be aborted before output quorum",
            ));
        }
        // Same mutex as open_submit: accepted-before-stop is retained, after-stop
        // submissions fail. Retain identities and ORIGINAL indices, never values.
        let accepted_metadata = state.inputs.keys().map(|slot| OpenAcceptedMetadata {
            execution_id,
            client: state.clients[*slot as usize].clone(),
            reserved_indices: (u64::from(*slot) * state.policy.inputs_per_client
                ..(u64::from(*slot) + 1) * state.policy.inputs_per_client).collect(),
        }).collect::<Vec<_>>();
        let receipt = OpenTerminationReceipt {
            execution_id,
            accepted_clients: accepted_metadata.len() as u32,
            accepted_metadata,
            program_hash: state.frozen.as_ref().map(|f| f.registration.program_hash),
            encrypted_output_shares: state.output_shares.len() as u32,
        };
        state.termination = Some(receipt.clone());
        state.inputs.clear();
        state.reservations.clear();
        state.clients.clear();
        state.output_shares.clear();
        Ok(receipt)
    }

    /// Identity is supplied by the authenticated TLS connection or signed browser
    /// envelope, never by request body. All lifecycle mutations linearize on `d`.
    pub async fn open_register_policy(&self, policy: OpenCollectionPolicy) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error("only configured MPC parties register policies"));
        }
        shared.register_open_collection(policy)
    }

    pub async fn open_reserve(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<Vec<AssignedMaskReservation>> {
        let mut shared = self.d.lock().await;
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_admitting()?;
        if state.frozen.is_some() {
            return Err(error("collection is frozen"));
        }
        if !valid_identity(&self.id) {
            return Err(error("canonical P-256 identity required"));
        }
        if state.clients.contains(&self.id) {
            return Err(error("identity already reserved"));
        }
        if state.inputs.len() >= state.policy.max_clients as usize {
            return Err(error("accepted collection capacity reached"));
        }
        if state.clients.len() >= state.policy.reservation_clients() as usize {
            return Err(error("one-time reservation budget exhausted"));
        }
        let start = state.reservations.len() as u64;
        let reservations = (0..state.policy.inputs_per_client)
            .map(|ordinal| AssignedMaskReservation {
                client: self.id.clone(),
                reserved_index: start + ordinal,
                input_ordinal: ordinal,
            })
            .collect::<Vec<_>>();
        state.clients.push(self.id.clone());
        state.reservations.extend(reservations.clone());
        Ok(reservations)
    }

    /// Atomic full-vector submission: no partial contribution counts toward the
    /// privacy threshold. Reservation and other clients' submissions may overlap.
    pub async fn open_submit(
        &self,
        execution_id: ExecutionId,
        indices: Vec<u64>,
        inputs: Vec<Vec<u8>>,
    ) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_admitting()?;
        if state.frozen.is_some() {
            return Err(error("collection is frozen"));
        }
        let slot = state
            .clients
            .iter()
            .position(|client| client == &self.id)
            .ok_or_else(|| error("identity has no reservation in this execution"))?
            as u32;
        if state.inputs.contains_key(&slot) {
            return Err(error("contribution already accepted"));
        }
        if state.inputs.len() >= state.policy.max_clients as usize {
            return Err(error("accepted collection capacity reached"));
        }
        let width = state.policy.inputs_per_client;
        let expected = (u64::from(slot) * width..(u64::from(slot) + 1) * width).collect::<Vec<_>>();
        if indices != expected
            || inputs.len() != width as usize
            || inputs.iter().any(|value| !canonical_masked_fr(value))
        {
            return Err(error(
                "submission must contain exactly the reserved vector in ordinal order",
            ));
        }
        state.inputs.insert(slot, inputs);
        Ok(())
    }

    /// Authenticated owner request starts computation by atomically sealing the
    /// accepted set and approved program binding. The caller cannot supply a roster,
    /// count, owner, execution destination, or replacement program. A hash mismatch
    /// leaves collection open. Retries of the same frozen selection are idempotent.
    pub async fn open_freeze(
        &self,
        execution_id: ExecutionId,
        expected_program_hash: [u8; 32],
    ) -> RpcResult<FrozenCollection> {
        let mut shared = self.d.lock().await;
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        if self.id != state.policy.owner {
            return Err(error("only the policy owner can freeze"));
        }
        state.ensure_live()?;
        state.freeze(execution_id, expected_program_hash)
    }

    /// Value-free status; a fresh authenticated identity may inspect capacity.
    pub async fn open_status(&self, execution_id: ExecutionId) -> RpcResult<OpenCollectionStatus> {
        let shared = self.d.lock().await;
        let state = shared
            .open_collections
            .get(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        let own_slot = state.clients.iter().position(|client| client == &self.id);
        Ok(OpenCollectionStatus {
            execution_id,
            reserved_clients: state.clients.len() as u32,
            accepted_clients: state.termination.as_ref().map_or(state.inputs.len() as u32, |t| t.accepted_clients),
            min_clients: state.policy.min_clients,
            max_clients: state.policy.max_clients,
            deadline_unix_ms: state.policy.deadline_unix_ms,
            closure_authorization: state.closure_authorization.clone(),
            termination: state.termination.clone(),
            own_indices: state
                .reservations
                .iter()
                .filter(|r| r.client == self.id)
                .map(|r| r.reserved_index)
                .collect(),
            own_input_accepted: state.termination.as_ref().map_or_else(
                || own_slot.is_some_and(|slot| state.inputs.contains_key(&(slot as u32))),
                |t| t.accepted_metadata.iter().any(|m| m.client == self.id)),
            frozen: state.frozen.clone(),
        })
    }

    /// Party-only data-plane API. Feed these execution-bound original reservations
    /// to NodeRPCServer::add_assigned_reserved_indices_for_execution before masks
    /// are released. Replays are snapshots, not instructions to reserve twice.
    pub async fn open_reservations(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<Vec<AssignedMaskReservation>> {
        let shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error("only configured MPC parties read reservations"));
        }
        let state = shared
            .open_collections
            .get(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        Ok(state.reservations.clone())
    }

    /// Party-only protected data plane, never exposed on the browser listener.
    /// Returns immutable original-index events only after freeze. Use frozen
    /// mapping to assemble shares, not a new execution or a new mask allocation.
    pub async fn open_frozen_inputs(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<Vec<AssignedMaskedInputEvent>> {
        let shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error("only configured MPC parties read protected inputs"));
        }
        let state = shared
            .open_collections
            .get(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        if state.frozen.is_none() {
            return Err(error("collection is not frozen"));
        }
        Ok(state
            .inputs
            .iter()
            .flat_map(|(slot, inputs)| {
                inputs
                    .iter()
                    .enumerate()
                    .map(|(ordinal, input)| AssignedMaskedInputEvent {
                        client: state.clients[*slot as usize].clone(),
                        reserved_index: u64::from(*slot) * state.policy.inputs_per_client
                            + ordinal as u64,
                        input_ordinal: ordinal as u64,
                        masked_input: input.clone(),
                    })
            })
            .collect())
    }

    /// Parties encrypt outputs to the precommitted owner using the existing HPKE
    /// share format. This coordinator never decrypts them or accepts a recipient.
    pub async fn open_send_output(
        &self,
        execution_id: ExecutionId,
        ciphertext: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(error("only configured MPC parties send outputs"));
        }
        let state = shared
            .open_collections
            .get_mut(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        if state.frozen.is_none() {
            return Err(error("collection is not frozen"));
        }
        if let Some(existing) = state.output_shares.get(&self.id) {
            return if existing == &ciphertext {
                Ok(())
            } else {
                Err(error("party output is immutable"))
            };
        }
        if ciphertext.0.is_empty() || ciphertext.1.is_empty() {
            return Err(error("empty encrypted output"));
        }
        state.output_shares.insert(self.id.clone(), ciphertext);
        Ok(())
    }

    pub async fn open_output_shares(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let shared = self.d.lock().await;
        let state = shared
            .open_collections
            .get(&execution_id)
            .ok_or_else(|| error("open execution not found"))?;
        state.ensure_live()?;
        if self.id != state.policy.owner {
            return Err(error("only the owner can obtain encrypted output shares"));
        }
        if state.output_shares.len() < state.policy.min_output_shares as usize {
            return Ok(None);
        }
        Ok(Some(state.output_shares.values().cloned().collect()))
    }
}

#[cfg(test)]
mod tests;
