//! The coordinator-mediated client (`docs/design/bootnode-elimination.md` §9.E.1), once.
//!
//! A client's participation in an execution is a per-execution **admission** the coordinator
//! decides, not an entry in any node's transport allowlist (§9, decision 3). So a client is
//! never configured into a node: it pins the coordinator, reads the execution's summary,
//! associates, and from then on operates only within the input range and output rights its
//! admission names. Its identity need not have been known to anyone before it associates.
//!
//! Every client surface runs this flow — `stoffel-run --client` on both backends,
//! [`crate::run_offchain_client`], and the Rust SDK's client — so the order of the steps and
//! what each refuses are decided here and nowhere else:
//!
//! 1. **Pinned coordinator, roster once** ([`CoordinatorClientConfig::connect`]): the served
//!    `NodeRoster` gives `n` and `t`, and `expected_roster_digest` refuses any other one.
//! 2. **Know what you are joining, before associating** — an association is irrevocable: the
//!    summary's slot table, its program against `expected_program_hash`, the backend's minimum
//!    roster and sealed-output bound, and the slot's shape against the inputs this client has
//!    ([`CoordinatorClientConfig::inspect`]). A caller with slot checks of its own makes them
//!    against every slot [`PendingAssociation::bindable_slots`] names, before step 3.
//! 3. **Associate**, and check the admission against the inputs and outputs this client has.
//! 4. Reserve exactly the admitted range once reservations open.
//! 5. **Pinned node legs**: every node RPC leg is pinned to a distinct roster member and its
//!    shares are attributed to that member's roster position.
//! 6. Receive the masks, then submit the whole range in one call signed with the client's key.
//! 7. With output rights, obtain one signed item per node and reconstruct by position.
//!
//! A client whose admission has no input range (an output-only slot) skips steps 4–6.

use ark_ff::FftField;
use stoffel_mpc_coordinator_off_chain::{
    node_rpc::NodeRPCClient, CoordinatorLink, ExecutionSummary, OffChainCoordinatorClient,
};
use stoffel_mpc_coordinator_shared::{
    AdmissionPolicyKind, AssociationRequest, ClientAdmission, ClientIndex, ClientSlotSpec,
    Coordinator, CoordinatorError, ExecutionId, OutputRights, RegistrationError, RosterDigest,
    Round, ShareBound, SpkiDer,
};
use stoffel_vm::net::MpcBackendKind;

/// Where the coordinator listens, and the key it must prove it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorEndpoint {
    pub host: String,
    pub port: u16,
    /// The coordinator certificate's key (`--coord-cert`). A connection to a server holding any
    /// other key is refused before any RPC (§9.A).
    pub pin: SpkiDer,
}

/// Everything one coordinator-mediated client needs. It names no node and no other client:
/// the nodes come from the coordinator's roster, and this client's slot, input range and
/// output rights from its admission.
#[derive(Clone, Debug)]
pub struct CoordinatorClientConfig {
    pub coordinator: CoordinatorEndpoint,
    pub execution_id: ExecutionId,
    /// The share type's backend, for the refusals that name it.
    pub backend: MpcBackendKind,
    /// This client's own DER certificate and PKCS#8 key. Its admission is keyed on the
    /// certificate, and the key signs its masked inputs and opens its sealed outputs.
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// Node RPC addresses. Hints only: every leg is pinned to a member of the served roster.
    pub node_rpc_addresses: Vec<(String, u16)>,
    /// The slot this client asks for and, under `Invitation`, its invitation.
    pub request: AssociationRequest,
    /// `--expect-roster-digest`: refuse a coordinator that serves any other node roster.
    pub expected_roster_digest: Option<RosterDigest>,
    /// `--expect-program-hash`: refuse to associate with an execution of any other program.
    pub expected_program_hash: Option<[u8; 32]>,
    /// The number of outputs this client is prepared to decode. `None` accepts whatever the
    /// admission grants.
    pub expected_output_count: Option<u64>,
}

/// What one client got from an execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorClientRun<V> {
    /// The slot, input range and output rights the coordinator admitted this client to.
    pub admission: ClientAdmission,
    /// The reconstructed outputs, in output order; empty without output rights.
    pub outputs: Vec<V>,
}

/// Why a coordinator-mediated client stopped. [`Self::exit_code`] is `stoffel-run`'s exit
/// status for it (§9.D.3, §9.E.1): 2 for a refusal this client makes of what it was asked to
/// join, 13 for everything the coordinator or a node did.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorClientError {
    /// Step 1: the pinned connection or the roster it served.
    #[error("{0}")]
    Connect(CoordinatorError),
    /// The coordinator answered with the summary of another execution.
    #[error(
        "the coordinator served the summary of execution {served} when asked for {requested}; \
         refusing to associate."
    )]
    WrongExecution {
        requested: ExecutionId,
        served: ExecutionId,
    },
    #[error("execution {execution_id} has a client slot table this client refuses: {reason}")]
    SlotTable {
        execution_id: ExecutionId,
        reason: RegistrationError,
    },
    #[error(
        "execution {execution_id} runs program {}, not the --expect-program-hash {}; refusing \
         to associate.",
        hex::encode(served),
        hex::encode(expected)
    )]
    ProgramMismatch {
        execution_id: ExecutionId,
        served: [u8; 32],
        expected: [u8; 32],
    },
    #[error(
        "{} needs at least {required} nodes for threshold {t}, and the coordinator's roster has \
         {n}; refusing to associate.",
        backend.name()
    )]
    TopologyUnsupported {
        backend: MpcBackendKind,
        n: u64,
        t: u64,
        required: u64,
    },
    #[error(
        "execution {execution_id} gives client slot {client_index} {output_count} outputs, \
         {bytes} bytes sealed under {}, above the {max}-byte bound; refusing to associate.",
        backend.name()
    )]
    SealedOutputsTooLarge {
        execution_id: ExecutionId,
        backend: MpcBackendKind,
        client_index: ClientIndex,
        output_count: u64,
        bytes: u64,
        max: u64,
    },
    #[error(
        "execution {execution_id} has {capacity} client slot(s), so it has no client slot \
         {slot}; refusing to associate."
    )]
    NoSuchSlot {
        execution_id: ExecutionId,
        slot: ClientIndex,
        capacity: u32,
    },
    #[error("execution {execution_id} has client slots of different shapes; pass --client-slot <index>.")]
    SlotShapesDiffer { execution_id: ExecutionId },
    #[error("client slot {client_index} takes {count} inputs, but --inputs has {given}.")]
    InputCountMismatch {
        client_index: ClientIndex,
        count: u64,
        given: u64,
    },
    #[error(
        "client slot {client_index} is admitted to receive {admitted} outputs, but this client \
         decodes {expected}."
    )]
    OutputCountMismatch {
        client_index: ClientIndex,
        admitted: u64,
        expected: u64,
    },
    /// The coordinator honours a requested slot exactly or refuses; anything else is the
    /// coordinator misbehaving.
    #[error("asked the coordinator for client slot {requested}, but it admitted this client to slot {admitted}")]
    SlotNotGranted {
        requested: ClientIndex,
        admitted: ClientIndex,
    },
    #[error("the coordinator refused to associate this client: {0}")]
    Association(CoordinatorError),
    #[error("failed to connect to the node RPC servers: {0}")]
    NodeRpc(CoordinatorError),
    /// Any later coordinator or node refusal, including `ExecutionAborted`, whose message is
    /// `execution {id} was aborted by the coordinator: {reason}`.
    #[error("{0}")]
    Coordinator(CoordinatorError),
}

impl CoordinatorClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Connect(CoordinatorError::UnexpectedRosterDigest { .. })
            | Self::ProgramMismatch { .. }
            | Self::TopologyUnsupported { .. }
            | Self::SealedOutputsTooLarge { .. }
            | Self::NoSuchSlot { .. }
            | Self::SlotShapesDiffer { .. }
            | Self::InputCountMismatch { .. }
            | Self::OutputCountMismatch { .. } => 2,
            Self::Connect(_)
            | Self::WrongExecution { .. }
            | Self::SlotTable { .. }
            | Self::SlotNotGranted { .. }
            | Self::Association(_)
            | Self::NodeRpc(_)
            | Self::Coordinator(_) => 13,
        }
    }

    /// The coordinator error underneath, when there is one.
    pub fn coordinator_error(&self) -> Option<&CoordinatorError> {
        match self {
            Self::Connect(error)
            | Self::Association(error)
            | Self::NodeRpc(error)
            | Self::Coordinator(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoordinatorError> for CoordinatorClientError {
    fn from(error: CoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

impl CoordinatorClientConfig {
    /// Step 1: the pinned coordinator connection, which fetches and verifies the node roster
    /// exactly once. The link is never re-established.
    pub async fn connect(&self) -> Result<CoordinatorLink, CoordinatorClientError> {
        CoordinatorLink::connect(
            &self.coordinator.host,
            self.coordinator.port,
            &self.coordinator.pin,
            self.expected_roster_digest,
            self.cert_der.clone(),
            self.key_der.clone(),
        )
        .await
        .map_err(CoordinatorClientError::Connect)
    }

    /// The slot this client will hold, when it is settled before associating: the one it asks
    /// for, or the one its invitation names.
    fn known_slot(&self) -> Option<ClientIndex> {
        self.request.slot.or_else(|| {
            self.request
                .invitation
                .as_ref()
                .map(|signed| signed.invitation.client_index)
        })
    }

    /// Step 2, the refusals this client makes itself before an irrevocable association.
    ///
    /// An aborted execution is not refused here: its summary names only the round, and the
    /// association it answers next is refused with the reason and binds nothing.
    fn check_summary(
        &self,
        summary: &ExecutionSummary,
        input_count: u64,
    ) -> Result<(), CoordinatorClientError> {
        let execution_id = summary.execution_id;
        if execution_id != self.execution_id {
            return Err(CoordinatorClientError::WrongExecution {
                requested: self.execution_id,
                served: execution_id,
            });
        }
        summary.client_slots.check_bounds().map_err(|reason| {
            CoordinatorClientError::SlotTable {
                execution_id,
                reason,
            }
        })?;
        if summary.round == Round::Aborted {
            return Ok(());
        }
        if let Some(expected) = self.expected_program_hash {
            if summary.program_hash != expected {
                return Err(CoordinatorClientError::ProgramMismatch {
                    execution_id,
                    served: summary.program_hash,
                    expected,
                });
            }
        }
        let slots = summary.client_slots.slots();
        match self.known_slot() {
            Some(slot) => {
                let spec = usize::try_from(slot.0)
                    .ok()
                    .and_then(|position| slots.get(position))
                    .ok_or(CoordinatorClientError::NoSuchSlot {
                        execution_id,
                        slot,
                        capacity: summary.client_slots.capacity(),
                    })?;
                check_input_count(slot, spec, input_count)
            }
            // Under `Open` the coordinator picks the slot, so every slot it could pick must fit.
            None if summary.admission == AdmissionPolicyKind::Open => {
                let Some(first) = slots.first() else {
                    // No slot at all: the association is refused with the coordinator's reason.
                    return Ok(());
                };
                if slots.iter().any(|slot| slot != first) {
                    return Err(CoordinatorClientError::SlotShapesDiffer { execution_id });
                }
                check_input_count(ClientIndex(0), first, input_count)
            }
            // Under `PreRegistered` the slot was bound at registration, and association binds
            // nothing new: the admission is checked right after it.
            None => Ok(()),
        }
    }

    /// Which slot the association can bind, as `summary` settles it before associating.
    /// Meaningful once [`Self::check_summary`] has passed.
    fn bindable_slots(&self, summary: &ExecutionSummary) -> BindableSlots {
        if summary.round == Round::Aborted {
            return BindableSlots::Nothing;
        }
        match (self.known_slot(), &summary.admission) {
            (Some(slot), _) => BindableSlots::Settled(slot),
            (None, AdmissionPolicyKind::Open) => BindableSlots::AnyOf(
                (0..summary.client_slots.capacity())
                    .map(ClientIndex)
                    .collect(),
            ),
            (None, AdmissionPolicyKind::PreRegistered) => BindableSlots::Registered,
            // Invitation admission without an invitation: refused as `InvitationRequired`.
            (None, AdmissionPolicyKind::Invitation { .. }) => BindableSlots::Nothing,
        }
    }

    /// Step 3 on a summary [`Self::check_summary`] passed: associates and checks the admission
    /// against the inputs and outputs this client has.
    async fn admit<F, S>(
        &self,
        coord: &mut OffChainCoordinatorClient<F, S>,
        summary: &ExecutionSummary,
        input_count: u64,
    ) -> Result<ClientAdmission, CoordinatorClientError>
    where
        F: FftField,
        S: ShareBound<F>,
    {
        // `associate_client` reads the summary itself and refuses, without sending the
        // association, a roster below the backend's minimum or a slot whose outputs cannot be
        // sealed under the bound (§9.E.1 step 2).
        let admission = coord
            .associate_client(self.request.clone())
            .await
            .map_err(|error| match error {
                CoordinatorError::TopologyUnsupportedByBackend { n, t, required } => {
                    CoordinatorClientError::TopologyUnsupported {
                        backend: self.backend,
                        n,
                        t,
                        required,
                    }
                }
                CoordinatorError::SealedOutputsExceedBound {
                    client_index,
                    bytes,
                    max,
                } => CoordinatorClientError::SealedOutputsTooLarge {
                    execution_id: summary.execution_id,
                    backend: self.backend,
                    client_index,
                    output_count: usize::try_from(client_index.0)
                        .ok()
                        .and_then(|position| summary.client_slots.slots().get(position))
                        .map_or(0, |slot| slot.output_count),
                    bytes,
                    max,
                },
                error @ CoordinatorError::ExecutionAborted { .. } => {
                    CoordinatorClientError::Coordinator(error)
                }
                other => CoordinatorClientError::Association(other),
            })?;

        // The requested slot, or the invitation's, is bound exactly or refused.
        if let Some(requested) = self.known_slot() {
            if admission.client_index != requested {
                return Err(CoordinatorClientError::SlotNotGranted {
                    requested,
                    admitted: admission.client_index,
                });
            }
        }
        let admitted_inputs = admission.input_range.map_or(0, |range| range.count.get());
        if admitted_inputs != input_count {
            return Err(CoordinatorClientError::InputCountMismatch {
                client_index: admission.client_index,
                count: admitted_inputs,
                given: input_count,
            });
        }
        if let Some(expected) = self.expected_output_count {
            let admitted = match admission.output_rights {
                OutputRights::None => 0,
                OutputRights::Receive { output_count } => output_count.get(),
            };
            if admitted != expected {
                return Err(CoordinatorClientError::OutputCountMismatch {
                    client_index: admission.client_index,
                    admitted,
                    expected,
                });
            }
        }
        Ok(admission)
    }

    /// §9.E.1 step 2 over an already verified link (step 1, [`Self::connect`]): reads the
    /// execution's summary and refuses what a client that will submit `input_count` inputs will
    /// not join. Nothing is bound yet.
    ///
    /// A caller whose own checks depend on the slot it will hold — typed inputs and outputs,
    /// which the summary does not describe — makes them against every slot
    /// [`PendingAssociation::bindable_slots`] names before [`PendingAssociation::associate`],
    /// because an association is irrevocable: a client that associates and then refuses its
    /// slot holds it until the association deadline aborts the execution for everyone.
    pub async fn inspect<F, S>(
        &self,
        link: CoordinatorLink,
        input_count: u64,
    ) -> Result<PendingAssociation<'_, F, S>, CoordinatorClientError>
    where
        F: FftField,
        S: ShareBound<F, ValueType = F>,
    {
        let coord = OffChainCoordinatorClient::<F, S>::from_link(link, self.execution_id);
        let summary = coord.get_execution_summary().await?;
        self.check_summary(&summary, input_count)?;
        Ok(PendingAssociation {
            config: self,
            coord,
            summary,
            input_count,
        })
    }

    /// §9.E.1 steps 2–3 over an already verified link: [`Self::inspect`], then
    /// [`PendingAssociation::associate`], for a caller with no checks of its own to make on
    /// the slot. Stops before anything reaches a node.
    pub async fn associate<F, S>(
        &self,
        link: CoordinatorLink,
        input_count: u64,
    ) -> Result<AdmittedClient<'_, F, S>, CoordinatorClientError>
    where
        F: FftField,
        S: ShareBound<F, ValueType = F>,
    {
        self.inspect::<F, S>(link, input_count)
            .await?
            .associate()
            .await
    }

    /// §9.E.1 steps 2–7 over an already verified link (step 1, [`Self::connect`]).
    ///
    /// `inputs` are this client's values, one per admitted index, in order; a client of an
    /// output-only slot passes none.
    pub async fn run<F, S>(
        &self,
        link: CoordinatorLink,
        inputs: Vec<F>,
    ) -> Result<CoordinatorClientRun<F>, CoordinatorClientError>
    where
        F: FftField,
        S: ShareBound<F, ValueType = F>,
    {
        self.associate::<F, S>(link, inputs.len() as u64)
            .await?
            .complete(inputs)
            .await
    }

    /// Steps 1–7: [`Self::connect`], then [`Self::run`].
    pub async fn connect_and_run<F, S>(
        &self,
        inputs: Vec<F>,
    ) -> Result<CoordinatorClientRun<F>, CoordinatorClientError>
    where
        F: FftField,
        S: ShareBound<F, ValueType = F>,
    {
        let link = self.connect().await?;
        self.run::<F, S>(link, inputs).await
    }
}

/// Which client slot an association can bind, as the execution's summary settles it before
/// associating (§9.E.1 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindableSlots {
    /// The slot this client asks for, or the one its invitation names. The coordinator binds
    /// exactly it or refuses; an admission to any other slot is refused as
    /// [`CoordinatorClientError::SlotNotGranted`].
    Settled(ClientIndex),
    /// Open admission without a requested slot: the coordinator binds the lowest free slot,
    /// which can be any of these, so every one of them must accept this client.
    AnyOf(Vec<ClientIndex>),
    /// Pre-registration without a requested slot: the slot registered to this client's
    /// certificate. Association binds nothing new, and only the admission names the slot.
    Registered,
    /// The association will be refused with the coordinator's reason and bind nothing: the
    /// execution is aborted, or invitation admission was asked without an invitation.
    Nothing,
}

/// A client that has read and accepted the execution's summary (§9.E.1 step 2) and has not
/// associated yet.
pub struct PendingAssociation<'a, F, S>
where
    F: FftField,
    S: ShareBound<F>,
{
    config: &'a CoordinatorClientConfig,
    coord: OffChainCoordinatorClient<F, S>,
    summary: ExecutionSummary,
    input_count: u64,
}

impl<'a, F, S> PendingAssociation<'a, F, S>
where
    F: FftField,
    S: ShareBound<F, ValueType = F>,
{
    /// The summary this client read and accepted.
    pub fn summary(&self) -> &ExecutionSummary {
        &self.summary
    }

    /// Every slot the association can bind.
    pub fn bindable_slots(&self) -> BindableSlots {
        self.config.bindable_slots(&self.summary)
    }

    /// §9.E.1 step 3: associates, irrevocably, and checks the admission against the inputs and
    /// outputs this client has.
    pub async fn associate(self) -> Result<AdmittedClient<'a, F, S>, CoordinatorClientError> {
        let Self {
            config,
            mut coord,
            summary,
            input_count,
        } = self;
        let admission = config.admit(&mut coord, &summary, input_count).await?;
        Ok(AdmittedClient {
            config,
            coord,
            admission,
        })
    }
}

/// A client the coordinator has admitted (§9.E.1 step 3) that has sent nothing to any node yet.
pub struct AdmittedClient<'a, F, S>
where
    F: FftField,
    S: ShareBound<F>,
{
    config: &'a CoordinatorClientConfig,
    coord: OffChainCoordinatorClient<F, S>,
    admission: ClientAdmission,
}

impl<F, S> AdmittedClient<'_, F, S>
where
    F: FftField,
    S: ShareBound<F, ValueType = F>,
{
    /// The slot, input range and output rights this client was admitted to.
    pub fn admission(&self) -> &ClientAdmission {
        &self.admission
    }

    /// §9.E.1 steps 4–7 within the admission.
    ///
    /// `inputs` are this client's values, one per admitted index, in order; a client of an
    /// output-only slot passes none.
    pub async fn complete(
        self,
        inputs: Vec<F>,
    ) -> Result<CoordinatorClientRun<F>, CoordinatorClientError> {
        let Self {
            config,
            mut coord,
            admission,
        } = self;
        let admitted_inputs = admission.input_range.map_or(0, |range| range.count.get());
        let given = inputs.len() as u64;
        if admitted_inputs != given {
            return Err(CoordinatorClientError::InputCountMismatch {
                client_index: admission.client_index,
                count: admitted_inputs,
                given,
            });
        }
        let label = admission.client_index;
        eprintln!(
            "[client slot {label}] admitted to execution {}: inputs {}, outputs {}",
            config.execution_id,
            admission.input_range.map_or_else(
                || "none".to_owned(),
                |range| format!("{}..{}", range.start, range.end())
            ),
            match admission.output_rights {
                OutputRights::None => 0,
                OutputRights::Receive { output_count } => output_count.get(),
            }
        );

        if let Some(range) = admission.input_range {
            // Step 4: one reservation, exactly the admitted range, once reservations open.
            coord.wait_for_round(Round::InputMaskReservation).await?;
            let indices = (range.start..range.end()).collect::<Vec<_>>();
            eprintln!(
                "[client slot {label}] reserving {} input mask(s)",
                indices.len()
            );
            coord.reserve_mask_indices(&indices).await?;

            // Step 5: every leg pinned to a distinct member of the served roster.
            let node_rpc = NodeRPCClient::<F, S>::start_rpc_client_for_execution(
                coord.node_roster(),
                config.node_rpc_addresses.clone(),
                config.execution_id,
                config.cert_der.clone(),
                config.key_der.clone(),
            )
            .await
            .map_err(CoordinatorClientError::NodeRpc)?;

            // Step 6: the nodes release a mask only for a reservation the agreed admissions
            // name, and every mask is reconstructed by roster position.
            eprintln!(
                "[client slot {label}] waiting for {} assigned mask share(s)",
                range.count
            );
            let masks = node_rpc
                .receive_assigned_masks(range.start, range.count.get())
                .await?;
            let masked_inputs = inputs
                .into_iter()
                .zip(masks)
                .enumerate()
                .map(|(offset, (input, mask))| (range.start + offset as u64, input + mask))
                .collect::<Vec<_>>();
            coord.wait_for_round(Round::InputCollection).await?;
            eprintln!(
                "[client slot {label}] submitting {} masked input(s)",
                masked_inputs.len()
            );
            coord.send_masked_inputs(&masked_inputs).await?;
        }

        let outputs = match admission.output_rights {
            OutputRights::None => {
                eprintln!("[client slot {label}] done; no outputs admitted");
                Vec::new()
            }
            OutputRights::Receive { output_count } => {
                // Step 7: one signed item per node, reconstructed by position.
                eprintln!("[client slot {label}] waiting for {output_count} output(s)");
                coord.wait_for_round(Round::OutputDistribution).await?;
                coord.obtain_outputs().await?
            }
        };
        Ok(CoordinatorClientRun { admission, outputs })
    }
}

fn check_input_count(
    slot: ClientIndex,
    spec: &ClientSlotSpec,
    input_count: u64,
) -> Result<(), CoordinatorClientError> {
    if spec.input_count != input_count {
        return Err(CoordinatorClientError::InputCountMismatch {
            client_index: slot,
            count: spec.input_count,
            given: input_count,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_mpc_coordinator_shared::{ClientSlotTable, RegistrationNonce, MAX_INPUTS_PER_SLOT};

    const EXECUTION: ExecutionId = ExecutionId::from_bytes([7; 32]);

    fn config(request: AssociationRequest) -> CoordinatorClientConfig {
        CoordinatorClientConfig {
            coordinator: CoordinatorEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 9,
                pin: SpkiDer::from_certificate_der(
                    stoffel_mpc_coordinator_shared::self_signed_certs::server_cert()
                        .cert
                        .der(),
                )
                .unwrap(),
            },
            execution_id: EXECUTION,
            backend: MpcBackendKind::HoneyBadger,
            cert_der: Vec::new(),
            key_der: Vec::new(),
            node_rpc_addresses: Vec::new(),
            request,
            expected_roster_digest: None,
            expected_program_hash: None,
            expected_output_count: None,
        }
    }

    fn slot(input_count: u64, output_count: u64) -> ClientSlotSpec {
        ClientSlotSpec {
            input_count,
            output_count,
        }
    }

    fn summary(slots: Vec<ClientSlotSpec>, admission: AdmissionPolicyKind) -> ExecutionSummary {
        ExecutionSummary {
            execution_id: EXECUTION,
            registration_nonce: RegistrationNonce::from_bytes([1; 32]),
            program_hash: [3; 32],
            client_slots: ClientSlotTable::new(slots),
            admission,
            deadlines: None,
            round: Round::Preprocessing,
        }
    }

    fn open(slot: Option<u32>) -> AssociationRequest {
        AssociationRequest {
            slot: slot.map(ClientIndex),
            invitation: None,
        }
    }

    #[test]
    fn a_client_refuses_before_associating_what_it_was_not_asked_to_join() {
        let open_table = summary(vec![slot(1, 1), slot(2, 0)], AdmissionPolicyKind::Open);

        // A slot this client names must exist and take its inputs.
        assert!(config(open(Some(1))).check_summary(&open_table, 2).is_ok());
        let error = config(open(Some(1)))
            .check_summary(&open_table, 1)
            .unwrap_err();
        assert!(matches!(
            error,
            CoordinatorClientError::InputCountMismatch {
                client_index: ClientIndex(1),
                count: 2,
                given: 1
            }
        ));
        assert_eq!(
            error.to_string(),
            "client slot 1 takes 2 inputs, but --inputs has 1."
        );
        assert!(matches!(
            config(open(Some(2))).check_summary(&open_table, 1),
            Err(CoordinatorClientError::NoSuchSlot {
                slot: ClientIndex(2),
                capacity: 2,
                ..
            })
        ));

        // Under `Open` without a slot, every slot the coordinator could pick must fit.
        let error = config(open(None))
            .check_summary(&open_table, 1)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "execution {EXECUTION} has client slots of different shapes; pass --client-slot \
                 <index>."
            )
        );
        assert_eq!(error.exit_code(), 2);
        let uniform = summary(vec![slot(1, 0), slot(1, 0)], AdmissionPolicyKind::Open);
        assert!(config(open(None)).check_summary(&uniform, 1).is_ok());
        assert!(config(open(None)).check_summary(&uniform, 2).is_err());

        // Under `PreRegistered` the slot is bound at registration: checked after association.
        let pre = summary(
            vec![slot(1, 1), slot(2, 0)],
            AdmissionPolicyKind::PreRegistered,
        );
        assert!(config(open(None)).check_summary(&pre, 5).is_ok());

        // Another program is refused by name, exit 2.
        let mut pinned = config(open(None));
        pinned.expected_program_hash = Some([4; 32]);
        let error = pinned.check_summary(&uniform, 1).unwrap_err();
        assert!(matches!(
            error,
            CoordinatorClientError::ProgramMismatch { .. }
        ));
        assert_eq!(error.exit_code(), 2);
        pinned.expected_program_hash = Some([3; 32]);
        assert!(pinned.check_summary(&uniform, 1).is_ok());

        // A slot table past its bounds is the coordinator's fault: exit 13.
        let oversized = summary(
            vec![slot(MAX_INPUTS_PER_SLOT + 1, 0)],
            AdmissionPolicyKind::Open,
        );
        let error = config(open(None)).check_summary(&oversized, 1).unwrap_err();
        assert!(matches!(error, CoordinatorClientError::SlotTable { .. }));
        assert_eq!(error.exit_code(), 13);

        // Another execution's summary is refused.
        let mut other = uniform.clone();
        other.execution_id = ExecutionId::from_bytes([8; 32]);
        assert!(matches!(
            config(open(None)).check_summary(&other, 1),
            Err(CoordinatorClientError::WrongExecution { .. })
        ));
    }

    /// The slots an association can bind, which a caller with slot-dependent checks of its
    /// own — the SDK's typed inputs and outputs — checks before associating.
    #[test]
    fn the_summary_names_every_slot_the_association_can_bind() {
        let table = vec![slot(1, 0), slot(1, 0), slot(1, 0)];
        let open_summary = summary(table.clone(), AdmissionPolicyKind::Open);

        // Under `Open` without a request the coordinator picks the lowest free slot: any of them.
        assert_eq!(
            config(open(None)).bindable_slots(&open_summary),
            BindableSlots::AnyOf(vec![ClientIndex(0), ClientIndex(1), ClientIndex(2)])
        );
        // A requested slot is bound exactly or refused.
        assert_eq!(
            config(open(Some(2))).bindable_slots(&open_summary),
            BindableSlots::Settled(ClientIndex(2))
        );
        // Under `PreRegistered` only the admission names the registered slot.
        let pre = summary(table.clone(), AdmissionPolicyKind::PreRegistered);
        assert_eq!(
            config(open(None)).bindable_slots(&pre),
            BindableSlots::Registered
        );
        assert_eq!(
            config(open(Some(1))).bindable_slots(&pre),
            BindableSlots::Settled(ClientIndex(1))
        );
        // An aborted execution binds nothing: the association names the reason.
        let mut aborted = open_summary.clone();
        aborted.round = Round::Aborted;
        assert_eq!(
            config(open(None)).bindable_slots(&aborted),
            BindableSlots::Nothing
        );
    }

    #[test]
    fn an_aborted_execution_is_left_to_the_association_that_names_its_reason() {
        let mut aborted = summary(vec![slot(1, 0), slot(2, 0)], AdmissionPolicyKind::Open);
        aborted.round = Round::Aborted;
        let mut pinned = config(open(None));
        pinned.expected_program_hash = Some([4; 32]);
        assert!(pinned.check_summary(&aborted, 7).is_ok());
    }
}
