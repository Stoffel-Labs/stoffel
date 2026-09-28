//! Node-side checks of what the coordinator serves (`docs/design/bootnode-elimination.md`
//! §9.D.6, §9.D.7).
//!
//! The coordinator is the admission authority: it alone decides which identity holds which
//! client slot. It is not trusted to tell every node the same thing, nor to relay what it
//! decided faithfully. A node therefore
//!
//! * checks the execution summary against what it loaded before preprocessing
//!   ([`check_execution_summary`]);
//! * agrees the summary and the frozen [`ClientAdmissionSet`] with every other node of its mesh
//!   before it releases anything ([`admission_agreement_digest`], carried by the
//!   `AdmissionsAgreed` digest barrier);
//! * releases mask shares only for reservations that set implies
//!   ([`reservations_matching_admissions`]);
//! * accepts masked inputs only as the agreed set implies them, signed by the agreed identity
//!   ([`submissions_matching_admissions`]), and agrees them with every other node before it
//!   unmasks any ([`inputs_agreement_digest`], carried by the `InputsAgreed` barrier);
//! * stores inputs and sends outputs by the agreed `ClientIndex`
//!   ([`inputs_by_admission`], [`outputs_by_admission`]).
//!
//! The barriers detect a coordinator equivocating between nodes that share a roster and a mesh;
//! they cannot detect one that partitioned the nodes into different rosters (§9.G).

use std::collections::{BTreeMap, HashMap};

use ark_ff::FftField;
use stoffel_mpc_coordinator_off_chain::{
    admitted_reservations, AssignedMaskReservation, ExecutionSummary, MaskedInputSubmission,
};
use stoffel_mpc_coordinator_shared::{
    masked_inputs_signing_bytes, verify_identity_signature, AdmissionPolicyKind,
    ClientAdmissionRecord, ClientAdmissionSet, ClientIdentity, ClientIndex, ExecutionId,
    OutputRights, RegistrationError, ShareBound, MAX_SEALED_OUTPUT_BYTES,
};
use stoffel_vm::net::MpcBackendKind;
use stoffel_vm_types::compiled_binary::ClientIoManifest;

/// The blake3 key-derivation context of [`admission_agreement_digest`].
pub const ADMISSION_AGREEMENT_CONTEXT: &str = "stoffel-admission-agreement-v1";
/// The blake3 key-derivation context of [`inputs_agreement_digest`].
pub const INPUTS_AGREEMENT_CONTEXT: &str = "stoffel-inputs-agreement-v1";

/// What a node knows independently of the coordinator, checked against the summary it serves.
#[derive(Clone, Copy, Debug)]
pub struct SummaryExpectations<'a> {
    /// The execution this node asked for.
    pub execution_id: ExecutionId,
    /// `program_id_from_bytes` of the program this node loaded, which is `program_hash_of`.
    pub program_hash: [u8; 32],
    pub backend: MpcBackendKind,
    /// The mesh's party count and threshold.
    pub n: usize,
    pub t: usize,
    /// The loaded program's client IO manifest.
    pub manifest: &'a ClientIoManifest,
}

/// Why a node refuses a slot table the summary serves.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SlotTableRefusal {
    #[error(transparent)]
    Bounds(#[from] RegistrationError),
    #[error(
        "client slot {client_index} is registered for {registered} inputs, but the program \
         declares {declared}"
    )]
    InputCountDiffersFromManifest {
        client_index: ClientIndex,
        registered: u64,
        declared: u64,
    },
    #[error(
        "client slot {client_index} is registered for {registered} outputs, but the program \
         sends it {declared}"
    )]
    OutputCountBelowManifest {
        client_index: ClientIndex,
        registered: u64,
        declared: u64,
    },
}

/// `check_execution_summary` refused: the node must not preprocess for this execution.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SummaryMismatch {
    #[error(
        "the coordinator served the summary of execution {served} when asked for {requested}; \
         refusing to run it."
    )]
    WrongExecution {
        requested: ExecutionId,
        served: ExecutionId,
    },
    #[error(
        "execution {execution_id} is registered for program {}, but this node loaded {}; \
         refusing to run it.",
        hex::encode(served),
        hex::encode(local)
    )]
    ProgramMismatch {
        execution_id: ExecutionId,
        served: [u8; 32],
        local: [u8; 32],
    },
    #[error(
        "{} needs at least {required} nodes for threshold {t}, and the coordinator's roster has \
         {n}; refusing to run execution {execution_id}.",
        backend.name()
    )]
    TopologyUnsupported {
        execution_id: ExecutionId,
        backend: MpcBackendKind,
        n: usize,
        t: usize,
        required: usize,
    },
    #[error(
        "execution {execution_id} gives client slot {client_index} {output_count} outputs, \
         {bytes} bytes sealed under {}, above the {max}-byte bound; refusing to run it.",
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
    #[error("execution {execution_id} has a client slot table this node refuses: {reason}")]
    SlotTable {
        execution_id: ExecutionId,
        reason: SlotTableRefusal,
    },
}

/// `8 + output_count × share_len + 16`: a sealed vector of `output_count` shares, its length
/// prefix and the AES-GCM tag (§9.C.1).
fn sealed_outputs_bytes(output_count: u64, share_len: usize) -> u64 {
    8u64.saturating_add(output_count.saturating_mul(share_len as u64))
        .saturating_add(16)
}

/// §9.D.7 step 1: the summary, before any preprocessing. `S` is this node's share type, which
/// fixes the backend's minimum topology and its share length.
pub fn check_execution_summary<F, S>(
    summary: &ExecutionSummary,
    expected: &SummaryExpectations<'_>,
) -> Result<(), SummaryMismatch>
where
    F: FftField,
    S: ShareBound<F>,
{
    let execution_id = summary.execution_id;
    if execution_id != expected.execution_id {
        return Err(SummaryMismatch::WrongExecution {
            requested: expected.execution_id,
            served: execution_id,
        });
    }
    summary
        .client_slots
        .check_bounds()
        .map_err(|error| SummaryMismatch::SlotTable {
            execution_id,
            reason: error.into(),
        })?;
    if summary.program_hash != expected.program_hash {
        return Err(SummaryMismatch::ProgramMismatch {
            execution_id,
            served: summary.program_hash,
            local: expected.program_hash,
        });
    }
    let required = S::min_parties(expected.t);
    if expected.n < required {
        return Err(SummaryMismatch::TopologyUnsupported {
            execution_id,
            backend: expected.backend,
            n: expected.n,
            t: expected.t,
            required,
        });
    }
    let share_len = S::serialized_share_len(expected.t);
    for (position, slot) in summary.client_slots.slots().iter().enumerate() {
        if slot.output_count == 0 {
            continue;
        }
        let bytes = sealed_outputs_bytes(slot.output_count, share_len);
        if bytes > MAX_SEALED_OUTPUT_BYTES {
            return Err(SummaryMismatch::SealedOutputsTooLarge {
                execution_id,
                backend: expected.backend,
                client_index: ClientIndex(position as u32),
                output_count: slot.output_count,
                bytes,
                max: MAX_SEALED_OUTPUT_BYTES,
            });
        }
    }
    // Only slots both sides declare are compared, and that is deliberate in BOTH directions.
    //
    // A manifest slot the registration lacks is not an error: a program may use clients only
    // when `ClientStore.get_number_clients()` is non-zero (§9.F.1).
    //
    // A registration slot BEYOND the manifest is not an error either, and must not become one.
    // Stoffel supports programs with a dynamic number of input/output clients, so the manifest
    // is a lower bound on the client shape, not an exact description of it: an execution
    // registered for more client slots than the manifest names is the ordinary way to run such
    // a program. What is checked is that every slot the two sides SHARE agrees.
    for schema in &expected.manifest.clients {
        let Some(slot) = usize::try_from(schema.client_slot)
            .ok()
            .and_then(|position| summary.client_slots.slots().get(position))
        else {
            continue;
        };
        let client_index = ClientIndex(schema.client_slot as u32);
        let declared_inputs = schema.inputs.len() as u64;
        if slot.input_count != declared_inputs {
            return Err(SummaryMismatch::SlotTable {
                execution_id,
                reason: SlotTableRefusal::InputCountDiffersFromManifest {
                    client_index,
                    registered: slot.input_count,
                    declared: declared_inputs,
                },
            });
        }
        let declared_outputs = schema.outputs.len() as u64;
        if slot.output_count < declared_outputs {
            return Err(SummaryMismatch::SlotTable {
                execution_id,
                reason: SlotTableRefusal::OutputCountBelowManifest {
                    client_index,
                    registered: slot.output_count,
                    declared: declared_outputs,
                },
            });
        }
    }
    Ok(())
}

fn update_len(hasher: &mut blake3::Hasher, len: usize) {
    hasher.update(&(len as u64).to_le_bytes());
}

/// §9.D.6: the digest every node of a mesh must agree on before it releases a mask share. It
/// covers the summary the node provisioned from — all of it but `round` — and the frozen
/// admission set, so a coordinator that served different slot tables, nonces, policies or
/// admissions to nodes of one mesh is caught.
pub fn admission_agreement_digest(
    summary: &ExecutionSummary,
    set: &ClientAdmissionSet,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ADMISSION_AGREEMENT_CONTEXT);
    hasher.update(summary.execution_id.as_bytes());
    hasher.update(summary.registration_nonce.as_bytes());
    hasher.update(&summary.program_hash);
    match &summary.admission {
        AdmissionPolicyKind::PreRegistered => {
            hasher.update(&[0]);
        }
        AdmissionPolicyKind::Open => {
            hasher.update(&[1]);
        }
        AdmissionPolicyKind::Invitation { issuer } => {
            hasher.update(&[2]);
            let spki = issuer.spki().as_bytes();
            update_len(&mut hasher, spki.len());
            hasher.update(spki);
        }
    }
    match summary.deadlines {
        None => {
            hasher.update(&[0]);
        }
        Some(deadlines) => {
            hasher.update(&[1]);
            hasher.update(&deadlines.association.0.to_le_bytes());
            hasher.update(&deadlines.input.0.to_le_bytes());
        }
    }
    let slots = summary.client_slots.slots();
    update_len(&mut hasher, slots.len());
    for slot in slots {
        hasher.update(&slot.input_count.to_le_bytes());
        hasher.update(&slot.output_count.to_le_bytes());
    }
    let mut records: Vec<&ClientAdmissionRecord> = set.records.iter().collect();
    records.sort_by_key(|record| record.client_index);
    update_len(&mut hasher, records.len());
    for record in records {
        hasher.update(&record.client_index.0.to_le_bytes());
        update_len(&mut hasher, record.client.len());
        hasher.update(&record.client);
        match record.input_range {
            None => {
                hasher.update(&[0]);
            }
            Some(range) => {
                hasher.update(&[1]);
                hasher.update(&range.start.to_le_bytes());
                hasher.update(&range.count.get().to_le_bytes());
            }
        }
        match record.output_rights {
            OutputRights::None => {
                hasher.update(&[0]);
            }
            OutputRights::Receive { output_count } => {
                hasher.update(&[1]);
                hasher.update(&output_count.get().to_le_bytes());
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// §9.D.6: the digest every node of a mesh must agree on before it unmasks any input — the
/// submissions exactly as delivered, signatures included.
pub fn inputs_agreement_digest(
    execution_id: ExecutionId,
    submissions: &[MaskedInputSubmission],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(INPUTS_AGREEMENT_CONTEXT);
    hasher.update(execution_id.as_bytes());
    let mut ordered: Vec<&MaskedInputSubmission> = submissions.iter().collect();
    ordered.sort_by_key(|submission| submission.first_index);
    update_len(&mut hasher, ordered.len());
    for submission in ordered {
        hasher.update(&submission.first_index.to_le_bytes());
        update_len(&mut hasher, submission.client.len());
        hasher.update(&submission.client);
        update_len(&mut hasher, submission.masked_inputs.len());
        for input in &submission.masked_inputs {
            update_len(&mut hasher, input.len());
            hasher.update(input);
        }
        update_len(&mut hasher, submission.signature.len());
        hasher.update(&submission.signature);
    }
    *hasher.finalize().as_bytes()
}

/// How the delivered masked inputs differ from what the agreed admissions imply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MaskedInputReason {
    #[error("no submission covers its agreed input range")]
    MissingSubmission,
    #[error("the submission does not cover exactly its agreed input range")]
    RangeMismatch,
    #[error("the submission names another identity than the slot's agreed client")]
    UnexpectedClient,
    #[error("its signature was not made by the slot's agreed client")]
    BadSignature,
}

/// `submissions_matching_admissions` refused: no input may be unmasked or stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MaskedInputMismatch {
    #[error(
        "the coordinator delivered masked inputs for client slot {client_index} that the agreed \
         admissions do not match: {reason}; refusing to use any input."
    )]
    Slot {
        client_index: ClientIndex,
        reason: MaskedInputReason,
    },
    /// A submission starting where no agreed slot's range starts, or a second submission for
    /// a range already covered.
    #[error(
        "the coordinator delivered a masked input submission at index {first_index} that no \
         agreed admission implies; refusing to use any input."
    )]
    UnexpectedSubmission { first_index: u64 },
}

impl MaskedInputMismatch {
    fn slot(client_index: ClientIndex, reason: MaskedInputReason) -> Self {
        Self::Slot {
            client_index,
            reason,
        }
    }
}

/// §9.D.7 step 9: the submissions partition `0..summary.client_slots.n_inputs()` exactly along
/// the agreed input ranges, each submitted by its slot's agreed identity and signed by it over
/// the agreed nonce and slot — never over the coordinator's say-so.
pub fn submissions_matching_admissions(
    summary: &ExecutionSummary,
    set: &ClientAdmissionSet,
    submissions: &[MaskedInputSubmission],
) -> Result<(), MaskedInputMismatch> {
    let mut by_start: BTreeMap<u64, &MaskedInputSubmission> = BTreeMap::new();
    for submission in submissions {
        if by_start
            .insert(submission.first_index, submission)
            .is_some()
        {
            return Err(MaskedInputMismatch::UnexpectedSubmission {
                first_index: submission.first_index,
            });
        }
    }
    for position in 0..summary.client_slots.slots().len() {
        let client_index = ClientIndex(position as u32);
        let Some(range) = summary.client_slots.input_range(client_index) else {
            continue;
        };
        let record = set
            .records
            .iter()
            .find(|record| record.client_index == client_index)
            .ok_or(MaskedInputMismatch::slot(
                client_index,
                MaskedInputReason::MissingSubmission,
            ))?;
        if record.input_range != Some(range) {
            return Err(MaskedInputMismatch::slot(
                client_index,
                MaskedInputReason::RangeMismatch,
            ));
        }
        let submission = by_start
            .remove(&range.start)
            .ok_or(MaskedInputMismatch::slot(
                client_index,
                MaskedInputReason::MissingSubmission,
            ))?;
        if submission.masked_inputs.len() as u64 != range.count.get() {
            return Err(MaskedInputMismatch::slot(
                client_index,
                MaskedInputReason::RangeMismatch,
            ));
        }
        if submission.client != record.client {
            return Err(MaskedInputMismatch::slot(
                client_index,
                MaskedInputReason::UnexpectedClient,
            ));
        }
        let signing_bytes = masked_inputs_signing_bytes(
            summary.execution_id,
            summary.registration_nonce,
            client_index,
            submission.first_index,
            &submission.masked_inputs,
        );
        verify_identity_signature(&record.client, &signing_bytes, &submission.signature).map_err(
            |_| MaskedInputMismatch::slot(client_index, MaskedInputReason::BadSignature),
        )?;
    }
    if let Some(first_index) = by_start.keys().next() {
        return Err(MaskedInputMismatch::UnexpectedSubmission {
            first_index: *first_index,
        });
    }
    Ok(())
}

/// §9.D.7 step 10: unmasked inputs grouped by agreed `ClientIndex`, each slot's in
/// `input_ordinal` order. `unmasked` is `unmask_submissions`' output for submissions that
/// passed [`submissions_matching_admissions`]; an index no agreed range covers is dropped.
pub fn inputs_by_admission<S>(
    set: &ClientAdmissionSet,
    unmasked: Vec<(u64, ClientIdentity, S)>,
) -> BTreeMap<ClientIndex, Vec<S>> {
    let mut by_index: BTreeMap<u64, S> = unmasked
        .into_iter()
        .map(|(index, _, share)| (index, share))
        .collect();
    let mut grouped = BTreeMap::new();
    for record in &set.records {
        let Some(range) = record.input_range else {
            continue;
        };
        let shares: Vec<S> = (range.start..range.end())
            .filter_map(|index| by_index.remove(&index))
            .collect();
        grouped.insert(record.client_index, shares);
    }
    grouped
}

/// The program sent a client output the agreed admissions do not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OutputRightsViolation {
    #[error(
        "the program sent output to client slot {client_index}, which the registration gives no \
         output rights"
    )]
    NoOutputRights { client_index: u64 },
    #[error(
        "the program sent {sent} outputs to client slot {client_index}, which the registration \
         gives {admitted}"
    )]
    CountMismatch {
        client_index: ClientIndex,
        sent: u64,
        admitted: u64,
    },
}

/// §9.D.7 step 12: the program's captured client outputs — `(client slot, shares)` in the order
/// the program sent them — grouped by the agreed identity of each slot. Every slot sent to must
/// have output rights, and must have been sent exactly its admitted `output_count`. A slot with
/// output rights the program sends nothing to is not an error.
pub fn outputs_by_admission<S>(
    set: &ClientAdmissionSet,
    captured: impl IntoIterator<Item = (usize, Vec<S>)>,
) -> Result<Vec<(ClientIdentity, Vec<S>)>, OutputRightsViolation> {
    let mut by_slot: BTreeMap<u64, Vec<S>> = BTreeMap::new();
    for (slot, shares) in captured {
        by_slot.entry(slot as u64).or_default().extend(shares);
    }
    let mut outputs = Vec::with_capacity(by_slot.len());
    for (slot, shares) in by_slot {
        let record = u32::try_from(slot).ok().and_then(|index| {
            set.records
                .iter()
                .find(|record| record.client_index == ClientIndex(index))
        });
        let Some(record) = record else {
            return Err(OutputRightsViolation::NoOutputRights { client_index: slot });
        };
        let OutputRights::Receive { output_count } = record.output_rights else {
            return Err(OutputRightsViolation::NoOutputRights { client_index: slot });
        };
        if shares.len() as u64 != output_count.get() {
            return Err(OutputRightsViolation::CountMismatch {
                client_index: record.client_index,
                sent: shares.len() as u64,
                admitted: output_count.get(),
            });
        }
        outputs.push((record.client.clone(), shares));
    }
    Ok(outputs)
}

/// How a coordinator's reservations differ from the agreed admissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationMismatchKind {
    /// The reservation's identity holds no admitted input range.
    UnadmittedClient,
    /// The agreed set names the reservation's identity in more than one slot.
    AmbiguousClient { client_index: ClientIndex },
    /// The identity's reserved indices are not exactly its agreed input range.
    RangeMismatch { client_index: ClientIndex },
    /// An agreed input range has no reservation at all.
    Unreserved { client_index: ClientIndex },
}

/// `reservations_matching_admissions` refused: nothing may be released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "the coordinator's reservation for index {index} does not match the agreed client admissions"
)]
pub struct ReservationMismatch {
    /// The first index at which the reservations and the admissions disagree.
    pub index: u64,
    pub kind: ReservationMismatchKind,
}

/// The reservations a node registers for `set`, provided the coordinator's `reserved` indices
/// are exactly what `set` implies: every identity's reserved indices are exactly its agreed
/// `input_range`, and every agreed range is reserved. Each reservation's `input_ordinal` is
/// `reserved_index - input_range.start`, never derived from the reported indices.
pub fn reservations_matching_admissions(
    set: &ClientAdmissionSet,
    reserved: &HashMap<ClientIdentity, Vec<u64>>,
) -> Result<Vec<AssignedMaskReservation>, ReservationMismatch> {
    // Ascending by first reported index, so the refusal names the lowest offending index
    // independently of hash order.
    let mut reported: Vec<(u64, &ClientIdentity, Vec<u64>)> = reserved
        .iter()
        .map(|(client, indices)| {
            let mut sorted = indices.clone();
            sorted.sort_unstable();
            (sorted.first().copied().unwrap_or(0), client, sorted)
        })
        .collect();
    reported.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

    for (first, client, indices) in &reported {
        let mut records = set
            .records
            .iter()
            .filter(|record| record.client == **client);
        let Some(record) = records.next() else {
            return Err(ReservationMismatch {
                index: *first,
                kind: ReservationMismatchKind::UnadmittedClient,
            });
        };
        if let Some(duplicate) = records.next() {
            return Err(ReservationMismatch {
                index: *first,
                kind: ReservationMismatchKind::AmbiguousClient {
                    client_index: duplicate.client_index,
                },
            });
        }
        let Some(range) = record.input_range else {
            return Err(ReservationMismatch {
                index: *first,
                kind: ReservationMismatchKind::UnadmittedClient,
            });
        };
        if !range.is_exactly(indices) {
            let index = indices
                .iter()
                .enumerate()
                .find(|(offset, index)| range.start.checked_add(*offset as u64) != Some(**index))
                .map(|(_, index)| *index)
                .unwrap_or_else(|| {
                    range
                        .start
                        .saturating_add(indices.len() as u64)
                        .min(range.end())
                });
            return Err(ReservationMismatch {
                index,
                kind: ReservationMismatchKind::RangeMismatch {
                    client_index: record.client_index,
                },
            });
        }
    }

    if let Some((record, range)) = set
        .records
        .iter()
        .filter_map(|record| record.input_range.map(|range| (record, range)))
        .find(|(record, _)| !reserved.contains_key(&record.client))
    {
        return Err(ReservationMismatch {
            index: range.start,
            kind: ReservationMismatchKind::Unreserved {
                client_index: record.client_index,
            },
        });
    }

    Ok(admitted_reservations(set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use stoffel_mpc_coordinator_shared::{
        ClientAdmissionRecord, ExecutionId, InputRange, OutputRights,
    };

    fn record(client: u8, index: u32, range: Option<(u64, u64)>) -> ClientAdmissionRecord {
        ClientAdmissionRecord {
            client: vec![client; 65],
            client_index: ClientIndex(index),
            input_range: range.map(|(start, count)| InputRange {
                start,
                count: NonZeroU64::new(count).expect("nonzero test count"),
            }),
            output_rights: OutputRights::None,
        }
    }

    fn set(records: Vec<ClientAdmissionRecord>) -> ClientAdmissionSet {
        ClientAdmissionSet {
            execution_id: ExecutionId::from_bytes([7; 32]),
            records,
        }
    }

    fn reserved(entries: &[(u8, &[u64])]) -> HashMap<ClientIdentity, Vec<u64>> {
        entries
            .iter()
            .map(|(client, indices)| (vec![*client; 65], indices.to_vec()))
            .collect()
    }

    #[test]
    fn reservations_are_released_only_when_they_match_the_agreed_admissions() {
        let agreed = set(vec![
            record(1, 0, Some((0, 2))),
            record(2, 1, None),
            record(3, 2, Some((2, 3))),
        ]);

        // Reported out of order: ordinals still come from the agreed range starts.
        let released =
            reservations_matching_admissions(&agreed, &reserved(&[(3, &[4, 2, 3]), (1, &[1, 0])]))
                .expect("matching reservations are released");
        let ordinals: Vec<(u8, u64, u64)> = released
            .iter()
            .map(|r| (r.client[0], r.reserved_index, r.input_ordinal))
            .collect();
        assert_eq!(
            ordinals,
            vec![(1, 0, 0), (1, 1, 1), (3, 2, 0), (3, 3, 1), (3, 4, 2)]
        );

        // Another identity holding an admitted range.
        assert_eq!(
            reservations_matching_admissions(&agreed, &reserved(&[(9, &[0, 1]), (3, &[2, 3, 4])])),
            Err(ReservationMismatch {
                index: 0,
                kind: ReservationMismatchKind::UnadmittedClient,
            })
        );
        // An identity admitted without inputs.
        assert_eq!(
            reservations_matching_admissions(
                &agreed,
                &reserved(&[(1, &[0, 1]), (2, &[5]), (3, &[2, 3, 4])])
            ),
            Err(ReservationMismatch {
                index: 5,
                kind: ReservationMismatchKind::UnadmittedClient,
            })
        );
        // A partial range: the ordinal a `min()` rule would derive is not trusted.
        assert_eq!(
            reservations_matching_admissions(&agreed, &reserved(&[(1, &[0, 1]), (3, &[3, 4])])),
            Err(ReservationMismatch {
                index: 3,
                kind: ReservationMismatchKind::RangeMismatch {
                    client_index: ClientIndex(2),
                },
            })
        );
        // A shifted range of the right length.
        assert_eq!(
            reservations_matching_admissions(&agreed, &reserved(&[(1, &[1, 2]), (3, &[2, 3, 4])])),
            Err(ReservationMismatch {
                index: 1,
                kind: ReservationMismatchKind::RangeMismatch {
                    client_index: ClientIndex(0),
                },
            })
        );
        // A range reserved one index too long.
        assert_eq!(
            reservations_matching_admissions(
                &agreed,
                &reserved(&[(1, &[0, 1]), (3, &[2, 3, 4, 5])])
            ),
            Err(ReservationMismatch {
                index: 5,
                kind: ReservationMismatchKind::RangeMismatch {
                    client_index: ClientIndex(2),
                },
            })
        );
        // An agreed range nobody reserved.
        assert_eq!(
            reservations_matching_admissions(&agreed, &reserved(&[(1, &[0, 1])])),
            Err(ReservationMismatch {
                index: 2,
                kind: ReservationMismatchKind::Unreserved {
                    client_index: ClientIndex(2),
                },
            })
        );
        // One identity named in two slots.
        let ambiguous = set(vec![record(1, 0, Some((0, 1))), record(1, 1, Some((1, 1)))]);
        assert_eq!(
            reservations_matching_admissions(&ambiguous, &reserved(&[(1, &[0])])),
            Err(ReservationMismatch {
                index: 0,
                kind: ReservationMismatchKind::AmbiguousClient {
                    client_index: ClientIndex(1),
                },
            })
        );
        // No inputs admitted and none reserved.
        assert_eq!(
            reservations_matching_admissions(&set(vec![record(2, 0, None)]), &HashMap::new()),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_reservation_mismatch_names_its_index() {
        let error = ReservationMismatch {
            index: 4,
            kind: ReservationMismatchKind::UnadmittedClient,
        };
        assert_eq!(
            error.to_string(),
            "the coordinator's reservation for index 4 does not match the agreed client admissions"
        );
    }
    mod summary_and_agreement {
        use super::super::*;
        use ark_bls12_381::{Fr, G1Projective};
        use std::num::NonZeroU64;
        use stoffel_mpc_coordinator_shared::self_signed_certs;
        use stoffel_mpc_coordinator_shared::{
            sign_with_pkcs8, ClientSlotSpec, ClientSlotTable, ExecutionDeadlines, InputRange,
            KeyAlgorithm, RegistrationNonce, Round, SpkiDer, UnixSeconds,
        };
        use stoffel_vm_types::compiled_binary::ClientIoSchema;
        use stoffel_vm_types::core_types::ShareType;
        use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
        use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

        type Hb = RobustShare<Fr>;
        type Avss = FeldmanShamirShare<Fr, G1Projective>;

        const EXECUTION: ExecutionId = ExecutionId::from_bytes([7; 32]);
        const PROGRAM: [u8; 32] = [9; 32];

        fn summary(slots: &[(u64, u64)]) -> ExecutionSummary {
            ExecutionSummary {
                execution_id: EXECUTION,
                registration_nonce: RegistrationNonce::from_bytes([3; 32]),
                program_hash: PROGRAM,
                client_slots: ClientSlotTable::new(
                    slots
                        .iter()
                        .map(|(input_count, output_count)| ClientSlotSpec {
                            input_count: *input_count,
                            output_count: *output_count,
                        })
                        .collect(),
                ),
                admission: AdmissionPolicyKind::PreRegistered,
                deadlines: None,
                round: Round::Idle,
            }
        }

        fn expectations(manifest: &ClientIoManifest) -> SummaryExpectations<'_> {
            SummaryExpectations {
                execution_id: EXECUTION,
                program_hash: PROGRAM,
                backend: MpcBackendKind::HoneyBadger,
                n: 5,
                t: 1,
                manifest,
            }
        }

        fn schema(slot: u64, inputs: usize, outputs: usize) -> ClientIoSchema {
            ClientIoSchema {
                client_slot: slot,
                inputs: vec![ShareType::default_secret_int(); inputs],
                outputs: vec![ShareType::default_secret_int(); outputs],
            }
        }

        #[test]
        fn a_summary_for_this_execution_program_topology_and_manifest_passes() {
            let manifest = ClientIoManifest {
                clients: vec![schema(0, 1, 1), schema(3, 2, 0)],
                ..Default::default()
            };
            // Slot 3 is declared by the program but not registered: not an error.
            check_execution_summary::<Fr, Hb>(
                &summary(&[(1, 2), (2, 0)]),
                &expectations(&manifest),
            )
            .expect("a matching summary passes");
        }

        #[test]
        fn a_summary_is_refused_for_every_mismatch_it_can_carry() {
            let manifest = ClientIoManifest::default();
            let mut other_execution = summary(&[(1, 0)]);
            other_execution.execution_id = ExecutionId::from_bytes([8; 32]);
            assert!(matches!(
                check_execution_summary::<Fr, Hb>(&other_execution, &expectations(&manifest)),
                Err(SummaryMismatch::WrongExecution { .. })
            ));

            let mut other_program = summary(&[(1, 0)]);
            other_program.program_hash = [1; 32];
            let error = check_execution_summary::<Fr, Hb>(&other_program, &expectations(&manifest))
                .expect_err("another program");
            assert_eq!(
                error.to_string(),
                format!(
                    "execution {EXECUTION} is registered for program {}, but this node loaded {}; \
                     refusing to run it.",
                    hex::encode([1u8; 32]),
                    hex::encode(PROGRAM)
                )
            );

            assert!(matches!(
                check_execution_summary::<Fr, Hb>(&summary(&[(0, 0)]), &expectations(&manifest)),
                Err(SummaryMismatch::SlotTable {
                    reason: SlotTableRefusal::Bounds(RegistrationError::EmptyClientSlot { .. }),
                    ..
                })
            ));

            // HoneyBadger needs 3t + 1 nodes; AVSS needs 2t + 1.
            let small = SummaryExpectations {
                n: 3,
                ..expectations(&manifest)
            };
            assert_eq!(
                check_execution_summary::<Fr, Hb>(&summary(&[(1, 0)]), &small),
                Err(SummaryMismatch::TopologyUnsupported {
                    execution_id: EXECUTION,
                    backend: MpcBackendKind::HoneyBadger,
                    n: 3,
                    t: 1,
                    required: 4,
                })
            );
            check_execution_summary::<Fr, Avss>(
                &summary(&[(1, 0)]),
                &SummaryExpectations {
                    backend: MpcBackendKind::Avss,
                    ..small
                },
            )
            .expect("three AVSS nodes suffice for t = 1");

            // A Feldman share carries t + 1 commitments, so a wide threshold makes the maximum
            // output count unsealable.
            let wide = SummaryExpectations {
                backend: MpcBackendKind::Avss,
                n: 201,
                t: 100,
                ..expectations(&manifest)
            };
            assert!(matches!(
                check_execution_summary::<Fr, Avss>(&summary(&[(0, 1024)]), &wide),
                Err(SummaryMismatch::SealedOutputsTooLarge {
                    client_index: ClientIndex(0),
                    output_count: 1024,
                    ..
                })
            ));

            let manifest = ClientIoManifest {
                clients: vec![schema(0, 2, 0)],
                ..Default::default()
            };
            assert!(matches!(
                check_execution_summary::<Fr, Hb>(&summary(&[(1, 0)]), &expectations(&manifest)),
                Err(SummaryMismatch::SlotTable {
                    reason: SlotTableRefusal::InputCountDiffersFromManifest {
                        registered: 1,
                        declared: 2,
                        ..
                    },
                    ..
                })
            ));
            let manifest = ClientIoManifest {
                clients: vec![schema(0, 1, 2)],
                ..Default::default()
            };
            assert!(matches!(
                check_execution_summary::<Fr, Hb>(&summary(&[(1, 1)]), &expectations(&manifest)),
                Err(SummaryMismatch::SlotTable {
                    reason: SlotTableRefusal::OutputCountBelowManifest {
                        registered: 1,
                        declared: 2,
                        ..
                    },
                    ..
                })
            ));
        }

        fn record(
            client: &ClientIdentity,
            index: u32,
            range: Option<(u64, u64)>,
            outputs: u64,
        ) -> ClientAdmissionRecord {
            ClientAdmissionRecord {
                client: client.clone(),
                client_index: ClientIndex(index),
                input_range: range.map(|(start, count)| InputRange {
                    start,
                    count: NonZeroU64::new(count).expect("nonzero count"),
                }),
                output_rights: NonZeroU64::new(outputs)
                    .map(|output_count| OutputRights::Receive { output_count })
                    .unwrap_or(OutputRights::None),
            }
        }

        #[test]
        fn the_admission_digest_has_the_documented_layout() {
            let agreed = summary(&[(2, 1)]);
            let client = vec![0xab; 65];
            let set = ClientAdmissionSet {
                execution_id: EXECUTION,
                records: vec![record(&client, 0, Some((0, 2)), 1)],
            };

            let mut hasher = blake3::Hasher::new_derive_key("stoffel-admission-agreement-v1");
            hasher.update(&[7; 32]);
            hasher.update(&[3; 32]);
            hasher.update(&PROGRAM);
            hasher.update(&[0]); // PreRegistered
            hasher.update(&[0]); // no deadlines
            hasher.update(&1u64.to_le_bytes());
            hasher.update(&2u64.to_le_bytes());
            hasher.update(&1u64.to_le_bytes());
            hasher.update(&1u64.to_le_bytes());
            hasher.update(&0u32.to_le_bytes());
            hasher.update(&65u64.to_le_bytes());
            hasher.update(&client);
            hasher.update(&[1]);
            hasher.update(&0u64.to_le_bytes());
            hasher.update(&2u64.to_le_bytes());
            hasher.update(&[1]);
            hasher.update(&1u64.to_le_bytes());
            assert_eq!(
                admission_agreement_digest(&agreed, &set),
                *hasher.finalize().as_bytes()
            );
        }

        #[test]
        fn the_admission_digest_covers_the_summary_and_every_record() {
            let agreed = summary(&[(1, 0), (0, 1)]);
            let (a, b) = (vec![1; 65], vec![2; 65]);
            let set = ClientAdmissionSet {
                execution_id: EXECUTION,
                records: vec![record(&a, 0, Some((0, 1)), 0), record(&b, 1, None, 1)],
            };
            let digest = admission_agreement_digest(&agreed, &set);

            let mut reordered = set.clone();
            reordered.records.reverse();
            assert_eq!(admission_agreement_digest(&agreed, &reordered), digest);

            let mut round = agreed.clone();
            round.round = Round::InputCollection;
            assert_eq!(
                admission_agreement_digest(&round, &set),
                digest,
                "the round is not agreed: nodes read the summary at different rounds"
            );

            let mut nonce = agreed.clone();
            nonce.registration_nonce = RegistrationNonce::from_bytes([4; 32]);
            let mut deadlines = agreed.clone();
            deadlines.deadlines = Some(ExecutionDeadlines {
                association: UnixSeconds(1),
                input: UnixSeconds(2),
            });
            let mut policy = agreed.clone();
            policy.admission = AdmissionPolicyKind::Open;
            let mut slots = agreed.clone();
            slots.client_slots = ClientSlotTable::new(vec![
                ClientSlotSpec {
                    input_count: 1,
                    output_count: 0,
                },
                ClientSlotSpec {
                    input_count: 0,
                    output_count: 2,
                },
            ]);
            for changed in [nonce, deadlines, policy, slots] {
                assert_ne!(admission_agreement_digest(&changed, &set), digest);
            }

            let mut swapped = set.clone();
            swapped.records[0].client = b.clone();
            swapped.records[1].client = a.clone();
            let mut rights = set.clone();
            rights.records[1].output_rights = OutputRights::None;
            let mut range = set.clone();
            range.records[0].input_range = None;
            for changed in [swapped, rights, range] {
                assert_ne!(admission_agreement_digest(&agreed, &changed), digest);
            }
        }

        struct Client {
            identity: ClientIdentity,
            pkcs8: Vec<u8>,
        }

        fn client() -> Client {
            let certified = self_signed_certs::client_cert();
            Client {
                identity: SpkiDer::from_certificate_der(certified.cert.der())
                    .expect("rcgen certificate")
                    .client_identity(),
                pkcs8: certified.signing_key.serialize_der(),
            }
        }

        fn submit(
            agreed: &ExecutionSummary,
            signer: &Client,
            as_client: &ClientIdentity,
            client_index: u32,
            first_index: u64,
            count: usize,
        ) -> MaskedInputSubmission {
            let masked_inputs: Vec<Vec<u8>> = (0..count)
                .map(|offset| vec![first_index as u8 + offset as u8; 32])
                .collect();
            let signature = sign_with_pkcs8(
                KeyAlgorithm::EcdsaP256,
                &signer.pkcs8,
                &masked_inputs_signing_bytes(
                    agreed.execution_id,
                    agreed.registration_nonce,
                    ClientIndex(client_index),
                    first_index,
                    &masked_inputs,
                ),
            )
            .expect("sign");
            MaskedInputSubmission {
                client: as_client.clone(),
                first_index,
                masked_inputs,
                signature,
            }
        }

        #[test]
        fn submissions_must_partition_the_agreed_ranges_as_the_agreed_clients_signed_them() {
            let agreed = summary(&[(2, 0), (0, 1), (1, 0)]);
            let (a, b, c) = (client(), client(), client());
            let set = ClientAdmissionSet {
                execution_id: EXECUTION,
                records: vec![
                    record(&a.identity, 0, Some((0, 2)), 0),
                    record(&b.identity, 1, None, 1),
                    record(&c.identity, 2, Some((2, 1)), 0),
                ],
            };
            let good = vec![
                submit(&agreed, &c, &c.identity, 2, 2, 1),
                submit(&agreed, &a, &a.identity, 0, 0, 2),
            ];
            submissions_matching_admissions(&agreed, &set, &good).expect("matching submissions");

            let slot = |index, reason| {
                Err(MaskedInputMismatch::Slot {
                    client_index: ClientIndex(index),
                    reason,
                })
            };
            assert_eq!(
                submissions_matching_admissions(&agreed, &set, &good[..1]),
                slot(0, MaskedInputReason::MissingSubmission)
            );
            assert_eq!(
                submissions_matching_admissions(
                    &agreed,
                    &set,
                    &[submit(&agreed, &a, &a.identity, 0, 0, 1), good[0].clone()]
                ),
                slot(0, MaskedInputReason::RangeMismatch)
            );
            // Client c signs and submits for a's range under a's slot: another identity.
            assert_eq!(
                submissions_matching_admissions(
                    &agreed,
                    &set,
                    &[submit(&agreed, &c, &c.identity, 0, 0, 2), good[0].clone()]
                ),
                slot(0, MaskedInputReason::UnexpectedClient)
            );
            // The coordinator relabels c's submission as a's: the signature is not a's.
            assert_eq!(
                submissions_matching_admissions(
                    &agreed,
                    &set,
                    &[submit(&agreed, &c, &a.identity, 0, 0, 2), good[0].clone()]
                ),
                slot(0, MaskedInputReason::BadSignature)
            );
            // Signed under another registration's nonce.
            let mut replayed = agreed.clone();
            replayed.registration_nonce = RegistrationNonce::from_bytes([5; 32]);
            assert_eq!(
                submissions_matching_admissions(
                    &agreed,
                    &set,
                    &[submit(&replayed, &a, &a.identity, 0, 0, 2), good[0].clone()]
                ),
                slot(0, MaskedInputReason::BadSignature)
            );
            let mut extra = good.clone();
            extra.push(submit(&agreed, &b, &b.identity, 1, 3, 1));
            assert_eq!(
                submissions_matching_admissions(&agreed, &set, &extra),
                Err(MaskedInputMismatch::UnexpectedSubmission { first_index: 3 })
            );
            let mut duplicate = good.clone();
            duplicate.push(good[1].clone());
            assert_eq!(
                submissions_matching_admissions(&agreed, &set, &duplicate),
                Err(MaskedInputMismatch::UnexpectedSubmission { first_index: 0 })
            );
            // An admission set whose range disagrees with the agreed slot table.
            let mut shifted = set.clone();
            shifted.records[2].input_range = Some(InputRange {
                start: 3,
                count: NonZeroU64::MIN,
            });
            assert_eq!(
                submissions_matching_admissions(&agreed, &shifted, &good),
                slot(2, MaskedInputReason::RangeMismatch)
            );
        }

        #[test]
        fn the_inputs_digest_covers_every_submission_as_delivered() {
            let agreed = summary(&[(1, 0), (1, 0)]);
            let (a, b) = (client(), client());
            let submissions = vec![
                submit(&agreed, &a, &a.identity, 0, 0, 1),
                submit(&agreed, &b, &b.identity, 1, 1, 1),
            ];
            let digest = inputs_agreement_digest(EXECUTION, &submissions);
            let mut reversed = submissions.clone();
            reversed.reverse();
            assert_eq!(inputs_agreement_digest(EXECUTION, &reversed), digest);
            assert_ne!(
                inputs_agreement_digest(ExecutionId::from_bytes([1; 32]), &submissions),
                digest
            );
            let mut resigned = submissions.clone();
            resigned[0].signature.push(0);
            let mut altered = submissions.clone();
            altered[1].masked_inputs[0][0] ^= 1;
            for changed in [resigned, altered, submissions[..1].to_vec()] {
                assert_ne!(inputs_agreement_digest(EXECUTION, &changed), digest);
            }
        }

        #[test]
        fn inputs_and_outputs_are_keyed_on_the_agreed_client_index() {
            let (a, b, c) = (vec![1; 65], vec![2; 65], vec![3; 65]);
            // A zero-input slot sits before an input slot: slot 2 is still slot 2.
            let set = ClientAdmissionSet {
                execution_id: EXECUTION,
                records: vec![
                    record(&a, 0, Some((0, 2)), 0),
                    record(&b, 1, None, 2),
                    record(&c, 2, Some((2, 1)), 1),
                ],
            };
            let grouped = inputs_by_admission(
                &set,
                vec![
                    (2, c.clone(), "c0"),
                    (1, a.clone(), "a1"),
                    (0, a.clone(), "a0"),
                ],
            );
            assert_eq!(
                grouped.into_iter().collect::<Vec<_>>(),
                vec![
                    (ClientIndex(0), vec!["a0", "a1"]),
                    (ClientIndex(2), vec!["c0"])
                ]
            );

            assert_eq!(
                outputs_by_admission(&set, vec![(1, vec!["x"]), (2, vec!["y"]), (1, vec!["z"])]),
                Ok(vec![(b.clone(), vec!["x", "z"]), (c.clone(), vec!["y"])])
            );
            assert_eq!(
                outputs_by_admission(&set, Vec::<(usize, Vec<&str>)>::new()),
                Ok(Vec::new()),
                "output rights the program does not use are not an error"
            );
            assert_eq!(
                outputs_by_admission(&set, vec![(0, vec!["x"])]),
                Err(OutputRightsViolation::NoOutputRights { client_index: 0 })
            );
            assert_eq!(
                outputs_by_admission(&set, vec![(7, vec!["x"])]),
                Err(OutputRightsViolation::NoOutputRights { client_index: 7 })
            );
            let error = outputs_by_admission(&set, vec![(1, vec!["x"])]).expect_err("one of two");
            assert_eq!(
                error.to_string(),
                "the program sent 1 outputs to client slot 1, which the registration gives 2"
            );
        }
    }
}
