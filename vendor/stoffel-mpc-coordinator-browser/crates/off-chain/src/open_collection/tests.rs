use super::*;
mod closure;
mod stop;
fn fr(value: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(
        &ark_bls12_381::Fr::from(value as u64),
        &mut bytes,
    )
    .unwrap();
    bytes
}
use p256::ecdsa::SigningKey;

fn key(seed: u8) -> ClientIdentity {
    SigningKey::from_bytes((&[seed; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn id() -> ExecutionId {
    ExecutionId::from_bytes([8; 32])
}
fn policy() -> OpenCollectionPolicy {
    OpenCollectionPolicy {
        execution_id: id(),
        owner: key(1),
        min_clients: 2,
        max_clients: 3,
        inputs_per_client: 2,
        approved_programs: [(2, [2; 32]), (3, [3; 32])].into(),
        min_output_shares: 3,
        deadline_unix_ms: None,
    }
}
fn setup() -> Arc<Mutex<CoordinatorRPCServerSharedBase>> {
    let mut shared =
        CoordinatorRPCServerSharedBase::new(3, 1, vec![key(10), key(11), key(12)]).unwrap();
    shared.register_open_collection(policy()).unwrap();
    Arc::new(Mutex::new(shared))
}
fn conn(
    shared: &Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    seed: u8,
) -> CoordinatorRPCServerConnectionBase {
    CoordinatorRPCServerConnectionBase::new(shared.clone(), key(seed))
}
async fn reserve_submit(shared: &Arc<Mutex<CoordinatorRPCServerSharedBase>>, seed: u8) {
    let c = conn(shared, seed);
    let rs = c.open_reserve(id()).await.unwrap();
    c.open_submit(
        id(),
        rs.iter().map(|r| r.reserved_index).collect(),
        vec![fr(seed); 2],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn fresh_identity_joins_while_existing_contributions_remain_accepted() {
    let s = setup();
    reserve_submit(&s, 2).await;
    reserve_submit(&s, 3).await;
    let status = conn(&s, 4).open_status(id()).await.unwrap();
    assert_eq!(status.accepted_clients, 2);
    assert_eq!(status.reserved_clients, 2);
    let late = conn(&s, 4).open_reserve(id()).await.unwrap();
    assert_eq!(
        late.iter().map(|r| r.reserved_index).collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(
        conn(&s, 1)
            .open_status(id())
            .await
            .unwrap()
            .accepted_clients,
        2
    );
    let frozen = conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap();
    assert_eq!(
        frozen.registration.input_assignment.clients,
        vec![key(2), key(3)]
    );
    assert_eq!(frozen.registration.n_inputs, 4);
    assert_eq!(frozen.registration.output_clients, vec![key(1)]);
    assert!(conn(&s, 4)
        .open_submit(id(), vec![4, 5], vec![fr(4); 2])
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_reservations_and_submissions_are_atomic_and_unique() {
    let s = setup();
    let a = conn(&s, 2);
    let b = conn(&s, 3);
    let c = conn(&s, 4);
    let (ar, br) = tokio::join!(a.open_reserve(id()), b.open_reserve(id()));
    let ai = ar
        .unwrap()
        .iter()
        .map(|r| r.reserved_index)
        .collect::<Vec<_>>();
    let bi = br
        .unwrap()
        .iter()
        .map(|r| r.reserved_index)
        .collect::<Vec<_>>();
    assert!(ai.iter().all(|i| !bi.contains(i)));
    let (a_result, b_result, c_result) = tokio::join!(
        a.open_submit(id(), ai, vec![fr(2); 2]),
        b.open_submit(id(), bi, vec![fr(3); 2]),
        c.open_reserve(id()),
    );
    assert!(a_result.is_ok() && b_result.is_ok() && c_result.is_ok());
    assert_eq!(a.open_status(id()).await.unwrap().accepted_clients, 2);
    let d = conn(&s, 5);
    assert!(d.open_reserve(id()).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freeze_submission_race_is_linearizable() {
    // Repeat real spawned races; hash-checked freeze may lose a count race and
    // safely leave collection open. A retry selects the newly approved count.
    for _ in 0..32 {
        let s = setup();
        reserve_submit(&s, 2).await;
        reserve_submit(&s, 3).await;
        conn(&s, 4).open_reserve(id()).await.unwrap();
        let submit = conn(&s, 4);
        let owner = conn(&s, 1);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let b = barrier.clone();
        let task = tokio::spawn(async move {
            b.wait().await;
            submit.open_submit(id(), vec![4, 5], vec![fr(4); 2]).await
        });
        barrier.wait().await;
        let freeze = owner.open_freeze(id(), [2; 32]).await;
        let submission = task.await.unwrap();
        match freeze {
            Ok(frozen) => {
                assert!(submission.is_err());
                assert_eq!(frozen.registration.n_inputs, 4);
                assert_eq!(owner.open_status(id()).await.unwrap().accepted_clients, 2);
            }
            Err(_) => {
                submission.unwrap();
                assert!(owner.open_status(id()).await.unwrap().frozen.is_none());
                assert_eq!(
                    owner
                        .open_freeze(id(), [3; 32])
                        .await
                        .unwrap()
                        .registration
                        .n_inputs,
                    6
                );
            }
        }
    }
}

#[tokio::test]
async fn below_minimum_reservations_and_invalid_vectors_do_not_count() {
    let s = setup();
    reserve_submit(&s, 2).await;
    let b = conn(&s, 3);
    b.open_reserve(id()).await.unwrap();
    assert!(b.open_submit(id(), vec![2], vec![fr(3)]).await.is_err());
    assert!(b
        .open_submit(id(), vec![2, 2], vec![fr(3); 2])
        .await
        .is_err());
    assert!(b
        .open_submit(id(), vec![2, 3], vec![vec![], fr(3)])
        .await
        .is_err());
    assert!(conn(&s, 1).open_freeze(id(), [2; 32]).await.is_err());
    assert_eq!(b.open_status(id()).await.unwrap().accepted_clients, 1);
    b.open_submit(id(), vec![2, 3], vec![fr(3); 2])
        .await
        .unwrap();
    assert!(b
        .open_submit(id(), vec![2, 3], vec![fr(3); 2])
        .await
        .is_err());
    conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap();
}

#[tokio::test]
async fn duplicate_keys_aliases_and_one_time_masks_are_rejected() {
    let s = setup();
    let a = conn(&s, 2);
    a.open_reserve(id()).await.unwrap();
    assert!(a.open_reserve(id()).await.is_err());
    let compressed = SigningKey::from_bytes((&[2; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert!(
        CoordinatorRPCServerConnectionBase::new(s.clone(), compressed)
            .open_reserve(id())
            .await
            .is_err()
    );
    let b = conn(&s, 3);
    b.open_reserve(id()).await.unwrap();
    assert!(b
        .open_submit(id(), vec![0, 1], vec![fr(3); 2])
        .await
        .is_err());
    assert!(conn(&s, 9)
        .open_submit(id(), vec![0, 1], vec![fr(9); 2])
        .await
        .is_err());
    assert_eq!(a.open_status(id()).await.unwrap().accepted_clients, 0);
}

#[tokio::test]
async fn unauthorized_owner_and_malicious_program_leave_collection_open() {
    let s = setup();
    reserve_submit(&s, 2).await;
    reserve_submit(&s, 3).await;
    assert!(conn(&s, 2).open_freeze(id(), [2; 32]).await.is_err());
    assert!(conn(&s, 1).open_freeze(id(), [99; 32]).await.is_err());
    assert!(conn(&s, 1).open_freeze(id(), [3; 32]).await.is_err());
    assert!(conn(&s, 1)
        .open_status(id())
        .await
        .unwrap()
        .frozen
        .is_none());
    let frozen = conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap();
    assert_eq!(
        conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap(),
        frozen
    );
    assert!(conn(&s, 1).open_freeze(id(), [3; 32]).await.is_err());
    assert!(conn(&s, 4).open_reserve(id()).await.is_err());
    assert!(conn(&s, 2)
        .open_submit(id(), vec![0, 1], vec![fr(2); 2])
        .await
        .is_err());
}

#[tokio::test]
async fn freeze_preserves_original_mask_indices_across_unsubmitted_gaps() {
    let s = setup();
    conn(&s, 2).open_reserve(id()).await.unwrap(); // Burned, never reassigned.
    reserve_submit(&s, 3).await;
    reserve_submit(&s, 4).await;
    let frozen = conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap();
    assert_eq!(
        frozen.registration.input_assignment.clients,
        vec![key(3), key(4)]
    );
    assert_eq!(
        frozen
            .input_mapping
            .iter()
            .map(|m| (m.original_index, m.client_slot, m.input_ordinal))
            .collect::<Vec<_>>(),
        vec![(2, 0, 0), (3, 0, 1), (4, 1, 0), (5, 1, 1)]
    );
    let party = conn(&s, 10);
    assert_eq!(party.open_reservations(id()).await.unwrap().len(), 6);
    let inputs = party.open_frozen_inputs(id()).await.unwrap();
    assert_eq!(
        inputs.iter().map(|e| e.reserved_index).collect::<Vec<_>>(),
        vec![2, 3, 4, 5]
    );
    assert_eq!(
        inputs
            .iter()
            .map(|e| e.masked_input.clone())
            .collect::<Vec<_>>(),
        vec![fr(3), fr(3), fr(4), fr(4)]
    );
}

#[tokio::test]
async fn protected_values_are_party_only_and_ciphertext_outputs_are_owner_only() {
    let s = setup();
    reserve_submit(&s, 2).await;
    reserve_submit(&s, 3).await;
    let owner = conn(&s, 1);
    let party = conn(&s, 10);
    assert!(party.open_frozen_inputs(id()).await.is_err());
    assert!(party
        .open_send_output(id(), (vec![1], vec![2]))
        .await
        .is_err());
    owner.open_freeze(id(), [2; 32]).await.unwrap();
    assert!(owner.open_frozen_inputs(id()).await.is_err());
    assert!(conn(&s, 2).open_frozen_inputs(id()).await.is_err());
    assert!(conn(&s, 2).open_reservations(id()).await.is_err());
    assert!(owner
        .open_send_output(id(), (vec![1], vec![2]))
        .await
        .is_err());
    party
        .open_send_output(id(), (vec![1], vec![2]))
        .await
        .unwrap();
    party
        .open_send_output(id(), (vec![1], vec![2]))
        .await
        .unwrap();
    assert_eq!(owner.open_output_shares(id()).await.unwrap(), None);
    conn(&s, 11)
        .open_send_output(id(), (vec![3], vec![4]))
        .await
        .unwrap();
    conn(&s, 12)
        .open_send_output(id(), (vec![5], vec![6]))
        .await
        .unwrap();
    assert_eq!(
        owner.open_output_shares(id()).await.unwrap().unwrap().len(),
        3
    );
    assert!(conn(&s, 2).open_output_shares(id()).await.is_err());
    assert!(party.open_output_shares(id()).await.is_err());
    let json = serde_json::to_string(&owner.open_status(id()).await.unwrap()).unwrap();
    assert!(!json.contains("masked_input"));
    assert!(!json.contains("ciphertext"));
}

#[tokio::test]
async fn immutable_legacy_registration_and_open_policy_cannot_be_rewritten_or_crossed() {
    let s = setup();
    assert!(conn(&s, 1).open_register_policy(policy()).await.is_err());
    let mut changed = policy();
    changed.owner = key(2);
    assert!(conn(&s, 10).open_register_policy(changed).await.is_err());
    conn(&s, 10).open_register_policy(policy()).await.unwrap();
    let mut registration = ExecutionRegistration {
        execution_id: id(),
        program_hash: [2; 32],
        n_inputs: 2,
        output_clients: vec![key(1)],
        input_assignment: InputAssignment::default(),
        min_output_shares: 3,
    };
    assert!(s
        .lock()
        .await
        .register_execution(registration.clone())
        .is_err());
    registration.execution_id = ExecutionId::from_bytes([9; 32]);
    s.lock()
        .await
        .register_execution(registration.clone())
        .unwrap();
    s.lock()
        .await
        .register_execution(registration.clone())
        .unwrap();
    let mut changed = registration.clone();
    changed.input_assignment = InputAssignment {
        clients: vec![key(2)],
        ranges: vec![InputClientRange {
            client_index: 0,
            count: 2,
        }],
    };
    assert!(s.lock().await.register_execution(changed).is_err());
    let mut p = policy();
    p.execution_id = registration.execution_id;
    assert!(s.lock().await.register_open_collection(p).is_err());
    assert!(conn(&s, 2)
        .open_reserve(registration.execution_id)
        .await
        .is_err());
    assert!(conn(&s, 2)
        .reserve_mask_indices(id(), vec![0, 1])
        .await
        .is_err());
}

#[tokio::test]
async fn no_input_or_reservation_can_be_transferred_between_executions() {
    let s = setup();
    reserve_submit(&s, 2).await;
    let other = ExecutionId::from_bytes([42; 32]);
    let mut p = policy();
    p.execution_id = other;
    s.lock().await.register_open_collection(p).unwrap();
    assert!(conn(&s, 2)
        .open_submit(other, vec![0, 1], vec![fr(2); 2])
        .await
        .is_err());
    assert_eq!(
        conn(&s, 1)
            .open_status(other)
            .await
            .unwrap()
            .accepted_clients,
        0
    );
    assert_eq!(
        conn(&s, 1)
            .open_status(id())
            .await
            .unwrap()
            .accepted_clients,
        1
    );
    assert!(conn(&s, 1).open_freeze(other, [2; 32]).await.is_err());
}

#[test]
fn invalid_privacy_bounds_program_sets_and_output_quorums_fail_closed() {
    for mutation in 0..9 {
        let mut shared =
            CoordinatorRPCServerSharedBase::new(3, 1, vec![key(10), key(11), key(12)]).unwrap();
        let mut p = policy();
        match mutation {
            0 => p.min_clients = 1,
            1 => p.max_clients = 1,
            2 => p.max_clients = MAX_OPEN_CLIENTS + 1,
            3 => p.inputs_per_client = u64::MAX,
            4 => p.min_output_shares = 2,
            5 => {
                p.approved_programs.remove(&2);
            }
            6 => {
                p.approved_programs.insert(2, [0; 32]);
            }
            7 => p.owner = vec![1],
            _ => p.execution_id = ExecutionId::from_bytes([0; 32]),
        }
        assert!(
            shared.register_open_collection(p).is_err(),
            "mutation {mutation}"
        );
    }
}
