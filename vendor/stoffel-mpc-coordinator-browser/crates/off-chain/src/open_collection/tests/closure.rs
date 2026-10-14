use super::*;

#[tokio::test]
async fn abandoned_reservation_does_not_consume_accepted_capacity() {
    let (s, d) = auto_setup();
    s.lock().await.open_collections.get_mut(&id()).unwrap().policy.inputs_per_client = 1;
    conn(&s, 1).open_authorize_closure_at(id(), permit(d), d - 1).await.unwrap();
    for seed in 2..5 {
        assert_eq!(conn(&s, seed).open_reserve(id()).await.unwrap()[0].reserved_index, u64::from(seed - 2));
    }
    conn(&s, 2).open_submit(id(), vec![0], vec![fr(2)]).await.unwrap();
    assert!(conn(&s, 10).open_freeze_eligible_at(id(), d).await.is_err());
    conn(&s, 4).open_submit(id(), vec![2], vec![fr(4)]).await.unwrap();
    assert!(conn(&s, 10).open_freeze_eligible_at(id(), d - 1).await.is_err());
    assert_eq!(conn(&s, 5).open_reserve(id()).await.unwrap()[0].reserved_index, 3);
    // Reserve another identity before reaching capacity: even its valid vector
    // must not become a fourth accepted input while automatic freeze polls.
    conn(&s, 6).open_reserve(id()).await.unwrap();
    conn(&s, 5).open_submit(id(), vec![3], vec![fr(5)]).await.unwrap();
    assert!(conn(&s, 6).open_submit(id(), vec![4], vec![fr(6)]).await.is_err());
    assert!(conn(&s, 3).open_submit(id(), vec![1], vec![fr(3)]).await.is_err());
    let frozen = conn(&s, 10).open_freeze_eligible_at(id(), d - 1).await.unwrap();
    assert_eq!(frozen.registration.n_inputs, 3);
    assert_eq!(frozen.registration.program_hash, [3; 32]);
    assert_eq!(frozen.input_mapping.iter().map(|m| m.original_index).collect::<Vec<_>>(), vec![0, 2, 3]);
    assert_eq!(frozen.input_mapping.iter().map(|m| m.client_slot).collect::<Vec<_>>(), vec![0, 1, 2]);
}

#[tokio::test]
async fn exhausted_one_time_budget_never_reuses_masks_or_freezes_below_minimum() {
    let (s, d) = auto_setup();
    conn(&s, 1).open_authorize_closure_at(id(), permit(d), d - 1).await.unwrap();
    let budget = policy().reservation_clients();
    assert_eq!(budget, 48);
    for slot in 0..budget {
        let rs = conn(&s, (slot + 20) as u8).open_reserve(id()).await.unwrap();
        assert_eq!(rs[0].reserved_index, u64::from(slot) * 2);
    }
    let exhausted = conn(&s, 99).open_reserve(id()).await.unwrap_err();
    assert!(exhausted.message().contains("reservation budget exhausted"));
    assert!(conn(&s, 10).open_freeze_eligible_at(id(), d).await.is_err());
    conn(&s, 20).open_submit(id(), vec![0, 1], vec![fr(20); 2]).await.unwrap();
    assert!(conn(&s, 10).open_freeze_eligible_at(id(), d).await.is_err());
    // Existing reservations may still submit after resource exhaustion.
    conn(&s, 67).open_submit(id(), vec![94, 95], vec![fr(67); 2]).await.unwrap();
    let f = conn(&s, 10).open_freeze_eligible_at(id(), d).await.unwrap();
    assert_eq!(f.registration.program_hash, [2; 32]);
    assert_eq!(f.registration.n_inputs, 4);
    assert_eq!(f.input_mapping.iter().map(|m| m.original_index).collect::<Vec<_>>(), vec![0, 1, 94, 95]);
}


#[tokio::test]
async fn authorization_clock_is_sampled_after_state_lock_not_before_queueing() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let (s, d) = auto_setup();
    let time = Arc::new(AtomicU64::new(d - 1));
    let sampled = Arc::new(AtomicBool::new(false));
    let guard = s.lock().await;
    let owner = conn(&s, 1);
    let clock_time = time.clone();
    let clock_sampled = sampled.clone();
    let task = tokio::spawn(async move {
        owner
            .open_authorize_closure_with_clock(id(), permit(d), || {
                clock_sampled.store(true, Ordering::SeqCst);
                clock_time.load(Ordering::SeqCst)
            })
            .await
    });
    tokio::task::yield_now().await;
    assert!(!sampled.load(Ordering::SeqCst));
    time.store(d, Ordering::SeqCst);
    drop(guard);
    assert!(task.await.unwrap().is_err());
    assert!(sampled.load(Ordering::SeqCst));
    assert!(conn(&s, 1)
        .open_status(id())
        .await
        .unwrap()
        .closure_authorization
        .is_none());
}

#[test]
fn bounded_deadline_exact_edges() {
    let now = 123_456;
    assert!(!valid_deadline(now, now));
    assert!(!valid_deadline(now - 1, now));
    assert!(valid_deadline(now + 1, now));
    assert!(valid_deadline(now + MAX_OPEN_CLOSURE_DELAY_MS, now));
    assert!(!valid_deadline(now + MAX_OPEN_CLOSURE_DELAY_MS + 1, now));
    assert!(!valid_deadline(u64::MAX, now));
}

#[tokio::test]
async fn deadline_closes_admission_and_auto_freeze_excludes_sparse_reservations() {
    let (s, d) = auto_setup();
    let owner = conn(&s, 1);
    owner
        .open_authorize_closure_at(id(), permit(d), d - 1)
        .await
        .unwrap();
    conn(&s, 2).open_reserve(id()).await.unwrap();
    reserve_submit(&s, 3).await;
    reserve_submit(&s, 4).await;
    // Deterministically advance the saved deadline, rather than sleep in a test.
    // The real reserve/submit RPCs read the wall clock while holding the lock.
    {
        let mut shared = s.lock().await;
        let state = shared.open_collections.get_mut(&id()).unwrap();
        state.policy.deadline_unix_ms = Some(unix_ms() - 1);
    }
    assert!(conn(&s, 2)
        .open_submit(id(), vec![0, 1], vec![fr(2); 2])
        .await
        .is_err());
    assert!(conn(&s, 5).open_reserve(id()).await.is_err());
    let party = conn(&s, 10);
    let metadata = party.open_accepted_metadata(id()).await.unwrap();
    assert_eq!(
        metadata
            .iter()
            .map(|m| m.reserved_indices.clone())
            .collect::<Vec<_>>(),
        vec![vec![2, 3], vec![4, 5]]
    );
    let frozen = party.open_freeze_eligible_at(id(), d).await.unwrap();
    assert_eq!(frozen.registration.program_hash, [2; 32]);
    assert_eq!(
        frozen.registration.input_assignment.clients,
        vec![key(3), key(4)]
    );
    assert_eq!(
        frozen
            .input_mapping
            .iter()
            .map(|m| (m.original_index, m.client_slot))
            .collect::<Vec<_>>(),
        vec![(2, 0), (3, 0), (4, 1), (5, 1)]
    );
}

#[test]
fn canonical_fr_accepts_zero_and_modulus_minus_one_but_no_alternate_encodings() {
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;
    let largest = -ark_bls12_381::Fr::from(1u64);
    let mut bytes = Vec::new();
    largest.serialize_compressed(&mut bytes).unwrap();
    assert_eq!(bytes.len(), 32);
    assert!(canonical_masked_fr(&bytes));
    assert!(canonical_masked_fr(&fr(0)));
    assert_eq!(fr(0), vec![0; 32]);
    assert!(ark_bls12_381::Fr::from_bigint(ark_bls12_381::Fr::MODULUS).is_none());
}

fn auto_setup() -> (Arc<Mutex<CoordinatorRPCServerSharedBase>>, u64) {
    let deadline = unix_ms() + 60_000;
    let mut p = policy();
    p.deadline_unix_ms = Some(deadline);
    let mut shared =
        CoordinatorRPCServerSharedBase::new(3, 1, vec![key(10), key(11), key(12)]).unwrap();
    shared.register_open_collection(p).unwrap();
    (Arc::new(Mutex::new(shared)), deadline)
}
fn permit(deadline: u64) -> OpenClosureAuthorization {
    OpenClosureAuthorization {
        deadline_unix_ms: deadline,
        freeze_at_capacity: true,
    }
}

#[tokio::test]
async fn closure_permit_is_owner_only_bounded_policy_bound_and_immutable() {
    let (s, d) = auto_setup();
    let owner = conn(&s, 1);
    let party = conn(&s, 10);
    assert!(party.open_freeze_eligible_at(id(), d).await.is_err());
    for seed in [2, 10, 99] {
        assert!(conn(&s, seed)
            .open_authorize_closure_at(id(), permit(d), d - 1)
            .await
            .is_err());
    }
    for (auth, now) in [
        (permit(d), d),
        (permit(d), d + 1),
        (permit(d), d - MAX_OPEN_CLOSURE_DELAY_MS - 1),
        (permit(d + 1), d - 1),
        (
            OpenClosureAuthorization {
                deadline_unix_ms: d,
                freeze_at_capacity: false,
            },
            d - 1,
        ),
    ] {
        assert!(owner
            .open_authorize_closure_at(id(), auth, now)
            .await
            .is_err());
    }
    assert_eq!(
        owner
            .open_authorize_closure_at(id(), permit(d), d - 1)
            .await
            .unwrap(),
        permit(d)
    );
    // Exact semantic retries work after deadline, with no deadline extension.
    assert_eq!(
        owner
            .open_authorize_closure_at(id(), permit(d), d + 1)
            .await
            .unwrap(),
        permit(d)
    );
    assert!(owner
        .open_authorize_closure_at(id(), permit(d + 1), d)
        .await
        .is_err());
    assert_eq!(
        owner.open_status(id()).await.unwrap().closure_authorization,
        Some(permit(d))
    );
    let manual = setup();
    assert!(conn(&manual, 1)
        .open_authorize_closure_at(id(), permit(d), d - 1)
        .await
        .is_err());
    let other = ExecutionId::from_bytes([88; 32]);
    let mut p = policy();
    p.execution_id = other;
    p.deadline_unix_ms = Some(d);
    s.lock().await.register_open_collection(p).unwrap();
    assert!(party.open_freeze_eligible_at(other, d).await.is_err());
}

#[tokio::test]
async fn auto_freeze_requires_accepted_capacity_or_deadline_and_enforces_minimum() {
    let (s, d) = auto_setup();
    conn(&s, 1)
        .open_authorize_closure_at(id(), permit(d), d - 1)
        .await
        .unwrap();
    reserve_submit(&s, 2).await;
    assert!(conn(&s, 10).open_freeze_eligible_at(id(), d).await.is_err());
    reserve_submit(&s, 3).await;
    conn(&s, 4).open_reserve(id()).await.unwrap();
    // Reserved capacity is not accepted capacity.
    assert!(conn(&s, 10)
        .open_freeze_eligible_at(id(), d - 1)
        .await
        .is_err());
    for seed in [1, 2, 99] {
        assert!(conn(&s, seed)
            .open_freeze_eligible_at(id(), d)
            .await
            .is_err());
    }
    let frozen = conn(&s, 10).open_freeze_eligible_at(id(), d).await.unwrap();
    assert_eq!(frozen.registration.program_hash, [2; 32]);
    for seed in [10, 11, 12] {
        assert_eq!(
            conn(&s, seed)
                .open_freeze_eligible_at(id(), d + 1)
                .await
                .unwrap(),
            frozen
        );
    }
    assert!(conn(&s, 4)
        .open_submit(id(), vec![4, 5], vec![fr(4); 2])
        .await
        .is_err());
    let (s, d) = auto_setup();
    conn(&s, 1)
        .open_authorize_closure_at(id(), permit(d), d - 1)
        .await
        .unwrap();
    for seed in [2, 3, 4] {
        reserve_submit(&s, seed).await;
    }
    assert_eq!(
        conn(&s, 10)
            .open_freeze_eligible_at(id(), d - 1)
            .await
            .unwrap()
            .registration
            .program_hash,
        [3; 32]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_freeze_sparse_roster_and_submission_race_selects_exact_program_under_lock() {
    for _ in 0..24 {
        let (s, d) = auto_setup();
        conn(&s, 1)
            .open_authorize_closure_at(id(), permit(d), d - 1)
            .await
            .unwrap();
        let last = conn(&s, 2);
        last.open_reserve(id()).await.unwrap(); // A gap until the racing submission.
        reserve_submit(&s, 3).await;
        reserve_submit(&s, 4).await;
        let party = conn(&s, 10);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let submit_barrier = barrier.clone();
        let submission_task = tokio::spawn(async move {
            submit_barrier.wait().await;
            last.open_submit(id(), vec![0, 1], vec![fr(2); 2]).await
        });
        barrier.wait().await;
        let frozen = party.open_freeze_eligible_at(id(), d).await.unwrap();
        let submission = submission_task.await.unwrap();
        let n = if submission.is_ok() { 3 } else { 2 };
        assert_eq!(frozen.registration.program_hash, [n as u8; 32]);
        assert_eq!(frozen.registration.n_inputs, n * 2);
        if n == 2 {
            assert_eq!(
                frozen
                    .input_mapping
                    .iter()
                    .map(|m| m.original_index)
                    .collect::<Vec<_>>(),
                vec![2, 3, 4, 5]
            );
        }
        assert_eq!(
            conn(&s, 11).open_freeze_eligible_at(id(), d).await.unwrap(),
            frozen
        );
        assert_eq!(
            party.open_frozen_inputs(id()).await.unwrap().len(),
            n as usize * 2
        );
    }
}

#[tokio::test]
async fn canonical_fr_rejection_is_atomic_and_does_not_satisfy_privacy_minimum() {
    use ark_ff::{BigInteger, PrimeField};
    let s = setup();
    reserve_submit(&s, 2).await;
    let b = conn(&s, 3);
    b.open_reserve(id()).await.unwrap();
    let mut trailing = fr(7);
    trailing.push(0);
    let mut twice = fr(7);
    twice.extend(fr(8));
    let modulus = ark_bls12_381::Fr::MODULUS.to_bytes_le();
    for bad in [
        vec![],
        vec![7],
        vec![0; 31],
        vec![255; 32],
        modulus,
        trailing,
        twice,
        vec![0; 1025],
    ] {
        assert!(b
            .open_submit(id(), vec![2, 3], vec![fr(0), bad])
            .await
            .is_err());
        assert_eq!(b.open_status(id()).await.unwrap().accepted_clients, 1);
        assert!(conn(&s, 1).open_freeze(id(), [2; 32]).await.is_err());
    }
    assert!(b
        .open_submit(id(), vec![3, 2], vec![fr(0), fr(1)])
        .await
        .is_err());
    b.open_submit(id(), vec![2, 3], vec![fr(0), fr(1)])
        .await
        .unwrap();
    assert_eq!(b.open_status(id()).await.unwrap().accepted_clients, 2);
    conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap();
}

#[tokio::test]
async fn public_receipts_encrypted_archive_exact_output_retry_and_retirement_tombstone() {
    let s = setup();
    reserve_submit(&s, 2).await;
    reserve_submit(&s, 3).await;
    let party = conn(&s, 10);
    for seed in [1, 2, 99] {
        assert!(conn(&s, seed).open_accepted_metadata(id()).await.is_err());
        assert!(conn(&s, seed).open_encrypted_archive(id()).await.is_err());
        assert!(conn(&s, seed).open_stop(id()).await.is_err());
    }
    let metadata = party.open_accepted_metadata(id()).await.unwrap();
    assert_eq!(metadata[0].client, key(2));
    assert_eq!(metadata[0].reserved_indices, vec![0, 1]);
    let encoded = serde_json::to_string(&metadata).unwrap();
    assert!(!encoded.contains("masked_input") && !encoded.contains("ciphertext"));
    conn(&s, 1).open_freeze(id(), [2; 32]).await.unwrap();
    let ciphertext = (vec![1, 2], vec![3, 4]);
    party
        .open_send_output(id(), ciphertext.clone())
        .await
        .unwrap();
    party
        .open_send_output(id(), ciphertext.clone())
        .await
        .unwrap();
    assert!(party
        .open_send_output(id(), (vec![1, 2], vec![5]))
        .await
        .is_err());
    assert_eq!(party.open_encrypted_archive(id()).await.unwrap(), None);
    for seed in [11, 12] {
        conn(&s, seed)
            .open_send_output(id(), ciphertext.clone())
            .await
            .unwrap();
    }
    let archive = party.open_encrypted_archive(id()).await.unwrap().unwrap();
    assert_eq!(archive.len(), 3);
    assert_eq!(archive[0].party, key(10).min(key(11)).min(key(12)));
    assert!(archive.iter().all(|share| share.ciphertext == ciphertext));
    let receipt = party.open_stop(id()).await.unwrap();
    assert_eq!(receipt.accepted_clients, 2);
    assert_eq!(receipt.program_hash, Some([2; 32]));
    assert_eq!(receipt.encrypted_output_shares, 3);
    assert_eq!(conn(&s, 11).open_stop(id()).await.unwrap(), receipt);
    assert_eq!(
        conn(&s, 1).open_status(id()).await.unwrap().termination,
        Some(receipt)
    );
    assert!(party.open_frozen_inputs(id()).await.is_err());
    assert!(party.open_reservations(id()).await.is_err());
    assert_eq!(party.open_accepted_metadata(id()).await.unwrap().len(), 2);
    assert!(party.open_encrypted_archive(id()).await.is_err());
    assert!(conn(&s, 1).open_output_shares(id()).await.is_err());
    assert!(party.open_send_output(id(), ciphertext).await.is_err());
    assert!(conn(&s, 4).open_reserve(id()).await.is_err());
    assert!(conn(&s, 2)
        .open_submit(id(), vec![0, 1], vec![fr(2); 2])
        .await
        .is_err());
    assert!(conn(&s, 1).open_freeze(id(), [2; 32]).await.is_err());
    assert!(s.lock().await.register_open_collection(policy()).is_err());
    assert!(s
        .lock()
        .await
        .register_execution(ExecutionRegistration {
            execution_id: id(),
            program_hash: [2; 32],
            n_inputs: 4,
            output_clients: vec![key(1)],
            input_assignment: InputAssignment::default(),
            min_output_shares: 3,
        })
        .is_err());
    let shared = s.lock().await;
    let state = shared.open_collections.get(&id()).unwrap();
    assert!(
        state.inputs.is_empty() && state.output_shares.is_empty() && state.reservations.is_empty()
    );
}

#[test]
fn policy_rejects_past_and_unbounded_deadlines() {
    for deadline in [
        0,
        unix_ms() - 1,
        unix_ms() + MAX_OPEN_CLOSURE_DELAY_MS + 60_000,
        u64::MAX,
    ] {
        let mut shared =
            CoordinatorRPCServerSharedBase::new(3, 1, vec![key(10), key(11), key(12)]).unwrap();
        let mut p = policy();
        p.deadline_unix_ms = Some(deadline);
        assert!(shared.register_open_collection(p).is_err());
    }
}
