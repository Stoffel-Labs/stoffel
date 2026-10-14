use super::*;

#[tokio::test]
async fn frozen_computation_and_partial_output_cannot_be_aborted() {
    let s = setup();
    reserve_submit(&s, 2).await;
    reserve_submit(&s, 3).await;
    let owner = conn(&s, 1);
    let party = conn(&s, 10);
    let frozen = owner.open_freeze(id(), [2; 32]).await.unwrap();
    for seed in [10, 11, 12] {
        assert!(conn(&s, seed).open_stop(id()).await.is_err());
    }
    assert_eq!(party.open_frozen_inputs(id()).await.unwrap().len(), 4);
    for seed in [10, 11] {
        conn(&s, seed)
            .open_send_output(id(), (vec![seed], vec![1]))
            .await
            .unwrap();
        assert!(party.open_stop(id()).await.is_err());
        assert!(owner.open_status(id()).await.unwrap().termination.is_none());
        assert_eq!(
            owner.open_status(id()).await.unwrap().frozen,
            Some(frozen.clone())
        );
    }
    conn(&s, 12)
        .open_send_output(id(), (vec![12], vec![1]))
        .await
        .unwrap();
    assert_eq!(
        party
            .open_encrypted_archive(id())
            .await
            .unwrap()
            .unwrap()
            .len(),
        3
    );
    let receipt = party.open_stop(id()).await.unwrap();
    assert_eq!(receipt.encrypted_output_shares, 3);
    assert_eq!(receipt.program_hash, Some([2; 32]));
}

#[tokio::test]
async fn prefrozen_abort_burns_id_and_blocks_every_lifecycle_data_plane() {
    let s = setup();
    reserve_submit(&s, 2).await;
    conn(&s, 3).open_reserve(id()).await.unwrap();
    let party = conn(&s, 10);
    let owner = conn(&s, 1);
    let receipt = party.open_stop(id()).await.unwrap();
    assert_eq!(receipt.accepted_clients, 1);
    assert_eq!(receipt.program_hash, None);
    assert_eq!(receipt.encrypted_output_shares, 0);
    assert_eq!(conn(&s, 11).open_stop(id()).await.unwrap(), receipt);
    assert!(conn(&s, 4).open_reserve(id()).await.is_err());
    assert!(conn(&s, 3)
        .open_submit(id(), vec![2, 3], vec![fr(3); 2])
        .await
        .is_err());
    assert!(party.open_reservations(id()).await.is_err());
    assert_eq!(party.open_accepted_metadata(id()).await.unwrap(), receipt.accepted_metadata);
    assert!(party.open_frozen_inputs(id()).await.is_err());
    assert!(party.open_freeze_eligible(id()).await.is_err());
    assert!(party.open_encrypted_archive(id()).await.is_err());
    assert!(party
        .open_send_output(id(), (vec![1], vec![2]))
        .await
        .is_err());
    assert!(owner.open_output_shares(id()).await.is_err());
    assert!(owner.open_freeze(id(), [2; 32]).await.is_err());
    assert!(owner
        .open_authorize_closure(
            id(),
            OpenClosureAuthorization {
                deadline_unix_ms: unix_ms() + 60_000,
                freeze_at_capacity: true,
            }
        )
        .await
        .is_err());
    assert!(party.open_register_policy(policy()).await.is_err());
    let status = owner.open_status(id()).await.unwrap();
    assert_eq!(status.termination, Some(receipt));
    assert!(status.own_indices.is_empty());
    assert_eq!(status.accepted_clients, 1);
    assert_eq!(status.reserved_clients, 0);
}

// Native RPC/state boundary tests, NOT an MPC computation test.
#[tokio::test]
async fn stop_retains_original_indices_and_historical_acceptance_after_clear() {
    let s = setup();
    conn(&s, 2).open_reserve(id()).await.unwrap(); // abandoned mask indices 0,1
    reserve_submit(&s, 3).await;
    let party = conn(&s, 10);
    let receipt = party.open_stop(id()).await.unwrap();
    assert_eq!(receipt.accepted_metadata, vec![OpenAcceptedMetadata {
        execution_id: id(), client: key(3), reserved_indices: vec![2,3],
    }]);
    assert!(conn(&s, 3).open_status(id()).await.unwrap().own_input_accepted);
    assert!(!conn(&s, 2).open_status(id()).await.unwrap().own_input_accepted);
    assert_eq!(conn(&s, 11).open_stop(id()).await.unwrap(), receipt);
    let locked = s.lock().await;
    let state = locked.open_collections.get(&id()).unwrap();
    assert!(state.inputs.is_empty() && state.clients.is_empty() && state.reservations.is_empty());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_stop_race_retains_exactly_the_linearized_acceptance() {
    for _ in 0..32 {
        let s = setup();
        let client = conn(&s, 2);
        client.open_reserve(id()).await.unwrap();
        let party = conn(&s, 10);
        let (submitted, stopped) = tokio::join!(
            client.open_submit(id(), vec![0,1], vec![fr(2);2]), party.open_stop(id()));
        let t = stopped.unwrap();
        assert_eq!(t.accepted_metadata.iter().any(|m| m.client == key(2)), submitted.is_ok());
        assert_eq!(t.accepted_clients as usize, t.accepted_metadata.len());
        assert_eq!(party.open_stop(id()).await.unwrap(), t);
        assert!(client.open_submit(id(), vec![0,1], vec![fr(2);2]).await.is_err());
    }
}
