use super::{HoneyBadgerEngineConfig, HoneyBadgerMpcEngine, HoneyBadgerPreprocessingConfig};
use crate::net::engine_config::MpcSessionConfig;
use crate::net::mpc_engine::{DurableIdentityDigest, MpcEngine, MpcEngineConsensus, MpcPartyId};
use crate::net::reservation::ReservationRegistry;
use crate::storage::preproc::{
    self, LmdbPreprocStore, MaterialKind, PreprocBlob, PreprocKeyScope, PreprocStore,
};
use ark_ff::UniformRand;
use ark_std::rand::SeedableRng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::transports::quic::QuicNetworkManager;

fn next_instance_id() -> u64 {
    static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1_000_000);
    NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed)
}

fn test_engine(
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
) -> Arc<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>> {
    let session = MpcSessionConfig::try_new(
        instance_id,
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .expect("test topology should be valid")
    .with_open_message_router(open_message_router);
    let config = HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(1, 1));
    HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_config(config)
        .expect("engine construction should succeed")
}

fn open_exp_test_payload(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: Vec<u8>,
) -> Vec<u8> {
    crate::net::open_registry::encode_hb_open_exp_wire_message(
        instance_id,
        sender_party_id,
        share_id,
        &partial_point,
    )
    .expect("serialize test payload")
}

#[test]
fn robust_open_requires_full_bft_quorum() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    assert_eq!(Engine::robust_open_required_contributions(0), 1);
    assert_eq!(Engine::robust_open_required_contributions(1), 4);
    assert_eq!(Engine::robust_open_required_contributions(2), 7);
}

#[test]
fn robust_reconstruction_with_byzantine_share_rejects_two_t_plus_one_quorum() {
    let n = 4;
    let t = 1;
    let secret = ark_bls12_381::Fr::from(42u64);
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(138);
    let shares =
        RobustShare::compute_shares(secret, n, t, None, &mut rng).expect("valid robust shares");

    let mut insufficient = shares[..(2 * t + 1)].to_vec();
    insufficient[0] = RobustShare::new(
        insufficient[0].share[0] + ark_bls12_381::Fr::from(99u64),
        insufficient[0].id,
        insufficient[0].degree,
    );

    let insufficient_result = RobustShare::recover_secret(&insufficient, n, t);
    assert!(
        insufficient_result
            .as_ref()
            .map(|(_coeffs, recovered)| *recovered != secret)
            .unwrap_or(true),
        "2t + 1 shares must not be treated as enough to correct one Byzantine contribution"
    );

    let mut full_quorum = insufficient;
    full_quorum.push(shares[3].clone());
    let (_coeffs, recovered) =
        RobustShare::recover_secret(&full_quorum, n, t).expect("3t + 1 shares recover");
    assert_eq!(recovered, secret);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preprocess_reserves_persistent_random_shares_when_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xA5; 32];
    let party_id = 0;
    let n = 4;
    let t = 1;
    let scope = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        DurableIdentityDigest::from_legacy_party_id(party_id),
    );
    let key = scope.key(MaterialKind::RandomShare);

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let shares: Vec<_> = (0..3)
        .map(|_| RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t))
        .collect();
    let (data, item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    store
        .store(
            &key,
            &PreprocBlob::try_new(data, item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();

    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        party_id,
        n,
        t,
    );
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();

    engine.preprocess().await.unwrap();

    assert_eq!(
        store.available(&key).await.unwrap(),
        0,
        "persistent random shares loaded into the runtime pool must be consumed"
    );
    assert!(
        store.load(&key).await.unwrap().is_none(),
        "consumed persistent random shares should be evicted after preload"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_mask_share_reserves_requested_persistent_index_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0x5A; 32];
    let party_id = 0;
    let n = 4;
    let t = 1;
    let scope = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        DurableIdentityDigest::from_legacy_party_id(party_id),
    );
    let key = scope.random_share();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(11);
    let shares: Vec<_> = (0..2)
        .map(|_| RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t))
        .collect();
    let (data, item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    store
        .store(
            &key,
            &PreprocBlob::try_new(data, item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();

    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        party_id,
        n,
        t,
    );
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();

    let reservation = engine.reservation_ops().unwrap();
    let first = reservation.get_mask_share(0).await.unwrap();
    assert!(!first.is_empty());
    assert_eq!(store.available(&key).await.unwrap(), 1);

    let err = reservation.get_mask_share(0).await.unwrap_err();
    assert!(
        err.to_string().contains("preprocessing cursor mismatch"),
        "unexpected error: {err}"
    );
    assert_eq!(
        store.available(&key).await.unwrap(),
        1,
        "rejected duplicate mask retrieval must not consume another share"
    );

    let second = reservation.get_mask_share(1).await.unwrap();
    assert!(!second.is_empty());
    assert_eq!(store.available(&key).await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserve_masks_persists_registry_cursor_for_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0x9B; 32];
    let party_id = 0;
    let n = 4;
    let t = 1;

    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        party_id,
        n,
        t,
    );
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();
    let reservations = engine.reservation_ops().unwrap();
    reservations
        .init_reservations(program_hash, 5)
        .await
        .unwrap();
    let first = reservations.reserve_masks(42, 2).await.unwrap();
    assert_eq!(first.start, 0);
    assert_eq!(first.count, 2);

    let restarted = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        party_id,
        n,
        t,
    );
    restarted
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store, program_hash)
        .unwrap();
    let restarted_reservations = restarted.reservation_ops().unwrap();
    restarted_reservations
        .init_reservations(program_hash, 5)
        .await
        .unwrap();

    assert_eq!(restarted_reservations.available_masks().await, 3);
    let second = restarted_reservations.reserve_masks(43, 1).await.unwrap();
    assert_eq!(
        second.start, 2,
        "restart must not reallocate previously reserved mask indices"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consume_masked_inputs_evicts_fully_used_persistent_masks() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0x6C; 32];
    let party_id = 0;
    let n = 4;
    let t = 1;
    let scope = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        DurableIdentityDigest::from_legacy_party_id(party_id),
    );
    let key = scope.random_share();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(19);
    let shares = vec![RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t)];
    let (data, item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    store
        .store(
            &key,
            &PreprocBlob::try_new(data, item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();

    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        party_id,
        n,
        t,
    );
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();
    let reservations = engine.reservation_ops().unwrap();
    reservations
        .init_reservations(program_hash, 5)
        .await
        .unwrap();
    let grant = reservations.reserve_masks(42, 1).await.unwrap();
    assert_eq!(grant.start, 0);

    let mask_share = reservations.get_mask_share(0).await.unwrap();
    assert_eq!(store.available(&key).await.unwrap(), 0);
    assert!(
        store.load(&key).await.unwrap().is_some(),
        "mask data must remain available until masked input consumption"
    );

    reservations
        .submit_masked_input(42, 0, mask_share)
        .await
        .unwrap();
    let unmasked = reservations.consume_masked_inputs(&[0]).await.unwrap();
    assert_eq!(unmasked.len(), 1);
    assert!(
        store.load(&key).await.unwrap().is_none(),
        "fully consumed persistent masks should be evicted after use"
    );

    let restored = ReservationRegistry::load(
        store.as_ref(),
        &program_hash,
        DurableIdentityDigest::from_legacy_party_id(party_id),
    )
    .await
    .unwrap()
    .unwrap();
    let snapshot = restored.snapshot().await;
    assert!(
        snapshot.masked_inputs.is_empty(),
        "consumed masked input payloads should be evicted from persisted reservation state"
    );
}

#[test]
fn rbc_receive_delivers_new_broadcast_each_call_in_order() {
    let instance_id = next_instance_id();
    let n = 4;
    let t = 1;
    let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
    let sender = test_engine(router.clone(), instance_id, 0, n, t);
    let receiver = test_engine(router, instance_id, 1, n, t);

    sender.rbc_broadcast(b"first").expect("broadcast first");
    sender.rbc_broadcast(b"second").expect("broadcast second");

    let first = receiver
        .rbc_receive(MpcPartyId::new(0), 50)
        .expect("receive first");
    let second = receiver
        .rbc_receive(MpcPartyId::new(0), 50)
        .expect("receive second");

    assert_eq!(
        first, b"first",
        "first receive should return first broadcast"
    );
    assert_eq!(
        second, b"second",
        "second receive should return second broadcast"
    );
}

#[test]
fn open_exp_wire_rejects_mismatched_share_id() {
    let instance_id = next_instance_id();
    let router = crate::net::open_registry::OpenMessageRouter::new();
    let registry = router.register_instance(instance_id);
    let payload = open_exp_test_payload(instance_id, 1, 0, vec![1, 2, 3, 4]);

    let err = router
        .try_handle_hb_open_exp_wire_message(1, &payload)
        .expect_err("mismatched share_id must be rejected");
    assert!(
        err.contains("open-exp share_id mismatch"),
        "unexpected error: {}",
        err
    );
    assert!(
        !registry.exp.lock().contains_key(&0),
        "rejected payload must not be inserted into the registry"
    );
}

#[test]
fn open_exp_wire_accepts_matching_share_id() {
    let instance_id = next_instance_id();
    let router = crate::net::open_registry::OpenMessageRouter::new();
    let registry = router.register_instance(instance_id);
    let payload = open_exp_test_payload(instance_id, 1, 1, vec![9, 8, 7, 6]);

    let handled = router
        .try_handle_hb_open_exp_wire_message(1, &payload)
        .expect("matching sender/share is valid");
    assert!(handled, "open-exp prefix payload must be handled");

    let reg = registry.exp.lock();
    let entry = reg
        .get(&0)
        .expect("entry should be inserted for valid payload");
    assert_eq!(entry.party_ids, vec![1]);
    assert_eq!(entry.partial_points, vec![(1, vec![9, 8, 7, 6])]);
}
