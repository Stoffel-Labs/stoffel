use super::{HoneyBadgerEngineConfig, HoneyBadgerMpcEngine, HoneyBadgerPreprocessingConfig};
use crate::net::engine_config::{DeploymentMode, MpcSessionConfig};
use crate::net::mpc_engine::{
    AsyncMpcEngineConsensus, DurableIdentityDigest, MpcEngine, MpcEngineConsensus, MpcPartyId,
};
use crate::net::session::ExecutionId;
use crate::storage::preproc::{
    self, LmdbPreprocStore, MaterialKind, OwnedPreprocBundle, PoolAvailability, PreprocBlob,
    PreprocKeyScope, PreprocStore, TakenPreproc,
};
use ark_ff::UniformRand;
use ark_std::rand::SeedableRng;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::CertificateIdentity;
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
    test_engine_with_targets(
        open_message_router,
        instance_id,
        party_id,
        n,
        t,
        HoneyBadgerPreprocessingConfig::new(1, 1),
    )
}

/// [`test_engine`] for the tests whose subject is what this engine declares it
/// needs: `preprocess` runs the preprocessing protocol unless the pool covers
/// those counts, so a test that must not reach the network has to declare
/// counts its fixture can satisfy.
fn test_engine_with_targets(
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    preprocessing: HoneyBadgerPreprocessingConfig,
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
    let config = HoneyBadgerEngineConfig::new(session, preprocessing);
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
        0,
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
fn honeybadger_config_always_selects_execution_scoped_transport() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let one_shot = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        0,
        5,
        1,
    );
    assert_eq!(
        one_shot.execution_id(),
        crate::net::session::derive_execution_id_for_instance(one_shot.current_instance_id())
    );

    let execution_id = ExecutionId::from_bytes([0xC7; 32]);
    let session = MpcSessionConfig::try_new(
        next_instance_id(),
        0,
        5,
        1,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let scoped = Engine::from_config(HoneyBadgerEngineConfig::new(
        session,
        HoneyBadgerPreprocessingConfig::new(1, 1),
    ))
    .unwrap();
    assert_eq!(scoped.execution_id(), execution_id);
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

#[tokio::test]
async fn individual_random_reservations_transfer_the_upstream_vec_once_in_order() {
    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        0,
        5,
        1,
    );
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xCA_C4_E0);
    let shares = (0..8)
        .map(|_| RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, 1))
        .collect::<Vec<_>>();
    engine
        .clone_node()
        .await
        .preprocessing_material
        .lock()
        .await
        .add(None, None, Some(shares.clone()), None, None, None);

    for (index, expected) in shares.iter().enumerate() {
        let taken = engine.reserve_random_share().await.unwrap();
        assert_eq!(taken.share, expected.share);
        if index == 0 {
            assert_eq!(
                engine
                    .clone_node()
                    .await
                    .preprocessing_material
                    .lock()
                    .await
                    .length()
                    .random_shr,
                0,
                "the first reservation should move the complete upstream Vec"
            );
            assert_eq!(
                engine.random_share_cache.lock().await.len(),
                shares.len() - 1
            );
        }
    }
    assert!(engine.random_share_cache.lock().await.is_empty());
}

/// Scale regression for the `Share.random_field()` hot path. The user-facing
/// stress program executes exactly this many individual reservations. Keep it
/// ignored in the regular suite because its purpose is to validate the large
/// production workload explicitly, not to add a large allocation to every
/// unit-test run.
#[tokio::test]
#[ignore = "large 409,600-share regression workload"]
async fn random_field_program_scales_to_client_mask_workload() {
    const RANDOM_SHARE_COUNT: usize = 4_096 * 100;

    let source = r#"
def main() -> int64:
  var num_elements: int64 = 4096
  var num_clients: int64 = 100
  var i: int64 = 0

  while i < num_elements * num_clients:
    var s: Share = Share.random_field()
    i = i + 1
  return 0
"#;
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<random-field-stress>", &options)
        .expect("stress program should compile");
    let functions = stoffellang::convert_to_binary(&compiled)
        .try_to_vm_functions()
        .expect("stress program should decode");

    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        0,
        5,
        1,
    );
    let expected = RobustShare::new(ark_bls12_381::Fr::from(42_u64), 1, 1);
    engine
        .clone_node()
        .await
        .preprocessing_material
        .lock()
        .await
        .add(
            None,
            None,
            Some(vec![expected.clone(); RANDOM_SHARE_COUNT]),
            None,
            None,
            None,
        );
    engine.ready.store(true, Ordering::SeqCst);

    let mut vm = crate::core_vm::VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register stress program function");
    }
    let started = std::time::Instant::now();
    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("stress program should execute");
    eprintln!(
        "409,600 Share.random_field calls completed in {:?}",
        started.elapsed()
    );

    assert_eq!(result, stoffel_vm_types::core_types::Value::I64(0));
    assert!(engine.random_share_cache.lock().await.is_empty());
    assert_eq!(
        engine
            .clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .length()
            .random_shr,
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preprocess_reserves_persistent_random_shares_when_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xA5; 32];
    let party_id = 0;
    let n = 5;
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
        .seed_items(
            &key,
            &PreprocBlob::try_new(data, item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();

    // This execution needs exactly the three random shares the store holds
    // and no multiplications, so the load covers it and `preprocess` returns
    // without a preprocessing round. Declaring a triple it cannot load would
    // make the engine generate the shortfall, which needs the network: see
    // `a_load_that_does_not_cover_the_targets_is_not_full_provisioning` in
    // `preprocessing::persisted_item_identity_tests`.
    let engine = test_engine_with_targets(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        party_id,
        n,
        t,
        HoneyBadgerPreprocessingConfig::new(0, shares.len()),
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
async fn standing_mask_reservation_reads_owned_preprocessing_bundle() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xD3; 32];
    let execution_id = ExecutionId::from_bytes([0xE4; 32]);
    let party_id = 0;
    let n = 5;
    let t = 1;
    let identity = DurableIdentityDigest::from_legacy_party_id(party_id);
    let scope = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    let key = scope.random_share();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(31);
    let shares: Vec<_> = (0..3)
        .map(|_| RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t))
        .collect();
    let (data, item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    store
        .seed_items(
            &key,
            &PreprocBlob::try_new(data, item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();
    // Remove one share the way production draws from a reservoir, so the two
    // the store still holds are what the assertions below are about.
    store
        .take_bundle_from_reservoir(
            &scope,
            PoolAvailability {
                random: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let session = MpcSessionConfig::try_new(
        next_instance_id(),
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let engine = Engine::from_config(
        HoneyBadgerEngineConfig::new(
            session,
            HoneyBadgerPreprocessingConfig::new(0, shares.len()),
        )
        .with_deployment_mode(DeploymentMode::Standing),
    )
    .unwrap();
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();
    let admitted_client = DurableIdentityDigest::from_certificate_identity(
        CertificateIdentity::from_bytes([0xA5; 32]),
    );
    engine
        .install_standing_client_identities(BTreeMap::from([(0, admitted_client)]))
        .await
        .unwrap();
    let (bundle_data, bundle_item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    engine
        .activate_preallocated_standing(OwnedPreprocBundle {
            random: Some(TakenPreproc {
                count: shares.len() as u32,
                item_size: bundle_item_size,
                data: bundle_data,
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    let reservation = engine.reservation_ops().unwrap();
    reservation
        .init_reservations(program_hash, 1)
        .await
        .unwrap();
    let grant = reservation.reserve_masks(0, 1).await.unwrap();
    assert_eq!(grant.start, 0);
    let mask_share = reservation.get_mask_share(grant.start).await.unwrap();

    assert!(!mask_share.is_empty());
    assert_eq!(
        store.available(&key).await.unwrap(),
        2,
        "reservation consumes the owned in-memory bundle; LMDB allocation happens before activation"
    );
    let restarted_session = MpcSessionConfig::try_new(
        next_instance_id(),
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let restarted = Engine::from_config(
        HoneyBadgerEngineConfig::new(
            restarted_session,
            HoneyBadgerPreprocessingConfig::new(0, shares.len()),
        )
        .with_deployment_mode(DeploymentMode::Standing),
    )
    .unwrap();
    restarted
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();
    restarted
        .install_standing_client_identities(BTreeMap::from([(0, admitted_client)]))
        .await
        .unwrap();
    let restarted_reservation = restarted.reservation_ops().unwrap();
    restarted_reservation
        .init_reservations(program_hash, 1)
        .await
        .unwrap();
    assert_eq!(restarted_reservation.available_masks().await, 1);
    let (restarted_data, restarted_item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    restarted
        .activate_preallocated_standing(OwnedPreprocBundle {
            random: Some(TakenPreproc {
                count: shares.len() as u32,
                item_size: restarted_item_size,
                data: restarted_data,
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    let restarted_grant = restarted_reservation.reserve_masks(0, 1).await.unwrap();
    assert_eq!(restarted_grant.start, 0);
    let restarted_mask = restarted_reservation
        .get_mask_share(restarted_grant.start)
        .await
        .unwrap();
    assert!(!restarted_mask.is_empty());
    assert_eq!(store.available(&key).await.unwrap(), 2);
}

/// A standing node holds its mask shares in process memory and writes nothing
/// of its own into the volume that holds its preprocessing material.
///
/// Three facts keep a client's masked input off that volume. Nothing on
/// `MpcEngineReservation` accepts one: a client's `x + r` goes to the
/// coordinator, and the node subtracts its mask share in memory. The
/// reservation registry has no way to reach disk — the persistence that wrote
/// it into this very LMDB environment, under `rsv:`, is gone. And a record
/// under that prefix is now contamination
/// (`CondemnedNamespace::RetiredReservation`), so a node that somehow grew one
/// would refuse its own volume on the next open rather than carry it.
///
/// Asserted against the volume's keys rather than against an API, because the
/// typed API has no variant that could name the prefix under test — which is
/// the property. Re-add a registry write to `reserve_masks` or `retire_masks`
/// and this test fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_standing_engine_writes_nothing_into_the_volume_holding_its_preprocessing() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xB1; 32];
    let execution_id = ExecutionId::from_bytes([0xB2; 32]);
    let party_id = 0;
    let n = 5;
    let t = 1;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(97);
    let shares: Vec<_> = (0..2)
        .map(|_| RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t))
        .collect();

    // The volume must actually hold this node's preprocessing material, or
    // "writes nothing of its own beside it" is asserted over an empty volume.
    let scope = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        DurableIdentityDigest::from_legacy_party_id(party_id),
    );
    let (seed_data, seed_item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    store
        .seed_items(
            &scope.random_share(),
            &PreprocBlob::try_new(seed_data, seed_item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();

    let session = MpcSessionConfig::try_new(
        next_instance_id(),
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let engine = Engine::from_config(
        HoneyBadgerEngineConfig::new(
            session,
            HoneyBadgerPreprocessingConfig::new(0, shares.len()),
        )
        .with_deployment_mode(DeploymentMode::Standing),
    )
    .unwrap();
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();
    let admitted_client = DurableIdentityDigest::from_certificate_identity(
        CertificateIdentity::from_bytes([0xB3; 32]),
    );
    engine
        .install_standing_client_identities(BTreeMap::from([(0, admitted_client)]))
        .await
        .unwrap();
    let (data, item_size) = preproc::serialize_robust_shares(&shares).unwrap();
    engine
        .activate_preallocated_standing(OwnedPreprocBundle {
            random: Some(TakenPreproc {
                count: shares.len() as u32,
                item_size,
                data,
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    let reservation = engine.reservation_ops().unwrap();
    reservation
        .init_reservations(program_hash, shares.len() as u64)
        .await
        .unwrap();
    let grant = reservation
        .reserve_masks(0, shares.len() as u64)
        .await
        .unwrap();
    // The production end-of-input-phase call, which is where the registry used
    // to be written out.
    reservation.retire_masks(&[grant.start]).await.unwrap();

    assert_eq!(
        engine.reserved_mask_shares.lock().await.len(),
        shares.len() - 1,
        "the engine must still be holding the mask share it has not retired, \
         or this test is asserting about a node that holds no mask material"
    );

    let keys = store.volume_keys().await.unwrap();
    assert!(
        keys.iter()
            .any(|key| key.starts_with(&scope.random_share().encode().unwrap())),
        "the volume under test must hold this node's preprocessing material: {keys:?}"
    );
    for condemned in preproc::CondemnedNamespace::ALL {
        assert!(
            keys.iter()
                .all(|key| !key.starts_with(condemned.as_bytes())),
            "a standing engine left a record under {condemned} in the volume that \
             holds its mask shares"
        );
    }
}

#[tokio::test]
async fn standing_client_reservation_identity_is_frozen_by_execution_ordinal() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let make_engine = |execution_byte| {
        let session = MpcSessionConfig::try_new(
            next_instance_id(),
            0,
            5,
            1,
            Arc::new(QuicNetworkManager::new()),
        )
        .unwrap()
        .try_with_execution_id(ExecutionId::from_bytes([execution_byte; 32]))
        .unwrap();
        Engine::from_config(
            HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(1, 1))
                .with_deployment_mode(DeploymentMode::Standing),
        )
        .unwrap()
    };
    let admitted = DurableIdentityDigest::from_certificate_identity(
        CertificateIdentity::from_bytes([0x11; 32]),
    );
    let first_unrelated = DurableIdentityDigest::from_certificate_identity(
        CertificateIdentity::from_bytes([0x21; 32]),
    );
    let second_unrelated = DurableIdentityDigest::from_certificate_identity(
        CertificateIdentity::from_bytes([0x22; 32]),
    );
    let first = make_engine(0x31);
    let second = make_engine(0x32);

    first
        .install_standing_client_identities(BTreeMap::from([(0, admitted), (1, first_unrelated)]))
        .await
        .unwrap();
    second
        .install_standing_client_identities(BTreeMap::from([(0, admitted), (1, second_unrelated)]))
        .await
        .unwrap();

    assert_eq!(first.client_identity(0).await.unwrap(), admitted);
    assert_eq!(second.client_identity(0).await.unwrap(), admitted);
    assert_eq!(first.client_identity(1).await.unwrap(), first_unrelated);
    assert_eq!(second.client_identity(1).await.unwrap(), second_unrelated);
    assert!(first
        .client_identity(2)
        .await
        .unwrap_err()
        .contains("not admitted"));
    assert!(first
        .install_standing_client_identities(BTreeMap::from([(0, second_unrelated)]))
        .await
        .unwrap_err()
        .contains("immutable"));

    let without_roster = make_engine(0x33);
    assert!(without_roster
        .client_identity(0)
        .await
        .unwrap_err()
        .contains("was not installed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_hb_reservoir_uses_stable_program_scope_despite_execution_transport() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let execution_id = ExecutionId::from_bytes([0xE1; 32]);
    let program_a = [0xA1; 32];
    let program_b = [0xB1; 32];
    let party_id = 0;
    let n = 5;
    let t = 1;
    let identity = DurableIdentityDigest::from_legacy_party_id(party_id);
    let stable_a = PreprocKeyScope::new(
        program_a,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    let stable_b = PreprocKeyScope::new(
        program_b,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    for (key, count, fill) in [
        (stable_a.random_share(), 2, 0xA1),
        (stable_b.random_share(), 3, 0xB1),
    ] {
        store
            .seed_items(
                &key,
                &PreprocBlob::try_new(vec![fill; count], 1, count).unwrap(),
            )
            .await
            .unwrap();
    }

    let make_reservoir = |program_hash| {
        let session = MpcSessionConfig::try_new(
            next_instance_id(),
            party_id,
            n,
            t,
            Arc::new(QuicNetworkManager::new()),
        )
        .unwrap()
        .try_with_execution_id(execution_id)
        .unwrap();
        let engine = Engine::from_config(
            HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(1, 1))
                .with_deployment_mode(DeploymentMode::Standing),
        )
        .unwrap();
        engine
            .preproc_persistence_ops()
            .unwrap()
            .set_preproc_store(store.clone(), program_hash)
            .unwrap();
        engine.use_program_preproc_reservoir();
        engine
    };

    let reservoir_a = make_reservoir(program_a);
    let snapshot_a = reservoir_a.standing_preproc_snapshot().await.unwrap();
    let snapshot_b = make_reservoir(program_b)
        .standing_preproc_snapshot()
        .await
        .unwrap();

    assert_eq!(snapshot_a.random.count, 2);
    assert_eq!(snapshot_b.random.count, 3);
    let error = reservoir_a
        .activate_preallocated_standing(OwnedPreprocBundle::default())
        .await
        .unwrap_err();
    assert!(
        error.contains("program reservoir engine cannot be activated"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_hb_activation_requires_complete_owned_bundle_without_top_up() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xC1; 32];
    let execution_id = ExecutionId::from_bytes([0xD1; 32]);
    let party_id = 0;
    let n = 5;
    let t = 1;
    let identity = DurableIdentityDigest::from_legacy_party_id(party_id);
    let stable = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC1D1);
    let stable_random = vec![RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t)];
    let execution_random = (0..4)
        .map(|_| RobustShare::new(ark_bls12_381::Fr::rand(&mut rng), 1, t))
        .collect::<Vec<_>>();
    let (data, item_size) = preproc::serialize_robust_shares(&stable_random).unwrap();
    store
        .seed_items(
            &stable.random_share(),
            &PreprocBlob::try_new(data, item_size, 1).unwrap(),
        )
        .await
        .unwrap();

    let session = MpcSessionConfig::try_new(
        next_instance_id(),
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let engine = Engine::from_config(
        HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(0, 4))
            .with_deployment_mode(DeploymentMode::Standing),
    )
    .unwrap();
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();

    let before_stable = store.scope_availability(&stable).await.unwrap();
    let error = engine
        .activate_preallocated_standing(OwnedPreprocBundle::default())
        .await
        .unwrap_err();
    assert!(
        error.contains("does not match target"),
        "unexpected error: {error}"
    );
    assert!(!engine.is_ready());
    assert_eq!(
        store.scope_availability(&stable).await.unwrap(),
        before_stable
    );
    let (data, item_size) = preproc::serialize_robust_shares(&execution_random).unwrap();
    let bundle = OwnedPreprocBundle {
        random: Some(TakenPreproc {
            count: execution_random.len() as u32,
            item_size,
            data,
        }),
        ..Default::default()
    };
    engine.activate_preallocated_standing(bundle).await.unwrap();
    assert!(engine.is_ready());
    assert_eq!(
        engine
            .clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .length()
            .random_shr,
        0,
        "standing activation should bypass the upstream front-draining Vec"
    );
    assert_eq!(engine.random_share_cache.lock().await.len(), 4);
    for expected in &execution_random {
        let taken = engine.reserve_random_share().await.unwrap();
        assert_eq!(taken.share, expected.share);
    }
    assert!(engine.random_share_cache.lock().await.is_empty());
    assert_eq!(
        store.available(&stable.random_share()).await.unwrap(),
        1,
        "execution consumption must not touch the program reservoir"
    );
}

/// A one-shot engine offers no reservation capability at all.
///
/// The reservation lifecycle is a draw: `reserve_masks` removes the mask share
/// from the live pool and `get_mask_share` serves what it removed. A one-shot
/// engine generates its pool for one execution and takes its masks straight out
/// of it, so it has no drawn share to serve — calling `get_mask_share` on one
/// could only succeed by reading the store and leaving the item where a later
/// execution could be handed it, which is the defect the division fixed.
///
/// So the type says so, rather than the method failing closed one call later:
/// `as_reservation` and `capabilities` both withhold it, which is what makes
/// the error "does not support preprocessing reservation" instead of "advertises
/// reservation but does not implement MpcEngineReservation".
#[tokio::test]
async fn a_one_shot_engine_offers_no_reservation_capability() {
    type Engine = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;

    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        0,
        5,
        1,
    );
    assert!(
        !engine.is_standing(),
        "this test is about a one-shot engine"
    );

    assert!(
        !engine
            .capabilities()
            .contains(crate::net::mpc_engine::MpcCapabilities::RESERVATION),
        "a one-shot engine must not advertise a capability it cannot serve"
    );
    assert!(!engine.supports_reservation());
    assert!(engine.as_reservation().is_none());

    let error = match engine.reservation_ops() {
        Ok(_) => panic!("a one-shot engine must not hand out reservation ops"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("does not support preprocessing reservation"),
        "the refusal must read as an unsupported capability, not a missing impl: {error}"
    );

    let standing = Engine::from_config(
        HoneyBadgerEngineConfig::new(
            MpcSessionConfig::try_new(
                next_instance_id(),
                0,
                5,
                1,
                Arc::new(QuicNetworkManager::new()),
            )
            .unwrap(),
            HoneyBadgerPreprocessingConfig::new(1, 1),
        )
        .with_deployment_mode(DeploymentMode::Standing),
    )
    .unwrap();
    assert!(
        standing
            .capabilities()
            .contains(crate::net::mpc_engine::MpcCapabilities::RESERVATION)
            && standing.as_reservation().is_some(),
        "a standing engine must still offer the capability, or this test passes \
         by withholding it from everyone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rbc_receive_delivers_new_broadcast_each_call_in_order() {
    let instance_id = next_instance_id();
    let n = 5;
    let t = 1;
    let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
    let sender = test_engine(router.clone(), instance_id, 0, n, t);
    let receiver1 = test_engine(router.clone(), instance_id, 1, n, t);
    let receiver2 = test_engine(router.clone(), instance_id, 2, n, t);
    let receiver3 = test_engine(router.clone(), instance_id, 3, n, t);
    let receiver4 = test_engine(router, instance_id, 4, n, t);

    sender.rbc_broadcast(b"first").expect("broadcast first");
    let receive_first = async {
        tokio::join!(
            receiver1.rbc_receive_async(MpcPartyId::new(0), 500),
            receiver2.rbc_receive_async(MpcPartyId::new(0), 500),
            receiver3.rbc_receive_async(MpcPartyId::new(0), 500),
            receiver4.rbc_receive_async(MpcPartyId::new(0), 500),
        )
    };
    let first = receive_first.await;
    for result in [first.0, first.1, first.2, first.3] {
        assert_eq!(result.expect("receive first"), b"first");
    }

    sender.rbc_broadcast(b"second").expect("broadcast second");
    let second = tokio::join!(
        receiver1.rbc_receive_async(MpcPartyId::new(0), 500),
        receiver2.rbc_receive_async(MpcPartyId::new(0), 500),
        receiver3.rbc_receive_async(MpcPartyId::new(0), 500),
        receiver4.rbc_receive_async(MpcPartyId::new(0), 500),
    );
    for result in [second.0, second.1, second.2, second.3] {
        assert_eq!(result.expect("receive second"), b"second");
    }
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

#[test]
fn honeybadger_exponent_open_fails_closed_without_verifiable_shares() {
    let engine = test_engine(
        Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        next_instance_id(),
        0,
        5,
        1,
    );

    let error = engine
        .open_share_in_exp_impl(
            stoffel_vm_types::core_types::ShareType::default_secret_int(),
            b"untrusted share bytes",
            b"untrusted generator bytes",
        )
        .expect_err("unverifiable HoneyBadger exponent opening must fail closed");
    assert!(error.contains("disabled for Byzantine-threshold sessions"));
    assert!(error.contains("AVSS backend"));
}
