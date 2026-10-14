use super::*;
use ark_bls12_381::Fr;
use hpke::{single_shot_open, OpModeR};
use p256::ecdsa::SigningKey;
use std::sync::Arc;
use stoffel_mpc_coordinator_off_chain::{CoordinatorRPCServerConnectionBase, CoordinatorRPCServerSharedBase};
use tokio::sync::Mutex;

fn identity(seed: u8) -> Vec<u8> {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap().verifying_key()
        .to_encoded_point(false).as_bytes().to_vec()
}
fn policy() -> OpenCollectionPolicy {
    OpenCollectionPolicy { execution_id: ExecutionId::from_bytes([8; 32]), owner: identity(1),
        min_clients: 2, max_clients: 3, inputs_per_client: 1,
        approved_programs: [(2, [2; 32]), (3, [3; 32])].into(), min_output_shares: 5, deadline_unix_ms: None }
}
// Real coordinator transitions with explicitly synthetic, canonically encoded
// protected-input fixtures. This is not a five-party MPC execution test.
async fn sparse_snapshot() -> (OpenCollectionPolicy, FrozenCollection, Vec<AssignedMaskReservation>, Vec<AssignedMaskedInputEvent>) {
    let p = policy();
    let mut server = CoordinatorRPCServerSharedBase::new(5, 1, (10..15).map(identity).collect()).unwrap();
    server.register_open_collection(p.clone()).unwrap();
    let shared = Arc::new(Mutex::new(server));
    let connection = |seed| CoordinatorRPCServerConnectionBase::new(shared.clone(), identity(seed));
    for seed in 2..5 {
        let reservation = connection(seed).open_reserve(p.execution_id).await.unwrap();
        if seed != 3 {
            let mut encoded = Vec::new();
            Fr::from(u64::from(seed)).serialize_compressed(&mut encoded).unwrap();
            connection(seed).open_submit(p.execution_id, vec![reservation[0].reserved_index], vec![encoded]).await.unwrap();
        }
    }
    let frozen = connection(1).open_freeze(p.execution_id, [2; 32]).await.unwrap();
    let reservations = connection(10).open_reservations(p.execution_id).await.unwrap();
    let events = connection(10).open_frozen_inputs(p.execution_id).await.unwrap();
    (p, frozen, reservations, events)
}

#[test]
fn approved_policy_rejects_missing_variants_and_wrong_topology() {
    let p = policy();
    validate_policy(&p, 5, 1).unwrap();
    assert!(validate_policy(&p, 5, 0).is_err());
    assert!(validate_policy(&p, 3, 1).is_err());
    let mut bad = p.clone(); bad.min_output_shares = 3;
    assert!(validate_policy(&bad, 5, 1).is_err(), "all five encrypted output shares are required");
    let mut bad = p.clone(); bad.approved_programs.remove(&2);
    assert!(validate_policy(&bad, 5, 1).is_err());
    let mut bad = p.clone(); bad.min_clients = 1;
    assert!(validate_policy(&bad, 5, 1).is_err());
    let mut bad = p; bad.execution_id = ExecutionId::from_bytes([0; 32]);
    assert!(validate_policy(&bad, 5, 1).is_err());
}
#[test]
fn program_files_must_match_preapproved_counts_before_any_file_is_read() {
    assert!(ApprovedOpenCollection::load(OpenCollectionConfig { policy: policy(), programs: BTreeMap::new() }, 5, 1).is_err());
}

#[test]
fn exact_manifest_rejects_extra_slots_and_output_routes() {
    use stoffel_vm_types::{compiled_binary::ClientIoSchema, core_types::ShareType};
    let scalar = ShareType::secret_int(64);
    let manifest = ClientIoManifest {
        mpc_backend: MpcBackend::HoneyBadger,
        mpc_curve: MpcCurve::Bls12_381,
        clients: vec![
            ClientIoSchema { client_slot: 0, inputs: vec![scalar], outputs: vec![] },
            ClientIoSchema { client_slot: 1, inputs: vec![scalar], outputs: vec![] },
            ClientIoSchema { client_slot: 2, inputs: vec![], outputs: vec![scalar] },
        ],
        ..Default::default()
    };
    validate_manifest(&manifest, 2, 1, 2).unwrap();
    assert!(validate_manifest(&manifest, 2, 1, 1).is_err());
    let mut extra = manifest.clone();
    extra.clients.push(ClientIoSchema { client_slot: 3, inputs: vec![], outputs: vec![] });
    assert!(validate_manifest(&extra, 2, 1, 2).is_err());
    let mut duplicate_output = manifest.clone();
    duplicate_output.clients[2].outputs.push(scalar);
    assert!(validate_manifest(&duplicate_output, 2, 1, 2).is_err());
    let mut participant_output = manifest;
    participant_output.clients[0].outputs.push(scalar);
    assert!(validate_manifest(&participant_output, 2, 1, 2).is_err());
}
#[tokio::test]
async fn sparse_freeze_keeps_original_masks_and_dense_vm_slots_distinct() {
    let (p, f, reservations, events) = sparse_snapshot().await;
    assert_eq!(f.registration.n_inputs, 2);
    assert_eq!(f.input_mapping.iter().map(|m| m.original_index).collect::<Vec<_>>(), vec![0, 2]);
    assert_eq!(f.input_mapping.iter().map(|m| m.client_slot).collect::<Vec<_>>(), vec![0, 1]);
    validate_frozen(&p, &f, &reservations, &events).unwrap();
    let mut bad = f; bad.input_mapping[1].original_index = 1;
    assert!(validate_frozen(&p, &bad, &reservations, &events).is_err());
}
#[tokio::test]
async fn no_padding_or_rebinding_of_program_owner_identity_or_events() {
    let (p, f, reservations, events) = sparse_snapshot().await;
    let mut bad = f.clone(); bad.registration.n_inputs = 3;
    assert!(validate_frozen(&p, &bad, &reservations, &events).is_err());
    let mut bad = f.clone(); bad.registration.output_clients = vec![identity(3)];
    assert!(validate_frozen(&p, &bad, &reservations, &events).is_err());
    let mut bad = f.clone(); bad.registration.program_hash = [3; 32];
    assert!(validate_frozen(&p, &bad, &reservations, &events).is_err());
    let mut bad = f.clone(); bad.registration.input_assignment.clients[1] = identity(3);
    assert!(validate_frozen(&p, &bad, &reservations, &events).is_err());
    let mut bad_events = events.clone(); bad_events.push(events[0].clone());
    assert!(validate_frozen(&p, &f, &reservations, &bad_events).is_err());
    assert!(validate_frozen(&p, &f, &reservations, &events[..1]).is_err());
    let mut bad_events = events; bad_events[1].client = identity(3);
    assert!(validate_frozen(&p, &f, &reservations, &bad_events).is_err());
}
#[test]
fn output_hpke_opens_only_for_intended_owner_and_original_execution() {
    let p = policy();
    let fixture = vec![Fr::from(9u64)];
    let (enc, ciphertext) = seal_output(p.execution_id, &p.owner, &fixture).unwrap();
    let key = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&[1; 32]).unwrap();
    let encapsulated = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc).unwrap();
    let mut info = b"StoffelOutputShareEncryption".to_vec(); info.extend_from_slice(p.execution_id.as_bytes());
    let plain = single_shot_open::<AesGcm256,HkdfSha256,DhP256HkdfSha256>(&OpModeR::Base,&key,&encapsulated,&info,&ciphertext,b"").unwrap();
    let decoded = Vec::<Fr>::deserialize_compressed(plain.as_slice()).unwrap();
    assert_eq!(decoded, fixture);
    let wrong_key = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&[2; 32]).unwrap();
    assert!(single_shot_open::<AesGcm256,HkdfSha256,DhP256HkdfSha256>(&OpModeR::Base,&wrong_key,&encapsulated,&info,&ciphertext,b"").is_err());
    *info.last_mut().unwrap() ^= 1;
    assert!(single_shot_open::<AesGcm256,HkdfSha256,DhP256HkdfSha256>(&OpModeR::Base,&key,&encapsulated,&info,&ciphertext,b"").is_err());
}

#[test]
fn approved_pool_preprocesses_all_reservations_not_only_accepted_capacity() {
    let p = policy();
    let approved = ApprovedOpenCollection { policy: p.clone(), programs: BTreeMap::new(), demand: PreprocessingDemand::default() };
    assert_eq!(approved.mask_count(), 48);
    assert_eq!(approved.preprocessing_demand().randoms, 0);
    let mut too_wide = p;
    too_wide.inputs_per_client = 1_000_000 / 48 + 1;
    assert!(validate_policy(&too_wide, 5, 1).is_err());
}

#[tokio::test]
async fn late_original_index_beyond_max_accepted_remains_bound_to_original_mask() {
    let p = policy();
    let mut server = CoordinatorRPCServerSharedBase::new(5, 1, (10..15).map(identity).collect()).unwrap();
    server.register_open_collection(p.clone()).unwrap();
    let shared = Arc::new(Mutex::new(server));
    let connection = |seed| CoordinatorRPCServerConnectionBase::new(shared.clone(), identity(seed));
    for seed in 2..5 { connection(seed).open_reserve(p.execution_id).await.unwrap(); }
    for (seed, index) in [(2, 0), (4, 2)] {
        let mut encoded = Vec::new();
        Fr::from(seed as u64).serialize_compressed(&mut encoded).unwrap();
        connection(seed).open_submit(p.execution_id, vec![index], vec![encoded]).await.unwrap();
    }
    assert_eq!(connection(5).open_reserve(p.execution_id).await.unwrap()[0].reserved_index, 3);
    let mut encoded = Vec::new();
    Fr::from(5u64).serialize_compressed(&mut encoded).unwrap();
    connection(5).open_submit(p.execution_id, vec![3], vec![encoded]).await.unwrap();
    let frozen = connection(1).open_freeze(p.execution_id, [3; 32]).await.unwrap();
    let reservations = connection(10).open_reservations(p.execution_id).await.unwrap();
    let events = connection(10).open_frozen_inputs(p.execution_id).await.unwrap();
    validate_frozen(&p, &frozen, &reservations, &events).unwrap();
    assert_eq!(frozen.input_mapping.iter().map(|m| m.original_index).collect::<Vec<_>>(), vec![0, 2, 3]);
    assert_eq!(frozen.registration.n_inputs, 3);
    let mut rebound = frozen;
    rebound.input_mapping[2].original_index = 1;
    assert!(validate_frozen(&p, &rebound, &reservations, &events).is_err());
}

#[test]
fn artifact_commitment_is_sha256_not_vm_transport_program_id() {
    let bytes = b"abc";
    assert_eq!(hex::encode(artifact_sha256(bytes)),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_ne!(artifact_sha256(bytes), stoffel_vm::net::program_id_from_bytes(bytes));
}
