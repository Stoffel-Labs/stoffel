use super::*;
mod closure;
fn fr(value: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(
        &ark_bls12_381::Fr::from(value as u64),
        &mut bytes,
    )
    .unwrap();
    bytes
}
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::{json, Value};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}
fn identity(seed: u8) -> Vec<u8> {
    key(seed)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn setup() -> (
    RpcModule<Arc<CoordinatorBrowserState>>,
    Arc<Mutex<CoordinatorRPCServerSharedBase>>,
) {
    setup_with_deadline(None)
}
fn setup_with_deadline(
    deadline_unix_ms: Option<u64>,
) -> (
    RpcModule<Arc<CoordinatorBrowserState>>,
    Arc<Mutex<CoordinatorRPCServerSharedBase>>,
) {
    let mut coordinator =
        CoordinatorRPCServerSharedBase::new(3, 1, vec![identity(10), identity(11), identity(12)])
            .unwrap();
    coordinator
        .register_open_collection(crate::OpenCollectionPolicy {
            execution_id: ExecutionId::from_bytes([8; 32]),
            owner: identity(1),
            min_clients: 2,
            max_clients: 3,
            inputs_per_client: 1,
            approved_programs: [(2, [2; 32]), (3, [3; 32])].into(),
            min_output_shares: 3,
            deadline_unix_ms,
        })
        .unwrap();
    let shared = Arc::new(Mutex::new(coordinator));
    (coordinator_browser_module(shared.clone()).unwrap(), shared)
}
fn request(method: &str, seed: u8, nonce: u64, body: Value) -> Value {
    let id = ExecutionId::from_bytes([8; 32]);
    let body = serde_json::to_vec(&body).unwrap();
    let sig: Signature = key(seed).sign(&authentication_message(method, id, nonce, &body));
    json!({"jsonrpc":"2.0", "id": 1, "method":method, "params":[{
        "execution_id":id, "request": {
            "public_key":identity(seed), "nonce":nonce,
            "signature":sig.to_bytes().to_vec(), "body":body,
        }
    }]})
}
async fn dispatch(module: &RpcModule<Arc<CoordinatorBrowserState>>, request: Value) -> Value {
    let (response, _) = module
        .raw_json_request(&request.to_string(), 1)
        .await
        .unwrap();
    serde_json::from_str(&response.to_string()).unwrap()
}
async fn good(
    module: &RpcModule<Arc<CoordinatorBrowserState>>,
    method: &str,
    seed: u8,
    nonce: u64,
    body: Value,
) -> Value {
    let response = dispatch(module, request(method, seed, nonce, body)).await;
    assert!(response.get("error").is_none(), "{response}");
    response["result"].clone()
}

#[tokio::test]
async fn signed_browser_open_lifecycle_accepts_new_identity_after_submission() {
    let (module, shared) = setup();
    let reserve = good(&module, "browser_open_reserve", 2, 1, json!(null)).await;
    assert_eq!(reserve[0]["reserved_index"], 0);
    good(
        &module,
        "browser_open_submit",
        2,
        2,
        json!({"reserved_indices":[0],"masked_inputs":[fr(23)]}),
    )
    .await;
    good(&module, "browser_open_reserve", 3, 1, json!(null)).await;
    good(
        &module,
        "browser_open_submit",
        3,
        2,
        json!({"reserved_indices":[1],"masked_inputs":[fr(24)]}),
    )
    .await;
    let status = good(&module, "browser_open_status", 4, 1, json!(null)).await;
    assert_eq!(status["accepted_clients"], 2);
    good(&module, "browser_open_reserve", 4, 2, json!(null)).await;
    let frozen = good(
        &module,
        "browser_open_freeze",
        1,
        1,
        json!([2; 32].to_vec()),
    )
    .await;
    assert_eq!(frozen["registration"]["n_inputs"], 2);
    assert_eq!(
        frozen["registration"]["output_clients"],
        json!([identity(1)])
    );
    assert!(!frozen.to_string().contains("masked_input"));
    assert!(dispatch(
        &module,
        request(
            "browser_open_submit",
            4,
            3,
            json!({"reserved_indices":[2],"masked_inputs":[fr(25)]})
        )
    )
    .await
    .get("error")
    .is_some());
    let party = CoordinatorRPCServerConnectionBase::new(shared, identity(10));
    assert_eq!(
        party
            .open_frozen_inputs(ExecutionId::from_bytes([8; 32]))
            .await
            .unwrap()
            .len(),
        2
    );
    // No private data-plane RPC or policy registration exposed on browser module.
    for method in [
        "open_frozen_inputs",
        "browser_open_frozen_inputs",
        "open_register_policy",
        "browser_open_register_policy",
    ] {
        assert_eq!(
            dispatch(&module, request(method, 1, 10, json!(null))).await["error"]["code"],
            -32601
        );
    }
}

#[tokio::test]
async fn browser_signatures_bind_method_execution_body_and_owner_identity() {
    let (module, _) = setup();
    let original = request("browser_open_reserve", 2, 1, json!(null));
    for mutation in 0..5 {
        let mut bad = original.clone();
        match mutation {
            0 => bad["method"] = json!("browser_open_freeze"),
            1 => bad["params"][0]["execution_id"] = json!([9; 32].to_vec()),
            2 => {
                bad["params"][0]["request"]["body"] =
                    json!(serde_json::to_vec(&vec![2; 32]).unwrap())
            }
            3 => bad["params"][0]["request"]["public_key"] = json!(identity(1)),
            _ => bad["params"][0]["request"]["nonce"] = json!(2),
        }
        assert_eq!(dispatch(&module, bad).await["error"]["code"], AUTH_ERROR);
    }
    // Invalid signatures did not reserve or burn the legitimate key's nonce.
    assert!(dispatch(&module, original).await.get("error").is_none());
    assert!(dispatch(
        &module,
        request("browser_open_freeze", 2, 2, json!([2; 32].to_vec()))
    )
    .await
    .get("error")
    .is_some());
}

#[tokio::test]
async fn duplicate_and_cross_method_nonces_cannot_mutate_collection() {
    let (module, _) = setup();
    good(&module, "browser_open_reserve", 2, 7, json!(null)).await;
    assert_eq!(
        dispatch(&module, request("browser_open_reserve", 2, 7, json!(null))).await["error"]
            ["code"],
        AUTH_ERROR
    );
    assert_eq!(
        dispatch(
            &module,
            request(
                "browser_open_submit",
                2,
                7,
                json!({"reserved_indices":[0],"masked_inputs":[fr(23)]})
            )
        )
        .await["error"]["code"],
        AUTH_ERROR
    );
    assert_eq!(
        dispatch(&module, request("browser_open_status", 2, 6, json!(null))).await["error"]["code"],
        AUTH_ERROR
    );
    let status = good(&module, "browser_open_status", 2, 8, json!(null)).await;
    assert_eq!(status["accepted_clients"], 0);
    good(
        &module,
        "browser_open_submit",
        2,
        9,
        json!({"reserved_indices":[0],"masked_inputs":[fr(23)]}),
    )
    .await;
    assert!(dispatch(
        &module,
        request(
            "browser_open_submit",
            2,
            10,
            json!({"reserved_indices":[0],"masked_inputs":[fr(24)]})
        )
    )
    .await
    .get("error")
    .is_some());
}

#[tokio::test]
async fn signed_owner_only_output_polling_and_unauthenticated_calls_fail_closed() {
    let (module, _) = setup();
    let mut unsigned = request("browser_open_freeze", 1, 1, json!([2; 32].to_vec()));
    unsigned["params"][0]["request"]["signature"] = json!(vec![0; 64]);
    assert_eq!(
        dispatch(&module, unsigned).await["error"]["code"],
        AUTH_ERROR
    );
    assert!(dispatch(
        &module,
        request("browser_open_output_shares", 2, 1, json!(null))
    )
    .await
    .get("error")
    .is_some());
    assert_eq!(
        good(&module, "browser_open_output_shares", 1, 1, json!(null)).await,
        Value::Null
    );
}
