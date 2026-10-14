use super::*;
const METHOD: &str = "browser_open_authorize_closure";

#[tokio::test]
async fn signed_closure_permit_binds_owner_body_method_execution_and_nonce() {
    let deadline = crate::open_collection::unix_ms() + 60_000;
    let (module, shared) = setup_with_deadline(Some(deadline));
    let body = json!({"deadline_unix_ms":deadline,"freeze_at_capacity":true});
    let original = request(METHOD, 1, 7, body.clone());
    for mutation in 0..5 {
        let mut bad = original.clone();
        match mutation {
            0 => bad["params"][0]["request"]["public_key"] = json!(identity(2)),
            1 => {
                bad["params"][0]["request"]["body"] = json!(serde_json::to_vec(
                    &json!({"deadline_unix_ms":deadline+1,"freeze_at_capacity":true})
                )
                .unwrap())
            }
            2 => bad["params"][0]["execution_id"] = json!([9; 32].to_vec()),
            3 => bad["params"][0]["request"]["nonce"] = json!(8),
            _ => bad["method"] = json!("browser_open_freeze"),
        }
        assert_eq!(dispatch(&module, bad).await["error"]["code"], AUTH_ERROR);
    }
    for seed in [2, 10] {
        assert!(dispatch(&module, request(METHOD, seed, 1, body.clone()))
            .await
            .get("error")
            .is_some());
    }
    let auth = good(&module, METHOD, 1, 7, body.clone()).await;
    assert_eq!(auth, body);
    assert_eq!(
        dispatch(&module, original).await["error"]["code"],
        AUTH_ERROR
    );
    assert_eq!(good(&module, METHOD, 1, 8, body.clone()).await, body);
    assert!(dispatch(
        &module,
        request(
            METHOD,
            1,
            9,
            json!({"deadline_unix_ms":deadline+1,"freeze_at_capacity":true})
        )
    )
    .await
    .get("error")
    .is_some());
    assert_eq!(
        dispatch(&module, request("browser_open_status", 1, 9, json!(null))).await["error"]["code"],
        AUTH_ERROR
    );
    let status = good(&module, "browser_open_status", 1, 10, json!(null)).await;
    assert_eq!(status["deadline_unix_ms"], deadline);
    assert_eq!(status["closure_authorization"], body);
    // Only mTLS-configured native parties can exercise freeze/archive/stop.
    for method in [
        "open_freeze_eligible",
        "browser_open_freeze_eligible",
        "open_accepted_metadata",
        "browser_open_accepted_metadata",
        "open_encrypted_archive",
        "browser_open_encrypted_archive",
        "open_stop",
        "browser_open_stop",
    ] {
        assert_eq!(
            dispatch(&module, request(method, 10, 99, json!(null))).await["error"]["code"],
            -32601
        );
    }
    let party = CoordinatorRPCServerConnectionBase::new(shared, identity(10));
    assert!(party
        .open_freeze_eligible(ExecutionId::from_bytes([8; 32]))
        .await
        .is_err());
}

#[tokio::test]
async fn malformed_signed_closure_bodies_fail_closed_and_burn_authenticated_nonce() {
    let deadline = crate::open_collection::unix_ms() + 60_000;
    let (module, _) = setup_with_deadline(Some(deadline));
    let bodies = [
        json!({"deadline_unix_ms":-1,"freeze_at_capacity":true}),
        json!({"deadline_unix_ms":"tomorrow","freeze_at_capacity":true}),
        json!({"deadline_unix_ms":deadline,"freeze_at_capacity":false}),
        json!({"deadline_unix_ms":deadline}),
        json!({"deadline_unix_ms":deadline,"freeze_at_capacity":true,"owner":identity(2)}),
        json!({"deadline_unix_ms":u64::MAX,"freeze_at_capacity":true}),
        json!({"deadline_unix_ms":0,"freeze_at_capacity":true}),
    ];
    for (i, body) in bodies.into_iter().enumerate() {
        assert!(dispatch(&module, request(METHOD, 1, i as u64 + 1, body))
            .await
            .get("error")
            .is_some());
    }
    let status = good(&module, "browser_open_status", 1, 100, json!(null)).await;
    assert_eq!(status["closure_authorization"], Value::Null);
}

#[tokio::test]
async fn malformed_browser_inputs_never_advance_acceptance_and_hide_protected_values() {
    let (module, shared) = setup();
    good(&module, "browser_open_reserve", 2, 1, json!(null)).await;
    let mut trailing = fr(23);
    trailing.push(0);
    for (i, bad) in [vec![], vec![23], vec![255; 32], trailing]
        .into_iter()
        .enumerate()
    {
        assert!(dispatch(
            &module,
            request(
                "browser_open_submit",
                2,
                i as u64 + 2,
                json!({"reserved_indices":[0],"masked_inputs":[bad]})
            )
        )
        .await
        .get("error")
        .is_some());
    }
    let status = good(&module, "browser_open_status", 2, 20, json!(null)).await;
    assert_eq!(status["accepted_clients"], 0);
    good(
        &module,
        "browser_open_submit",
        2,
        21,
        json!({"reserved_indices":[0],"masked_inputs":[fr(23)]}),
    )
    .await;
    let party = CoordinatorRPCServerConnectionBase::new(shared, identity(10));
    let metadata = party
        .open_accepted_metadata(ExecutionId::from_bytes([8; 32]))
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].client, identity(2));
    assert!(!serde_json::to_string(&metadata)
        .unwrap()
        .contains("masked_input"));
}
