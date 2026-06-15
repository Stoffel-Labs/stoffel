use std::sync::Arc;

use stoffel_vm_types::core_types::ClearShareValue;

use super::wire::{
    AVSS_EXP_WIRE_PREFIX, AVSS_G2_EXP_WIRE_PREFIX, HB_EXP_OPEN_WIRE_PREFIX, MAX_WIRE_MESSAGE_LEN,
    OPEN_REGISTRY_WIRE_PREFIX,
};
use super::*;

#[test]
fn unknown_sender_single_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_single_share_wire_message(1, 0, "test-key", 0, b"share0").unwrap();
    let result = router.try_handle_wire_message(UNKNOWN_SENDER_ID, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not authenticated"));
}

#[test]
fn unknown_sender_batch_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg =
        encode_batch_share_wire_message(1, 0, "test-key", 0, &[b"s0".to_vec(), b"s1".to_vec()])
            .unwrap();
    let result = router.try_handle_wire_message(UNKNOWN_SENDER_ID, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not authenticated"));
}

#[test]
fn sender_mismatch_single_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_single_share_wire_message(1, 0, "test-key", 0, b"share0").unwrap();
    let result = router.try_handle_wire_message(1, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sender mismatch"));
}

#[test]
fn sender_mismatch_batch_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_batch_share_wire_message(1, 0, "test-key", 0, &[b"s0".to_vec()]).unwrap();
    let result = router.try_handle_wire_message(1, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sender mismatch"));
}

#[test]
fn valid_single_contribution_is_accepted() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(10001);
    let msg = encode_single_share_wire_message(10001, 0, "test-key", 3, b"share3").unwrap();
    let result = router.try_handle_wire_message(3, &msg);
    assert!(result.unwrap());
}

#[test]
fn valid_batch_contribution_is_accepted() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(10002);
    let shares = vec![b"s0".to_vec(), b"s1".to_vec()];
    let msg = encode_batch_share_wire_message(10002, 0, "test-batch", 5, &shares).unwrap();
    let result = router.try_handle_wire_message(5, &msg);
    assert!(result.unwrap());
}

#[test]
fn unregistered_instance_returns_false() {
    let router = OpenMessageRouter::new();
    let msg = encode_single_share_wire_message(99999999, 0, "test-key", 0, b"share").unwrap();
    let result = router.try_handle_wire_message(0, &msg);
    assert!(!result.unwrap());
}

#[test]
fn non_prefixed_message_returns_false() {
    let router = OpenMessageRouter::new();
    let result = router.try_handle_wire_message(0, b"NOT_OPEN_MSG");
    assert!(!result.unwrap());
}

#[test]
fn oversized_payload_is_rejected() {
    let router = OpenMessageRouter::new();
    let mut msg = Vec::new();
    msg.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    msg.extend(vec![0u8; MAX_WIRE_MESSAGE_LEN + 1]);
    let result = router.try_handle_wire_message(0, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too large"));
}

#[test]
fn oversized_exp_payloads_are_rejected_before_deserialize() {
    let router = OpenMessageRouter::new();

    let mut hb = Vec::new();
    hb.extend_from_slice(HB_EXP_OPEN_WIRE_PREFIX);
    hb.extend(vec![0u8; MAX_WIRE_MESSAGE_LEN + 1]);
    let err = router
        .try_handle_hb_open_exp_wire_message(0, &hb)
        .expect_err("oversized HoneyBadger open-exp payload must be rejected");
    assert!(
        err.contains("open-exp wire payload too large"),
        "unexpected error: {err}"
    );

    let mut avss = Vec::new();
    avss.extend_from_slice(AVSS_EXP_WIRE_PREFIX);
    avss.extend(vec![0u8; MAX_WIRE_MESSAGE_LEN + 1]);
    let err = router
        .try_handle_avss_open_exp_wire_message(0, &avss)
        .expect_err("oversized AVSS open-exp payload must be rejected");
    assert!(
        err.contains("avss open-exp wire payload too large"),
        "unexpected error: {err}"
    );

    let mut avss_g2 = Vec::new();
    avss_g2.extend_from_slice(AVSS_G2_EXP_WIRE_PREFIX);
    avss_g2.extend(vec![0u8; MAX_WIRE_MESSAGE_LEN + 1]);
    let err = router
        .try_handle_avss_g2_exp_wire_message(0, &avss_g2)
        .expect_err("oversized AVSS G2 open-exp payload must be rejected");
    assert!(
        err.contains("avss g2 open-exp wire payload too large"),
        "unexpected error: {err}"
    );
}

#[test]
fn avss_exp_wire_rejects_share_id_mismatch_without_inserting() {
    let router = OpenMessageRouter::new();
    let registry = router.register_instance(20011);
    let payload = encode_avss_open_exp_wire_message(20011, 0, 1, 1, b"point")
        .expect("serialize AVSS open-exp payload");

    let err = router
        .try_handle_avss_open_exp_wire_message(1, &payload)
        .expect_err("AVSS share_id must be party_id + 1");
    assert!(
        err.contains("avss open-exp share_id mismatch"),
        "unexpected error: {err}"
    );
    assert!(registry.exp.lock().is_empty());
}

#[test]
fn avss_g2_exp_wire_rejects_share_id_mismatch_without_inserting() {
    let router = OpenMessageRouter::new();
    let registry = router.register_instance(20012);
    let payload = encode_avss_g2_open_exp_wire_message(20012, 0, 1, 1, b"point")
        .expect("serialize AVSS G2 open-exp payload");

    let err = router
        .try_handle_avss_g2_exp_wire_message(1, &payload)
        .expect_err("AVSS G2 share_id must be party_id + 1");
    assert!(
        err.contains("avss g2 open-exp share_id mismatch"),
        "unexpected error: {err}"
    );
    assert!(registry.exp_g2.lock().is_empty());
}

#[test]
fn wire_message_roundtrip_single() {
    let encoded = encode_single_share_wire_message(42, 11, "rt-key", 7, b"test_share").unwrap();
    assert!(encoded.starts_with(OPEN_REGISTRY_WIRE_PREFIX));
    assert!(encoded.len() < MAX_WIRE_MESSAGE_LEN + OPEN_REGISTRY_WIRE_PREFIX.len());
}

#[test]
fn wire_message_roundtrip_batch() {
    let shares = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    let encoded = encode_batch_share_wire_message(99, 12, "batch-rt", 2, &shares).unwrap();
    assert!(encoded.starts_with(OPEN_REGISTRY_WIRE_PREFIX));
}

#[test]
fn explicit_single_sequence_prevents_reordered_share_mixing() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(21001);

    let seq1_first = encode_single_share_wire_message(21001, 1, "same-type", 1, b"remote-seq1")
        .expect("encode reordered seq1 share");
    assert!(router.try_handle_wire_message(1, &seq1_first).unwrap());
    let seq0_second = encode_single_share_wire_message(21001, 0, "same-type", 1, b"remote-seq0")
        .expect("encode reordered seq0 share");
    assert!(router.try_handle_wire_message(1, &seq0_second).unwrap());

    let opened = reg
        .open_bytes_at_wait(0, "same-type", 0, b"local-seq0", 2, |shares| {
            Ok(shares.concat())
        })
        .expect("seq0 should open with seq0 shares only");

    assert_eq!(opened, b"remote-seq0local-seq0".to_vec());
    assert_eq!(
        reg.single
            .lock()
            .get(&(1, "same-type".to_string()))
            .expect("seq1 bucket should remain separate")
            .shares,
        vec![b"remote-seq1".to_vec()]
    );
}

#[test]
fn duplicate_single_sequence_from_same_sender_must_match_payload() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(21002);

    let first = encode_single_share_wire_message(21002, 0, "dup-type", 1, b"first").unwrap();
    assert!(router.try_handle_wire_message(1, &first).unwrap());
    assert!(router.try_handle_wire_message(1, &first).unwrap());

    let conflict = encode_single_share_wire_message(21002, 0, "dup-type", 1, b"second").unwrap();
    let err = router
        .try_handle_wire_message(1, &conflict)
        .expect_err("conflicting duplicate single share must be rejected");
    assert!(err.contains("conflicting open_share payload"));
}

#[test]
fn explicit_rbc_session_rejects_conflicting_duplicate_payload() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(21003);

    let first = encode_rbc_wire_message(21003, 7, 1, b"payload-a").unwrap();
    assert!(router.try_handle_wire_message(1, &first).unwrap());
    assert!(router.try_handle_wire_message(1, &first).unwrap());

    let conflict = encode_rbc_wire_message(21003, 7, 1, b"payload-b").unwrap();
    let err = router
        .try_handle_wire_message(1, &conflict)
        .expect_err("conflicting duplicate RBC payload must be rejected");
    assert!(err.contains("conflicting RBC payload"));
}

#[test]
fn explicit_exp_sequence_prevents_reordered_partial_point_mixing() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(21004);

    let seq1_first = encode_hb_open_exp_wire_message(21004, 1, 1, 1, b"remote-exp-seq1")
        .expect("encode reordered exp seq1 contribution");
    assert!(router
        .try_handle_hb_open_exp_wire_message(1, &seq1_first)
        .unwrap());
    let seq0_second = encode_hb_open_exp_wire_message(21004, 0, 1, 1, b"remote-exp-seq0")
        .expect("encode reordered exp seq0 contribution");
    assert!(router
        .try_handle_hb_open_exp_wire_message(1, &seq0_second)
        .unwrap());

    let opened = reg
        .exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                sequence: Some(0),
                party_id: 0,
                share_id: 0,
                partial_point: b"local-exp-seq0",
                required: 2,
                timeout_message: "timeout waiting for explicit exp sequence test",
            },
            |partial_points| {
                Ok(partial_points
                    .iter()
                    .flat_map(|(_, point)| point.clone())
                    .collect())
            },
        )
        .expect("seq0 should open with seq0 partial points only");

    assert_eq!(opened, b"remote-exp-seq0local-exp-seq0".to_vec());
    assert_eq!(
        reg.exp
            .lock()
            .get(&1)
            .expect("seq1 bucket should remain separate")
            .partial_points,
        vec![(1, b"remote-exp-seq1".to_vec())]
    );
}

#[test]
fn duplicate_exp_sequence_from_same_sender_must_match_payload() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(21005);

    let first = encode_hb_open_exp_wire_message(21005, 0, 1, 1, b"first").unwrap();
    assert!(router
        .try_handle_hb_open_exp_wire_message(1, &first)
        .unwrap());
    assert!(router
        .try_handle_hb_open_exp_wire_message(1, &first)
        .unwrap());

    let conflict = encode_hb_open_exp_wire_message(21005, 0, 1, 1, b"second").unwrap();
    let err = router
        .try_handle_hb_open_exp_wire_message(1, &conflict)
        .expect_err("conflicting duplicate EXP contribution must be rejected");
    assert!(err.contains("conflicting G1 open-in-exponent payload"));
}

#[test]
fn open_share_wait_rejects_zero_required_contributions() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20003);

    let err = reg
        .open_share_wait(0, "zero-required", b"s0", 0, |_| {
            Ok(ClearShareValue::Integer(0))
        })
        .unwrap_err();

    assert!(
        err.contains("requires at least one contribution"),
        "unexpected error: {err}"
    );
    assert!(reg.single.lock().is_empty());
}

#[test]
fn batch_open_wait_rejects_zero_required_contributions() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20004);

    let err = reg
        .batch_open_wait(0, "zero-required-batch", &[b"s0".to_vec()], 0, |_, _| {
            Ok(ClearShareValue::Integer(0))
        })
        .unwrap_err();

    assert!(
        err.contains("requires at least one contribution"),
        "unexpected error: {err}"
    );
    assert!(reg.batch.lock().is_empty());
}

#[test]
fn open_bytes_wait_returns_raw_reconstruction_result() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20008);

    let result = reg
        .open_bytes_wait(0, "field-open", b"raw-share", 1, |shares| {
            Ok(shares[0].clone())
        })
        .expect("field opening bytes should reconstruct");

    assert_eq!(result, b"raw-share".to_vec());
}

#[test]
fn open_share_wait_reports_missing_registry_entry_without_panicking() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20005);
    let reg_for_reconstruct = Arc::clone(&reg);

    let err = reg
        .open_share_wait(0, "missing-single", b"s0", 1, move |_| {
            reg_for_reconstruct.single.lock().clear();
            Ok(ClearShareValue::Integer(1))
        })
        .unwrap_err();

    assert!(
        err.contains("open_share registry entry disappeared"),
        "unexpected error: {err}"
    );
}

#[test]
fn batch_open_wait_reports_missing_registry_entry_without_panicking() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20006);
    let reg_for_reconstruct = Arc::clone(&reg);

    let err = reg
        .batch_open_wait(0, "missing-batch", &[b"s0".to_vec()], 1, move |_, _| {
            reg_for_reconstruct.batch.lock().clear();
            Ok(ClearShareValue::Integer(1))
        })
        .unwrap_err();

    assert!(
        err.contains("batch_open_shares registry entry disappeared"),
        "unexpected error: {err}"
    );
}

#[test]
fn exp_open_contribution_collects_and_reuses_completed_result() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20007);
    let mut sequence = None;

    let progress = reg
        .contribute_exp_open(ExpOpenRegistryKind::G1, &mut sequence, None, 0, 3, b"p0", 1)
        .unwrap();
    let ExpOpenProgress::Collected {
        sequence: seq,
        partial_points,
    } = progress
    else {
        panic!("expected collected contribution, got {progress:?}");
    };
    assert_eq!(sequence, Some(seq));
    assert_eq!(partial_points, vec![(3, b"p0".to_vec())]);

    reg.complete_exp_open(ExpOpenRegistryKind::G1, seq, b"result".to_vec())
        .unwrap();

    let ready = reg
        .contribute_exp_open(
            ExpOpenRegistryKind::G1,
            &mut sequence,
            None,
            0,
            3,
            b"ignored",
            1,
        )
        .unwrap();
    assert_eq!(ready, ExpOpenProgress::Ready(b"result".to_vec()));
}

#[test]
fn exp_open_contribution_reports_missing_registry_entry_without_panicking() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20008);
    let mut sequence = Some(0);

    let err = reg
        .contribute_exp_open(ExpOpenRegistryKind::G2, &mut sequence, None, 0, 3, b"p0", 1)
        .unwrap_err();

    assert!(
        err.contains("open-in-exponent registry entry disappeared"),
        "unexpected error: {err}"
    );
}

#[test]
fn exp_open_wait_reconstructs_and_completes_result() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20009);

    let result = reg
        .exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                sequence: None,
                party_id: 0,
                share_id: 3,
                partial_point: b"p0",
                required: 1,
                timeout_message: "timeout waiting for test exp open",
            },
            |partial_points| {
                assert_eq!(partial_points, &[(3, b"p0".to_vec())]);
                Ok(b"result".to_vec())
            },
        )
        .expect("single contribution should reconstruct");

    assert_eq!(result, b"result".to_vec());
    assert_eq!(
        reg.exp
            .lock()
            .get(&0)
            .and_then(|entry| entry.result.clone()),
        Some(b"result".to_vec())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_exp_insert_wakes_waiters() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20010);

    let reg2 = reg.clone();
    let waiter = tokio::spawn(async move {
        reg2.exp_open_async(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                sequence: Some(0),
                party_id: 0,
                share_id: 3,
                partial_point: b"p0",
                required: 2,
                timeout_message: "timeout waiting for test exp open",
            },
            |partial_points| {
                Ok(partial_points
                    .iter()
                    .flat_map(|(_, point)| point.clone())
                    .collect())
            },
        )
        .await
    });

    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            let ready = {
                let r = reg.exp.lock();
                r.get(&0).is_some_and(|entry| entry.party_ids == vec![0])
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first exp contribution should be registered");

    let reg3 = reg.clone();
    let finalizer = tokio::spawn(async move {
        reg3.exp_open_async(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                sequence: Some(0),
                party_id: 1,
                share_id: 4,
                partial_point: b"p1",
                required: 2,
                timeout_message: "timeout waiting for test exp open",
            },
            |partial_points| {
                Ok(partial_points
                    .iter()
                    .flat_map(|(_, point)| point.clone())
                    .collect())
            },
        )
        .await
    });

    let (waiter, finalizer) = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        tokio::join!(waiter, finalizer)
    })
    .await
    .expect("exp open waiters should be notified by local insertion");

    assert_eq!(waiter.unwrap().unwrap(), b"p0p1".to_vec());
    assert_eq!(finalizer.unwrap().unwrap(), b"p0p1".to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_single_insert_wakes_waiters() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20001);

    let reg2 = reg.clone();
    let waiter = tokio::spawn(async move {
        reg2.open_share_at_async(
            0,
            "single-notify".to_string(),
            0,
            b"s0".to_vec(),
            2,
            |shares| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    // Wait for first contribution to be registered
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            let ready = {
                let r = reg.single.lock();
                r.get(&(0usize, "single-notify".to_string()))
                    .is_some_and(|entry| entry.party_ids == vec![0])
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first single contribution should be registered");

    let reg3 = reg.clone();
    let finalizer = tokio::spawn(async move {
        reg3.open_share_at_async(
            1,
            "single-notify".to_string(),
            0,
            b"s1".to_vec(),
            2,
            |shares| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    let (waiter, finalizer) = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        tokio::join!(waiter, finalizer)
    })
    .await
    .expect("single open waiters should be notified by local insertion");

    assert_eq!(waiter.unwrap().unwrap(), ClearShareValue::Integer(2));
    assert_eq!(finalizer.unwrap().unwrap(), ClearShareValue::Integer(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_batch_insert_wakes_waiters() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20002);

    let reg2 = reg.clone();
    let waiter = tokio::spawn(async move {
        reg2.batch_open_at_async(
            0,
            "batch-notify".to_string(),
            Some(0),
            vec![b"a0".to_vec(), b"b0".to_vec()],
            2,
            |shares, _pos| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            let ready = {
                let r = reg.batch.lock();
                r.get(&(0usize, "batch-notify".to_string(), 2usize))
                    .is_some_and(|entry| entry.party_ids == vec![0])
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first batch contribution should be registered");

    let reg3 = reg.clone();
    let finalizer = tokio::spawn(async move {
        reg3.batch_open_at_async(
            1,
            "batch-notify".to_string(),
            Some(0),
            vec![b"a1".to_vec(), b"b1".to_vec()],
            2,
            |shares, _pos| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    let (waiter, finalizer) = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        tokio::join!(waiter, finalizer)
    })
    .await
    .expect("batch open waiters should be notified by local insertion");

    assert_eq!(
        waiter.unwrap().unwrap(),
        vec![ClearShareValue::Integer(2), ClearShareValue::Integer(2)]
    );
    assert_eq!(
        finalizer.unwrap().unwrap(),
        vec![ClearShareValue::Integer(2), ClearShareValue::Integer(2)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_instances_are_isolated() {
    let router = OpenMessageRouter::new();
    let reg_a = router.register_instance(30001);
    let reg_b = router.register_instance(30002);

    // Insert into instance A
    reg_a
        .insert_single(0, "key", 0, b"share_a".to_vec())
        .unwrap();
    // Insert into instance B
    reg_b
        .insert_single(0, "key", 0, b"share_b".to_vec())
        .unwrap();

    // Verify isolation
    let a_count = reg_a
        .single
        .lock()
        .get(&(0, "key".to_string()))
        .unwrap()
        .shares
        .len();
    let b_count = reg_b
        .single
        .lock()
        .get(&(0, "key".to_string()))
        .unwrap()
        .shares
        .len();
    assert_eq!(a_count, 1);
    assert_eq!(b_count, 1);
}
