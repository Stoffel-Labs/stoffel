use super::error::{ValueOpError, ValueOpResult};
use super::*;
use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::{MpcEngine, MpcSessionTopology, ShareAlgebraResult};
use crate::net::share_runtime::MpcShareRuntime;
use std::sync::{Arc, Mutex};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, Value, F64,
};

fn unavailable_runtime<'a>() -> ValueOpResult<MpcShareRuntime<'a>> {
    Err(ValueOpError::Unsupported {
        message: "share runtime should not be requested",
    })
}

#[derive(Default)]
struct ScalarRecordingEngine {
    add_scalars: Mutex<Vec<i64>>,
}

impl MpcEngine for ScalarRecordingEngine {
    fn protocol_name(&self) -> &'static str {
        "scalar-recording"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(0, 0, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn add_share_scalar_local(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        self.add_scalars.lock().unwrap().push(scalar);
        Ok(scalar.to_le_bytes().to_vec())
    }

    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

#[test]
fn clear_add_does_not_require_share_runtime() {
    let result = add(&Value::I64(2), &Value::I64(3), &unavailable_runtime)
        .expect("clear add should not touch MPC runtime");

    assert_eq!(result, Value::I64(5));
}

#[test]
fn clear_float_arithmetic_does_not_require_share_runtime() {
    assert_eq!(
        add(
            &Value::Float(F64(1.25)),
            &Value::Float(F64(2.5)),
            &unavailable_runtime
        )
        .expect("float add should be local"),
        Value::Float(F64(3.75))
    );
    assert_eq!(
        sub(
            &Value::Float(F64(0.0)),
            &Value::Float(F64(0.125)),
            &unavailable_runtime
        )
        .expect("float sub should be local"),
        Value::Float(F64(-0.125))
    );
    assert_eq!(
        mul(
            &Value::Float(F64(1.5)),
            &Value::I64(2),
            &unavailable_runtime
        )
        .expect("float mul should accept integer scalar"),
        Value::Float(F64(3.0))
    );
}

#[test]
fn share_type_mismatch_rejects_before_backend_dispatch() {
    let err = add(
        &Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![1])),
        &Value::Share(ShareType::secret_int(32), ShareData::Opaque(vec![2])),
        &unavailable_runtime,
    )
    .expect_err("mismatched share types should fail before asking for a backend");

    assert!(err
        .to_string()
        .contains("Share type mismatch in ADD operation"));
}

#[test]
fn share_scalar_ops_accept_vm_integer_widths() {
    let engine = Arc::new(ScalarRecordingEngine::default());
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let share_type = ShareType::secret_int(64);
    let share = Value::Share(share_type, ShareData::Opaque(vec![1]));
    let runtime =
        || MpcShareRuntime::from_configured(Some(runtime_engine.as_ref())).map_err(Into::into);

    let result = add(&share, &Value::U8(7), &runtime).expect("u8 scalar should be accepted");

    assert_eq!(
        result,
        Value::Share(share_type, ShareData::Opaque(7i64.to_le_bytes().to_vec()))
    );
    assert_eq!(engine.add_scalars.lock().unwrap().as_slice(), &[7]);
}

#[test]
fn share_scalar_ops_reject_scalars_outside_i64_domain_before_backend_dispatch() {
    let share = Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![1]));

    let err = add(
        &share,
        &Value::U64(i64::MAX as u64 + 1),
        &unavailable_runtime,
    )
    .expect_err("oversized scalar should fail before backend dispatch");

    assert_eq!(err.to_string(), "share scalar exceeds i64 range");
}

#[test]
fn compare_rejects_secret_shares() {
    let err = compare(
        &Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![1])),
        &Value::I64(1),
    )
    .expect_err("secret comparisons require an explicit MPC comparison protocol");

    assert!(err.to_string().contains("CMP on secret shares"));
}

#[test]
fn clear_compare_helper_handles_ordered_values() {
    assert_eq!(
        try_clear_compare(&Value::I64(2), &Value::I64(7)).expect("i64 is comparable"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        try_clear_compare(&Value::Bool(true), &Value::Bool(false)).expect("bool is comparable"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        try_clear_compare(&Value::I64(1), &Value::U64(1)).expect("mixed integers are comparable"),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn clear_compare_helper_handles_public_float64_values() {
    assert_eq!(
        try_clear_compare(&Value::Float(F64(0.0)), &Value::Float(F64(0.0)))
            .expect("float64 equality should be comparable"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        try_clear_compare(&Value::Float(F64(0.0)), &Value::I64(0))
            .expect("float64 and integer literals should be comparable"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        try_clear_compare(
            &Value::U64(9_007_199_254_740_993),
            &Value::Float(F64(9_007_199_254_740_992.0)),
        )
        .expect("large integer and float values should be comparable"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        try_clear_compare(&Value::U64(0), &Value::Float(F64(f64::MIN_POSITIVE)))
            .expect("zero and a tiny positive float should be comparable"),
        std::cmp::Ordering::Less
    );
    assert!(
        try_clear_compare(&Value::Float(F64(f64::NAN)), &Value::Float(F64(0.0))).is_none(),
        "NaN remains unordered because the VM comparison flag has no unordered state"
    );
}

#[test]
fn unsupported_secret_bit_ops_classify_any_share_type() {
    let fixed_share = Value::Share(
        ShareType::default_secret_fixed_point(),
        ShareData::Opaque(vec![1]),
    );

    let err = bit_and(&fixed_share, &Value::Bool(true), &unavailable_runtime)
        .expect_err("secret shares need explicit bitwise protocols");
    assert!(err
        .to_string()
        .contains("Bitwise AND is only supported on secret bool shares"));

    let err = shl(&Value::I64(1), &fixed_share).expect_err("secret shift amounts are unsupported");
    assert!(err
        .to_string()
        .contains("Left shift is not supported on secret shares"));

    let err =
        bit_not(&fixed_share, &unavailable_runtime).expect_err("secret bitwise NOT is unsupported");
    assert!(err
        .to_string()
        .contains("Bitwise NOT is only supported on secret bool shares"));
}
