use super::error::{type_error, unsupported, ShareRuntimeProvider, ValueOpError, ValueOpResult};
use super::share_operands::{contains_share_operand, matching_share_pair};
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

pub(crate) fn bit_and(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_and(left, right) {
        return result;
    }

    if let Some(pair) = matching_share_pair("AND", left, right)? {
        ensure_secret_bool(pair.share_type, "Bitwise AND")?;
        let data = share_runtime()?.multiply_share_data(
            pair.share_type,
            pair.left_data,
            pair.right_data,
        )?;
        return Ok(Value::Share(pair.share_type, data));
    }

    if contains_share_operand(left, right) {
        unsupported("Bitwise AND is only supported on secret bool shares")
    } else {
        type_error("AND")
    }
}

pub(crate) fn bit_or(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_or(left, right) {
        return result;
    }

    if let Some(pair) = matching_share_pair("OR", left, right)? {
        ensure_secret_bool(pair.share_type, "Bitwise OR")?;
        let product = share_runtime()?.multiply_share_data(
            pair.share_type,
            pair.left_data,
            pair.right_data,
        )?;
        let data = bool_or_data(
            share_runtime,
            pair.share_type,
            pair.left_data,
            pair.right_data,
            &product,
        )?;
        return Ok(Value::Share(pair.share_type, data));
    }

    if contains_share_operand(left, right) {
        unsupported("Bitwise OR is only supported on secret bool shares")
    } else {
        type_error("OR")
    }
}

pub(crate) fn bit_xor(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_xor(left, right) {
        return result;
    }

    if let Some(pair) = matching_share_pair("XOR", left, right)? {
        ensure_secret_bool(pair.share_type, "Bitwise XOR")?;
        let product = share_runtime()?.multiply_share_data(
            pair.share_type,
            pair.left_data,
            pair.right_data,
        )?;
        let data = bool_xor_data(
            share_runtime,
            pair.share_type,
            pair.left_data,
            pair.right_data,
            &product,
        )?;
        return Ok(Value::Share(pair.share_type, data));
    }

    if contains_share_operand(left, right) {
        unsupported("Bitwise XOR is only supported on secret bool shares")
    } else {
        type_error("XOR")
    }
}

pub(crate) fn bit_not(
    value: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_not(value) {
        return result;
    }

    if let Value::Share(share_type, share_data) = value {
        ensure_secret_bool(*share_type, "Bitwise NOT")?;
        let data = share_runtime()?.scalar_sub_data(*share_type, 1, share_data)?;
        Ok(Value::Share(*share_type, data))
    } else if matches!(value, Value::Share(_, _)) {
        unsupported("Bitwise NOT is only supported on secret bool shares")
    } else {
        type_error("NOT")
    }
}

pub(crate) fn shl(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_shl(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Left shift is not supported on secret shares")
    } else {
        type_error("SHL")
    }
}

pub(crate) fn shr(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_shr(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Right shift is not supported on secret shares")
    } else {
        type_error("SHR")
    }
}

pub(crate) fn try_clear_bit_and(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a & b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a && *b)),
        _ => return None,
    })
}

pub(crate) fn try_clear_bit_or(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a | b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a || *b)),
        _ => return None,
    })
}

pub(crate) fn try_clear_bit_xor(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a ^ b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a ^ b)),
        _ => return None,
    })
}

pub(crate) fn try_clear_bit_not(value: &Value) -> Option<ValueOpResult<Value>> {
    Some(match value {
        Value::I64(value) => Ok(Value::I64(!*value)),
        Value::Bool(value) => Ok(Value::Bool(!*value)),
        _ => return None,
    })
}

pub(crate) fn try_clear_shl(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_i64_shl(*a, *b).map(Value::I64),
        _ => return None,
    })
}

pub(crate) fn try_clear_shr(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_i64_shr(*a, *b).map(Value::I64),
        _ => return None,
    })
}

fn checked_shift_amount(operation: &'static str, amount: i64) -> ValueOpResult<u32> {
    u32::try_from(amount).map_err(|_| ValueOpError::InvalidShiftAmount { operation, amount })
}

fn checked_i64_shl(value: i64, amount: i64) -> ValueOpResult<i64> {
    let amount = checked_shift_amount("SHL", amount)?;
    value
        .checked_shl(amount)
        .ok_or(ValueOpError::ShiftOutOfRange {
            operation: "SHL",
            amount,
        })
}

fn checked_i64_shr(value: i64, amount: i64) -> ValueOpResult<i64> {
    let amount = checked_shift_amount("SHR", amount)?;
    value
        .checked_shr(amount)
        .ok_or(ValueOpError::ShiftOutOfRange {
            operation: "SHR",
            amount,
        })
}

pub(crate) fn bool_xor_data(
    share_runtime: ShareRuntimeProvider<'_>,
    share_type: ShareType,
    left_data: &ShareData,
    right_data: &ShareData,
    product_data: &ShareData,
) -> ValueOpResult<ShareData> {
    ensure_secret_bool(share_type, "Bitwise XOR")?;
    let runtime = share_runtime()?;
    let sum = runtime.add_data(share_type, left_data, right_data)?;
    let doubled_product = runtime.mul_scalar_data(share_type, product_data, 2)?;
    Ok(runtime.sub_data(share_type, &sum, &doubled_product)?)
}

pub(crate) fn bool_or_data(
    share_runtime: ShareRuntimeProvider<'_>,
    share_type: ShareType,
    left_data: &ShareData,
    right_data: &ShareData,
    product_data: &ShareData,
) -> ValueOpResult<ShareData> {
    ensure_secret_bool(share_type, "Bitwise OR")?;
    let runtime = share_runtime()?;
    let sum = runtime.add_data(share_type, left_data, right_data)?;
    Ok(runtime.sub_data(share_type, &sum, product_data)?)
}

fn ensure_secret_bool(share_type: ShareType, operation: &'static str) -> ValueOpResult<()> {
    if share_type == ShareType::boolean() {
        Ok(())
    } else {
        unsupported(match operation {
            "Bitwise AND" => "Bitwise AND is only supported on secret bool shares",
            "Bitwise OR" => "Bitwise OR is only supported on secret bool shares",
            "Bitwise XOR" => "Bitwise XOR is only supported on secret bool shares",
            "Bitwise NOT" => "Bitwise NOT is only supported on secret bool shares",
            _ => "Bitwise share operation is only supported on secret bool shares",
        })
    }
}
