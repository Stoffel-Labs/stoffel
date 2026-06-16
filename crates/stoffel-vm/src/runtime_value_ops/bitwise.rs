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

macro_rules! integer_bitwise_arms {
    ($left:expr, $right:expr, $op:tt) => {
        match ($left, $right) {
            (Value::I64(a), Value::I64(b)) => Some(Ok(Value::I64(a $op b))),
            (Value::I32(a), Value::I32(b)) => Some(Ok(Value::I32(a $op b))),
            (Value::I16(a), Value::I16(b)) => Some(Ok(Value::I16(a $op b))),
            (Value::I8(a), Value::I8(b)) => Some(Ok(Value::I8(a $op b))),
            (Value::U8(a), Value::U8(b)) => Some(Ok(Value::U8(a $op b))),
            (Value::U16(a), Value::U16(b)) => Some(Ok(Value::U16(a $op b))),
            (Value::U32(a), Value::U32(b)) => Some(Ok(Value::U32(a $op b))),
            (Value::U64(a), Value::U64(b)) => Some(Ok(Value::U64(a $op b))),
            _ => None,
        }
    };
}

pub(crate) fn try_clear_bit_and(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    if let (Value::Bool(a), Value::Bool(b)) = (left, right) {
        return Some(Ok(Value::Bool(*a && *b)));
    }
    integer_bitwise_arms!(left, right, &)
}

pub(crate) fn try_clear_bit_or(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    if let (Value::Bool(a), Value::Bool(b)) = (left, right) {
        return Some(Ok(Value::Bool(*a || *b)));
    }
    integer_bitwise_arms!(left, right, |)
}

pub(crate) fn try_clear_bit_xor(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    if let (Value::Bool(a), Value::Bool(b)) = (left, right) {
        return Some(Ok(Value::Bool(a ^ b)));
    }
    integer_bitwise_arms!(left, right, ^)
}

pub(crate) fn try_clear_bit_not(value: &Value) -> Option<ValueOpResult<Value>> {
    Some(match value {
        Value::I64(value) => Ok(Value::I64(!*value)),
        Value::I32(value) => Ok(Value::I32(!*value)),
        Value::I16(value) => Ok(Value::I16(!*value)),
        Value::I8(value) => Ok(Value::I8(!*value)),
        Value::U8(value) => Ok(Value::U8(!*value)),
        Value::U16(value) => Ok(Value::U16(!*value)),
        Value::U32(value) => Ok(Value::U32(!*value)),
        Value::U64(value) => Ok(Value::U64(!*value)),
        Value::Bool(value) => Ok(Value::Bool(!*value)),
        _ => return None,
    })
}

macro_rules! integer_shift_arms {
    ($left:expr, $right:expr, $operation:expr, $method:ident) => {
        match ($left, $right) {
            (Value::I64(a), Value::I64(b)) => {
                Some(checked_shift($operation, *a, *b, i64::$method).map(Value::I64))
            }
            (Value::I32(a), Value::I32(b)) => {
                Some(checked_shift($operation, *a, i64::from(*b), i32::$method).map(Value::I32))
            }
            (Value::I16(a), Value::I16(b)) => {
                Some(checked_shift($operation, *a, i64::from(*b), i16::$method).map(Value::I16))
            }
            (Value::I8(a), Value::I8(b)) => {
                Some(checked_shift($operation, *a, i64::from(*b), i8::$method).map(Value::I8))
            }
            (Value::U8(a), Value::U8(b)) => {
                Some(checked_shift($operation, *a, i64::from(*b), u8::$method).map(Value::U8))
            }
            (Value::U16(a), Value::U16(b)) => {
                Some(checked_shift($operation, *a, i64::from(*b), u16::$method).map(Value::U16))
            }
            (Value::U32(a), Value::U32(b)) => {
                Some(checked_shift($operation, *a, i64::from(*b), u32::$method).map(Value::U32))
            }
            (Value::U64(a), Value::U64(b)) => Some(match i64::try_from(*b) {
                Ok(amount) => checked_shift($operation, *a, amount, u64::$method).map(Value::U64),
                Err(_) => Err(ValueOpError::ShiftOutOfRange {
                    operation: $operation,
                    amount: u32::MAX,
                }),
            }),
            _ => None,
        }
    };
}

pub(crate) fn try_clear_shl(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    integer_shift_arms!(left, right, "SHL", checked_shl)
}

pub(crate) fn try_clear_shr(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    integer_shift_arms!(left, right, "SHR", checked_shr)
}

fn checked_shift_amount(operation: &'static str, amount: i64) -> ValueOpResult<u32> {
    u32::try_from(amount).map_err(|_| ValueOpError::InvalidShiftAmount { operation, amount })
}

fn checked_shift<T>(
    operation: &'static str,
    value: T,
    amount: i64,
    shift: impl FnOnce(T, u32) -> Option<T>,
) -> ValueOpResult<T> {
    let amount = checked_shift_amount(operation, amount)?;
    shift(value, amount).ok_or(ValueOpError::ShiftOutOfRange { operation, amount })
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
