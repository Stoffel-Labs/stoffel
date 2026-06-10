use super::error::{unsupported, ValueOpError, ValueOpResult};
use std::cmp::Ordering;
use stoffel_vm_types::core_types::{Value, F64};

#[inline]
pub(crate) fn compare(left: &Value, right: &Value) -> ValueOpResult<Ordering> {
    if let Some(ordering) = try_clear_compare(left, right) {
        return Ok(ordering);
    }

    match (left, right) {
        (Value::Share(_, _), _) | (_, Value::Share(_, _)) => {
            unsupported("CMP on secret shares is not supported without an MPC comparison protocol")
        }
        _ => Err(ValueOpError::CannotCompare {
            left: format!("{left:?}"),
            right: format!("{right:?}"),
        }),
    }
}

#[inline]
pub(crate) fn try_clear_compare(left: &Value, right: &Value) -> Option<Ordering> {
    if let (Some(left), Some(right)) = (numeric_value(left), numeric_value(right)) {
        return compare_numeric(left, right);
    }

    Some(match (left, right) {
        (Value::String(a), Value::String(b)) => compare_ordered(a, b),
        (Value::Bool(a), Value::Bool(b)) => compare_ordered(a, b),
        _ => return None,
    })
}

#[inline]
fn compare_ordered<T: Ord>(left: &T, right: &T) -> Ordering {
    left.cmp(right)
}

#[derive(Clone, Copy)]
enum NumericValue {
    Signed(i128),
    Unsigned(u128),
    Float(f64),
}

fn numeric_value(value: &Value) -> Option<NumericValue> {
    Some(match value {
        Value::I64(value) => NumericValue::Signed(*value as i128),
        Value::I32(value) => NumericValue::Signed(*value as i128),
        Value::I16(value) => NumericValue::Signed(*value as i128),
        Value::I8(value) => NumericValue::Signed(*value as i128),
        Value::U64(value) => NumericValue::Unsigned(*value as u128),
        Value::U32(value) => NumericValue::Unsigned(*value as u128),
        Value::U16(value) => NumericValue::Unsigned(*value as u128),
        Value::U8(value) => NumericValue::Unsigned(*value as u128),
        Value::Float(F64(value)) => NumericValue::Float(*value),
        _ => return None,
    })
}

fn compare_numeric(left: NumericValue, right: NumericValue) -> Option<Ordering> {
    Some(match (left, right) {
        (NumericValue::Signed(a), NumericValue::Signed(b)) => a.cmp(&b),
        (NumericValue::Unsigned(a), NumericValue::Unsigned(b)) => a.cmp(&b),
        (NumericValue::Signed(a), NumericValue::Unsigned(b)) => compare_i128_u128(a, b),
        (NumericValue::Unsigned(a), NumericValue::Signed(b)) => compare_i128_u128(b, a).reverse(),
        (NumericValue::Float(a), NumericValue::Float(b)) => a.partial_cmp(&b)?,
        (NumericValue::Signed(a), NumericValue::Float(b)) => compare_i128_f64(a, b)?,
        (NumericValue::Float(a), NumericValue::Signed(b)) => compare_i128_f64(b, a)?.reverse(),
        (NumericValue::Unsigned(a), NumericValue::Float(b)) => compare_u128_f64(a, b)?,
        (NumericValue::Float(a), NumericValue::Unsigned(b)) => compare_u128_f64(b, a)?.reverse(),
    })
}

fn compare_i128_u128(left: i128, right: u128) -> Ordering {
    if left < 0 {
        Ordering::Less
    } else {
        (left as u128).cmp(&right)
    }
}

fn compare_i128_f64(left: i128, right: f64) -> Option<Ordering> {
    if right.is_nan() {
        return None;
    }
    if right.is_infinite() {
        return Some(if right.is_sign_positive() {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }

    if left >= 0 {
        compare_u128_f64(left as u128, right)
    } else if right >= 0.0 {
        Some(Ordering::Less)
    } else {
        compare_u128_positive_f64(left.unsigned_abs(), -right).map(Ordering::reverse)
    }
}

fn compare_u128_f64(left: u128, right: f64) -> Option<Ordering> {
    if right.is_nan() {
        return None;
    }
    if right.is_infinite() {
        return Some(if right.is_sign_positive() {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    if right < 0.0 {
        return Some(Ordering::Greater);
    }

    compare_u128_positive_f64(left, right)
}

fn compare_u128_positive_f64(left: u128, right: f64) -> Option<Ordering> {
    debug_assert!(right.is_finite());
    debug_assert!(right >= 0.0);

    let bits = right.to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);

    if exponent_bits == 0 && fraction == 0 {
        return Some(left.cmp(&0));
    }

    let (mantissa, exponent) = if exponent_bits == 0 {
        (fraction, 1 - 1023 - 52)
    } else {
        ((1u64 << 52) | fraction, exponent_bits - 1023 - 52)
    };

    if exponent >= 0 {
        let shift = exponent as u32;
        return if shift >= 128 || (mantissa as u128).checked_shl(shift).is_none() {
            Some(Ordering::Less)
        } else {
            Some(left.cmp(&((mantissa as u128) << shift)))
        };
    }

    let shift = (-exponent) as u32;
    let floor = if shift >= 64 {
        0
    } else {
        (mantissa >> shift) as u128
    };
    match left.cmp(&floor) {
        Ordering::Equal => {
            let has_fraction = (shift >= 64 && mantissa != 0)
                || (shift < 64 && (mantissa & ((1u64 << shift) - 1)) != 0);
            Some(if has_fraction {
                Ordering::Less
            } else {
                Ordering::Equal
            })
        }
        ordering => Some(ordering),
    }
}
