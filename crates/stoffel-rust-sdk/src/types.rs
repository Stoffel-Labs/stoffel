//! Common SDK value and identifier types.
//!
//! `Value` is the SDK payload type used by local execution and client handles.
//! The crypto wrapper types are intentionally small handles around protocol data
//! owned by the VM and MPC protocol crates.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub type PartyId = usize;
pub type ClientId = stoffelnet::network_utils::ClientId;
pub type Round = stoffel_mpc_coordinator::Round;
pub type MaskIndex = u64;

/// Public SDK value type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    I64(i64),
    U64(u64),
    Bool(bool),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Unit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueSummary {
    pub kind: String,
    pub item_count: Option<usize>,
    pub byte_len: Option<usize>,
}

impl Value {
    pub fn kind(&self) -> &'static str {
        match self {
            Value::I64(_) => "i64",
            Value::U64(_) => "u64",
            Value::Bool(_) => "bool",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::List(_) => "list",
            Value::Unit => "unit",
        }
    }

    pub fn summary(&self) -> ValueSummary {
        ValueSummary {
            kind: self.kind().to_owned(),
            item_count: match self {
                Value::List(values) => Some(values.len()),
                _ => None,
            },
            byte_len: match self {
                Value::Bytes(bytes) => Some(bytes.len()),
                Value::String(value) => Some(value.len()),
                _ => None,
            },
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::I64(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(values) => Some(values),
            _ => None,
        }
    }

    pub fn is_unit(&self) -> bool {
        matches!(self, Value::Unit)
    }

    pub fn into_string(self) -> Option<String> {
        match self {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Value::Bytes(value) => Some(value),
            _ => None,
        }
    }

    pub fn into_list(self) -> Option<Vec<Value>> {
        match self {
            Value::List(values) => Some(values),
            _ => None,
        }
    }

    pub(crate) fn to_vm_value(&self) -> Result<stoffel_vm_types::core_types::Value> {
        match self {
            Value::I64(value) => Ok(stoffel_vm_types::core_types::Value::I64(*value)),
            Value::U64(value) => Ok(stoffel_vm_types::core_types::Value::U64(*value)),
            Value::Bool(value) => Ok(stoffel_vm_types::core_types::Value::Bool(*value)),
            Value::Float(value) => Ok(stoffel_vm_types::core_types::Value::Float((*value).into())),
            Value::String(value) => Ok(stoffel_vm_types::core_types::Value::String(value.clone())),
            Value::Bytes(_) => Err(Error::InvalidInput(
                "byte inputs are only supported for local coordinator client inputs".to_owned(),
            )),
            Value::List(_) => Err(Error::InvalidInput(
                "list inputs are not supported by clear VM execution yet".to_owned(),
            )),
            Value::Unit => Ok(stoffel_vm_types::core_types::Value::Unit),
        }
    }

    pub(crate) fn from_vm_value(value: stoffel_vm_types::core_types::Value) -> Option<Self> {
        match value {
            stoffel_vm_types::core_types::Value::I64(value) => Some(Value::I64(value)),
            stoffel_vm_types::core_types::Value::I32(value) => Some(Value::I64(i64::from(value))),
            stoffel_vm_types::core_types::Value::I16(value) => Some(Value::I64(i64::from(value))),
            stoffel_vm_types::core_types::Value::I8(value) => Some(Value::I64(i64::from(value))),
            stoffel_vm_types::core_types::Value::U64(value) => Some(Value::U64(value)),
            stoffel_vm_types::core_types::Value::U32(value) => Some(Value::U64(u64::from(value))),
            stoffel_vm_types::core_types::Value::U16(value) => Some(Value::U64(u64::from(value))),
            stoffel_vm_types::core_types::Value::U8(value) => Some(Value::U64(u64::from(value))),
            stoffel_vm_types::core_types::Value::Bool(value) => Some(Value::Bool(value)),
            stoffel_vm_types::core_types::Value::Float(value) => Some(Value::Float(value.value())),
            stoffel_vm_types::core_types::Value::String(value) => Some(Value::String(value)),
            stoffel_vm_types::core_types::Value::Unit => Some(Value::Unit),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::I64(value) => write!(f, "{value}"),
            Value::U64(value) => write!(f, "{value}"),
            Value::Bool(value) => write!(f, "{value}"),
            Value::Float(value) => write!(f, "{value}"),
            Value::String(value) => write!(f, "{value}"),
            Value::Bytes(value) => write!(f, "0x{}", hex_encode(value)),
            Value::List(values) => {
                write!(f, "[")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{value}")?;
                }
                write!(f, "]")
            }
            Value::Unit => write!(f, "()"),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

macro_rules! value_from_int {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for Value {
                fn from(value: $ty) -> Self {
                    Value::I64(value as i64)
                }
            }
        )*
    };
}

value_from_int!(i8, i16, i32, i64, isize);

macro_rules! value_from_uint {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for Value {
                fn from(value: $ty) -> Self {
                    Value::U64(value as u64)
                }
            }
        )*
    };
}

value_from_uint!(u8, u16, u32, u64, usize);

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Bool(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Value::Float(value)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Value::Float(f64::from(value))
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::String(value.to_owned())
    }
}

impl From<&String> for Value {
    fn from(value: &String) -> Self {
        Value::String(value.clone())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::String(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Value::Bytes(value.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Value {
    fn from(value: [u8; N]) -> Self {
        Value::Bytes(value.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Value::Bytes(value)
    }
}

impl From<Vec<Value>> for Value {
    fn from(value: Vec<Value>) -> Self {
        Value::List(value)
    }
}

impl From<()> for Value {
    fn from((): ()) -> Self {
        Value::Unit
    }
}

fn value_type_error(expected: &'static str, actual: &Value) -> Error {
    Error::InvalidInput(format!(
        "expected {expected} SDK value, got {}",
        actual.kind()
    ))
}

macro_rules! try_from_value_copy {
    ($target:ty, $variant:ident, $expected:literal) => {
        impl TryFrom<Value> for $target {
            type Error = Error;

            fn try_from(value: Value) -> Result<Self> {
                <$target>::try_from(&value)
            }
        }

        impl TryFrom<&Value> for $target {
            type Error = Error;

            fn try_from(value: &Value) -> Result<Self> {
                match value {
                    Value::$variant(value) => Ok(*value),
                    actual => Err(value_type_error($expected, actual)),
                }
            }
        }
    };
}

try_from_value_copy!(i64, I64, "i64");
try_from_value_copy!(u64, U64, "u64");
try_from_value_copy!(bool, Bool, "bool");
try_from_value_copy!(f64, Float, "float");

impl TryFrom<Value> for String {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::String(value) => Ok(value),
            actual => Err(value_type_error("string", &actual)),
        }
    }
}

impl TryFrom<&Value> for String {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::String(value) => Ok(value.clone()),
            actual => Err(value_type_error("string", actual)),
        }
    }
}

impl<'a> TryFrom<&'a Value> for &'a str {
    type Error = Error;

    fn try_from(value: &'a Value) -> Result<Self> {
        match value {
            Value::String(value) => Ok(value),
            actual => Err(value_type_error("string", actual)),
        }
    }
}

impl TryFrom<Value> for Vec<u8> {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Bytes(value) => Ok(value),
            actual => Err(value_type_error("bytes", &actual)),
        }
    }
}

impl TryFrom<&Value> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Bytes(value) => Ok(value.clone()),
            actual => Err(value_type_error("bytes", actual)),
        }
    }
}

impl<'a> TryFrom<&'a Value> for &'a [u8] {
    type Error = Error;

    fn try_from(value: &'a Value) -> Result<Self> {
        match value {
            Value::Bytes(value) => Ok(value),
            actual => Err(value_type_error("bytes", actual)),
        }
    }
}

impl TryFrom<Value> for Vec<Value> {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::List(values) => Ok(values),
            actual => Err(value_type_error("list", &actual)),
        }
    }
}

impl<'a> TryFrom<&'a Value> for &'a [Value] {
    type Error = Error;

    fn try_from(value: &'a Value) -> Result<Self> {
        match value {
            Value::List(values) => Ok(values),
            actual => Err(value_type_error("list", actual)),
        }
    }
}

impl TryFrom<Value> for () {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Unit => Ok(()),
            actual => Err(value_type_error("unit", &actual)),
        }
    }
}

impl TryFrom<&Value> for () {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Unit => Ok(()),
            actual => Err(value_type_error("unit", actual)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub key_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commitments: Vec<Vec<u8>>,
}

impl Share {
    pub fn new(key_name: impl Into<String>) -> Self {
        Self {
            key_name: key_name.into(),
            data: None,
            commitments: Vec::new(),
        }
    }

    pub fn opaque(key_name: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            key_name: key_name.into(),
            data: Some(data.into()),
            commitments: Vec::new(),
        }
    }

    pub fn feldman(
        key_name: impl Into<String>,
        data: impl Into<Vec<u8>>,
        commitments: impl IntoIterator<Item = impl Into<Vec<u8>>>,
    ) -> Self {
        Self {
            key_name: key_name.into(),
            data: Some(data.into()),
            commitments: commitments.into_iter().map(Into::into).collect(),
        }
    }

    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn commitments(&self) -> &[Vec<u8>] {
        &self.commitments
    }

    pub fn commitment(&self, index: usize) -> Option<&[u8]> {
        self.commitments.get(index).map(Vec::as_slice)
    }

    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    pub fn has_commitments(&self) -> bool {
        !self.commitments.is_empty()
    }

    pub fn is_feldman(&self) -> bool {
        self.has_commitments()
    }

    pub fn is_opaque(&self) -> bool {
        !self.has_commitments()
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        self.commitment(0)
            .map(|bytes| PublicKey::new(self.key_name.clone(), bytes.to_vec()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub key_name: String,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    pub fn new(key_name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            key_name: key_name.into(),
            bytes: bytes.into(),
        }
    }

    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldElement(pub Vec<u8>);

impl FieldElement {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for FieldElement {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<&[u8]> for FieldElement {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupElement(pub Vec<u8>);

impl GroupElement {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for GroupElement {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<&[u8]> for GroupElement {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}
