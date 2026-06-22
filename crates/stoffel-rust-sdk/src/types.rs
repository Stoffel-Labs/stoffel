//! Common SDK value and identifier types.
//!
//! `Value` is the SDK payload type used by local execution and client handles.
//! The crypto wrapper types are intentionally small handles around protocol data
//! owned by the VM and MPC protocol crates.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use stoffel_vm_types::core_types::ShareType;

use crate::config::MpcBackend;
use crate::error::{Error, Result};

pub type PartyId = usize;
pub type ClientId = stoffelnet::network_utils::ClientId;
pub type Round = stoffel_mpc_coordinator::Round;
pub type MaskIndex = u64;

/// SDK-level scalar type expected by a typed client input or output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientValueType {
    Integer,
    Boolean,
    FixedPoint,
}

impl ClientValueType {
    pub fn is_compatible_with_share_type(self, share_type: ShareType) -> bool {
        match (self, share_type) {
            (ClientValueType::Boolean, ShareType::SecretInt { bit_length: 1 }) => true,
            (ClientValueType::Integer, ShareType::SecretInt { bit_length }) => bit_length > 1,
            (ClientValueType::Integer, ShareType::SecretUInt { .. }) => true,
            (ClientValueType::FixedPoint, ShareType::SecretFixedPoint { .. }) => true,
            _ => false,
        }
    }
}

/// A Rust scalar that can be used as a typed client input.
pub trait ClientInputValue {
    const VALUE_TYPE: ClientValueType;

    fn into_sdk_value(self) -> Value;
}

/// A Rust scalar that can be decoded from typed client output.
pub trait ClientOutputValue: Sized {
    const VALUE_TYPE: ClientValueType;

    fn try_from_sdk_value(value: Value) -> Result<Self>;
}

/// Compile-time typed client input payload.
///
/// Implement this trait for domain structs when tuple inputs are not expressive
/// enough. The SDK still validates the declared Rust type shape against the
/// loaded program manifest before network submission.
pub trait TypedClientInputs {
    fn into_values(self) -> Vec<Value>;

    fn value_types() -> Vec<ClientValueType>;
}

/// Compile-time typed client output payload.
///
/// Implement this trait for domain structs when tuple outputs are not
/// expressive enough.
pub trait TypedClientOutputs: Sized {
    fn from_values(values: Vec<Value>) -> Result<Self>;

    fn value_types() -> Vec<ClientValueType>;
}

/// Positional arguments for direct program execution.
///
/// Rust does not support variadic methods, so the SDK accepts `()`, one scalar
/// value, or tuples of scalar values:
///
/// ```
/// # use stoffel::prelude::*;
/// # fn example(program: &StoffelRuntime) -> stoffel::Result<()> {
/// let result = program.execute("main", (40_i64, 2_i64))?;
/// # let _ = result;
/// # Ok(())
/// # }
/// ```
pub trait ProgramArgs {
    fn into_values(self) -> Vec<Value>;
}

/// Generated program metadata emitted by `stoffel-bindgen`.
///
/// This marker trait lets application code carry the bytecode manifest's
/// backend, curve, and client IO shape at the Rust type level. Builders can use
/// it to select the program backend without hand-written backend/curve literals,
/// and clients can validate generated bindings against the loaded bytecode
/// before submitting network inputs.
pub trait GeneratedProgramManifest {
    const BACKEND: MpcBackend;

    fn client_input_types(client_slot: u64) -> Option<&'static [ClientValueType]>;

    fn client_output_types(client_slot: u64) -> Option<&'static [ClientValueType]>;
}

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
    Object(BTreeMap<String, Value>),
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
            Value::Object(_) => "object",
            Value::Unit => "unit",
        }
    }

    pub fn summary(&self) -> ValueSummary {
        ValueSummary {
            kind: self.kind().to_owned(),
            item_count: match self {
                Value::List(values) => Some(values.len()),
                Value::Object(fields) => Some(fields.len()),
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

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(fields) => Some(fields),
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

    pub fn into_object(self) -> Option<BTreeMap<String, Value>> {
        match self {
            Value::Object(fields) => Some(fields),
            _ => None,
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
            Value::Object(fields) => {
                write!(f, "{{")?;
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{name}: {value}")?;
                }
                write!(f, "}}")
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

macro_rules! client_integer_input {
    ($($ty:ty),* $(,)?) => {
        $(
            impl ClientInputValue for $ty {
                const VALUE_TYPE: ClientValueType = ClientValueType::Integer;

                fn into_sdk_value(self) -> Value {
                    Value::from(self)
                }
            }
        )*
    };
}

client_integer_input!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Bool(value)
    }
}

impl ClientInputValue for bool {
    const VALUE_TYPE: ClientValueType = ClientValueType::Boolean;

    fn into_sdk_value(self) -> Value {
        Value::Bool(self)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Value::Float(value)
    }
}

impl ClientInputValue for f64 {
    const VALUE_TYPE: ClientValueType = ClientValueType::FixedPoint;

    fn into_sdk_value(self) -> Value {
        Value::Float(self)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Value::Float(f64::from(value))
    }
}

impl ClientInputValue for f32 {
    const VALUE_TYPE: ClientValueType = ClientValueType::FixedPoint;

    fn into_sdk_value(self) -> Value {
        Value::Float(f64::from(self))
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

impl From<BTreeMap<String, Value>> for Value {
    fn from(value: BTreeMap<String, Value>) -> Self {
        Value::Object(value)
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

try_from_value_copy!(f64, Float, "float");

macro_rules! try_from_signed_integer_value {
    ($($target:ty),* $(,)?) => {
        $(
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
                        Value::I64(value) => <$target>::try_from(*value).map_err(|_| {
                            Error::InvalidInput(format!("{value} is out of range for {}", stringify!($target)))
                        }),
                        Value::U64(value) => <$target>::try_from(*value).map_err(|_| {
                            Error::InvalidInput(format!("{value} is out of range for {}", stringify!($target)))
                        }),
                        actual => Err(value_type_error(stringify!($target), actual)),
                    }
                }
            }
        )*
    };
}

macro_rules! try_from_unsigned_integer_value {
    ($($target:ty),* $(,)?) => {
        $(
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
                        Value::U64(value) => <$target>::try_from(*value).map_err(|_| {
                            Error::InvalidInput(format!("{value} is out of range for {}", stringify!($target)))
                        }),
                        Value::I64(value) => <$target>::try_from(*value).map_err(|_| {
                            Error::InvalidInput(format!("{value} is out of range for {}", stringify!($target)))
                        }),
                        actual => Err(value_type_error(stringify!($target), actual)),
                    }
                }
            }
        )*
    };
}

try_from_signed_integer_value!(i8, i16, i32, i64);
try_from_unsigned_integer_value!(u8, u16, u32, u64);

impl TryFrom<Value> for bool {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        bool::try_from(&value)
    }
}

impl TryFrom<&Value> for bool {
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self> {
        match value {
            Value::Bool(value) => Ok(*value),
            Value::U64(0) | Value::I64(0) => Ok(false),
            Value::U64(1) | Value::I64(1) => Ok(true),
            actual => Err(value_type_error("bool or integer 0/1", actual)),
        }
    }
}

macro_rules! client_integer_output {
    ($($ty:ty),* $(,)?) => {
        $(
            impl ClientOutputValue for $ty {
                const VALUE_TYPE: ClientValueType = ClientValueType::Integer;

                fn try_from_sdk_value(value: Value) -> Result<Self> {
                    <$ty>::try_from(value)
                }
            }
        )*
    };
}

client_integer_output!(i8, i16, i32, i64, u8, u16, u32, u64);

impl ClientOutputValue for bool {
    const VALUE_TYPE: ClientValueType = ClientValueType::Boolean;

    fn try_from_sdk_value(value: Value) -> Result<Self> {
        bool::try_from(value)
    }
}

impl ClientOutputValue for f64 {
    const VALUE_TYPE: ClientValueType = ClientValueType::FixedPoint;

    fn try_from_sdk_value(value: Value) -> Result<Self> {
        f64::try_from(value)
    }
}

impl TypedClientInputs for () {
    fn into_values(self) -> Vec<Value> {
        Vec::new()
    }

    fn value_types() -> Vec<ClientValueType> {
        Vec::new()
    }
}

impl ProgramArgs for () {
    fn into_values(self) -> Vec<Value> {
        Vec::new()
    }
}

impl<T> TypedClientInputs for T
where
    T: ClientInputValue,
{
    fn into_values(self) -> Vec<Value> {
        vec![self.into_sdk_value()]
    }

    fn value_types() -> Vec<ClientValueType> {
        vec![T::VALUE_TYPE]
    }
}

macro_rules! program_arg_scalar {
    ($($ty:ty),* $(,)?) => {
        $(
            impl ProgramArgs for $ty {
                fn into_values(self) -> Vec<Value> {
                    vec![self.into()]
                }
            }
        )*
    };
}

program_arg_scalar!(
    i8, i16, i32, i64, isize,
    u8, u16, u32, u64, usize,
    bool, f32, f64,
    String, &str, Value,
    Vec<u8>, &[u8], Vec<Value>, BTreeMap<String, Value>,
);

impl<const N: usize> ProgramArgs for [u8; N] {
    fn into_values(self) -> Vec<Value> {
        vec![self.into()]
    }
}

impl ProgramArgs for &String {
    fn into_values(self) -> Vec<Value> {
        vec![self.into()]
    }
}

impl TypedClientOutputs for () {
    fn from_values(values: Vec<Value>) -> Result<Self> {
        if values.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidInput(format!(
                "expected 0 typed outputs, got {}",
                values.len()
            )))
        }
    }

    fn value_types() -> Vec<ClientValueType> {
        Vec::new()
    }
}

impl<T> TypedClientOutputs for T
where
    T: ClientOutputValue,
{
    fn from_values(values: Vec<Value>) -> Result<Self> {
        let [value]: [Value; 1] = values.try_into().map_err(|values: Vec<Value>| {
            Error::InvalidInput(format!("expected 1 typed output, got {}", values.len()))
        })?;
        T::try_from_sdk_value(value)
    }

    fn value_types() -> Vec<ClientValueType> {
        vec![T::VALUE_TYPE]
    }
}

macro_rules! typed_client_tuple {
    ($(($($type_name:ident $value_name:ident),+)),+ $(,)?) => {
        $(
            impl<$($type_name),+> TypedClientInputs for ($($type_name,)+)
            where
                $($type_name: ClientInputValue),+
            {
                fn into_values(self) -> Vec<Value> {
                    let ($($value_name,)+) = self;
                    vec![$($value_name.into_sdk_value()),+]
                }

                fn value_types() -> Vec<ClientValueType> {
                    vec![$($type_name::VALUE_TYPE),+]
                }
            }

            impl<$($type_name),+> TypedClientOutputs for ($($type_name,)+)
            where
                $($type_name: ClientOutputValue),+
            {
                fn from_values(values: Vec<Value>) -> Result<Self> {
                    let expected = Self::value_types().len();
                    let actual = values.len();
                    if actual != expected {
                        return Err(Error::InvalidInput(format!(
                            "expected {expected} typed outputs, got {actual}"
                        )));
                    }
                    let mut values = values.into_iter();
                    Ok((
                        $(
                            $type_name::try_from_sdk_value(values.next().expect("length checked"))?,
                        )+
                    ))
                }

                fn value_types() -> Vec<ClientValueType> {
                    vec![$($type_name::VALUE_TYPE),+]
                }
            }

            impl<$($type_name),+> ProgramArgs for ($($type_name,)+)
            where
                $($type_name: Into<Value>),+
            {
                fn into_values(self) -> Vec<Value> {
                    let ($($value_name,)+) = self;
                    vec![$($value_name.into()),+]
                }
            }
        )+
    };
}

typed_client_tuple!(
    (A a, B b),
    (A a, B b, C c),
    (A a, B b, C c, D d),
    (A a, B b, C c, D d, E e),
    (A a, B b, C c, D d, E e, F f),
    (A a, B b, C c, D d, E e, F f, G g),
    (A a, B b, C c, D d, E e, F f, G g, H h),
);

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
