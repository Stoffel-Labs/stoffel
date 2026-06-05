//! Compiled program metadata and bytecode helpers.
//!
//! `Program` wraps `stoffel-vm-types` bytecode and exposes SDK-friendly
//! metadata for functions, ClientStore schemas, and CLI-compatible bytecode
//! round trips.

use std::fmt;
use std::io::Cursor;
use std::path::Path;

use serde::{Deserialize, Serialize};
use stoffel_vm_types::compiled_binary::{
    utils, ClientIoManifest, ClientIoSchema, CompiledBinary, CompiledFunction, CompiledInstruction,
};
use stoffel_vm_types::core_types::{ShareType, Value as VmValue};
use stoffel_vm_types::registers::DEFAULT_SECRET_REGISTER_START;

use crate::compiler;
use crate::error::{Error, Result};
use crate::types::Value;

#[derive(Debug, Clone)]
pub struct Program {
    binary: CompiledBinary,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LocalInputShape {
    Clear(Value),
    Share,
    List(Vec<LocalInputShape>),
    Object(Vec<(String, LocalInputShape)>),
}

impl LocalInputShape {
    pub(crate) fn secret_from_value(value: &Value) -> Self {
        match value {
            Value::List(values) => Self::List(
                values
                    .iter()
                    .map(Self::secret_from_value)
                    .collect::<Vec<_>>(),
            ),
            Value::Object(fields) => Self::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), Self::secret_from_value(value)))
                    .collect(),
            ),
            Value::I64(_)
            | Value::U64(_)
            | Value::Bool(_)
            | Value::Float(_)
            | Value::String(_)
            | Value::Bytes(_)
            | Value::Unit => Self::Share,
        }
    }

    pub(crate) fn clear_from_value(value: &Value) -> Self {
        match value {
            Value::List(values) => Self::List(
                values
                    .iter()
                    .map(Self::clear_from_value)
                    .collect::<Vec<_>>(),
            ),
            Value::Object(fields) => Self::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), Self::clear_from_value(value)))
                    .collect(),
            ),
            value => Self::Clear(value.clone()),
        }
    }

    fn share_count(&self) -> usize {
        match self {
            Self::Clear(_) => 0,
            Self::Share => 1,
            Self::List(items) => items.iter().map(Self::share_count).sum(),
            Self::Object(fields) => fields.iter().map(|(_, shape)| shape.share_count()).sum(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSummary {
    pub function_count: usize,
    pub function_names: Vec<String>,
    pub functions: Vec<FunctionSummary>,
    pub total_instruction_count: usize,
    pub total_register_count: usize,
    pub bytecode_backend: String,
    pub bytecode_curve: String,
    pub client_count: usize,
    pub client_slots: Vec<u64>,
    pub clients: Vec<ClientMetadataSummary>,
    pub total_client_input_count: usize,
    pub total_client_output_count: usize,
    pub minimum_expected_clients: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub arg_count: usize,
    pub parameters: Vec<String>,
    pub register_count: usize,
    pub instruction_count: usize,
    pub upvalue_count: usize,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientMetadataSummary {
    pub client_slot: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub inputs: Vec<ShareType>,
    pub outputs: Vec<ShareType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeSummary {
    pub byte_len: usize,
    pub program: ProgramSummary,
}

impl Program {
    pub fn new(binary: CompiledBinary) -> Self {
        Self { binary }
    }

    pub fn from_bytecode(bytecode: &[u8]) -> Result<Self> {
        compiler::load_bytecode(bytecode)
    }

    pub fn from_bytecode_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytecode = std::fs::read(path)?;
        Self::from_bytecode(&bytecode)
    }

    pub fn to_bytecode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.binary
            .serialize(&mut Cursor::new(&mut bytes))
            .map_err(|error| Error::Bytecode(format!("{error:?}")))?;
        Ok(bytes)
    }

    pub fn save_bytecode(&self, path: impl AsRef<Path>) -> Result<()> {
        utils::save_to_file(&self.binary, path)
            .map_err(|error| Error::Bytecode(format!("{error:?}")))
    }

    pub fn bytecode_summary(&self) -> Result<BytecodeSummary> {
        Ok(BytecodeSummary {
            byte_len: self.to_bytecode()?.len(),
            program: self.summary(),
        })
    }

    pub fn disassemble(&self) -> String {
        stoffellang::binary_converter::disassemble(&self.binary)
    }

    pub fn function_count(&self) -> usize {
        self.binary.functions.len()
    }

    pub fn function_names(&self) -> impl Iterator<Item = &str> {
        self.binary
            .functions
            .iter()
            .map(|function| function.name.as_str())
    }

    pub fn total_instruction_count(&self) -> usize {
        self.binary
            .functions
            .iter()
            .map(|function| function.instructions.len())
            .sum()
    }

    pub fn total_register_count(&self) -> usize {
        self.binary
            .functions
            .iter()
            .map(|function| function.register_count)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.binary.functions.is_empty()
    }

    pub fn summary(&self) -> ProgramSummary {
        ProgramSummary {
            function_count: self.function_count(),
            function_names: self.function_names().map(ToOwned::to_owned).collect(),
            functions: self
                .functions()
                .map(|function| function.summary())
                .collect(),
            total_instruction_count: self.total_instruction_count(),
            total_register_count: self.total_register_count(),
            bytecode_backend: bytecode_backend_name(self.bytecode_backend()).to_owned(),
            bytecode_curve: bytecode_curve_name(self.bytecode_curve()).to_owned(),
            client_count: self.client_count(),
            client_slots: self.client_slots().collect(),
            clients: self.clients().map(|client| client.summary()).collect(),
            total_client_input_count: self.total_client_input_count(),
            total_client_output_count: self.total_client_output_count(),
            minimum_expected_clients: self.minimum_expected_clients(),
        }
    }

    pub fn client_io_manifest(&self) -> &ClientIoManifest {
        &self.binary.client_io_manifest
    }

    pub fn client_count(&self) -> usize {
        self.binary.client_io_manifest.clients.len()
    }

    pub fn client_slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| client.client_slot)
    }

    pub fn total_client_input_count(&self) -> usize {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| client.inputs.len())
            .sum()
    }

    pub fn total_client_output_count(&self) -> usize {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| client.outputs.len())
            .sum()
    }

    pub fn minimum_expected_clients(&self) -> usize {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| usize::try_from(client.client_slot).unwrap_or(usize::MAX))
            .map(|client_slot| client_slot.saturating_add(1))
            .max()
            .unwrap_or(0)
    }

    pub fn has_client_io(&self) -> bool {
        !self.binary.client_io_manifest.clients.is_empty()
    }

    pub fn validate_expected_clients(&self, expected_clients: usize) -> Result<()> {
        let minimum_expected_clients = self.minimum_expected_clients();
        if minimum_expected_clients > expected_clients {
            return Err(Error::Configuration(format!(
                "program declares ClientStore slot(s) requiring expected_clients >= {minimum_expected_clients}, but expected_clients is {expected_clients}"
            )));
        }
        Ok(())
    }

    pub fn validate_client_inputs(&self, inputs: &[(u64, &[Value])]) -> Result<()> {
        let has_declared_clients = self.has_client_io();
        if !has_declared_clients && inputs.is_empty() {
            return Ok(());
        }
        if has_declared_clients && inputs.is_empty() {
            return Err(Error::Configuration(
                "program declares ClientStore input metadata; provide local client inputs"
                    .to_owned(),
            ));
        }
        if !has_declared_clients {
            let mut seen_slots = std::collections::HashSet::with_capacity(inputs.len());
            for (client_slot, _values) in inputs {
                if !seen_slots.insert(*client_slot) {
                    return Err(Error::Configuration(format!(
                        "client slot {client_slot} was provided more than once"
                    )));
                }
            }
            return Ok(());
        }

        let mut seen_slots = std::collections::HashSet::with_capacity(inputs.len());
        for (client_slot, values) in inputs {
            if !seen_slots.insert(*client_slot) {
                return Err(Error::Configuration(format!(
                    "client slot {client_slot} was provided more than once"
                )));
            }
            let Some(metadata) = self.client(*client_slot) else {
                return Err(Error::Configuration(format!(
                    "client slot {client_slot} is not declared in the program client IO manifest"
                )));
            };
            if metadata.input_count() != values.len() {
                return Err(Error::Configuration(format!(
                    "client slot {client_slot} expects {} inputs, got {}",
                    metadata.input_count(),
                    values.len()
                )));
            }
        }

        for metadata in self.clients() {
            if !seen_slots.contains(&metadata.client_slot()) {
                return Err(Error::Configuration(format!(
                    "client slot {} is declared in the program client IO manifest but no input was provided",
                    metadata.client_slot()
                )));
            }
        }

        Ok(())
    }

    pub(crate) fn validate_owned_client_inputs(&self, inputs: &[(u64, Vec<Value>)]) -> Result<()> {
        let borrowed = inputs
            .iter()
            .map(|(client_slot, values)| (*client_slot, values.as_slice()))
            .collect::<Vec<_>>();
        self.validate_client_inputs(&borrowed)
    }

    pub fn clients(&self) -> impl Iterator<Item = ClientMetadata<'_>> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(ClientMetadata)
    }

    pub fn client(&self, client_slot: u64) -> Option<ClientMetadata<'_>> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .find(|client| client.client_slot == client_slot)
            .map(ClientMetadata)
    }

    pub fn bytecode_backend(&self) -> stoffel_vm_types::compiled_binary::MpcBackend {
        self.binary.client_io_manifest.mpc_backend
    }

    pub fn bytecode_curve(&self) -> stoffel_vm_types::compiled_binary::MpcCurve {
        self.binary.client_io_manifest.mpc_curve
    }

    pub(crate) fn with_local_client_input_wrapper(
        &self,
        call_name: &str,
        entry_name: &str,
        input_shapes: &[LocalInputShape],
    ) -> Result<Self> {
        if input_shapes.is_empty() {
            return Err(Error::Configuration(
                "local client input wrapper requires at least one input".to_owned(),
            ));
        }

        let mut binary = self.binary.clone();
        if binary
            .functions
            .iter()
            .any(|function| function.name == entry_name)
        {
            return Err(Error::Configuration(format!(
                "local client input wrapper entry '{entry_name}' already exists"
            )));
        }
        let Some(_target_function) = binary
            .functions
            .iter()
            .find(|function| function.name == call_name)
        else {
            return Err(Error::FunctionNotFound(call_name.to_owned()));
        };
        let input_count = input_shapes
            .iter()
            .map(LocalInputShape::share_count)
            .sum::<usize>();

        let mut instructions = Vec::with_capacity(input_count * 8 + input_shapes.len() + 2);
        let first_clear_arg_register = 2;
        let mut next_clear_register = first_clear_arg_register;
        let mut next_secret_register = DEFAULT_SECRET_REGISTER_START;
        let mut next_share_index = 0usize;
        let mut arg_registers = Vec::with_capacity(input_shapes.len());
        for shape in input_shapes {
            let register = emit_local_input_shape(
                shape,
                &mut binary,
                &mut instructions,
                &mut next_share_index,
                &mut next_clear_register,
                &mut next_secret_register,
            )?;
            arg_registers.push(register);
        }
        for register in arg_registers {
            instructions.push(CompiledInstruction::PUSHARG(register));
        }
        instructions.push(CompiledInstruction::CALL(call_name.to_owned()));
        instructions.push(CompiledInstruction::RET(0));

        let register_count = if next_secret_register == DEFAULT_SECRET_REGISTER_START {
            next_clear_register.max(first_clear_arg_register)
        } else {
            next_clear_register.max(next_secret_register)
        };
        binary.functions.push(CompiledFunction {
            name: entry_name.to_owned(),
            register_count,
            parameters: Vec::new(),
            upvalues: Vec::new(),
            parent: None,
            labels: Default::default(),
            instructions,
        });

        binary.client_io_manifest.clients = if input_count == 0 {
            Vec::new()
        } else {
            vec![ClientIoSchema {
                client_slot: 0,
                inputs: vec![ShareType::default_secret_int(); input_count],
                outputs: Vec::new(),
            }]
        };

        Ok(Self::new(binary))
    }

    pub fn functions(&self) -> impl Iterator<Item = FunctionMetadata<'_>> {
        self.binary.functions.iter().map(FunctionMetadata)
    }

    pub fn function(&self, name: &str) -> Option<FunctionMetadata<'_>> {
        self.binary
            .functions
            .iter()
            .find(|function| function.name == name)
            .map(FunctionMetadata)
    }

    pub fn main(&self) -> Option<FunctionMetadata<'_>> {
        self.function("main")
    }

    pub fn binary(&self) -> &CompiledBinary {
        &self.binary
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClientMetadata<'a>(&'a ClientIoSchema);

impl<'a> ClientMetadata<'a> {
    pub fn client_slot(&self) -> u64 {
        self.0.client_slot
    }

    pub fn input_count(&self) -> usize {
        self.0.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.0.outputs.len()
    }

    pub fn inputs(&self) -> &'a [ShareType] {
        &self.0.inputs
    }

    pub fn outputs(&self) -> &'a [ShareType] {
        &self.0.outputs
    }

    pub fn summary(&self) -> ClientMetadataSummary {
        ClientMetadataSummary {
            client_slot: self.client_slot(),
            input_count: self.input_count(),
            output_count: self.output_count(),
            inputs: self.inputs().to_vec(),
            outputs: self.outputs().to_vec(),
        }
    }
}

impl fmt::Display for ClientMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client {}: {} input(s), {} output(s)",
            self.client_slot(),
            self.input_count(),
            self.output_count()
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FunctionMetadata<'a>(&'a CompiledFunction);

impl<'a> FunctionMetadata<'a> {
    pub fn name(&self) -> &str {
        &self.0.name
    }

    pub fn arg_count(&self) -> usize {
        self.0.parameters.len()
    }

    pub fn parameters(&self) -> &[String] {
        &self.0.parameters
    }

    pub fn parameter_names(&self) -> impl Iterator<Item = &str> {
        self.0.parameters.iter().map(String::as_str)
    }

    pub fn register_count(&self) -> usize {
        self.0.register_count
    }

    pub fn instruction_count(&self) -> usize {
        self.0.instructions.len()
    }

    pub fn upvalue_count(&self) -> usize {
        self.0.upvalues.len()
    }

    pub fn parent(&self) -> Option<&str> {
        self.0.parent.as_deref()
    }

    pub fn summary(&self) -> FunctionSummary {
        FunctionSummary {
            name: self.name().to_owned(),
            arg_count: self.arg_count(),
            parameters: self.parameters().to_vec(),
            register_count: self.register_count(),
            instruction_count: self.instruction_count(),
            upvalue_count: self.upvalue_count(),
            parent: self.parent().map(ToOwned::to_owned),
        }
    }
}

impl fmt::Display for FunctionMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.name())?;
        for (index, parameter) in self.parameter_names().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(parameter)?;
        }
        write!(f, ")")
    }
}

fn bytecode_backend_name(backend: stoffel_vm_types::compiled_binary::MpcBackend) -> &'static str {
    match backend {
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger => "honeybadger",
        stoffel_vm_types::compiled_binary::MpcBackend::Avss => "avss",
    }
}

fn bytecode_curve_name(curve: stoffel_vm_types::compiled_binary::MpcCurve) -> &'static str {
    match curve {
        stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => "bls12_381",
        stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => "bn254",
        stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => "curve25519",
        stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => "ed25519",
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => "secp256k1",
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => "p-256",
    }
}

fn emit_local_input_shape(
    shape: &LocalInputShape,
    binary: &mut CompiledBinary,
    instructions: &mut Vec<CompiledInstruction>,
    next_share_index: &mut usize,
    next_clear_register: &mut usize,
    next_secret_register: &mut usize,
) -> Result<usize> {
    match shape {
        LocalInputShape::Clear(value) => {
            let dest = allocate_wrapper_register(next_clear_register);
            let const_index = binary.constants.len();
            binary
                .constants
                .push(clear_sdk_value_to_vm_constant(value)?);
            instructions.push(CompiledInstruction::LDI(dest, const_index));
            Ok(dest)
        }
        LocalInputShape::Share => {
            let dest = allocate_wrapper_register(next_secret_register);
            let client_index_const = binary.constants.len();
            binary.constants.push(VmValue::U64(0));
            let share_index_const = binary.constants.len();
            binary
                .constants
                .push(VmValue::U64(*next_share_index as u64));
            *next_share_index += 1;
            instructions.push(CompiledInstruction::LDI(0, client_index_const));
            instructions.push(CompiledInstruction::LDI(1, share_index_const));
            instructions.push(CompiledInstruction::PUSHARG(0));
            instructions.push(CompiledInstruction::PUSHARG(1));
            instructions.push(CompiledInstruction::CALL(
                "ClientStore.take_share".to_owned(),
            ));
            instructions.push(CompiledInstruction::MOV(dest, 0));
            Ok(dest)
        }
        LocalInputShape::List(items) => {
            let dest = allocate_wrapper_register(next_clear_register);
            instructions.push(CompiledInstruction::CALL("create_array".to_owned()));
            instructions.push(CompiledInstruction::MOV(dest, 0));
            for item in items {
                let item_register = emit_local_input_shape(
                    item,
                    binary,
                    instructions,
                    next_share_index,
                    next_clear_register,
                    next_secret_register,
                )?;
                instructions.push(CompiledInstruction::PUSHARG(dest));
                instructions.push(CompiledInstruction::PUSHARG(item_register));
                instructions.push(CompiledInstruction::CALL("array_push".to_owned()));
            }
            Ok(dest)
        }
        LocalInputShape::Object(fields) => {
            let dest = allocate_wrapper_register(next_clear_register);
            instructions.push(CompiledInstruction::CALL("create_object".to_owned()));
            instructions.push(CompiledInstruction::MOV(dest, 0));
            for (field_name, field_shape) in fields {
                let key_register = allocate_wrapper_register(next_clear_register);
                let key_const = binary.constants.len();
                binary.constants.push(VmValue::String(field_name.clone()));
                instructions.push(CompiledInstruction::LDI(key_register, key_const));
                let value_register = emit_local_input_shape(
                    field_shape,
                    binary,
                    instructions,
                    next_share_index,
                    next_clear_register,
                    next_secret_register,
                )?;
                instructions.push(CompiledInstruction::PUSHARG(dest));
                instructions.push(CompiledInstruction::PUSHARG(key_register));
                instructions.push(CompiledInstruction::PUSHARG(value_register));
                instructions.push(CompiledInstruction::CALL("set_field".to_owned()));
            }
            Ok(dest)
        }
    }
}

fn clear_sdk_value_to_vm_constant(value: &Value) -> Result<VmValue> {
    match value {
        Value::I64(value) => Ok(VmValue::I64(*value)),
        Value::U64(value) => Ok(VmValue::U64(*value)),
        Value::Bool(value) => Ok(VmValue::Bool(*value)),
        Value::Float(value) => Ok(VmValue::Float((*value).into())),
        Value::String(value) => Ok(VmValue::String(value.clone())),
        Value::Unit => Ok(VmValue::Unit),
        Value::Bytes(_) => Err(Error::InvalidInput(
            "clear byte values cannot be embedded in local named-input wrappers".to_owned(),
        )),
        Value::List(_) | Value::Object(_) => Err(Error::InvalidInput(
            "internal error: structured clear value was not lowered recursively".to_owned(),
        )),
    }
}

fn allocate_wrapper_register(next_register: &mut usize) -> usize {
    let register = *next_register;
    *next_register += 1;
    register
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MpcBackend;

    #[test]
    fn local_client_input_wrapper_places_secret_inputs_in_secret_registers() -> Result<()> {
        let program = crate::compiler::compile_source(
            "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
            "test.stfl",
            MpcBackend::HoneyBadger,
        )?;

        let wrapped = program.with_local_client_input_wrapper(
            "main",
            "__stoffel_sdk_local_entry",
            &[LocalInputShape::Share, LocalInputShape::Share],
        )?;
        let wrapper = wrapped
            .binary
            .functions
            .iter()
            .find(|function| function.name == "__stoffel_sdk_local_entry")
            .expect("wrapper function should be present");

        assert!(wrapper.register_count >= DEFAULT_SECRET_REGISTER_START + 2);
        assert!(
            wrapper
                .instructions
                .contains(&CompiledInstruction::MOV(DEFAULT_SECRET_REGISTER_START, 0)),
            "first ClientStore share must be moved into a secret register"
        );
        assert!(
            wrapper.instructions.contains(&CompiledInstruction::MOV(
                DEFAULT_SECRET_REGISTER_START + 1,
                0
            )),
            "second ClientStore share must be moved into a secret register"
        );

        let main_call = wrapper
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, CompiledInstruction::CALL(name) if name == "main")
            })
            .expect("wrapper should call main");
        assert_eq!(
            &wrapper.instructions[main_call - 2..main_call],
            &[
                CompiledInstruction::PUSHARG(DEFAULT_SECRET_REGISTER_START),
                CompiledInstruction::PUSHARG(DEFAULT_SECRET_REGISTER_START + 1),
            ]
        );
        assert!(
            !wrapper.instructions.iter().any(
                |instruction| matches!(instruction, CompiledInstruction::CALL(name) if name == "Share.open")
            ),
            "the local wrapper should return the VM value and leave share reveals to the runner"
        );

        Ok(())
    }

    #[test]
    fn local_client_input_wrapper_keeps_clear_only_inputs_in_clear_registers() -> Result<()> {
        let program = crate::compiler::compile_source(
            "def main(a: int64, b: int64) -> int64:\n  return a + b",
            "test.stfl",
            MpcBackend::HoneyBadger,
        )?;

        let wrapped = program.with_local_client_input_wrapper(
            "main",
            "__stoffel_sdk_local_entry",
            &[
                LocalInputShape::Clear(Value::I64(1)),
                LocalInputShape::Clear(Value::I64(2)),
            ],
        )?;
        let wrapper = wrapped
            .binary
            .functions
            .iter()
            .find(|function| function.name == "__stoffel_sdk_local_entry")
            .expect("wrapper function should be present");

        assert!(wrapper.register_count < DEFAULT_SECRET_REGISTER_START);
        assert!(
            wrapped.binary.client_io_manifest.clients.is_empty(),
            "clear-only named input wrappers must not declare client input metadata"
        );

        Ok(())
    }
}
