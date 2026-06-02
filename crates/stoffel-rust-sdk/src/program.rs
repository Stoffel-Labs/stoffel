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
            return Err(Error::Configuration(
                "client inputs require a program with ClientStore input metadata".to_owned(),
            ));
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
        input_count: usize,
    ) -> Result<Self> {
        if input_count == 0 {
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
        let Some(target_function) = binary
            .functions
            .iter()
            .find(|function| function.name == call_name)
        else {
            return Err(Error::FunctionNotFound(call_name.to_owned()));
        };
        let open_return = function_returns_secret_register(target_function);

        let mut instructions = Vec::with_capacity(input_count * 5 + input_count + 2);
        let first_arg_register = 2;
        for index in 0..input_count {
            let client_index_const = binary.constants.len();
            binary.constants.push(VmValue::U64(0));
            let share_index_const = binary.constants.len();
            binary.constants.push(VmValue::U64(index as u64));
            instructions.push(CompiledInstruction::LDI(0, client_index_const));
            instructions.push(CompiledInstruction::LDI(1, share_index_const));
            instructions.push(CompiledInstruction::PUSHARG(0));
            instructions.push(CompiledInstruction::PUSHARG(1));
            instructions.push(CompiledInstruction::CALL(
                "ClientStore.take_share".to_owned(),
            ));
            instructions.push(CompiledInstruction::MOV(first_arg_register + index, 0));
        }
        for index in 0..input_count {
            instructions.push(CompiledInstruction::PUSHARG(first_arg_register + index));
        }
        instructions.push(CompiledInstruction::CALL(call_name.to_owned()));
        if open_return {
            instructions.push(CompiledInstruction::PUSHARG(0));
            instructions.push(CompiledInstruction::CALL("Share.open".to_owned()));
        }
        instructions.push(CompiledInstruction::RET(0));

        let register_count = first_arg_register + input_count;
        binary.functions.push(CompiledFunction {
            name: entry_name.to_owned(),
            register_count,
            parameters: Vec::new(),
            upvalues: Vec::new(),
            parent: None,
            labels: Default::default(),
            instructions,
        });

        binary.client_io_manifest.clients = vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int(); input_count],
            outputs: Vec::new(),
        }];

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

fn function_returns_secret_register(function: &CompiledFunction) -> bool {
    function
        .instructions
        .iter()
        .rev()
        .find_map(|instruction| match instruction {
            CompiledInstruction::RET(register) => Some(*register >= DEFAULT_SECRET_REGISTER_START),
            _ => None,
        })
        .unwrap_or(false)
}
