//! StoffelVM execution integration.
//!
//! Clear execution embeds the VM directly. Local MPC execution delegates to the
//! real localhost coordinator/party runner in `stoffel-vm`, preserving the
//! PRD's non-simulated local network behavior.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::MpcBackend;
use crate::error::{Error, Result};
use crate::runtime::StoffelRuntime;
use crate::types::Value;
use stoffel_vm_types::core_types::{ShareType, TableRef, Value as VmValue};

pub fn execute_clear(runtime: &StoffelRuntime, function_name: &str) -> Result<Vec<Value>> {
    let args = runtime.input_values_for_function(function_name)?;
    execute_clear_with_sdk_args(runtime, function_name, &args)
}

pub(crate) fn execute_clear_with_sdk_args(
    runtime: &StoffelRuntime,
    function_name: &str,
    args: &[Value],
) -> Result<Vec<Value>> {
    runtime
        .program()
        .validate_function_args(function_name, args)?;

    let mut vm = stoffel_vm::core_vm::VirtualMachine::try_new()
        .map_err(|error| Error::Computation(error.to_string()))?;
    for function in runtime
        .program()
        .binary()
        .try_to_vm_functions()
        .map_err(|error| Error::Bytecode(format!("{error:?}")))?
    {
        vm.try_register_function(function)
            .map_err(|error| Error::Computation(error.to_string()))?;
    }

    let vm_args = args
        .iter()
        .map(|value| sdk_value_to_vm_value(&mut vm, value))
        .collect::<Result<Vec<_>>>()?;
    let value = vm
        .execute_with_args(function_name, &vm_args)
        .map_err(|error| Error::Computation(error.to_string()))?;
    let value = sdk_value_from_vm_value(&mut vm, value, &mut HashSet::new(), 0)?;
    match value {
        Value::List(values) => Ok(values),
        value => Ok(vec![value]),
    }
}

pub fn execute_clear_with_args(
    runtime: &StoffelRuntime,
    function_name: &str,
    args: &[stoffel_vm_types::core_types::Value],
) -> Result<Vec<Value>> {
    let sdk_args = args
        .iter()
        .filter_map(|value| Value::from_vm_value(value.clone()))
        .collect::<Vec<_>>();
    if sdk_args.len() == args.len() {
        runtime
            .program()
            .validate_function_args(function_name, &sdk_args)?;
    } else if runtime.program().function(function_name).is_none() {
        return Err(Error::FunctionNotFound(function_name.to_owned()));
    }

    let mut vm = stoffel_vm::core_vm::VirtualMachine::try_new()
        .map_err(|error| Error::Computation(error.to_string()))?;
    for function in runtime
        .program()
        .binary()
        .try_to_vm_functions()
        .map_err(|error| Error::Bytecode(format!("{error:?}")))?
    {
        vm.try_register_function(function)
            .map_err(|error| Error::Computation(error.to_string()))?;
    }

    let value = vm
        .execute_with_args(function_name, args)
        .map_err(|error| Error::Computation(error.to_string()))?;
    let value = sdk_value_from_vm_value(&mut vm, value, &mut HashSet::new(), 0)?;
    match value {
        Value::List(values) => Ok(values),
        value => Ok(vec![value]),
    }
}

pub async fn execute_local(runtime: &StoffelRuntime, function_name: &str) -> Result<Vec<Value>> {
    execute_local_with_options(runtime, function_name, LocalExecutionOptions::default()).await
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LocalExecutionOptions {
    pub(crate) runner_path: Option<PathBuf>,
    pub(crate) timeout: Option<Duration>,
}

/// A client's reconstructed output values, received via `send_to_client` and
/// reconstructed by the off-chain client — the actual client-side result, not
/// a public reveal to the compute nodes.
///
/// `values` are decoded through the loaded program's client-IO manifest, so a
/// 1-bit secret int comes back as [`Value::Bool`], a wider secret int as
/// [`Value::I64`], an unsigned secret int as [`Value::U64`], and a fixed-point
/// share as [`Value::Float`]. Output positions the manifest does not describe
/// (e.g. a developer-specified count with no static schema) fall back to
/// [`Value::U64`]. The untyped reconstructed field values remain available via
/// `raw` for callers that need them.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalClientOutput {
    pub client_slot: u64,
    pub values: Vec<Value>,
    pub raw: Vec<u64>,
}

impl LocalClientOutput {
    /// Pack boolean outputs into bytes, LSB-first within each byte (output bit
    /// `i` becomes bit `i % 8` of byte `i / 8`). This is the inverse of the
    /// LSB-first bit layout AES and other bit-decomposed circuits use, so a
    /// 128-bit ciphertext block round-trips straight back to its 16 bytes.
    ///
    /// Non-boolean outputs are treated as set when non-zero; the trailing
    /// partial byte (when the output count is not a multiple of 8) is
    /// zero-padded in its high bits.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.values.len().div_ceil(8)];
        for (index, value) in self.values.iter().enumerate() {
            if value_is_set(value) {
                out[index / 8] |= 1 << (index % 8);
            }
        }
        out
    }

    /// The outputs as booleans (non-zero ⇒ `true`), in order.
    pub fn bools(&self) -> Vec<bool> {
        self.values.iter().map(value_is_set).collect()
    }
}

fn value_is_set(value: &Value) -> bool {
    match value {
        Value::Bool(bit) => *bit,
        Value::I64(value) => *value != 0,
        Value::U64(value) => *value != 0,
        _ => false,
    }
}

/// Decode one reconstructed field value into a typed SDK [`Value`] using the
/// share type the manifest declared for that output position.
fn decode_client_output_value(raw: u64, share_type: ShareType) -> Value {
    match share_type {
        ShareType::SecretInt { bit_length: 1 } => Value::Bool(raw != 0),
        ShareType::SecretInt { .. } => Value::I64(raw as i64),
        ShareType::SecretUInt { .. } => Value::U64(raw),
        ShareType::SecretFixedPoint { precision } => {
            let scale = (1u128 << precision.fractional_bits()) as f64;
            Value::Float((raw as i64) as f64 / scale)
        }
    }
}

pub(crate) async fn execute_local_with_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<Vec<Value>> {
    let (returned, _program_output, _client_outputs) =
        execute_local_capturing_with_options(runtime, function_name, options).await?;
    Ok(returned)
}

/// Like [`execute_local_with_options`] but also returns the program's printed
/// output (everything the program emitted via `print`, with the VM's internal
/// `Program returned:` markers stripped). Used to surface client-facing results
/// that a returned aggregate (e.g. a `list`) only exposes as an opaque handle.
pub(crate) async fn execute_local_capturing_with_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<(Vec<Value>, String, Vec<LocalClientOutput>)> {
    if runtime.program().function(function_name).is_none() {
        return Err(Error::FunctionNotFound(function_name.to_owned()));
    }
    let vm_inputs = runtime.input_values_for_function(function_name)?;
    if !vm_inputs.is_empty() {
        return Err(Error::Unsupported(
            "SDK local coordinator execution does not support direct function parameters; use a no-argument entrypoint and `with_client_input` for ClientStore values"
                .to_owned(),
        ));
    }

    let mpc_config = runtime
        .mpc_config()
        .ok_or_else(|| Error::Configuration("MPC configuration is required".to_owned()))?;
    let flattened_client_inputs = flatten_local_client_inputs(runtime.client_inputs())?;
    validate_flattened_local_client_inputs(runtime, &flattened_client_inputs)?;
    if matches!(
        mpc_config.backend,
        MpcBackend::Avss {
            curve: crate::config::Curve::Bn254
                | crate::config::Curve::Curve25519
                | crate::config::Curve::Ed25519
        }
    ) && !runtime.client_inputs().is_empty()
    {
        return Err(Error::Unsupported(
            "SDK local coordinator execution currently supports AVSS local client inputs only for bls12_381"
                .to_owned(),
        ));
    }
    let local_client_inputs = flattened_client_inputs
        .iter()
        .map(|(client_slot, values)| {
            Ok(stoffel_vm_runner::LocalClientInput::raw(
                *client_slot,
                values
                    .iter()
                    .map(local_client_input_value)
                    .collect::<Result<Vec<_>>>()?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let runner_path = resolve_stoffel_run_binary(
        options
            .runner_path
            .as_deref()
            .or_else(|| runtime.local_runner_binary_path()),
    )?;

    let mut runner = stoffel_vm_runner::LocalCoordinatorRunner::builder(
        runner_path,
        runtime.program().binary().clone(),
    )
    .entry(function_name)
    .backend(local_runner_backend(mpc_config.backend))
    .curve(local_runner_curve(mpc_config.backend))
    .parties(mpc_config.parties)
    .threshold(mpc_config.threshold);
    if let Some(timeout) = options.timeout {
        runner = runner.timeout(timeout);
    }
    if let Some(expected_clients) = runtime.configured_expected_clients() {
        runner = runner.expected_output_clients(expected_clients);
    }
    for (client_slot, count) in runtime.client_output_counts() {
        runner = runner.client_output_count(*client_slot, *count);
    }
    runner = runner.client_inputs(local_client_inputs);

    let output = runner
        .build()
        .map_err(|error| Error::Configuration(error.to_string()))?
        .run()
        .await
        .map_err(|error| Error::Computation(error.to_string()))?;

    let program_output = local_program_output(&output);
    print!("{program_output}");

    let returned = output.consistent_returned_values().map_err(|error| {
        Error::Computation(format!(
            "local coordinator run did not produce consistent VM return values: {error}\noutput:\n{}",
            output.combined_output
        ))
    })?;
    let values = returned
        .iter()
        .map(|value| parse_runner_return_value(value))
        .collect::<Result<Vec<_>>>()?;
    let manifest = runtime.program().client_io_manifest();
    let client_outputs = output
        .client_outputs
        .iter()
        .map(|record| {
            let output_types = manifest
                .clients
                .iter()
                .find(|client| client.client_slot == record.client_slot)
                .map(|client| client.outputs.as_slice())
                .unwrap_or(&[]);
            let typed = record
                .values
                .iter()
                .enumerate()
                .map(|(index, &raw)| match output_types.get(index) {
                    Some(share_type) => decode_client_output_value(raw, *share_type),
                    None => Value::U64(raw),
                })
                .collect();
            LocalClientOutput {
                client_slot: record.client_slot,
                values: typed,
                raw: record.values.clone(),
            }
        })
        .collect();
    Ok((values, program_output, client_outputs))
}

/// The first party's printed program output, with `Program returned:` markers
/// removed. Empty when no party produced output.
fn local_program_output(output: &stoffel_vm_runner::LocalCoordinatorRunOutput) -> String {
    let Some(first_party) = output.party_outputs.first() else {
        return String::new();
    };
    local_program_output_without_return_markers(&first_party.stdout)
}

fn local_program_output_without_return_markers(stdout: &str) -> String {
    let mut output = String::new();
    for line in stdout.lines() {
        if line.trim().starts_with("Program returned: ") {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn local_runner_backend(backend: MpcBackend) -> stoffel_vm::net::MpcBackendKind {
    match backend {
        MpcBackend::HoneyBadger => stoffel_vm::net::MpcBackendKind::HoneyBadger,
        MpcBackend::Avss { .. } => stoffel_vm::net::MpcBackendKind::Avss,
    }
}

fn local_runner_curve(backend: MpcBackend) -> stoffel_vm::net::MpcCurveConfig {
    match backend.curve() {
        None | Some(crate::config::Curve::Bls12_381) => stoffel_vm::net::MpcCurveConfig::Bls12_381,
        Some(crate::config::Curve::Bn254) => stoffel_vm::net::MpcCurveConfig::Bn254,
        Some(crate::config::Curve::Curve25519) => stoffel_vm::net::MpcCurveConfig::Curve25519,
        Some(crate::config::Curve::Ed25519) => stoffel_vm::net::MpcCurveConfig::Ed25519,
        Some(crate::config::Curve::Secp256k1) => stoffel_vm::net::MpcCurveConfig::Secp256k1,
        Some(crate::config::Curve::Secp256r1) => stoffel_vm::net::MpcCurveConfig::Secp256r1,
    }
}

fn validate_flattened_local_client_inputs(
    runtime: &StoffelRuntime,
    flattened_client_inputs: &[(u64, Vec<Value>)],
) -> Result<()> {
    runtime
        .program()
        .validate_owned_client_inputs(flattened_client_inputs)
}

fn flatten_local_client_inputs(inputs: &[(u64, Vec<Value>)]) -> Result<Vec<(u64, Vec<Value>)>> {
    inputs
        .iter()
        .map(|(client_slot, values)| {
            let mut flattened = Vec::new();
            for value in values {
                flatten_local_client_input_value(value, &mut flattened)?;
            }
            Ok((*client_slot, flattened))
        })
        .collect()
}

fn flatten_local_client_input_value(value: &Value, out: &mut Vec<Value>) -> Result<()> {
    match value {
        Value::List(values) => {
            for value in values {
                flatten_local_client_input_value(value, out)?;
            }
            Ok(())
        }
        Value::Object(_) => Err(Error::InvalidInput(
            "local coordinator client inputs cannot directly encode objects; pass their scalar secret fields or use typed lowering"
                .to_owned(),
        )),
        Value::I64(_)
        | Value::U64(_)
        | Value::Bool(_)
        | Value::Bytes(_)
        | Value::Float(_)
        | Value::String(_)
        | Value::Unit => {
            out.push(value.clone());
            Ok(())
        }
    }
}

fn local_client_input_value(value: &Value) -> Result<String> {
    match value {
        Value::I64(value) => Ok(value.to_string()),
        Value::U64(value) if i64::try_from(*value).is_ok() => Ok(value.to_string()),
        Value::U64(value) => Ok(format!("0x{value:x}")),
        Value::Bool(value) => Ok(if *value { "1" } else { "0" }.to_owned()),
        Value::Bytes(value) => Ok(format!("0x{}", hex_encode(value))),
        Value::Float(_) | Value::String(_) | Value::List(_) | Value::Object(_) | Value::Unit => {
            Err(Error::InvalidInput(
                "local coordinator client inputs support integers, booleans, 0x-prefixed hex bytes, and lists of those values"
                    .to_owned(),
            ))
        }
    }
}

fn resolve_stoffel_run_binary(explicit_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit_path {
        return resolve_existing_runner_path(path).ok_or_else(|| {
            Error::Unsupported(format!(
                "SDK local coordinator execution requires an existing stoffel-run binary; configured path does not exist: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = std::env::var_os("STOFFEL_RUN_BIN").map(PathBuf::from) {
        return resolve_existing_runner_path(&path).ok_or_else(|| {
            Error::Unsupported(format!(
                "SDK local coordinator execution requires an existing stoffel-run binary; STOFFEL_RUN_BIN points to a missing path: {}",
                path.display()
            ))
        });
    }

    let Some(workspace_root) = workspace_root() else {
        return Err(Error::Unsupported(
            "SDK local coordinator execution requires a built stoffel-run binary; set STOFFEL_RUN_BIN, call `local_runner_path`, or build `cargo build -p stoffel-vm-runner --bin stoffel-run`"
                .to_owned(),
        ));
    };
    let candidate = workspace_root
        .join("target")
        .join("debug")
        .join("stoffel-run");
    candidate.exists().then_some(candidate).ok_or_else(|| {
        Error::Unsupported(
            "SDK local coordinator execution requires a built stoffel-run binary; set STOFFEL_RUN_BIN, call `local_runner_path`, or build `cargo build -p stoffel-vm-runner --bin stoffel-run`"
                .to_owned(),
        )
    })
}

fn resolve_existing_runner_path(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }
    if path.is_absolute() {
        return None;
    }
    workspace_root()
        .map(|root| root.join(path))
        .filter(|candidate| candidate.exists())
}

fn workspace_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
}

fn parse_runner_return_value(value: &str) -> Result<Value> {
    let value = value.trim();
    if value == "true" {
        return Ok(Value::Bool(true));
    }
    if value == "false" {
        return Ok(Value::Bool(false));
    }
    if value == "()" || value == "Unit" {
        return Ok(Value::Unit);
    }
    if let Ok(value) = value.parse::<i64>() {
        return Ok(Value::I64(value));
    }
    if let Ok(value) = value.parse::<u64>() {
        return Ok(Value::U64(value));
    }
    if let Ok(value) = value.parse::<f64>() {
        return Ok(Value::Float(value));
    }
    Ok(Value::String(value.to_owned()))
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

fn sdk_value_to_vm_value(
    vm: &mut stoffel_vm::core_vm::VirtualMachine,
    value: &Value,
) -> Result<VmValue> {
    match value {
        Value::I64(value) => Ok(VmValue::I64(*value)),
        Value::U64(value) => Ok(VmValue::U64(*value)),
        Value::Bool(value) => Ok(VmValue::Bool(*value)),
        Value::Float(value) => Ok(VmValue::Float((*value).into())),
        Value::String(value) => Ok(VmValue::String(value.clone())),
        Value::Bytes(_) => Err(Error::InvalidInput(
            "byte inputs are only supported for local coordinator client inputs".to_owned(),
        )),
        Value::List(values) => {
            let array_ref = vm
                .create_array_ref(values.len())
                .map_err(|error| Error::Computation(error.to_string()))?;
            let values = values
                .iter()
                .map(|value| sdk_value_to_vm_value(vm, value))
                .collect::<Result<Vec<_>>>()?;
            vm.push_array_ref_values(array_ref, &values)
                .map_err(|error| Error::Computation(error.to_string()))?;
            Ok(VmValue::from(array_ref))
        }
        Value::Object(fields) => {
            let object_ref = vm
                .create_object_ref()
                .map_err(|error| Error::Computation(error.to_string()))?;
            let table_ref = TableRef::from(object_ref);
            for (name, field_value) in fields {
                let field_value = sdk_value_to_vm_value(vm, field_value)?;
                vm.set_table_field(table_ref, VmValue::String(name.clone()), field_value)
                    .map_err(|error| Error::Computation(error.to_string()))?;
            }
            Ok(VmValue::from(object_ref))
        }
        Value::Unit => Ok(VmValue::Unit),
    }
}

fn sdk_value_from_vm_value(
    vm: &mut stoffel_vm::core_vm::VirtualMachine,
    value: VmValue,
    active_tables: &mut HashSet<TableRef>,
    depth: usize,
) -> Result<Value> {
    const MAX_TABLE_DEPTH: usize = 32;

    match value {
        VmValue::Array(array_ref) => {
            if depth >= MAX_TABLE_DEPTH {
                return Err(Error::Computation(format!(
                    "VM array output exceeds maximum SDK conversion depth of {MAX_TABLE_DEPTH}"
                )));
            }
            let table_ref = TableRef::from(array_ref);
            if !active_tables.insert(table_ref) {
                return Err(Error::Computation(format!(
                    "VM array output contains a cycle at array ref {}",
                    array_ref.id()
                )));
            }
            let len = vm
                .read_array_ref_len(array_ref)
                .map_err(|error| Error::Computation(error.to_string()))?;
            let mut values = Vec::with_capacity(len);
            for index in 0..len {
                let index = i64::try_from(index).map_err(|_| {
                    Error::Computation("VM array index cannot be represented as int64".to_owned())
                })?;
                let item = vm
                    .read_table_field(TableRef::from(array_ref), &VmValue::I64(index))
                    .map_err(|error| Error::Computation(error.to_string()))?
                    .ok_or_else(|| {
                        Error::Computation(format!("VM array is missing element at index {index}"))
                    })?;
                values.push(sdk_value_from_vm_value(vm, item, active_tables, depth + 1)?);
            }
            active_tables.remove(&table_ref);
            Ok(Value::List(values))
        }
        VmValue::Object(object_ref) => {
            if depth >= MAX_TABLE_DEPTH {
                return Err(Error::Computation(format!(
                    "VM object output exceeds maximum SDK conversion depth of {MAX_TABLE_DEPTH}"
                )));
            }
            let table_ref = TableRef::from(object_ref);
            if !active_tables.insert(table_ref) {
                return Err(Error::Computation(format!(
                    "VM object output contains a cycle at object ref {}",
                    object_ref.id()
                )));
            }
            let len = vm
                .read_object_ref_len(object_ref)
                .map_err(|error| Error::Computation(error.to_string()))?;
            let entries = vm
                .read_object_ref_entries(object_ref, len)
                .map_err(|error| Error::Computation(error.to_string()))?;
            let mut fields = std::collections::BTreeMap::new();
            for (key, value) in entries {
                let VmValue::String(key) = key else {
                    return Err(Error::Computation(format!(
                        "VM object output contains a non-string field key: {key:?}"
                    )));
                };
                fields.insert(
                    key,
                    sdk_value_from_vm_value(vm, value, active_tables, depth + 1)?,
                );
            }
            active_tables.remove(&table_ref);
            Ok(Value::Object(fields))
        }
        value => Value::from_vm_value(value).ok_or_else(|| {
            Error::Computation(
                "VM returned a value that cannot be represented by the public SDK Value type"
                    .to_owned(),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::local_program_output_without_return_markers;

    #[test]
    fn local_program_output_filter_removes_runner_return_markers() {
        let stdout = "polynomial p\nProgram returned: ()\n";

        assert_eq!(
            local_program_output_without_return_markers(stdout),
            "polynomial p\n"
        );
    }
}
