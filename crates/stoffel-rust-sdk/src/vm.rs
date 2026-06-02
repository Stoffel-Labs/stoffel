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
use stoffel_vm_types::core_types::{ArrayRef, TableRef, Value as VmValue};

pub fn execute_clear(runtime: &StoffelRuntime, function_name: &str) -> Result<Vec<Value>> {
    let args = runtime.input_values_for_function(function_name)?;
    execute_clear_with_args(runtime, function_name, &args)
}

pub fn execute_clear_with_args(
    runtime: &StoffelRuntime,
    function_name: &str,
    args: &[stoffel_vm_types::core_types::Value],
) -> Result<Vec<Value>> {
    if runtime.program().function(function_name).is_none() {
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

pub(crate) async fn execute_local_with_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<Vec<Value>> {
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
    validate_local_client_inputs(runtime)?;
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
    let local_client_inputs = runtime
        .client_inputs()
        .iter()
        .map(|(client_slot, values)| {
            Ok(stoffel_vm::net::LocalClientInput::raw(
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

    let mut runner = stoffel_vm::net::LocalCoordinatorRunner::builder(
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
    runner = runner.client_inputs(local_client_inputs);

    let output = runner
        .build()
        .map_err(|error| Error::Configuration(error.to_string()))?
        .run()
        .await
        .map_err(|error| Error::Computation(error.to_string()))?;

    let returned = output.consistent_returned_values().map_err(|error| {
        Error::Computation(format!(
            "local coordinator run did not produce consistent VM return values: {error}\noutput:\n{}",
            output.combined_output
        ))
    })?;
    returned
        .iter()
        .map(|value| parse_runner_return_value(value))
        .collect()
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
    }
}

fn validate_local_client_inputs(runtime: &StoffelRuntime) -> Result<()> {
    runtime
        .program()
        .validate_owned_client_inputs(runtime.client_inputs())
}

fn local_client_input_value(value: &Value) -> Result<String> {
    match value {
        Value::I64(value) => Ok(value.to_string()),
        Value::U64(value) if i64::try_from(*value).is_ok() => Ok(value.to_string()),
        Value::U64(value) => Ok(format!("0x{value:x}")),
        Value::Bool(value) => Ok(if *value { "1" } else { "0" }.to_owned()),
        Value::Bytes(value) => Ok(format!("0x{}", hex_encode(value))),
        Value::Float(_) | Value::String(_) | Value::List(_) | Value::Unit => {
            Err(Error::InvalidInput(
                "local coordinator client inputs support integers, booleans, and raw bytes"
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
            "SDK local coordinator execution requires a built stoffel-run binary; set STOFFEL_RUN_BIN, call `local_runner_path`, or build `cargo build -p stoffel-vm --bin stoffel-run`"
                .to_owned(),
        ));
    };
    let candidate = workspace_root
        .join("target")
        .join("debug")
        .join("stoffel-run");
    candidate.exists().then_some(candidate).ok_or_else(|| {
        Error::Unsupported(
            "SDK local coordinator execution requires a built stoffel-run binary; set STOFFEL_RUN_BIN, call `local_runner_path`, or build `cargo build -p stoffel-vm --bin stoffel-run`"
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

fn sdk_value_from_vm_value(
    vm: &mut stoffel_vm::core_vm::VirtualMachine,
    value: VmValue,
    active_arrays: &mut HashSet<ArrayRef>,
    depth: usize,
) -> Result<Value> {
    const MAX_ARRAY_DEPTH: usize = 32;

    match value {
        VmValue::Array(array_ref) => {
            if depth >= MAX_ARRAY_DEPTH {
                return Err(Error::Computation(format!(
                    "VM array output exceeds maximum SDK conversion depth of {MAX_ARRAY_DEPTH}"
                )));
            }
            if !active_arrays.insert(array_ref) {
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
                values.push(sdk_value_from_vm_value(vm, item, active_arrays, depth + 1)?);
            }
            active_arrays.remove(&array_ref);
            Ok(Value::List(values))
        }
        value => Value::from_vm_value(value).ok_or_else(|| {
            Error::Computation(
                "VM returned a value that cannot be represented by the public SDK Value type"
                    .to_owned(),
            )
        }),
    }
}
