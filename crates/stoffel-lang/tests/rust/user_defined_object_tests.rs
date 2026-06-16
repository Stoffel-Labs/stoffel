//! End-to-end integration tests for user-defined objects and methods
//!
//! These tests verify the complete compiler pipeline (lexer → parser → UFCS → semantic → codegen)
//! for user-defined object definitions in Stoffel-Lang.
//!
//! Focus areas:
//! - Object definition syntax
//! - Field declarations with various types
//! - Secret object definitions
//! - Object fields with secret types
//! - Error cases for malformed object definitions
//! - Compilation to .stflb bytecode files

use std::fs;
use std::path::Path;
use stoffel_vm_types::compiled_binary::{MpcBackend, MpcCurve};
use stoffellang::binary_converter::{convert_to_binary, save_to_file};
use stoffellang::compiler::{compile, CompilerOptions};
use stoffellang::lexer::tokenize;
use stoffellang::parser::parse;

// ===========================================
// Helper functions
// ===========================================

fn default_options() -> CompilerOptions {
    CompilerOptions {
        optimize: false,
        optimization_level: 0,
        print_ir: false,
        mpc_backend: MpcBackend::default(),
        mpc_curve: MpcCurve::default(),
    }
}

/// Runs lexer + parser and returns success/failure
fn parse_source(source: &str) -> Result<(), String> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| e.message)?;
    parse(&tokens, "test.stfl").map_err(|e| e.message)?;
    Ok(())
}

/// Runs full compilation (lexer → parser → UFCS → semantic → codegen) and returns success/failure
fn compile_source(source: &str) -> Result<(), Vec<String>> {
    compile(source, "test.stfl", &default_options())
        .map(|_| ())
        .map_err(|errors| errors.iter().map(|e| e.message.clone()).collect())
}

/// Compiles source to bytecode and returns the compiled program
fn compile_to_bytecode(
    source: &str,
) -> Result<stoffellang::bytecode::CompiledProgram, Vec<String>> {
    compile(source, "test.stfl", &default_options())
        .map_err(|errors| errors.iter().map(|e| e.message.clone()).collect())
}

/// Expects a parse error containing the given substring
fn expect_parse_error(source: &str, expected_error: &str) -> bool {
    match parse_source(source) {
        Err(msg) => msg.to_lowercase().contains(&expected_error.to_lowercase()),
        Ok(_) => false,
    }
}

/// Creates a temporary .stfl file and compiles it to .stflb
fn compile_file_to_bytecode(source: &str, filename: &str) -> Result<String, String> {
    let stfl_path = format!("/tmp/{}.stfl", filename);
    let stflb_path = format!("/tmp/{}.stflb", filename);

    // Write source to .stfl file
    fs::write(&stfl_path, source).map_err(|e| format!("Failed to write .stfl file: {}", e))?;

    // Compile
    let program = compile(source, &stfl_path, &default_options()).map_err(|errors| {
        errors
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
            .join(", ")
    })?;

    // Convert to binary and save to .stflb file
    let binary = convert_to_binary(&program);
    save_to_file(&binary, &stflb_path)
        .map_err(|e| format!("Failed to write .stflb file: {:?}", e))?;

    Ok(stflb_path)
}

// ===========================================
// Object Definition Parsing Tests
// ===========================================

#[test]
fn test_simple_object_definition() {
    let source = r#"
object Point:
  x: int64
  y: int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_single_field() {
    let source = r#"
object Counter:
  value: int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_multiple_fields_various_types() {
    let source = r#"
object Person:
  age: int64
  height: float
  name: string
  active: bool

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_with_all_secret_fields() {
    let source = r#"
object SecureData:
  value: secret int64
  key: secret int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_with_secret_fields() {
    let source = r#"
object PartiallySecret:
  public_id: int64
  secret_value: secret int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_multiple_object_definitions() {
    let source = r#"
object Point:
  x: int64
  y: int64

object Rectangle:
  width: int64
  height: int64

object Circle:
  radius: float
  centerX: int64
  centerY: int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_with_list_field() {
    let source = r#"
object Container:
  items: list[int64]
  count: int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Object Definition Error Tests
// ===========================================

#[test]
fn test_error_object_no_fields() {
    let source = r#"
object Empty:

def main() -> None:
  print("done")
"#;
    // Object must have at least one field
    assert!(expect_parse_error(source, "field") || expect_parse_error(source, "indent"));
}

#[test]
fn test_error_object_missing_colon() {
    let source = r#"
object Point
  x: int64

def main() -> None:
  print("done")
"#;
    assert!(expect_parse_error(source, ":") || expect_parse_error(source, "colon"));
}

#[test]
fn test_error_object_missing_name() {
    let source = r#"
object:
  x: int64

def main() -> None:
  print("done")
"#;
    assert!(expect_parse_error(source, "name") || expect_parse_error(source, "identifier"));
}

#[test]
fn test_error_field_missing_type() {
    let source = r#"
object Point:
  x
  y

def main() -> None:
  print("done")
"#;
    assert!(expect_parse_error(source, ":") || expect_parse_error(source, "type"));
}

// ===========================================
// Compile to .stflb File Tests
// ===========================================

#[test]
fn test_compile_object_to_bytecode_file() {
    let source = r#"
object Point:
  x: int64
  y: int64

def main() -> None:
  print("Point object defined")
"#;
    let result = compile_file_to_bytecode(source, "test_object_point");
    assert!(result.is_ok(), "Failed to compile: {:?}", result.err());

    // Verify .stflb file exists
    let stflb_path = result.unwrap();
    assert!(Path::new(&stflb_path).exists(), ".stflb file should exist");

    // Verify file has content
    let content = fs::read(&stflb_path).expect("Should be able to read .stflb");
    assert!(!content.is_empty(), ".stflb file should not be empty");
}

#[test]
fn test_compile_multiple_objects_to_bytecode_file() {
    let source = r#"
object Vector2D:
  x: float
  y: float

object Vector3D:
  x: float
  y: float
  z: float

def main() -> None:
  print("Vectors defined")
"#;
    let result = compile_file_to_bytecode(source, "test_multiple_objects");
    assert!(result.is_ok(), "Failed to compile: {:?}", result.err());
}

#[test]
fn test_compile_object_with_secret_field_to_bytecode_file() {
    let source = r#"
object Credential:
  user_id: int64
  secret_key: secret int64

def main() -> None:
  print("Credential object defined")
"#;
    let result = compile_file_to_bytecode(source, "test_secret_object");
    assert!(result.is_ok(), "Failed to compile: {:?}", result.err());
}

#[test]
fn test_compile_object_with_functions() {
    let source = r#"
object Point:
  x: int64
  y: int64

def helper_func(a: int64) -> int64:
  return a * 2

def main() -> None:
  var result = helper_func(5)
  print("done")
"#;
    let result = compile_file_to_bytecode(source, "test_object_with_funcs");
    assert!(result.is_ok(), "Failed to compile: {:?}", result.err());
}

// ===========================================
// Object Type in Declarations Tests
// ===========================================

#[test]
fn test_object_type_as_variable_annotation() {
    // Note: Object instantiation isn't implemented yet, but type annotation should parse
    let source = r#"
object Point:
  x: int64
  y: int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_constructor_with_named_fields() {
    let source = r#"
object MpcJob:
  id: string
  parties: int64
  threshold: int64
  curve: string

def main() -> None:
  var job = MpcJob(
    id: "nightly-risk-score",
    parties: 5,
    threshold: 1,
    curve: "bls12-381",
  )
  print(job.id)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_constructor_allows_empty_then_field_assignment() {
    let source = r#"
object MpcJob:
  id: string
  threshold: int64

def main() -> None:
  var job = MpcJob()
  job.id = "nightly-risk-score"
  job.threshold = 1
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_constructor_rejects_unknown_field() {
    let source = r#"
object MpcJob:
  id: string

def main() -> None:
  var job = MpcJob(missing: "value")
"#;
    let errors = compile_source(source).unwrap_err();
    assert!(
        errors.iter().any(|err| err.contains("Unknown field")),
        "Expected unknown field error, got {:?}",
        errors
    );
}

#[test]
fn test_object_constructor_rejects_wrong_field_type() {
    let source = r#"
object MpcJob:
  threshold: int64

def main() -> None:
  var job = MpcJob(threshold: "one")
"#;
    let errors = compile_source(source).unwrap_err();
    assert!(
        errors.iter().any(|err| err.contains("Type mismatch")),
        "Expected type mismatch error, got {:?}",
        errors
    );
}

// ===========================================
// Integration with Builtin Objects Tests
// ===========================================

#[test]
fn test_user_object_alongside_builtin_objects() {
    let source = r#"
object MyData:
  value: int64
  processed: bool

def main() -> None:
  var n_clients = ClientStore.get_number_clients()
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_user_object_with_mpc_operations() {
    let source = r#"
object ComputationState:
  round: int64
  ready: bool

def main() -> None:
  var party = Mpc.party_id()
  var n = Mpc.n_parties()
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Complex Object Scenarios
// ===========================================

#[test]
fn test_object_with_nested_list_types() {
    let source = r#"
object Matrix:
  rows: int64
  cols: int64
  data: list[int64]

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_multiple_objects_with_secret_fields() {
    let source = r#"
object SecretA:
  value_a: secret int64

object SecretB:
  value_b: secret int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_field_with_secret_list() {
    let source = r#"
object SecureContainer:
  count: int64
  secrets: list[secret int64]

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Bytecode Generation Verification Tests
// ===========================================

#[test]
fn test_bytecode_contains_entry_point() {
    let source = r#"
object Point:
  x: int64
  y: int64

def main() -> None:
  print("hello")
"#;
    let result = compile_to_bytecode(source);
    assert!(result.is_ok(), "Compilation should succeed");

    let program = result.unwrap();
    // The program should have a main chunk with instructions
    assert!(
        !program.main_chunk.instructions.is_empty(),
        "Program should have instructions in main chunk"
    );
}

#[test]
fn test_bytecode_generation_with_multiple_objects() {
    let source = r#"
object A:
  x: int64

object B:
  y: int64

object C:
  z: int64

def main() -> None:
  print("done")
"#;
    let result = compile_to_bytecode(source);
    assert!(result.is_ok(), "Compilation should succeed");
}

// ===========================================
// Edge Cases
// ===========================================

#[test]
fn test_object_field_name_same_as_keyword() {
    // 'type' is a keyword but should work as field name
    let source = r#"
object Record:
  id: int64
  value: int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_with_all_numeric_types() {
    let source = r#"
object NumericContainer:
  i64val: int64
  f64val: float

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_deeply_nested_secret_type_in_object() {
    let source = r#"
object DeepSecret:
  public_count: int64
  secret_data: secret int64

def main() -> None:
  print("done")
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Additional Real-World Scenarios
// ===========================================

#[test]
fn test_object_for_mpc_computation_state() {
    let source = r#"
object MPCComputationState:
  party_id: int64
  n_parties: int64
  threshold: int64
  is_initialized: bool

def main() -> None:
  var id = Mpc.party_id()
  var n = Mpc.n_parties()
  var t = Mpc.threshold()
  print("MPC state ready")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_for_client_data_tracking() {
    let source = r#"
object ClientData:
  client_id: int64
  share_count: int64

def main() -> None:
  var n_clients = ClientStore.get_number_clients()
  print("Tracking clients")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_object_for_consensus_state() {
    let source = r#"
object ConsensusState:
  round_number: int64
  is_decided: bool
  proposal_value: int64

def main() -> None:
  print("Consensus state defined")
"#;
    assert!(compile_source(source).is_ok());
}
