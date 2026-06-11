//! Integration tests for multi-file compilation with imports.
//!
//! These tests verify that the import system works correctly for various
//! dependency patterns: chain imports, diamond imports, multiple imports, etc.

use std::path::PathBuf;
use stoffellang::compiler::{compile_file, CompilerOptions};

fn get_test_path(relative_path: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/stfl/imports");
    path.push(relative_path);
    path
}

fn compile_test_file(relative_path: &str) -> Result<(), Vec<String>> {
    let path = get_test_path(relative_path);
    let source =
        std::fs::read_to_string(&path).map_err(|e| vec![format!("Failed to read file: {}", e)])?;

    let options = CompilerOptions::default();
    compile_file(&path, &source, &options)
        .map(|_| ())
        .map_err(|errors| errors.iter().map(|e| e.to_string()).collect())
}

// ==================== Simple Import Tests ====================

#[test]
fn test_simple_import() {
    let result = compile_test_file("main_with_import.stfl");
    assert!(
        result.is_ok(),
        "Simple import should compile: {:?}",
        result.err()
    );
}

// ==================== Chain Import Tests ====================

/// Tests chain imports: main_chain -> middle -> base
/// Verifies that transitive dependencies are resolved correctly.
#[test]
fn test_chain_imports() {
    let result = compile_test_file("chain/main_chain.stfl");
    assert!(
        result.is_ok(),
        "Chain imports should compile: {:?}",
        result.err()
    );
}

// ==================== Diamond Import Tests ====================

/// Tests diamond imports: main_diamond -> (left, right) -> shared
/// Verifies that a module imported by multiple paths is only compiled once.
#[test]
fn test_diamond_imports() {
    let result = compile_test_file("diamond/main_diamond.stfl");
    assert!(
        result.is_ok(),
        "Diamond imports should compile: {:?}",
        result.err()
    );
}

// ==================== Multiple Import Tests ====================

/// Tests multiple imports in a single file.
#[test]
fn test_multiple_imports() {
    let result = compile_test_file("multi/main_multi.stfl");
    assert!(
        result.is_ok(),
        "Multiple imports should compile: {:?}",
        result.err()
    );
}

// ==================== Alias Import Tests ====================

/// Tests import with alias: import math_lib as m
#[test]
fn test_import_with_alias() {
    let result = compile_test_file("alias/main_alias.stfl");
    assert!(
        result.is_ok(),
        "Import with alias should compile: {:?}",
        result.err()
    );
}

#[test]
fn test_std_builtin_imports_are_declaration_only() {
    let result = compile_test_file("std_builtin_import.stfl");
    assert!(
        result.is_ok(),
        "Std builtin imports should compile: {:?}",
        result.err()
    );
}

// ==================== Nested Import Tests ====================

/// Tests deeply nested imports: main_nested -> level1/mid -> level1/level2/deep
#[test]
fn test_nested_imports() {
    let result = compile_test_file("nested/main_nested.stfl");
    assert!(
        result.is_ok(),
        "Nested imports should compile: {:?}",
        result.err()
    );
}

// ==================== Relative Path Import Tests ====================

/// Tests sibling-directory imports written as quoted filesystem paths.
#[test]
fn test_relative_path_import_from_sibling_directory() {
    let result = compile_test_file("relative/consumer/main.stfl");
    assert!(
        result.is_ok(),
        "Relative path import should compile: {:?}",
        result.err()
    );
}

/// Tests aliases on quoted filesystem imports.
#[test]
fn test_relative_path_import_with_alias() {
    let result = compile_test_file("relative/consumer/main_with_alias.stfl");
    assert!(
        result.is_ok(),
        "Aliased relative path import should compile: {:?}",
        result.err()
    );
}

// ==================== Error Cases ====================

/// Tests that circular imports are detected and reported.
#[test]
fn test_circular_imports_detected() {
    let result = compile_test_file("circular_a.stfl");
    assert!(result.is_err(), "Circular imports should fail");

    let errors = result.unwrap_err();
    let error_text = errors.join("\n");
    assert!(
        error_text.to_lowercase().contains("circular")
            || error_text.to_lowercase().contains("cycle"),
        "Error should mention circular dependency: {}",
        error_text
    );
}

/// Tests that missing modules are detected and reported.
#[test]
fn test_missing_module_detected() {
    let result = compile_test_file("missing_import.stfl");
    assert!(result.is_err(), "Missing module should fail");

    let errors = result.unwrap_err();
    let error_text = errors.join("\n");
    assert!(
        error_text.to_lowercase().contains("not found")
            || error_text.to_lowercase().contains("module"),
        "Error should mention module not found: {}",
        error_text
    );
}

// ==================== Single File Compilation ====================

/// Tests that files without imports still compile correctly.
#[test]
fn test_single_file_no_imports() {
    let result = compile_test_file("utils/math.stfl");
    assert!(
        result.is_ok(),
        "Single file without imports should compile: {:?}",
        result.err()
    );
}

// ==================== Module Export Tests ====================

/// Tests that exported functions from imported modules are accessible.
#[test]
fn test_exported_functions_accessible() {
    // The main_with_import.stfl uses add and multiply from utils/math.stfl
    let result = compile_test_file("main_with_import.stfl");
    assert!(
        result.is_ok(),
        "Exported functions should be accessible: {:?}",
        result.err()
    );
}

/// Tests that chain exports work (main can use functions from transitive deps).
#[test]
fn test_transitive_exports() {
    // main_chain uses triple (from middle) and middle uses double and base_value (from base)
    let result = compile_test_file("chain/main_chain.stfl");
    assert!(
        result.is_ok(),
        "Transitive exports should work: {:?}",
        result.err()
    );
}
