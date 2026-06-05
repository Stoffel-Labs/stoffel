use std::path::Path;

use crate::bytecode::CompiledProgram;
use crate::codegen;
use crate::errors::{CompilerError, ErrorReporter};
use crate::lexer;
use crate::multi_file_compiler;
use crate::optimizations;
use crate::parser;
use crate::semantic;
use crate::ufcs;
use stoffel_vm_types::compiled_binary::{MpcBackend, MpcCurve};

/// Options to configure the compilation process.
#[derive(Debug, Clone, Default)]
pub struct CompilerOptions {
    /// Enable or disable optimization passes.
    pub optimize: bool,
    /// Set the optimization level (0-3).
    pub optimization_level: u8,
    /// Print intermediate representations (Tokens, AST) for debugging.
    pub print_ir: bool,
    /// MPC backend expected by the coordinator when running the emitted binary.
    pub mpc_backend: MpcBackend,
    /// MPC curve expected by AVSS when running the emitted binary.
    pub mpc_curve: MpcCurve,
    // Add more options as needed: output_path, target_platform, etc.
}

/// Compiles the given source code string.
///
/// This function orchestrates the different phases of the compiler:
/// Lexing, Parsing, AST Transformations (like UFCS), Semantic Analysis, and Code Generation.
///
/// # Arguments
///
/// * `source` - The source code to compile.
/// * `filename` - The name of the source file (used for error reporting).
/// * `options` - Configuration for the compilation process.
///
/// # Returns
///
/// * `Ok(CompiledProgram)` - If compilation is successful.
/// * `Err(Vec<CompilerError>)` - If any errors occur during compilation.
pub fn compile(
    source: &str,
    filename: &str,
    options: &CompilerOptions,
) -> Result<CompiledProgram, Vec<CompilerError>> {
    let mut error_reporter = ErrorReporter::new();

    // 1. Lexing
    let tokens = match lexer::tokenize(source, filename) {
        Ok(t) => t,
        Err(e) => {
            error_reporter.add_error(e);
            // Cannot proceed without tokens
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }
    };
    if options.print_ir {
        println!("--- Tokens ---");
        println!("{:?}", tokens);
        println!("--------------");
    }

    // 2. Parsing
    let parse_output = parser::parse_recovering(&tokens, filename);
    for error in parse_output.errors {
        error_reporter.add_error(error);
    }
    let ast_root = parse_output.ast;
    if options.print_ir {
        println!("--- Initial AST ---");
        println!("{:#?}", ast_root);
        println!("-------------------");
    }

    // 3. UFCS Transformation (AST Pass)
    let transformed_ast = ufcs::transform_ufcs(ast_root);
    if options.print_ir {
        println!("--- Transformed AST (UFCS) ---");
        println!("{:#?}", transformed_ast);
        println!("------------------------------");
    }

    // 4. Semantic Analysis (Symbol Table, Type Checking)
    let analyzed_ast = match semantic::analyze(transformed_ast, &mut error_reporter, filename) {
        Ok(ast) => ast,
        Err(_) => {
            // Errors were already added to the reporter by the analyzer
            // Stop compilation if semantic errors occurred
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }
    };
    if error_reporter.has_errors() {
        return Err(error_reporter.get_all().into_iter().cloned().collect());
    }
    if options.print_ir {
        println!("--- Analyzed AST (Semantic Check) ---");
        println!("{:#?}", analyzed_ast);
        println!("-------------------------------------");
    }

    // 5. Optimization Passes
    let optimized_ast = if options.optimize {
        let ast = optimizations::optimize_all(analyzed_ast);
        if options.print_ir {
            println!("--- Optimized AST (Reveal Batching + Reordering) ---");
            println!("{:#?}", ast);
            println!("----------------------------------------------------");
        }
        ast
    } else {
        analyzed_ast
    };

    // 6. Code Generation
    let mut compiled_program = match codegen::generate_bytecode(&optimized_ast) {
        Ok(program) => program,
        Err(e) => {
            error_reporter.add_error(e);
            // Stop if codegen fails
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }
    };
    compiled_program.client_io_manifest.mpc_backend = options.mpc_backend;
    compiled_program.client_io_manifest.mpc_curve = options.mpc_curve;

    if error_reporter.has_errors() {
        Err(error_reporter.get_all().into_iter().cloned().collect())
    } else {
        Ok(compiled_program)
    }
}

/// Compiles a project from a file path.
///
/// This function automatically detects whether the source file contains imports
/// and uses multi-file compilation if needed. For single-file programs without
/// imports, it falls back to the standard compilation path.
///
/// # Arguments
///
/// * `file_path` - Path to the entry source file.
/// * `source` - The source code of the entry file.
/// * `options` - Configuration for the compilation process.
///
/// # Returns
///
/// * `Ok(CompiledProgram)` - If compilation is successful.
/// * `Err(Vec<CompilerError>)` - If any errors occur during compilation.
pub fn compile_file(
    file_path: &Path,
    source: &str,
    options: &CompilerOptions,
) -> Result<CompiledProgram, Vec<CompilerError>> {
    // Check if the source contains import statements
    if multi_file_compiler::has_imports(source) {
        // Use multi-file compilation
        multi_file_compiler::compile_project(file_path, options)
    } else {
        // Use single-file compilation
        let filename = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.stfl");
        compile(source, filename, options)
    }
}
