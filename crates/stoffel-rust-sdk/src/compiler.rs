//! Stoffel-Lang compilation and bytecode loading helpers.
//!
//! This module is a thin SDK boundary over `stoffellang`; it translates compiler
//! and bytecode errors into SDK errors without reimplementing the language
//! compiler.

use std::io::Cursor;
use std::path::Path;

use stoffel_vm_types::compiled_binary::CompiledBinary;

use crate::backend::MpcBackend;
use crate::error::{format_compiler_errors, Error, Result};
use crate::program::Program;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompilationOptions {
    pub optimize: bool,
    pub optimization_level: u8,
    pub print_ir: bool,
}

pub fn compile_source(source: &str, filename: &str, backend: MpcBackend) -> Result<Program> {
    compile_source_with_options(source, filename, backend, CompilationOptions::default())
}

pub fn compile_source_with_options(
    source: &str,
    filename: &str,
    backend: MpcBackend,
    options: CompilationOptions,
) -> Result<Program> {
    let options = compiler_options(backend, options);
    let compiled = stoffellang::compile(source, filename, &options)
        .map_err(|errors| Error::Compilation(format_compiler_errors(&errors)))?;
    Ok(Program::new(stoffellang::convert_to_binary(&compiled)))
}

pub fn compile_file(path: &Path, backend: MpcBackend) -> Result<Program> {
    compile_file_with_options(path, backend, CompilationOptions::default())
}

pub fn compile_file_with_options(
    path: &Path,
    backend: MpcBackend,
    options: CompilationOptions,
) -> Result<Program> {
    let source = std::fs::read_to_string(path)?;
    let options = compiler_options(backend, options);
    let compiled = stoffellang::compile_file(path, &source, &options)
        .map_err(|errors| Error::Compilation(format_compiler_errors(&errors)))?;
    Ok(Program::new(stoffellang::convert_to_binary(&compiled)))
}

pub fn load_bytecode(bytecode: &[u8]) -> Result<Program> {
    let mut cursor = Cursor::new(bytecode);
    let binary = CompiledBinary::deserialize(&mut cursor)
        .map_err(|error| Error::Bytecode(format!("{error:?}")))?;
    if cursor.position() != bytecode.len() as u64 {
        return Err(Error::Bytecode(format!(
            "bytecode contains {} trailing byte(s)",
            bytecode.len() as u64 - cursor.position()
        )));
    }
    Ok(Program::new(binary))
}

fn compiler_options(
    backend: MpcBackend,
    options: CompilationOptions,
) -> stoffellang::CompilerOptions {
    // Optimizer budget knobs are honored here, at the SDK boundary, rather than
    // inside the optimizer — keeping the library compile path hermetic. The
    // Stoffel CLI populates these env vars from the project's build config.
    let env_budget = |name: &str| std::env::var(name).ok().and_then(|v| v.parse().ok());
    stoffellang::CompilerOptions {
        optimize: options.optimize || options.optimization_level > 0,
        optimization_level: options.optimization_level,
        print_ir: options.print_ir,
        mpc_backend: backend.compiler_backend(),
        mpc_curve: backend.compiler_curve(),
        inline_budget: env_budget("STOFFEL_INLINE_BUDGET"),
        unroll_budget: env_budget("STOFFEL_UNROLL_BUDGET"),
        unroll_max_expansion: env_budget("STOFFEL_UNROLL_MAX_EXPANSION"),
    }
}
