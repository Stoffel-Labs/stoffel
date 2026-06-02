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

pub fn compile_source(source: &str, filename: &str, backend: MpcBackend) -> Result<Program> {
    let options = compiler_options(backend);
    let compiled = stoffellang::compile(source, filename, &options)
        .map_err(|errors| Error::Compilation(format_compiler_errors(&errors)))?;
    Ok(Program::new(stoffellang::convert_to_binary(&compiled)))
}

pub fn compile_file(path: &Path, backend: MpcBackend) -> Result<Program> {
    let source = std::fs::read_to_string(path)?;
    let options = compiler_options(backend);
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

fn compiler_options(backend: MpcBackend) -> stoffellang::CompilerOptions {
    stoffellang::CompilerOptions {
        mpc_backend: backend.compiler_backend(),
        mpc_curve: backend.compiler_curve(),
        ..Default::default()
    }
}
