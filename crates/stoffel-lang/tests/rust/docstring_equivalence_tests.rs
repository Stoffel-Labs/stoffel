//! Docstrings are documentation only: adding them must never change the
//! compiled program.
//!
//! Every valid fixture and canonical example is compiled twice, once as
//! written and once with a docstring injected into every documentable
//! position, and the serialized bytecode (constant pool, function table and
//! instructions) must be byte-for-byte identical. `valid_docstrings.stfl`
//! runs the other way round: it is compared against itself with its
//! docstrings stripped.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use stoffel_vm_types::compiled_binary::MpcBackend;
use stoffellang::bytecode::BytecodeChunk;
use stoffellang::{compile, compile_file, convert_to_binary, CompiledProgram, CompilerOptions};

#[path = "support/docstring_injection.rs"]
mod docstring_injection;
use docstring_injection::{inject_docstrings, strip_docstrings};

/// The compiler recurses with expression depth; large examples need more
/// than the default test-thread stack in debug builds.
const COMPILE_STACK_SIZE: usize = 32 * 1024 * 1024;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn compiler_options_for(relative: &Path) -> CompilerOptions {
    let rel = relative.to_string_lossy();
    let mpc_backend = if rel.contains("avss_certificate/")
        || rel.contains("threshold_ecdsa_")
        || rel.contains("threshold_schnorr_")
        || rel.contains("threshold_eddsa_")
    {
        MpcBackend::Avss
    } else {
        MpcBackend::HoneyBadger
    };
    CompilerOptions {
        mpc_backend,
        ..CompilerOptions::default()
    }
}

fn collect_stfl_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_stfl_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "stfl") {
            out.push(path);
        }
    }
}

/// Deterministic serialized bytecode of a compiled program.
///
/// `CompiledProgram` keeps function chunks in a `HashMap`, so serializing
/// the whole program orders its functions (and with them the shared constant
/// pool) differently from one compile to the next. Each chunk is therefore
/// serialized on its own, in name order, through the regular binary
/// converter: instructions, constant pool and function table entry. Jump
/// labels are also a `HashMap` that the binary format writes in iteration
/// order, so they are compared as a sorted list instead.
fn serialized(program: &CompiledProgram) -> Vec<u8> {
    let mut chunks: Vec<(&str, &BytecodeChunk)> = program
        .function_chunks
        .iter()
        .map(|(name, chunk)| (name.as_str(), chunk))
        .collect();
    chunks.sort_by_key(|(name, _)| *name);
    chunks.insert(0, ("<main>", &program.main_chunk));

    let mut bytes = Vec::new();
    for (name, chunk) in chunks {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        let single = CompiledProgram {
            main_chunk: BytecodeChunk {
                labels: HashMap::new(),
                ..chunk.clone()
            },
            ..CompiledProgram::default()
        };
        convert_to_binary(&single)
            .serialize(&mut bytes)
            .expect("serialize compiled binary");
        let mut labels: Vec<_> = chunk.labels.iter().collect();
        labels.sort();
        bytes.extend_from_slice(format!("{labels:?}").as_bytes());
    }
    bytes.extend_from_slice(format!("{:?}", program.client_io_manifest).as_bytes());
    bytes
}

fn compile_path(path: &Path, options: &CompilerOptions) -> Result<Vec<u8>, String> {
    let source = fs::read_to_string(path).map_err(|err| err.to_string())?;
    compile_file(path, &source, options)
        .map(|program| serialized(&program))
        .map_err(|errors| {
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        })
}

/// Copies every `.stfl` file under `source_root` to the same relative path
/// under `target_root`, with docstrings injected. Returns the number of item
/// docstrings added.
fn mirror_with_docstrings(source_root: &Path, target_root: &Path) -> usize {
    let mut files = Vec::new();
    collect_stfl_files(source_root, &mut files);
    let mut injected_items = 0;
    for file in files {
        let relative = file.strip_prefix(source_root).expect("relative path");
        let target = target_root.join(relative);
        fs::create_dir_all(target.parent().expect("parent")).expect("create dirs");
        let injected = inject_docstrings(&fs::read_to_string(&file).expect("read source"));
        injected_items += injected.item_docstrings;
        fs::write(&target, injected.source).expect("write injected source");
    }
    injected_items
}

/// Compiles each program under `original_root` and its injected mirror under
/// `injected_root`, returning a failure description per mismatch.
fn compare_trees(original_root: &Path, injected_root: &Path, programs: &[PathBuf]) -> Vec<String> {
    let mut failures = Vec::new();
    for program in programs {
        let relative = program.strip_prefix(original_root).expect("relative path");
        let options = compiler_options_for(relative);
        let original = match compile_path(program, &options) {
            Ok(bytes) => bytes,
            Err(errors) => {
                failures.push(format!(
                    "{} failed to compile:\n{errors}",
                    program.display()
                ));
                continue;
            }
        };
        match compile_path(&injected_root.join(relative), &options) {
            Ok(injected) if injected == original => {}
            Ok(_) => failures.push(format!(
                "{}: docstrings changed the serialized bytecode",
                relative.display()
            )),
            Err(errors) => failures.push(format!(
                "{} failed to compile with docstrings:\n{errors}",
                relative.display()
            )),
        }
    }
    failures
}

fn run_on_big_stack(test: impl FnOnce() + Send + 'static) {
    thread::Builder::new()
        .stack_size(COMPILE_STACK_SIZE)
        .spawn(test)
        .expect("spawn test thread")
        .join()
        .expect("equivalence sweep panicked");
}

#[test]
fn valid_fixtures_compile_identically_with_docstrings() {
    run_on_big_stack(|| {
        let root = manifest_dir().join("tests/stfl");
        let temp = tempfile::tempdir().expect("temp dir");
        let injected_items = mirror_with_docstrings(&root, temp.path());

        let mut programs = Vec::new();
        collect_stfl_files(&root, &mut programs);
        programs.retain(|path| {
            let name = path.file_name().expect("file name").to_string_lossy();
            name.starts_with("valid_") && !name.contains("docstring")
        });
        programs.sort();
        assert!(programs.len() >= 10, "expected valid_* fixtures");
        assert!(
            injected_items >= programs.len(),
            "too few docstrings injected"
        );

        let failures = compare_trees(&root, temp.path(), &programs);
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    });
}

#[test]
fn canonical_examples_compile_identically_with_docstrings() {
    run_on_big_stack(|| {
        let root = manifest_dir().join("examples");
        let temp = tempfile::tempdir().expect("temp dir");
        let injected_items = mirror_with_docstrings(&root, temp.path());

        let mut programs = Vec::new();
        collect_stfl_files(&root, &mut programs);
        programs.retain(|path| path.file_name().is_some_and(|name| name == "main.stfl"));
        programs.sort();
        assert!(!programs.is_empty(), "expected canonical examples");
        assert!(
            injected_items >= programs.len(),
            "too few docstrings injected"
        );

        let failures = compare_trees(&root, temp.path(), &programs);
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    });
}

/// The dedicated fixture has a module docstring and `def main`, so it also
/// guards against docstrings turning into top-level code (which codegen
/// rejects next to `def main`).
#[test]
fn docstring_fixture_matches_its_stripped_source() {
    run_on_big_stack(|| {
        let path = manifest_dir().join("tests/stfl/valid_docstrings.stfl");
        let source = fs::read_to_string(&path).expect("read fixture");
        let stripped = strip_docstrings(&source);
        assert!(!stripped.contains("\"\"\""), "stripping left a docstring");

        for level in 0..=3 {
            let options = CompilerOptions {
                optimize: level > 0,
                optimization_level: level,
                ..CompilerOptions::default()
            };
            let documented = compile(&source, "valid_docstrings.stfl", &options)
                .unwrap_or_else(|errors| panic!("-O{level} documented: {errors:?}"));
            let plain = compile(&stripped, "valid_docstrings.stfl", &options)
                .unwrap_or_else(|errors| panic!("-O{level} stripped: {errors:?}"));
            assert_eq!(
                serialized(&documented),
                serialized(&plain),
                "-O{level}: docstrings changed the bytecode"
            );
        }
    });
}
