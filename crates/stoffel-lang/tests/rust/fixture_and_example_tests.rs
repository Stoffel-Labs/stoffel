use std::fs;
use std::path::{Path, PathBuf};

use stoffel_vm_types::compiled_binary::{
    utils::{load_from_file, try_to_vm_functions},
    MpcBackend,
};
use stoffellang::{compile_file, convert_to_binary, save_to_file, CompilerOptions};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn compiler_options_for(path: &Path) -> CompilerOptions {
    let rel = path
        .strip_prefix(manifest_dir())
        .unwrap_or(path)
        .to_string_lossy();
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

fn collect_stoffel_files(root: &Path) -> Vec<PathBuf> {
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                visit(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "stfl") {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    visit(root, &mut files);
    files.sort();
    files
}

fn compile_source_file(path: &Path) -> Result<stoffellang::CompiledProgram, Vec<String>> {
    let source = fs::read_to_string(path).map_err(|err| vec![err.to_string()])?;
    compile_file(path, &source, &compiler_options_for(path))
        .map_err(|errors| errors.into_iter().map(|err| err.to_string()).collect())
}

fn fixture_should_fail(path: &Path) -> bool {
    let file_name = path.file_name().unwrap().to_string_lossy();
    file_name.starts_with("error_")
        || file_name.ends_with("_invalid.stfl")
        || file_name == "missing_import.stfl"
        || file_name == "circular_a.stfl"
        || file_name == "circular_b.stfl"
}

#[test]
fn stfl_fixtures_follow_expected_success_by_name() {
    let fixtures_root = manifest_dir().join("tests/stfl");
    let fixtures = collect_stoffel_files(&fixtures_root);
    assert!(!fixtures.is_empty(), "expected Stoffel fixtures");

    let mut failures = Vec::new();
    for fixture in fixtures {
        let result = compile_source_file(&fixture);
        let should_fail = fixture_should_fail(&fixture);

        match (should_fail, result) {
            (true, Ok(_)) => failures.push(format!(
                "{} compiled but is named as an invalid fixture",
                fixture.display()
            )),
            (false, Err(errors)) => failures.push(format!(
                "{} failed to compile:\n{}",
                fixture.display(),
                errors.join("\n")
            )),
            _ => {}
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn canonical_examples_compile_to_vm_bytecode() {
    let examples_root = manifest_dir().join("examples");
    let examples = collect_stoffel_files(&examples_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "main.stfl"))
        .collect::<Vec<_>>();
    assert!(!examples.is_empty(), "expected canonical examples");

    let out_dir = tempfile::tempdir().expect("temp dir");
    let mut failures = Vec::new();

    for example in examples {
        match compile_source_file(&example) {
            Ok(program) => {
                let binary = convert_to_binary(&program);
                let rel = example.strip_prefix(&examples_root).expect("example path");
                let binary_name = rel
                    .parent()
                    .expect("example directory")
                    .to_string_lossy()
                    .replace(['/', ' '], "__");
                let out_path = out_dir.path().join(format!("{binary_name}.stflb"));
                if let Err(err) = save_to_file(&binary, &out_path) {
                    failures.push(format!("{} failed to save: {err:?}", example.display()));
                    continue;
                }

                match load_from_file(&out_path).and_then(|loaded| try_to_vm_functions(&loaded)) {
                    Ok(functions) if functions.iter().any(|function| function.name() == "main") => {
                    }
                    Ok(_) => failures.push(format!(
                        "{} bytecode did not contain a main function",
                        example.display()
                    )),
                    Err(err) => failures.push(format!(
                        "{} failed bytecode round-trip: {err:?}",
                        example.display()
                    )),
                }
            }
            Err(errors) => failures.push(format!(
                "{} failed to compile:\n{}",
                example.display(),
                errors.join("\n")
            )),
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn root_examples_directory_does_not_contain_stoffel_sources() {
    let workspace_examples = manifest_dir().join("../../examples");
    if !workspace_examples.exists() {
        return;
    }

    let sources = collect_stoffel_files(&workspace_examples);
    assert!(
        sources.is_empty(),
        "Stoffel source examples should live under crates/stoffel-lang/examples, found: {:?}",
        sources
    );
}
