//! Closures executed end to end through `stoffel run-node` in local mode.
//!
//! A closure names its target function (`create_closure_with_upvalue("f", ...)`)
//! and its upvalues (`"start"`) by string. Both the compiler's unreachable-function
//! pruning and its inliner once broke that: the target was pruned at every
//! optimization level (`Function increment_counter not found`), and at `-O3` the
//! function capturing the upvalue was inlined away from the local it names
//! (`Could not find upvalue start`). This runs the program at every level.

use std::process::Command;

use stoffel_vm_types::compiled_binary::utils::save_to_file;

const STOFFEL_BIN: &str = env!("CARGO_BIN_EXE_stoffel");

const CLOSURE_COUNTER_SOURCE: &str = r#"
def increment_counter(amount: int64) -> int64:
  var saved_amount = amount
  var current = get_upvalue("start")
  var updated = current + saved_amount
  discard set_upvalue("start", updated)
  return updated

def create_counter(start: int64) -> Closure:
  return create_closure_with_upvalue("increment_counter", "start")

def main() -> int64:
  var counter = create_counter(10)
  var first = call_closure_with_arg(counter, 5)
  var second = call_closure_with_arg(counter, 7)
  return first + second
"#;

#[test]
fn a_closure_counter_runs_at_every_optimization_level() {
    let dir = tempfile::tempdir().expect("temp dir");
    for level in 0..=3u8 {
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            ..Default::default()
        };
        let compiled = stoffellang::compile(CLOSURE_COUNTER_SOURCE, "<closure-counter>", &options)
            .unwrap_or_else(|error| panic!("-O{level}: compile: {error:?}"));
        let path = dir.path().join(format!("closure_counter_O{level}.stflb"));
        save_to_file(&stoffellang::convert_to_binary(&compiled), &path).expect("write the program");

        let output = Command::new(STOFFEL_BIN)
            .arg("run-node")
            .arg(&path)
            .arg("main")
            .output()
            .expect("run stoffel run-node");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "-O{level}: run-node failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        // (10 + 5) + (15 + 7): the upvalue carries the first call's update.
        assert!(
            stdout.contains("Program returned: 37"),
            "-O{level}: wrong result\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}
