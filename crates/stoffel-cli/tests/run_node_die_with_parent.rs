//! `STOFFEL_DIE_WITH_PARENT`: a `stoffel run-node` spawned with a piped stdin
//! exits once that stdin reaches EOF, which is how a party learns its parent
//! (the local coordinator runner) is gone.
//!
//! The regression this guards: when the parent dies, every pipe it held the
//! read end of dies with it, including the party's stderr. The watchdog once
//! announced the shutdown with `eprintln!`, which panics on EPIPE, so the
//! watchdog thread unwound before reaching `exit` and the party ran on as an
//! orphan.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use stoffel_vm_types::compiled_binary::utils::save_to_file;

const STOFFEL_BIN: &str = env!("CARGO_BIN_EXE_stoffel");

/// A program that runs until it is killed.
const SPIN_SOURCE: &str =
    "def main() -> int64:\n  var i: int64 = 0\n  while i >= 0:\n    i = i + 1\n  return i";

fn wait_for_exit(
    child: &mut std::process::Child,
    within: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll the node") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn run_node_exits_on_stdin_eof_even_when_its_stderr_reader_is_gone() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let compiled = stoffellang::compile(
        SPIN_SOURCE,
        "<die-with-parent>",
        &stoffellang::CompilerOptions::default(),
    )
    .expect("compile the spinning program");
    let program_path = dir.path().join("spin.stflb");
    save_to_file(&stoffellang::convert_to_binary(&compiled), &program_path)
        .expect("write the program");

    let mut child = Command::new(STOFFEL_BIN)
        .arg("run-node")
        .arg(&program_path)
        .env("STOFFEL_DIE_WITH_PARENT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stoffel run-node");

    // The node is running the program, not exiting on its own.
    std::thread::sleep(Duration::from_secs(1));
    if let Some(status) = child.try_wait().expect("poll the node") {
        panic!("stoffel run-node exited before its stdin closed: {status}");
    }

    // What a SIGKILLed parent does: first its stderr reader goes away...
    drop(child.stderr.take());
    // ...and then the stdin write end (a final write proves the pipe is live).
    let mut stdin = child.stdin.take().expect("piped stdin");
    let _ = stdin.write_all(b"\n");
    drop(stdin);

    match wait_for_exit(&mut child, Duration::from_secs(20)) {
        Some(_) => {}
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stoffel run-node kept running after its parent closed stdin and stderr");
        }
    }
}
