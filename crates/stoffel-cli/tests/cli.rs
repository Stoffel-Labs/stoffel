use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn local_mpc_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const LOCAL_MPC_TEST_TIMEOUT_SECS: &str = "120";

#[test]
fn init_creates_default_project() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path().join("hello"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Created Stoffel project"));

    assert!(temp.path().join("hello/Stoffel.toml").exists());
    assert!(temp.path().join("hello/src/main.stfl").exists());
}

#[test]
fn common_command_aliases_work() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("hello");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("new")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Created Stoffel project"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("doctor")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Config: ok"));
}

#[test]
fn run_executes_local_mpc_project_with_inputs() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=40",
            "--input",
            "b=2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
}

#[test]
fn build_writes_bytecode_to_target() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["build", "--output", "target/debug/app.stfb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Built"))
        .stdout(predicate::str::contains("Bytecode size:"))
        .stdout(predicate::str::contains("Optimization: O2"));

    assert!(temp.path().join("target/debug/app.stfb").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["build", "--release"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Profile: release"))
        .stdout(predicate::str::contains("Optimization: O3"));
    let release_artifacts = fs::read_dir(temp.path().join("target/release"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("stfb"))
        .collect::<Vec<_>>();
    assert!(!release_artifacts.is_empty());
}

#[test]
fn run_executes_bytecode_file() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["build", "--output", "target/debug/app.stfb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "target/debug/app.stfb",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=20",
            "--input",
            "b=22",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
}

#[test]
fn run_auto_discovers_built_bytecode() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&project)
        .arg("build")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "run",
            project.to_str().unwrap(),
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=21",
            "--input",
            "b=21",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
}

#[test]
fn run_recompiles_when_project_source_is_newer_than_bytecode() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success();

    thread::sleep(Duration::from_secs(1));
    fs::write(
        project.join("src/main.stfl"),
        "def main(a: Share, b: Share) -> int64:\n  var sum = Share.add(a, b)\n  var sum2 = Share.add(sum, b)\n  return sum2.open()\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args([
            "--summary",
            "--timeout-secs",
            "0",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Instructions: 14"))
        .stderr(predicate::str::contains(
            "local network timeout must be greater than zero",
        ));
}

#[test]
fn run_recompiles_when_project_config_is_newer_than_bytecode() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success();

    thread::sleep(Duration::from_secs(1));
    let config = fs::read_to_string(project.join("Stoffel.toml")).unwrap();
    fs::write(
        project.join("Stoffel.toml"),
        config.replace("threshold = 1", "threshold = 2"),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args([
            "--summary",
            "--timeout-secs",
            "0",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid Byzantine threshold"));
}

#[test]
fn run_folder_compiles_project_when_bytecode_is_missing() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app.with.dot");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(project)
        .args([
            "--summary",
            "--timeout-secs",
            "0",
            "--input",
            "a=21",
            "--input",
            "b=21",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Functions:"))
        .stdout(predicate::str::contains("Instructions:"))
        .stderr(predicate::str::contains(
            "local network timeout must be greater than zero",
        ));
}

#[test]
fn dev_once_executes_default_project_with_named_inputs() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args([
            "--once",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=40",
            "--input",
            "b=2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
}

#[test]
fn dev_once_explains_input_mistakes() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--once", "--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'a'"))
        .stderr(predicate::str::contains(
            "Pass inputs as: stoffel dev --entry main --input a=<value> --input b=<value>",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["a=40", "b=2", "--once"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "named inputs must use --input NAME=VALUE",
        ))
        .stderr(predicate::str::contains(
            "Try: stoffel dev --input a=40 --input b=2",
        ));
}

#[test]
fn run_help_exposes_mpc_network_flags() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--parties"))
        .stdout(predicate::str::contains("--threshold"))
        .stdout(predicate::str::contains("--config"))
        .stdout(predicate::str::contains("--network"))
        .stdout(predicate::str::contains("--local"))
        .stdout(predicate::str::contains("--client-input"))
        .stdout(predicate::str::contains("--connect-timeout-ms"));
}

#[test]
fn run_rejects_build_only_flags_and_honors_summary() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["run", "--output", "target/debug/app.stfb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--output is only used"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["run", "--disassemble"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--disassemble is only used"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--summary",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Functions:"))
        .stdout(predicate::str::contains("3"));
}

#[test]
fn run_validates_entry_and_inputs_before_timeout() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args([
            "--entry",
            "missing",
            "--input",
            "a=1",
            "--input",
            "b=2",
            "--timeout-secs",
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("function 'missing' not found"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1",
            "--input",
            "a=2",
            "--input",
            "b=3",
            "--timeout-secs",
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("duplicate input 'a'"))
        .stderr(predicate::str::contains("--input a=<value>"))
        .stderr(predicate::str::contains("--input b=<value>"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'a'"))
        .stderr(predicate::str::contains(
            "Pass inputs as: stoffel run --entry main --input a=<value> --input b=<value>",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--input", "a=1", "--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'b'"))
        .stderr(predicate::str::contains("--input b=<value>"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--input", "a=", "--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("input 'a' must include a value"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--client-input", "0=", "--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "client input slot 0 must include a value",
        ));
}

#[test]
fn run_explains_positional_input_mistakes() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args(["a=40", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "named inputs must use --input NAME=VALUE",
        ))
        .stderr(predicate::str::contains(
            "Try: stoffel run --input a=40 --input b=2",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&project)
        .args(["run", "a=40", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Try: stoffel run --input a=40 --input b=2",
        ));
}

#[test]
fn run_network_requires_config() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg("--network")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "network execution requires --config",
        ));
}

#[test]
fn run_network_validates_config_path_before_parsing() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--network", "--config", "missing.toml"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("network config")
                .and(predicate::str::contains("does not exist")),
        );

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .arg("--network")
        .arg("--config")
        .arg(temp.path().join("src/main.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "network config must be a .toml file",
        ));
}

#[test]
fn run_config_rejects_project_stoffel_toml() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .arg("--config")
        .arg(temp.path().join("Stoffel.toml"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not project Stoffel.toml"));
}

#[test]
fn run_network_accepts_network_config_and_attempts_connection() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("network.toml"),
        r#"
[network]
party_id = 0
bind_address = "127.0.0.1:39200"
expected_parties = 5
expected_clients = 1
consensus_timeout_ms = 1000

[network.peers]
1 = "127.0.0.1:39201"
2 = "127.0.0.1:39202"
3 = "127.0.0.1:39203"
4 = "127.0.0.1:39204"

[mpc]
threshold = 1
protocol = "honeybadger"

[preprocessing]
triples = 1
random_shares = 1
"#,
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--network",
            "--config",
            "network.toml",
            "--connect-timeout-ms",
            "50",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("failed to connect").or(predicate::str::contains("timed out")),
        );
}

#[test]
fn compile_disassembles_bytecode() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "-b", "-O2", "--output", "target/debug/app.stfb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "--disassemble", "target/debug/app.stfb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("main"));
}

#[test]
fn disassemble_rejects_source_files_with_actionable_error() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "--disassemble", "src/main.stfl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--disassemble requires .stfb or .stflb bytecode",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "--disassemble", "missing.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--disassemble requires .stfb or .stflb bytecode",
        ));
}

#[test]
fn build_compiles_all_project_sources() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("src/second.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("build")
        .assert()
        .success();

    let built_files = fs::read_dir(temp.path().join("target/debug"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("stfb"))
        .collect::<Vec<_>>();
    assert!(built_files.len() >= 2);
    assert!(temp.path().join("target/debug/second.stfb").exists());
}

#[test]
fn build_preserves_nested_source_paths_to_avoid_artifact_collisions() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("src/a")).unwrap();
    fs::create_dir_all(temp.path().join("src/b")).unwrap();
    fs::write(
        temp.path().join("src/a/calc.stfl"),
        "def main() -> int64:\n  return 1\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src/b/calc.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .success();

    assert!(temp.path().join("target/debug/a/calc.stfb").exists());
    assert!(temp.path().join("target/debug/b/calc.stfb").exists());
}

#[test]
fn build_and_check_accept_project_folder_paths() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Built"));
    assert!(project.join("target/debug/app.stfb").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Checked"));
}

#[test]
fn build_output_is_relative_to_project_root() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    let workdir = temp.path().join("work");
    fs::create_dir_all(&workdir).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&workdir)
        .arg("build")
        .arg(&project)
        .args(["--output", "target/debug/custom.stfb"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            project
                .join("target/debug/custom.stfb")
                .display()
                .to_string(),
        ));

    assert!(project.join("target/debug/custom.stfb").exists());
    assert!(!workdir.join("target/debug/custom.stfb").exists());
}

#[test]
fn build_missing_configured_source_reports_path() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::remove_file(temp.path().join("src/main.stfl")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("failed to compile")
                .and(predicate::str::contains("src/main.stfl")),
        );
}

#[test]
fn build_rejects_configured_source_with_wrong_extension() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("source = \"src/main.stfl\"", "source = \"src/main.txt\""),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid build.source src/main.txt",
        ))
        .stderr(predicate::str::contains(
            "expected a .stfl source file or source directory",
        ));
}

#[test]
fn build_rejects_unsafe_configured_target_dir() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();

    for (target_dir, expected) in [
        ("src", "must not be written under src/"),
        (".", "choose a dedicated build directory"),
        ("..", "build artifacts must stay inside the project"),
        ("target/..", "build artifacts must stay inside the project"),
    ] {
        fs::write(
            temp.path().join("Stoffel.toml"),
            config.replace(
                "target_dir = \"target\"",
                &format!("target_dir = \"{target_dir}\""),
            ),
        )
        .unwrap();
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("build")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid build.target_dir"))
            .stderr(predicate::str::contains(expected));
    }

    let absolute_src_target = temp.path().join("src/build");
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace(
            "target_dir = \"target\"",
            &format!("target_dir = \"{}\"", absolute_src_target.display()),
        ),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid build.target_dir"))
        .stderr(predicate::str::contains(
            "expected a relative directory inside the project",
        ));

    fs::write(temp.path().join("build-file"), "").unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("target_dir = \"target\"", "target_dir = \"build-file\""),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid build.target_dir build-file",
        ))
        .stderr(predicate::str::contains("is an existing file"));
}

#[test]
fn build_invalid_mpc_flags_report_configuration_context() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--parties", "3", "--threshold", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to compile or configure"))
        .stderr(predicate::str::contains("parties must be at least 5"))
        .stderr(predicate::str::contains("4 * threshold + 1"));
}

#[test]
fn run_broken_source_reports_command_and_path_context() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(temp.path().join("src/main.stfl"), "def main(\n").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "stoffel run could not compile or load",
        ))
        .stderr(predicate::str::contains(temp.path().display().to_string()))
        .stderr(predicate::str::contains("Syntax"));
}

#[test]
fn explicit_wrong_file_types_report_actionable_errors() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "target/debug/app.stfb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path().join("README.md"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("expected a .stfl source file"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path().join("target/debug/app.stfb"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("expected a .stfl source file"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("README.md"))
        .args(["--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "expected a .stfl source file, .stfb/.stflb bytecode file, or project directory",
        ));
}

#[test]
fn build_rejects_output_directory() {
    let temp = TempDir::new().unwrap();
    let output_dir = temp.path().join("outdir");
    fs::create_dir_all(&output_dir).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .arg("--output")
        .arg(&output_dir)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output must be a .stfb/.stflb bytecode file path",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "out.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output must end in .stfb or .stflb",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "target/debug"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output must end in .stfb or .stflb",
        ));
}

#[test]
fn explicit_missing_path_reports_missing_path() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("missing"))
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("missing").and(predicate::str::contains("does not exist")),
        );
}

#[test]
fn run_missing_bytecode_artifact_suggests_building_first() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("target/debug/app.stfb"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains("run `stoffel build` first"))
        .stderr(predicate::str::contains("pass a project/source path"))
        .stderr(predicate::str::contains("failed to load bytecode").not());
}

#[test]
fn run_invalid_bytecode_suggests_rebuilding_or_using_source() {
    let temp = TempDir::new().unwrap();
    let bytecode = temp.path().join("bad.stfb");
    fs::write(&bytecode, "not bytecode").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&bytecode)
        .args(["--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not load bytecode"))
        .stderr(predicate::str::contains("run `stoffel build`"))
        .stderr(predicate::str::contains("pass a .stfl source/project path"))
        .stderr(predicate::str::contains("InvalidMagicBytes"));
}

#[test]
fn run_auto_discovered_invalid_bytecode_suggests_rebuilding() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    let bytecode = project.join("target/debug/app.stfb");
    fs::create_dir_all(bytecode.parent().unwrap()).unwrap();
    thread::sleep(Duration::from_secs(1));
    fs::write(&bytecode, "not bytecode").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args(["--timeout-secs", "0", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not load bytecode"))
        .stderr(predicate::str::contains("run `stoffel build`"))
        .stderr(predicate::str::contains("InvalidMagicBytes"));
}

#[test]
fn project_discovery_errors_name_the_search_directory() {
    let temp = TempDir::new().unwrap();
    for command in ["run", "build", "status", "clean", "update"] {
        let mut cmd = Command::cargo_bin("stoffel").unwrap();
        cmd.current_dir(temp.path()).arg(command);
        if command == "update" {
            cmd.arg("--check");
        }
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("could not find Stoffel.toml"))
            .stderr(predicate::str::contains(temp.path().display().to_string()))
            .stderr(predicate::str::contains("run `stoffel init` first"))
            .stderr(predicate::str::contains("pass a project path"));
    }
}

#[test]
fn init_supports_declared_templates_and_library_mode() {
    let temp = TempDir::new().unwrap();
    for (name, marker) in [
        ("python", "requirements.txt"),
        ("rust", "Cargo.toml"),
        ("typescript", "package.json"),
        ("solidity-foundry", "foundry.toml"),
        ("solidity-hardhat", "hardhat.config.js"),
    ] {
        let path = temp.path().join(name);
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(["init", path.to_str().unwrap(), "--template", name])
            .assert()
            .success();
        assert!(path.join(marker).exists());
    }

    let library = temp.path().join("library");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", library.to_str().unwrap(), "--lib"])
        .assert()
        .success();
    assert!(library.join("src/lib.stfl").exists());
}

#[test]
fn nested_template_project_errors_suggest_nested_stoffel_path() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("rust-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", project.to_str().unwrap(), "--template", "rust"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args(["--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("found nested Stoffel project"))
        .stderr(predicate::str::contains(
            project.join("stoffel").display().to_string(),
        ))
        .stderr(predicate::str::contains("Pass one of those project paths"));
}

#[test]
fn init_rejects_library_with_template() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            temp.path().join("lib-rust").to_str().unwrap(),
            "--lib",
            "--template",
            "rust",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn init_errors_explain_existing_project_vs_nonempty_directory() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already contains Stoffel.toml"))
        .stderr(predicate::str::contains("stoffel status"))
        .stderr(predicate::str::contains("stoffel run"))
        .stderr(predicate::str::contains("refresh template files"));

    let non_project = temp.path().join("non-project");
    fs::create_dir_all(&non_project).unwrap();
    fs::write(non_project.join("notes.txt"), "keep me").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&non_project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists and is not empty"))
        .stderr(predicate::str::contains("Stoffel template files"))
        .stderr(predicate::str::contains("preserving unrelated files"));
}

#[test]
fn init_force_refreshes_existing_template_files() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("Stoffel.toml"), "not toml = ").unwrap();
    fs::write(project.join("notes.txt"), "keep me").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Config: ok"));
    assert_eq!(
        fs::read_to_string(project.join("notes.txt")).unwrap(),
        "keep me"
    );
}

#[test]
fn test_discovers_stfl_tests() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/add.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("test")
        .assert()
        .success()
        .stdout(predicate::str::contains("ok"));
}

#[test]
fn test_rejects_parameterized_programs_with_run_guidance() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path().join("src/main.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "stoffel test only runs no-argument test functions",
        ))
        .stderr(predicate::str::contains("requires inputs: a, b"))
        .stderr(predicate::str::contains("stoffel run"))
        .stderr(predicate::str::contains("--input a=<value>"))
        .stderr(predicate::str::contains("--input b=<value>"));
}

#[test]
fn test_accepts_project_folder_path() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::create_dir_all(project.join("tests")).unwrap();
    fs::write(
        project.join("tests/add.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("add.stfl"));
}

#[test]
fn test_flag_selects_specific_test_file() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/selected.stfl"),
        "def main() -> int64:\n  return 42\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("tests/ignored.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["test", "--test", "selected"])
        .assert()
        .success()
        .stdout(predicate::str::contains("selected.stfl"))
        .stdout(predicate::str::contains("ignored.stfl").not());
}

#[test]
fn test_flag_reports_when_name_matches_nothing() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/one.stfl"),
        "def main() -> int64:\n  return 1\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--test", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--test 'nope' did not match any test file or function",
        ));
}

#[test]
fn test_flag_selects_matching_function_files() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/one.stfl"),
        "def main() -> int64:\n  return 1\n\ndef selected() -> int64:\n  return 42\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("tests/two.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--test", "selected"])
        .assert()
        .success()
        .stdout(predicate::str::contains("one.stfl"))
        .stdout(predicate::str::contains("two.stfl").not());
}

#[test]
fn dev_help_exposes_hot_reload_controls() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["dev", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--once"))
        .stdout(predicate::str::contains("--poll-ms"))
        .stdout(predicate::str::contains("watching"));
}

#[test]
fn status_reports_project_health() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Project:"))
        .stdout(predicate::str::contains("Config: ok"))
        .stdout(predicate::str::contains("Compile: ok"))
        .stdout(predicate::str::contains("Network:"));
}

#[test]
fn status_compile_failures_suggest_check_after_fixing_source() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(temp.path().join("src/main.stfl"), "def main(\n").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("Compile: failed"))
        .stdout(predicate::str::contains("Syntax"))
        .stdout(predicate::str::contains("Next: fix the source error above"))
        .stdout(predicate::str::contains("stoffel check"))
        .stderr(predicate::str::contains("source file(s) failed to compile"));
}

#[test]
fn status_uses_consistent_mpc_validation_errors() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("threshold = 1", "threshold = 2"),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("4 * threshold"))
        .stdout(predicate::str::contains("3 * threshold").not());
}

#[test]
fn utility_commands_accept_project_folder_paths() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::create_dir_all(project.join("target/debug")).unwrap();
    fs::create_dir_all(project.join(".stoffel/cache")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Project: app"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check"])
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("clean")
        .arg(&project)
        .assert()
        .success();
    assert!(!project.join("target").exists());
    assert!(!project.join(".stoffel/cache").exists());
}

#[test]
fn clean_removes_target_and_cache_directories() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("target/debug")).unwrap();
    fs::create_dir_all(temp.path().join(".stoffel/cache")).unwrap();
    fs::create_dir_all(temp.path().join("node_modules")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["clean", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Cleaned Stoffel project artifacts and known ecosystem caches",
        ))
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("target"))
        .stdout(predicate::str::contains(".stoffel"))
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("Skipped missing"));

    assert!(!temp.path().join("target").exists());
    assert!(!temp.path().join(".stoffel").exists());
    assert!(!temp.path().join("node_modules").exists());
}

#[test]
fn update_check_reports_detected_update_targets() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["update", "--check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"))
        .stdout(predicate::str::contains("Update check:"));
}

#[test]
fn update_validates_project_path_before_self_update_output() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check"])
        .arg(temp.path().join("missing"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"))
        .stdout(predicate::str::contains("CLI self-update").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-project"])
        .arg(temp.path().join("missing"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"));
}

#[test]
fn utility_help_lists_status_clean_update_options() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("new"))
        .stdout(predicate::str::contains("doctor"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--all"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["test", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project directory or specific test file",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Project directory or source file"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["dev", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Project directory or source file"));
}
