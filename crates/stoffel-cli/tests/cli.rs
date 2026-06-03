use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

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
fn run_executes_local_mpc_project_with_inputs() {
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
        .args(["run", "--input", "a=40", "--input", "b=2"])
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
        .args(["--input", "a=21", "--input", "b=21"])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
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
        .stdout(predicate::str::contains("Removed Stoffel build artifacts"));

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
fn utility_help_lists_status_clean_update_options() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("update"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--all"));
}
