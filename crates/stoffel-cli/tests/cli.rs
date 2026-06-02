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
fn run_executes_clear_project_with_inputs() {
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
        .args(["build", "--output", "target/debug/app.stflb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Built"));

    assert!(temp.path().join("target/debug/app.stflb").exists());
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
        .args(["build", "--output", "target/debug/app.stflb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "target/debug/app.stflb",
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
