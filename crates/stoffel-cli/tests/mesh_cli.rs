use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// A `stoffel` command whose meshes live under `home`, not the user's.
fn stoffel(home: &Path) -> Command {
    let mut command = Command::cargo_bin("stoffel").unwrap();
    command.env("STOFFEL_HOME", home);
    command
}

/// A project with two mesh programs in `programs/`: one whose clients give
/// inputs and receive the sum, and one without clients.
fn project_with_programs(temp: &TempDir) -> std::path::PathBuf {
    let project = temp.path().join("proj");
    stoffel(temp.path())
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    let programs = project.join("programs");
    fs::create_dir_all(&programs).unwrap();
    fs::write(
        programs.join("sum.stfl"),
        "def main() -> int64:\n  var a = ClientStore.take_share(0, 0)\n  var b = ClientStore.take_share(1, 0)\n  var c = ClientStore.take_share(1, 1)\n  var sum = a.add(b).add(c)\n  sum.send_to_client(0)\n  return sum.open()\n",
    )
    .unwrap();
    fs::write(
        programs.join("product.stfl"),
        "def main() -> int64:\n  var share = Share.from_clear_int(6, 64)\n  var product = share.mul(Share.from_clear_int(7, 64))\n  return product.open()\n",
    )
    .unwrap();
    project
}

#[test]
fn run_on_a_mesh_that_is_not_running_says_how_to_start_it() {
    let temp = TempDir::new().unwrap();
    let project = project_with_programs(&temp);
    stoffel(temp.path())
        .current_dir(&project)
        .args(["run", "programs/product.stfl", "--mesh", "absent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mesh `absent` is not running"))
        .stderr(predicate::str::contains("stoffel start-mesh"));
}

#[test]
fn run_on_a_mesh_rejects_other_execution_modes_and_named_inputs() {
    let temp = TempDir::new().unwrap();
    let project = project_with_programs(&temp);
    for (flag, value) in [
        ("--local", None),
        ("--network", None),
        ("--runner", Some("/bin/sh")),
    ] {
        let mut command = stoffel(temp.path());
        command
            .current_dir(&project)
            .args(["run", "programs/product.stfl", "--mesh", "dev", flag]);
        if let Some(value) = value {
            command.arg(value);
        }
        command
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "--mesh runs on a standing mesh; remove {flag}"
            )));
    }
    stoffel(temp.path())
        .current_dir(&project)
        .args([
            "run",
            "programs/product.stfl",
            "--mesh",
            "dev",
            "--input",
            "a=1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--client-input SLOT=VALUE"));
}

#[test]
fn stopping_a_mesh_that_is_not_running_is_not_an_error() {
    let temp = TempDir::new().unwrap();
    stoffel(temp.path())
        .args(["stop-mesh", "absent"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Mesh `absent` is not running"));
}

#[test]
fn start_mesh_validates_its_arguments_before_starting_anything() {
    let temp = TempDir::new().unwrap();
    let project = project_with_programs(&temp);
    stoffel(temp.path())
        .args(["start-mesh", "programs", "--name", "bad/name"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mesh names use letters"));
    stoffel(temp.path())
        .current_dir(&project)
        .args([
            "start-mesh",
            "programs",
            "--name",
            "dev",
            "--parties",
            "3",
            "--threshold",
            "3",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--threshold must be smaller"));
    let empty = temp.path().join("empty");
    fs::create_dir_all(&empty).unwrap();
    stoffel(temp.path())
        .args(["start-mesh"])
        .arg(&empty)
        .args(["--name", "dev"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "contains no .stfl or .stflb programs",
        ));
    assert!(!temp.path().join("meshes/dev/mesh.toml").exists());
}

#[test]
#[ignore = "starts a real standing mesh; needs stoffel-run built (cargo build -p stoffel-vm-runner)"]
fn parallel_runs_share_a_detached_mesh_until_it_is_stopped() {
    let temp = TempDir::new().unwrap();
    let project = project_with_programs(&temp);
    stoffel(temp.path())
        .current_dir(&project)
        .args(["start-mesh", "programs", "--name", "dev", "--detach"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Mesh `dev` is ready"));

    // Starting it again while it runs is refused.
    stoffel(temp.path())
        .current_dir(&project)
        .args(["start-mesh", "programs", "--name", "dev", "--detach"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already running"));

    let runs = [
        (
            vec![
                "programs/sum.stfl",
                "--client-input",
                "0=1",
                "--client-input",
                "1=2",
                "--client-input",
                "1=3",
            ],
            "6\nclient 0: 6\n",
        ),
        (
            vec![
                "programs/sum.stfl",
                "--client-input",
                "0=10",
                "--client-input",
                "1=20",
                "--client-input",
                "1=30",
            ],
            "60\nclient 0: 60\n",
        ),
        (vec!["programs/product.stfl"], "42\n"),
    ];
    let children = runs
        .iter()
        .map(|(args, _)| {
            std::process::Command::new(assert_cmd::cargo::cargo_bin("stoffel"))
                .env("STOFFEL_HOME", temp.path())
                .current_dir(&project)
                .arg("run")
                .args(args)
                .args(["--mesh", "dev"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for (child, (_, expected)) in children.into_iter().zip(&runs) {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), *expected);
    }

    stoffel(temp.path())
        .args(["stop-mesh", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stopped mesh `dev`"));
    stoffel(temp.path())
        .current_dir(&project)
        .args(["run", "programs/product.stfl", "--mesh", "dev"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not running"));
}
