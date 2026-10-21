//! The command-line surface of `stoffel run-node` and `stoffel coord-ctl`: both
//! are listed by `stoffel --help`, forward their arguments untouched (their own
//! `--help` included), print a requested usage on stdout with exit 0, and keep
//! usage errors on stderr with a nonzero exit.

use assert_cmd::Command;
use predicates::prelude::*;

fn stoffel() -> Command {
    Command::cargo_bin("stoffel").expect("the stoffel binary is built")
}

#[test]
fn top_level_help_lists_both_subcommands() {
    stoffel()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("run-node"))
        .stdout(predicate::str::contains("coord-ctl"));
}

#[test]
fn run_node_help_is_the_driver_usage_on_stdout() {
    stoffel()
        .args(["run-node", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "stoffel run-node <path-to-compiled-binary>",
        ))
        .stderr(predicate::str::is_empty());
}

#[test]
fn run_node_usage_errors_go_to_stderr() {
    stoffel()
        .arg("run-node")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("stoffel run-node"));
}

#[test]
fn coord_ctl_help_is_its_usage_on_stdout() {
    stoffel()
        .args(["coord-ctl", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stoffel coord-ctl submit"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn coord_ctl_usage_errors_go_to_stderr() {
    stoffel()
        .arg("coord-ctl")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("stoffel coord-ctl"));
}
