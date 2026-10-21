//! Finding the `stoffel` binary whose `run-node` subcommand runs each party
//! this crate spawns.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

const STOFFEL_BINARY_NAME: &str = "stoffel";

fn stoffel_file_name() -> String {
    format!("{STOFFEL_BINARY_NAME}{}", std::env::consts::EXE_SUFFIX)
}

/// The `stoffel` binary to spawn as `stoffel run-node` parties, for `purpose`
/// (named in the error). In order: an explicit path, `STOFFEL_RUN_BIN`, a built
/// workspace `stoffel`, one next to the current executable, then `PATH`.
pub(crate) fn resolve_stoffel_binary(
    explicit_path: Option<&Path>,
    purpose: &str,
) -> Result<PathBuf> {
    if let Some(path) = explicit_path {
        return resolve_existing_runner_path(path).ok_or_else(|| {
            Error::Unsupported(format!(
                "{purpose} requires an existing stoffel binary to spawn `stoffel run-node` parties; configured path does not exist: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = std::env::var_os("STOFFEL_RUN_BIN").map(PathBuf::from) {
        return resolve_existing_runner_path(&path).ok_or_else(|| {
            Error::Unsupported(format!(
                "{purpose} requires an existing stoffel binary to spawn `stoffel run-node` parties; STOFFEL_RUN_BIN points to a missing path: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = built_workspace_runner() {
        return Ok(path);
    }

    if let Some(path) = sibling_runner() {
        return Ok(path);
    }

    if !running_from_workspace_target() {
        if let Some(path) = path_runner() {
            return Ok(path);
        }
    }

    if let Some(workspace_root) = workspace_root() {
        return Err(Error::Unsupported(format!(
            "{purpose} requires a built workspace stoffel binary at {} to spawn `stoffel run-node` parties; build it with `cargo build -p stoffel-cli`, set STOFFEL_RUN_BIN, or pass the path explicitly",
            workspace_root
                .join("target")
                .join(if cfg!(debug_assertions) { "debug" } else { "release" })
                .join(stoffel_file_name())
                .display()
        )));
    }

    if let Some(path) = path_runner() {
        return Ok(path);
    }

    Err(Error::Unsupported(format!(
        "{purpose} requires a stoffel binary to spawn `stoffel run-node` parties; install the stoffel CLI with `cargo install --path crates/stoffel-cli` so it lands on your PATH, set STOFFEL_RUN_BIN, pass the path explicitly, or build `cargo build -p stoffel-cli`"
    )))
}

/// Look for a `stoffel` binary sitting next to the current executable, as an
/// application installed beside the `stoffel` CLI (e.g. in `~/.local/bin`) is.
fn sibling_runner() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.with_file_name(STOFFEL_BINARY_NAME);
    candidate.exists().then_some(candidate)
}

/// Look for a `stoffel` binary anywhere on the user's PATH.
fn path_runner() -> Option<PathBuf> {
    find_binary_on_path(STOFFEL_BINARY_NAME)
}

fn built_workspace_runner() -> Option<PathBuf> {
    let workspace_root = workspace_root()?;
    let mut candidates = Vec::new();

    if let Some(profile_dir) = current_target_profile_dir() {
        candidates.push(profile_dir.join(stoffel_file_name()));
    }

    candidates.push(
        workspace_root
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join(stoffel_file_name()),
    );

    candidates.push(
        workspace_root
            .join("target")
            .join("debug")
            .join(stoffel_file_name()),
    );

    candidates
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
}

fn current_target_profile_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    target_profile_dir_from_exe(&exe)
}

fn running_from_workspace_target() -> bool {
    let (Some(workspace_root), Ok(exe)) = (workspace_root(), std::env::current_exe()) else {
        return false;
    };
    path_is_under(&exe, &workspace_root.join("target"))
}

fn path_is_under(path: &Path, ancestor: &Path) -> bool {
    path.ancestors().any(|candidate| candidate == ancestor)
}

fn target_profile_dir_from_exe(exe: &Path) -> Option<PathBuf> {
    let parent = exe.parent()?;
    let profile_dir = if parent.file_name().is_some_and(|name| name == "deps") {
        parent.parent()?
    } else {
        parent
    };
    profile_dir
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "target")
        .then(|| profile_dir.to_path_buf())
}

fn find_binary_on_path(binary_name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;

    find_binary_in_path(binary_name, &path)
}

fn find_binary_in_path(binary_name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    let binary_name = format!("{binary_name}{}", std::env::consts::EXE_SUFFIX);

    std::env::split_paths(&path)
        .map(|dir| dir.join(&binary_name))
        .find(|candidate| is_executable_file(candidate))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn resolve_existing_runner_path(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }
    if path.is_absolute() {
        return None;
    }
    workspace_root()
        .map(|root| root.join(path))
        .filter(|candidate| candidate.exists())
}

fn workspace_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_binary_in_path_finds_executable_file() {
        let missing_dir = tempfile::tempdir().unwrap();
        let bin_dir = tempfile::tempdir().unwrap();
        let binary = bin_dir.path().join(stoffel_file_name());
        std::fs::write(&binary, b"#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&binary, permissions).unwrap();
        }

        let path = std::env::join_paths([missing_dir.path(), bin_dir.path()]).unwrap();

        assert_eq!(
            find_binary_in_path(STOFFEL_BINARY_NAME, &path),
            Some(binary)
        );
    }

    #[test]
    fn target_profile_dir_from_test_exe_uses_parent_of_deps_dir() {
        let exe: PathBuf = ["workspace", "target", "debug", "deps", "sdk_usage-abc"]
            .iter()
            .collect();

        assert_eq!(
            target_profile_dir_from_exe(&exe),
            Some(["workspace", "target", "debug"].iter().collect())
        );
    }

    #[test]
    fn path_is_under_detects_workspace_target_executables() {
        let exe: PathBuf = ["workspace", "target", "debug", "deps", "sdk_usage-abc"]
            .iter()
            .collect();
        let target: PathBuf = ["workspace", "target"].iter().collect();
        let other: PathBuf = ["workspace", "other-target"].iter().collect();

        assert!(path_is_under(&exe, &target));
        assert!(!path_is_under(&exe, &other));
    }
}
