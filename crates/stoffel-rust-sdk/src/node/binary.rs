//! Finding the `stoffel` binary whose `run-node` subcommand runs a party.
//!
//! One resolution order for every SDK spawn site (local coordinator runs and
//! [`crate::StoffelServer`]):
//!
//! 1. an explicit path (`local_runner_path` / `runner_path` builders, the CLI's
//!    `--runner`);
//! 2. `STOFFEL_RUN_BIN`;
//! 3. `stoffel` next to the current executable;
//! 4. `stoffel` on `PATH`;
//! 5. the workspace's `target/{debug,release}/stoffel`.
//!
//! Every resolved path is a `stoffel` CLI binary, spawned as
//! `<path> run-node <argv>`.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The environment variable naming the `stoffel` binary to spawn parties with.
pub(crate) const STOFFEL_RUN_BIN_ENV: &str = "STOFFEL_RUN_BIN";

/// The binary every resolved path names.
const STOFFEL_BINARY_NAME: &str = "stoffel";

/// How to get a `stoffel` binary, for error messages.
const BUILD_HINT: &str = "build it with `cargo build -p stoffel-cli` or install it with \
     `cargo install --path crates/stoffel-cli`";

/// Resolves the `stoffel` binary that `purpose` spawns as `stoffel run-node`.
///
/// `purpose` names the caller in error messages, e.g. "server start".
pub(crate) fn resolve_stoffel_binary(
    explicit_path: Option<&Path>,
    purpose: &str,
) -> Result<PathBuf> {
    if let Some(path) = explicit_path {
        return resolve_existing_path(path).ok_or_else(|| {
            Error::Unsupported(format!(
                "{purpose} requires an existing stoffel binary to spawn `stoffel run-node` \
                 parties; configured path does not exist: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = std::env::var_os(STOFFEL_RUN_BIN_ENV).map(PathBuf::from) {
        return resolve_existing_path(&path).ok_or_else(|| {
            Error::Unsupported(format!(
                "{purpose} requires an existing stoffel binary to spawn `stoffel run-node` \
                 parties; {STOFFEL_RUN_BIN_ENV} points to a missing path: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = sibling_binary() {
        return Ok(path);
    }

    if let Some(path) = find_binary_on_path(STOFFEL_BINARY_NAME) {
        return Ok(path);
    }

    if let Some(path) = workspace_binary() {
        return Ok(path);
    }

    Err(Error::Unsupported(format!(
        "{purpose} requires a stoffel binary to spawn `stoffel run-node` parties; {BUILD_HINT}, \
         set {STOFFEL_RUN_BIN_ENV} to its path, or pass the path explicitly"
    )))
}

fn stoffel_file_name() -> String {
    format!("{STOFFEL_BINARY_NAME}{}", std::env::consts::EXE_SUFFIX)
}

/// `stoffel` sitting next to the current executable — the CLI itself, or an
/// application installed beside it (e.g. in `~/.local/bin`).
fn sibling_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.with_file_name(stoffel_file_name());
    is_executable_file(&candidate).then_some(candidate)
}

/// The workspace's own build of the CLI: the profile directory the current
/// executable was built into first (a test binary under `target/<profile>/deps`),
/// then `target/debug` and `target/release`.
fn workspace_binary() -> Option<PathBuf> {
    let target = workspace_root()?.join("target");
    let mut candidates = Vec::new();
    if let Some(profile_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| target_profile_dir_from_exe(&exe))
    {
        candidates.push(profile_dir.join(stoffel_file_name()));
    }
    candidates.push(target.join("debug").join(stoffel_file_name()));
    candidates.push(target.join("release").join(stoffel_file_name()));
    candidates
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
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

/// An explicit path as given, or, when relative and missing, relative to the
/// workspace root (so `target/debug/stoffel` works from any test directory).
fn resolve_existing_path(path: &Path) -> Option<PathBuf> {
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
    use super::{find_binary_in_path, target_profile_dir_from_exe};
    use std::path::PathBuf;

    #[test]
    fn find_binary_in_path_finds_executable_file() {
        let missing_dir = tempfile::tempdir().unwrap();
        let bin_dir = tempfile::tempdir().unwrap();
        let binary = bin_dir
            .path()
            .join(format!("stoffel{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&binary, b"#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&binary, permissions).unwrap();
        }

        let path = std::env::join_paths([missing_dir.path(), bin_dir.path()]).unwrap();

        assert_eq!(find_binary_in_path("stoffel", &path), Some(binary));
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
}
