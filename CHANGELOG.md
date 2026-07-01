# Changelog

All notable changes to the Stoffel crates are tracked here.

## [0.1.1]

### PR #67 - runner release and install updates

#### Added

- Added a release workflow for standalone `stoffel-run` binaries and extended `install.sh` with runner-only installation via `--runner-only` or `--component runner`.

#### Changed

- Changed the Rust SDK runner lookup to resolve `stoffel-run` from `PATH` instead of assuming Cargo's bin directory.
- Updated runner release targets and prebuilt target listings to publish macOS `arm64` binaries only.

## [0.1.0] - 2026-06-22

### Added

- Initial 0.1.0 crate release metadata for the Stoffel VM runtime, shared VM types, compiler, SDK, CLI, and binding generator crates.
- Documented the current CLI, SDK, VM runner, MPC, AVSS, and FFI workflows in the repository README.

### Notes

- `stoffel-bindgen` is currently marked `publish = false`; `stoffel-cli` is released as a GitHub binary artifact rather than a crates.io package.
- Publish order for the initial crate release is `stoffel-vm-types`, `stoffellang`, `stoffel-vm`, `stoffel-vm-runner`, `stoffel-rust-sdk`, then downstream binary artifacts such as `stoffel-cli`.
