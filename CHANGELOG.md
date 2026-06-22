# Changelog

All notable changes to the Stoffel crates are tracked here.

## [0.1.0] - 2026-06-22

### Added

- Initial 0.1.0 crate release metadata for the Stoffel VM runtime, shared VM types, compiler, SDK, CLI, and binding generator crates.
- Documented the current CLI, SDK, VM runner, MPC, AVSS, and FFI workflows in the repository README.

### Notes

- `stoffel-cli`, `stoffel-rust-sdk`, and `stoffel-bindgen` are currently marked `publish = false`.
- Publish order for the initial crate release is `stoffel-vm-types`, `stoffellang`, then downstream runtime/SDK crates such as `stoffel-vm`.
