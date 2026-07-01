# Changelog

All notable changes to the Stoffel crates are tracked here.

## [0.1.1]

### PR #67 - runner release and install updates

#### Added

- Added a release workflow for standalone `stoffel-run` binaries and extended `install.sh` with runner-only installation via `--runner-only` or `--component runner`.

#### Changed

- Changed the Rust SDK runner lookup to resolve `stoffel-run` from `PATH` instead of assuming Cargo's bin directory.
- Updated runner release targets and prebuilt target listings to publish macOS `arm64` binaries only.

### Dev - full branch changelog

#### Added

- Added compiler and VM measurement coverage for AES/CTR/CBC MPC round counts, full-unroll correctness, and regression cases around batching, public-gate folding, and secret-multiplication preservation.

#### Changed

- Reworked resolved bytecode handling with operand validation, compact resolved operands, resolved function headers, and improved constant/label/function metadata resolution.
- Improved `-O3` MPC optimization substantially: batched independent `Share.batch_mul` calls, cross-block CTR scheduling, constant branch folding, public-gate folding, bounded multi-return inlining, loop vectorization, and faster dependency tracking.
- Reduced AES-family MPC round counts in the tracked examples while preserving NIST/equivalence checks, including AES `-O3` from 3306 to 296 rounds, CTR `-O3` from 4774 to 418 rounds, and CBC `-O3` from 22876 to 1061 rounds across the optimizer and example updates.
- Updated MPC examples to use `add_constant` in place of `add_scalar` for clearer API semantics.

#### Fixed

- Fixed non-hermetic compiler optimization budgets that could leak through process-global environment variables across tests or concurrent compiles.
- Fixed full-unroll AES/CTR/CBC miscompiles caused by incomplete dependency modeling for in-place mutators, indexed writes, and field writes.
- Fixed `Share.batch_mul` fusion cases that could pass nested arrays to runtime scalar-share extraction by flattening nested operands and restoring result shape safely.
- Fixed public secret-multiplication batching edge cases by localizing provably public operands to local `mul_scalar` operations where appropriate.
- Fixed AVSS runner preprocessing so it no longer depends on receiving a client input.
- Fixed MPC runtime cloning so independent clones preserve client-store counts.

## [0.1.0] - 2026-06-22

### Added

- Initial 0.1.0 crate release metadata for the Stoffel VM runtime, shared VM types, compiler, SDK, CLI, and binding generator crates.
- Documented the current CLI, SDK, VM runner, MPC, AVSS, and FFI workflows in the repository README.

### Notes

- `stoffel-bindgen` is currently marked `publish = false`; `stoffel-cli` is released as a GitHub binary artifact rather than a crates.io package.
- Publish order for the initial crate release is `stoffel-vm-types`, `stoffellang`, `stoffel-vm`, `stoffel-vm-runner`, `stoffel-rust-sdk`, then downstream binary artifacts such as `stoffel-cli`.
