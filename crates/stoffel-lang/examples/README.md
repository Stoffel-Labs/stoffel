# Stoffel Examples

This directory contains runnable Stoffel programs grouped by feature area. Each
example folder has a `main.stfl` source file and a short README.

## Layout

- `local_control_flow`: loops, ranges, functions, branching, and arithmetic.
- `local_collections`: list literals, indexing, and `append`/`push`/`len` aliases.
- `local_nested_generics`: generic functions over nested list shapes.
- `local_storage`: VM local storage through `LocalStorage`.
- `local_dynamic_workflow`: dynamic objects, runtime type inspection, arrays, and callbacks.
- `local_closure_counter`: captured upvalues and stateful closure callbacks.
- `local_text_processing`: string iteration for text checksums.
- `language_policy_engine`: import-driven policy scoring with numeric widths and boolean logic.
- `language_mpc_schemas`: object schemas with secret-typed fields for MPC jobs.
- `mpc_client_private_score`: client input shares, private share computation, and client output shares.
- `mpc_share_arithmetic`: basic secret-share creation, arithmetic, and opening.
- `mpc_runtime_info`: MPC runtime metadata and capability builtins.
- `mpc_client_federated_average`: client-provided secret inputs via `ClientStore`.
- `mpc_protocol_coordination`: RBC/ABA coordination for distributed protocol phases.
- `mpc_share_toolkit`: broad Share builtin coverage for MPC service programs.
- `avss_share_auditor`: AVSS share metadata inspection helpers.
- `threshold_signatures/*`: threshold signature programs based on the VM fixtures.
- `avss_certificate/*`: AVSS certificate keygen/signing flows based on the VM fixtures.

See `COVERAGE.md` for the syntax, semantic, and builtin coverage matrix.

## Validate

Compile every example and run local-only examples through the VM:

```sh
./examples/validate_examples.sh
```

The script defaults to the workspace root that contains this crate.
Override it if needed:

```sh
STOFFEL_VM_DIR=/path/to/StoffelVM ./examples/validate_examples.sh
```

To run a distributed MPC example with Docker Compose after compiling:

```sh
STOFFEL_PROGRAM_NAME=mpc_runtime_info.stflb \
  ./examples/validate_examples.sh --docker-mpc
```

If Docker is unavailable, run the same 5-party smoke test as local host
processes:

```sh
STOFFEL_PROGRAM_NAME=mpc_runtime_info.stflb \
  ./examples/validate_examples.sh --host-mpc
```

For threshold ECDSA over secp256k1:

```sh
STOFFEL_PROGRAM_NAME=threshold_signatures_threshold_ecdsa_secp256k1.stflb \
STOFFEL_MPC_BACKEND=avss \
STOFFEL_MPC_CURVE=secp256k1 \
  ./examples/validate_examples.sh --docker-mpc
```

Compiled binaries are written to `examples/dist/`.
