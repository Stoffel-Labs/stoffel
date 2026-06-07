# Example Coverage

The examples are intended to be useful programs first and coverage fixtures
second. This matrix tracks the language and builtin surface that each program
exercises.

## Language Syntax And Semantics

| Surface | Example coverage |
| --- | --- |
| `main` entry points, typed and inferred-return `def` functions, explicit `return`, `discard` | Most examples; see `language_policy_engine`, `local_dynamic_workflow`, `mpc_client_private_score`, `mpc_share_toolkit` |
| Module imports and import aliases | `language_policy_engine` imports `math_rules as rules` |
| Type aliases and all core scalar type names | `language_policy_engine`, `language_mpc_schemas` |
| Integer literal widths and suffixes | `language_policy_engine` uses signed and unsigned 8/16/32/64-bit literals |
| `None`, `bool`, `float`/`float64`, `bytes` aliases | `language_policy_engine`, `language_mpc_schemas`, crypto and signature examples |
| Lists, dictionaries, nested generics, indexing, assignment through index | `language_policy_engine`, `language_mpc_schemas`, `local_dynamic_workflow`, `local_collections`, `local_nested_generics` |
| Dynamic objects and runtime field access | `local_dynamic_workflow` |
| Object schema declarations, base object syntax, secret-typed fields | `language_mpc_schemas` |
| Secret values and MPC secret flow | `mpc_boolean_circuit`, `mpc_client_federated_average`, `avss_certificate/sign`, `mpc_share_toolkit` |
| `if`/`elif`/`else`, `while`, `for` over ranges, lists, and strings | `language_policy_engine`, `local_control_flow`, `local_text_processing` |
| Unary `-` and `not`, arithmetic, comparison, boolean operators | `language_policy_engine`, `local_control_flow` |
| Compound assignment `+=`, `-=`, `*=`, `/=`, `%=` | `language_policy_engine` |
| Field-access method syntax and object builtin syntax | `local_collections`, `mpc_runtime_info`, `mpc_share_toolkit` |
| Closures exposed by the language stdlib | `local_dynamic_workflow`, `local_closure_counter` |

`enum`, `break`, `continue`, `yield`, and `try/catch` have AST or lexer traces
but are not implemented parser/runtime syntax today, so they are not represented
as supported language examples.

## Core Builtins

| Builtin surface | Example coverage |
| --- | --- |
| `print`, `type` | `local_dynamic_workflow`, `language_mpc_schemas` |
| `append`, `len` | `local_dynamic_workflow`, `local_collections`, `local_nested_generics` |
| `create_closure`, `create_closure_with_upvalue`, `call_closure`, `call_closure_with_arg`, `get_upvalue`, `set_upvalue` | `local_dynamic_workflow`, `local_closure_counter` |
| `LocalStorage.store`, `load`, `retrieve`, `delete`, `exists` | `local_storage`, `avss_share_auditor` |
| `LocalStorage.load_share` | `avss_certificate/sign` |

## MPC And Crypto Builtins

| Builtin surface | Example coverage |
| --- | --- |
| `Mpc.party_id`, `n_parties`, `threshold`, `is_ready`, `instance_id`, `protocol_name`, `curve`, `field`, `has_capability`, `capabilities` | `mpc_runtime_info` |
| `Mpc.rand`, `Mpc.rand_int` | `mpc_share_toolkit` |
| `ClientStore.take_share`, `take_share_fixed`, `get_number_clients` | `avss_certificate/sign`, `mpc_client_federated_average` |
| `MpcOutput.send_to_client` and `Share.send_to_client` | `mpc_client_private_score`, `mpc_share_toolkit`, `avss_certificate/sign` |
| Share creation, arithmetic, scalar ops, integer and fixed-point opening, batch opening, metadata, commitments, field arithmetic, client output, exponent opening | `mpc_boolean_circuit`, `mpc_client_private_score`, `mpc_share_toolkit`, `mpc_client_federated_average`, `mpc_share_arithmetic`, threshold signature examples |
| `Bytes.concat`, `Bytes.from_string` | threshold signature examples, `mpc_share_toolkit` |
| `Crypto.sha256`, `sha512`, `hash_to_field`, `field_inv`, `point_x_to_field`, `field_to_scalar_bytes`, `point_to_sec1`, `hash_to_g1` | threshold signature examples, `avss_certificate/keygen`, `avss_share_auditor` |
| `Avss.get_commitment`, `get_key_name`, `commitment_count`, `is_avss_share` | `avss_share_auditor` |
| `Rbc.broadcast`, `receive`, `receive_any`; `Aba.propose`, `result`, `propose_and_wait` | `mpc_protocol_coordination` |
