# MPC Bitwise Share

This example wraps `list[secret bool]` inputs in a small object and applies
native secret-boolean `not`, `and`, `or`, and `xor` operations element-by-element.

Run it through the local MPC CLI from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_bitwise_share/main.stfl --input 'a=[true,false,true,false]' --input 'b=[true,true,false,false]'
```

The local MPC run should keep the inputs and results as one-bit shares:

```text
Share(SecretInt { bit_length: 1 })
```
