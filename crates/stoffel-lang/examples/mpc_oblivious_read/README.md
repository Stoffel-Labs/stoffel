# MPC Oblivious Array Read

Read `arr[i]` for a **secret** index `i` without revealing `i` (or which cell was
accessed). The result is `Σⱼ [i == j] · arr[j]`: an equality bit per cell (secure
comparison) selects the matching entry, and the products are summed.

This is the foundational secret-indexed lookup that table-driven MPC needs.

The example reads index 2 of `[10,20,30,40]` (→ 30). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_oblivious_read
```
