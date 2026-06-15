# MPC Count / Frequency

Count how many elements of a secret list equal a secret `target` — the sum of
per-element equality bits. Returns a secret count.

The example counts occurrences of `5` in `[5,3,5,7,5]` (→ 3). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_count_frequency
```
