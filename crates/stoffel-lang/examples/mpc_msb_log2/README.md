# MPC MSB Index / floor(log2)

Index of the most significant set bit of a secret `x ≥ 1` (i.e. `⌊log₂ x⌋`).
Bit-decompose, take a top-down prefix-OR (`q_i = OR(bits[i..])`); the number of
ones equals `msb + 1`, so the answer is `(Σ q_i) − 1`. Result is a secret value.

The example computes `floor_log2(42) = 5`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_msb_log2
```
