# MPC Lowest Set Bit / Trailing Zeros

Trailing-zero count of a secret integer (position of the lowest set bit).
Bit-decompose, take a bottom-up prefix-OR `s_i = OR(bits[0..i])`; the number of
positions before the first set bit is `Σ (1 − s_i)`. Returns a secret value.

The example computes `tz_count(40) = 3` (`0b101000`). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_lowest_set_bit
```
