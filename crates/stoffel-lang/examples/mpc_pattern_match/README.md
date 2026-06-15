# MPC Pattern Match

Count occurrences of a secret pattern in a secret text. At each offset, a match is
the product (AND) of per-position equalities; summing over offsets gives the
occurrence count. Both text and pattern stay private.

The example finds `[2,3]` in `[1,2,3,2,3]` at offsets 1 and 3 → 2. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_pattern_match
```
