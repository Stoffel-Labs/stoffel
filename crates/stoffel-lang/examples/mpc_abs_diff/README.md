# MPC Absolute Difference

`|a − b|` for secret `a, b`: one secure comparison `[a < b]` selects between
`b − a` and `a − b`. The building block for L1 distances.

The example checks `|3−10| = |10−3| = 7`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_abs_diff
```
