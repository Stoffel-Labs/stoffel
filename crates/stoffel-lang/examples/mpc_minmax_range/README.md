# MPC Min / Max / Range

Reduce a secret list to its minimum, maximum, and range (`max − min`) by folding
oblivious `select` over secure comparisons. Returns secret values.

The example reduces `[50,20,40,10,30]` → min 10, max 50, range 40. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_minmax_range
```
