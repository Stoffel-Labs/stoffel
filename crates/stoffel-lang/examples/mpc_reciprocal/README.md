# MPC Reciprocal

Fixed-point reciprocal of a secret `d`: `⌊2^F / d⌋`, i.e. `1/d` scaled by `2^F`.
Computed exactly by dividing the public constant `2^F` by the secret `d` with the
long-division routine (`mpc_secure_division`) — no Newton iteration or
convergence tuning needed.

The example computes `1/5` in Q8 = `⌊256/5⌋ = 51` (≈ 0.199). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_reciprocal
```
