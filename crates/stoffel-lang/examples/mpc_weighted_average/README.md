# MPC Weighted Average

Weighted mean of secret values with secret weights:
`⌊Σ(wᵢ·xᵢ) / Σ wᵢ⌋`. The numerator uses a batched secure multiply; the division
is by the (secret) weight sum.

The example computes `wavg([10,20,30], w=[1,2,3]) = ⌊140/6⌋ = 23`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_weighted_average --client-input 0=10 --client-input 1=20 --client-input 2=30 --expected-output-clients 3
```
