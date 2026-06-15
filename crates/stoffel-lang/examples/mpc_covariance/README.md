# MPC Covariance

Covariance of two secret vectors, computed exactly without division as
`n·Σ(xᵢyᵢ) − Σxᵢ·Σyᵢ` ( = `covariance · n²`). Uses a batched multiply for the
cross term; divide by `n²` publicly for the final value (and by the std-devs for
correlation).

The example computes `n²·cov([1,2,3],[2,4,6]) = 12`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_covariance
```
