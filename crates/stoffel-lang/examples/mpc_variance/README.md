# MPC Variance

Variance of a secret list, computed exactly without division as `n·Σx² − (Σx)²`
( = `variance · n²`). Multiply-and-sum only; divide by `n²` afterward (publicly)
for the final value.

The example computes `n²·var([2,4,6,8]) = 80` (variance 5, `n² = 16`).

```sh
stoffel run crates/stoffel-lang/examples/mpc_variance --client-input 0=2 --client-input 1=4 --client-input 2=6 --client-input 3=8 --expected-output-clients 4
```
