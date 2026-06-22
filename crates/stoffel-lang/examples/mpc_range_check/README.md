# MPC Range Check

Secret bit `[lo ≤ x ≤ hi]` for secret `x`, `lo`, `hi`: `(x ≥ lo) ∧ (x ≤ hi)`, each
half a secure comparison, combined with one multiply. Nothing about `x` leaks.

The example checks `50 ∈ [10,100]` (→1) and `5 ∈ [10,100]` (→0). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_range_check --client-input 0=50 --expected-output-clients 1
```
