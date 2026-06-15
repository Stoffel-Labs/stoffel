# MPC Zero Test

`[x == 0]` for a secret `x ∈ [0, 2ˡ)` with a single secure comparison:
`x == 0` iff `¬(0 < x)`. Returns a secret bit (the cheap building block behind
equality-to-a-constant and predicate gating).

The example checks `is_zero(0) = 1` and `is_zero(5) = 0`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_is_zero --client-input 0=0 --expected-output-clients 1
```
