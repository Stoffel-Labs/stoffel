# MPC Integer Square Root

`⌊√n⌋` for a secret `n`, computed as the count of `k ∈ {1..K}` with `k² ≤ n`.
Each `k²` is a public constant, so every term is a single secure comparison and
the result is their sum — no division or Newton iteration.

The example checks `isqrt(49)=7` and `isqrt(50)=7`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_sqrt
```
