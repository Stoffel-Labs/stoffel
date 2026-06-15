# MPC Secure Comparison

Secure comparison from Damgård, Fitzi, Kiltz, Nielsen and Toft: compute a
secret-shared bit `[a < b]` for secrets `a, b ∈ [0, 2ˡ)` without revealing the
inputs or the result.

It uses a single bit-decomposition (see `mpc_bit_decomposition`): for
`z = 2ˡ + a − b ∈ [0, 2^{l+1})`, `a < b` holds iff bit `l` of `z` is `0`
(if `a ≥ b` then `z ≥ 2ˡ` so the bit is 1; if `a < b` then `z = 2ˡ − (b − a) < 2ˡ`
so the bit is 0). The protocol decomposes `z` and returns `1 − z_l`.

The example checks both directions (`100 < 150` and `150 < 100`) and asserts the
results.

`κ` is kept small here so it runs quickly; a real deployment uses `κ ≈ 40`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_secure_comparison
```
