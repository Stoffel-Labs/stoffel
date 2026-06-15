# MPC Secure Comparison

Secure comparison from Damgård–Fitzi–Kiltz–Nielsen–Toft (with the Catrina–de
Hoogh masking): compute a secret-shared bit `[a < b]` for secrets `a, b ∈ [0, 2ˡ)`
without revealing the inputs or the result.

The answer is a **single secret bit**, and this protocol extracts just that bit —
it does **not** bit-decompose the whole value (see `mpc_bit_decomposition` for the
full decomposition).

`z = 2ˡ + a − b` lies in `[0, 2^{l+1})`, and `a < b` iff bit `l` of `z` is `0`.
We obtain that one bit without the others:

1. Mask `z` by `r = r_low + 2^{l+1}·r_high`, where `r_low` is `l+1` shared random
   bits and `r_high` is a single `κ`-bit bounded random (`Share.random_int`) — so
   only `l+1` random *bits* are generated, not `l+κ`.
2. Reveal `c = z + r` (statistically hides `z`, leakage ≈ `2⁻κ`).
3. `z = c − r`: a borrow chain over bits `0..l-1` (public `cᵢ`, shared `rᵢ`, one
   multiply per bit) gives the borrow into bit `l`, then `z_l = c_l ⊕ r_l ⊕ borrow`.
   Return `1 − z_l`.

The example checks `<`, `>` and `=` and asserts the results.

`κ` is kept small here so it runs quickly; a real deployment uses `κ ≈ 40`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_secure_comparison
```
