# MPC Bit Decomposition

Bit-decomposition from Damgård, Fitzi, Kiltz, Nielsen and Toft: given a secret
`[a]` known to lie in `[0, 2ˡ)`, produce shares of its bits `[a₀..a_{l-1}]`
without revealing `a`. It is the building block that paper uses for equality,
comparison and exponentiation (see `mpc_secure_comparison`).

How it works:

1. Draw `m = l + κ` shared random bits (via the joint-random-bit protocol from
   `mpc_random_bit`) and form `[r] = Σ 2ⁱ[rᵢ]`.
2. Reveal `c = a + r`. The `κ` extra random bits statistically hide `a`
   (leakage ≈ `2⁻κ`).
3. `a = c − r`. Because `c` is public, a borrow-chain subtractor over the public
   bits of `c` and the shared bits of `[r]` yields `a`'s bits — one secure
   multiply per bit.

The example decomposes `42`, reveals the low bits, and asserts they reconstruct
the input.

`κ` is kept small here so it runs quickly; a real deployment uses `κ ≈ 40`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_bit_decomposition
```
