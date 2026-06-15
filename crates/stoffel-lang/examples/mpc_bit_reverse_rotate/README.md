# MPC Bit Reverse / Rotate

Reverse or rotate the bits of a secret word: bit-decompose, reindex the
bit-shares (reversal `i ↦ l−1−i`, left rotation `i ↦ (i+r) mod l`), and recombine.
Purely a permutation of shares — no secure multiplies beyond the decomposition.

The example reverses `1 → 128` and rotates `rotl(1,1) → 2` over 8 bits. `κ` is
small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_bit_reverse_rotate
```
