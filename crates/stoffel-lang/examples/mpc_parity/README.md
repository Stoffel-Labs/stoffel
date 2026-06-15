# MPC Parity

Parity (XOR of all bits) of a secret integer: bit-decompose, then XOR-fold the
bit-shares (`p ← p ⊕ bᵢ`). Returns a secret bit — 1 for an odd number of set bits.

The example checks `parity(7) = 1` and `parity(5) = 0`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_parity
```
