# MPC Bitwise Integer Ops

Bitwise `AND`/`OR`/`XOR` and logical right shift on secret integers — i.e.
crossing from the arithmetic domain into bit-level logic.

Each operand is bit-decomposed once (see `mpc_bit_decomposition`); then each
output bit is a gate on the shared bits (`AND = a·b`, `OR = a+b−ab`,
`XOR = a+b−2ab`) and the bits are recombined into an integer share. A logical
right shift by a public `k` is just truncation — drop the low `k` bits.

The example computes `22 & 13`, `22 | 13`, `22 ^ 13` and `22 >> 2` on shares and
asserts each against the clear result. `κ` is small for speed; production uses
`κ ≈ 40`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_bitwise_int
```
