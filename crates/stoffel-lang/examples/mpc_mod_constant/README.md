# MPC Modulo by a Power of Two

Secret `x mod 2ᵏ` = the low `k` bits of `x`: bit-decompose and recombine
`bits[0..k)`. (Reduction modulo a power of two is local once the bits are shared.)
Modulo by a general public constant instead needs division — see
`mpc_secure_division` / `mpc_modulo_secret`.

The example computes `181 mod 16 = 5`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_mod_constant
```
