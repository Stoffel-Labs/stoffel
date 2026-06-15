# MPC Modular Exponentiation

`base^e mod m` for a **secret** exponent `e` and public modulus `m`, via
square-and-multiply over the decomposed exponent with a reduction `mod m` after
every multiply (so values stay `< m`). The control flow is data-oblivious.

The example computes `3^5 mod 7 = 5`. Parameters are small (one of the heavier
examples — a secret modulo per step). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_modexp
```
