# MPC Secret-Base Power

`base^e` for a **secret** base and a public exponent `e`, by repeated secure
multiplication. (Companion to `mpc_secret_exponentiation`, which hides the
exponent instead.)

The example computes `3^4 = 81`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_secret_base_power
```
