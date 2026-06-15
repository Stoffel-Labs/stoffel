# MPC Modulo (secret divisor)

Remainder `a mod d` for a **secret** divisor `d`, via the same comparison-based
long division as `mpc_secure_division` — but returning the final remainder
instead of the quotient. Exact, data-oblivious.

The example computes `47 mod 5 = 2`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_modulo_secret
```
