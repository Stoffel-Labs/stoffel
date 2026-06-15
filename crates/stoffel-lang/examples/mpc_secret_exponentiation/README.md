# MPC Secret Exponentiation

Compute `base^e` where the exponent `e` is **secret**, via square-and-multiply
over `e`'s bits — a data-oblivious loop, so nothing about `e` leaks.

Bit-decompose `e`; `acc` starts at 1, and each step obliviously multiplies `acc`
by the running power when the exponent bit is 1
(`acc = select(e_i, acc·power, acc)`) and squares the power. Every bit is
processed regardless of its value, so the control flow is independent of `e`.

The example computes `3^5 = 243` with a secret exponent. Keep `base`/`e` small so
`base^e` fits the integer width; `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_secret_exponentiation
```
