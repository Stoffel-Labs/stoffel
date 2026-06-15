# MPC GCD

Greatest common divisor of two secret integers via Euclid's algorithm with a
**fixed iteration bound** (so the loop is data-oblivious): each step replaces
`(a, b)` with `(b, a mod b)` while `b ≠ 0` (using `mpc_modulo_secret` + oblivious
select); the value settles to `gcd`.

The example computes `gcd(12, 8) = 4`. Parameters are small (`l=5`) so it runs in
reasonable time; this is the heaviest example (a secret modulo per round).

```sh
stoffel run crates/stoffel-lang/examples/mpc_gcd
```
