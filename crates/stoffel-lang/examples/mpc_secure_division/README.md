# MPC Secure Division

Integer division `a / d` where the divisor `d` is **secret** — the quotient is
computed without revealing `a`, `d`, or intermediate remainders.

This uses comparison-based **long division** (restoring division), which is exact
and has no convergence parameters to tune: bit-decompose `a`, then for each bit
from MSB to LSB shift it into the remainder (`R = 2R + aᵢ`), test `R ≥ d` with the
secure comparison, set that quotient bit, and conditionally subtract `d`. The
comparator sequence is fixed, so it is data-oblivious. Cost: `l` comparisons + `l`
multiplies.

(For fixed-point *reciprocal* `1/d` you would instead iterate Newton–Raphson /
Goldschmidt on shares; long division is the simplest exact route for integers.)

The example computes `47 / 5 = 9`. `κ` is small for speed; production uses `κ ≈ 40`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_secure_division
```
