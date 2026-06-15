# MPC LCM

Least common multiple of two secret integers: `lcm(a,b) = a·b / gcd(a,b)`,
composing the bounded-Euclid GCD (`mpc_gcd`) with secure division
(`mpc_secure_division`). Only the LCM is revealed.

The example computes `lcm(4,6) = 12` (gcd 2, `24/2`). Parameters are small (GCD is
the heavy part). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_lcm --client-input 0=4 --client-input 0=6 --expected-output-clients 1
```
