# MPC Popcount

Population count (number of set bits) of a secret integer: bit-decompose it, then
sum the bit-shares. Returns a secret count.

The example computes `popcount(181) = 5` (`0b10110101`). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_popcount_secret --client-input 0=181 --expected-output-clients 1
```
