# MPC Mode

Most frequent value of a secret list over a **public** candidate domain: count
each candidate's occurrences (sum of equality bits) and keep the one with the
largest count (argmax via comparison + select). Returns the secret mode value.

The example finds the mode of `[3,5,3,7,3]` over candidates `{3,5,7}` (→ 3). `κ`
is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_mode --client-input 0=3 --client-input 1=5 --client-input 2=3 --client-input 3=7 --client-input 4=3 --expected-output-clients 5
```
