# MPC Multiplexer Tree

`n`-way multiplexer (for `n` a power of two): select `options[idx]` for a secret
index `idx` using a **log-depth** select tree driven by the *bits* of `idx`,
rather than a linear equality scan. At each level the candidates are halved by an
oblivious select on one index bit.

The example selects index 2 of `[10,20,30,40]` (→ 30). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_mux_tree --client-input 0=2 --expected-output-clients 1
```
