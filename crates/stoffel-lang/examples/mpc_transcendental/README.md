# MPC Transcendental (fixed-point function approximation)

Approximate a transcendental function on **fixed-point** secret shares via a
polynomial, evaluated with a *truncate after each multiply* (`>> f` via
bit-decomposition) to stay in `Q_f`. This is the machinery behind secure
`exp`/`log`/`sigmoid`/`tanh`; higher-degree or minimax coefficients improve
accuracy.

The example computes a degree-2 Taylor `exp(x) ≈ 1 + x + x²/2` at `x = 1.0` in Q8,
giving `2.5 = 640` (the real `exp(1) ≈ 2.718`; degree-2 truncates to 2.5). `κ` is
small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_transcendental
```
