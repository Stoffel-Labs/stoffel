# MPC Clamp

Clamp a secret `x` to `[lo, hi]` = `max(lo, min(x, hi))`, built from secure
comparison + oblivious select. The result stays secret-shared.

The example clamps `50 → 50`, `5 → 10`, `150 → 100` against `[10,100]`. `κ` is
small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_clamp --client-input 0=150 --expected-output-clients 1
```
