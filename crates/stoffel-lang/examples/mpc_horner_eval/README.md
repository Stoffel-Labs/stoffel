# MPC Polynomial Evaluation (Horner)

Evaluate a polynomial with public coefficients at a **secret** point using
Horner's rule on shares: `p(x) = ((cₙ·x + c_{n-1})·x + ...)`. Each step is one
secure multiply + a public-constant add. This is the kernel behind function
approximation (`mpc_transcendental`).

The example evaluates `2x² + 3x + 1` at `x = 5` (→ 66).

```sh
stoffel run crates/stoffel-lang/examples/mpc_horner_eval
```
