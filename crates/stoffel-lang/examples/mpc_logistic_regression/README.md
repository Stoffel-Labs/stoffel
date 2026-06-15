# MPC Logistic Regression (private inference)

Binary logistic-regression classification on secret features with public weights
and bias: the predicted class is `[w·x + b ≥ 0]` (since `sigmoid(s) ≥ 0.5` iff
`s ≥ 0`, the class is the sign bit of the score). The score is a public-weighted
sum (cheap `mul_scalar`); the sign is one secure comparison. For the actual
probability you would apply `mpc_transcendental`'s sigmoid.

The example classifies a feature vector under two weight sets (→ 1 and 0). `κ` is
small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_logistic_regression --client-input 0=3 --client-input 0=5 --expected-output-clients 1
```
