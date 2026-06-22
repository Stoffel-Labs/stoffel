# MPC Logistic Regression (classification)

Logistic-regression classification over a realistic feature dimension
(`d = 32`). The model weights and bias are public; the client's feature vector
is secret-shared. The class is the sign of the score:
`class = [w·x + b >= 0]` (since `sigmoid(score) >= 0.5` iff `score >= 0`).

Because the weights are public, the dot product `w·x` is free local scaling
(`mul_scalar`, no beaver triples); the only MPC cost is the single secure
comparison for the sign test. So scaling the feature dimension is essentially
free.

With an all-ones weight vector and all-ones features, `w·x = 32 >= 0`, so the
predicted class is `1`.

Run it from the repository root (32 secret features for client 0):

```sh
stoffel run crates/stoffel-lang/examples/mpc_logistic_regression --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --expected-output-clients 1
```
