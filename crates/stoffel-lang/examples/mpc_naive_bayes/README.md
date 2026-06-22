# MPC Naive Bayes (classification)

Multinomial naive-Bayes classification over a realistic feature dimension
(`d = 32`). Each class score is `log-prior + Σ x_i · log p[c][i]` using public
log-probability tables; the predicted class is the argmax of the per-class
scores. The client's feature counts are secret-shared.

Because the log tables are public, every class score is free local scaling
(`mul_scalar`, no beaver triples) — the only MPC cost is the argmax comparison
between the two class scores.

With all-ones features, class-0 weights of `1` and class-1 weights of `2`:
`s0 = 32`, `s1 = 64`, so the argmax is class `1`.

Run it from the repository root (32 secret feature counts for client 0):

```sh
stoffel run crates/stoffel-lang/examples/mpc_naive_bayes --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --expected-output-clients 1
```
