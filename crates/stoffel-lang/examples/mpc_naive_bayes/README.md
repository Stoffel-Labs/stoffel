# MPC Naive Bayes

Multinomial naive-Bayes scoring on secret feature counts with public
log-probability tables: each class score is `log-prior + Σ xᵢ·log p[c][i]`
(a public-weighted sum), and the prediction is the argmax over class scores. Only
the predicted class is revealed.

The example scores two classes for features `[2,1]` and predicts class 1. `κ` is
small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_naive_bayes --client-input 0=2 --client-input 0=1 --expected-output-clients 1
```
