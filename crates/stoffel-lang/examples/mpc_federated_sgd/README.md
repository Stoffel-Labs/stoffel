# MPC Federated Logistic-Regression SGD Step

One step of federated stochastic gradient descent for logistic regression at a
realistic feature dimension (`d = 32`). The servers hold the global weight
vector `w` as secret shares; a client contributes a single private training row
`(features x, label y)`. The step computes:

```
z    = w · x                  (inner product, d secret multiplications)
pred = clamp(2 + z, 0, 4)      (sigmoid approximation in a scale of 4, so the
                                linearization 1/2 + z/4 needs no secret division)
err  = pred - 4·y
w_j  = w_j - err · x_j          (gradient update, lr = 1)
```

The inner product and the gradient run as literal-bound loops so the compiler
provisions exactly `d` beaver triples for each; only the `clamp` uses the
carry-based secure comparison. Updated weights go back to the client. This
extends [`mpc_client_federated_average`](../mpc_client_federated_average) from
averaging to a real training update.

With all-ones features, label `0`, and all-ones initial weights: `z = 32`,
`pred = 4`, `err = 4`, so each weight updates to `1 - 4 = -3`.

Run it from the repository root (32 feature inputs + a label for client 0):

```sh
stoffel run crates/stoffel-lang/examples/mpc_federated_sgd --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=0 --expected-output-clients 1
```
