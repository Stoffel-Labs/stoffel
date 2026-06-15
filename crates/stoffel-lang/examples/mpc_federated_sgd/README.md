# MPC Federated Logistic-Regression SGD Step

One step of federated stochastic gradient descent for logistic regression. The
servers hold the global weight vector `w` as secret shares; a client contributes
a single private training row `(features x, label y)`. The step computes:

```
z    = w · x                  (inner product)
pred = clamp(2 + z, 0, 4)      (sigmoid approximation in a scale of 4, so the
                                linearization 1/2 + z/4 needs no secret division)
err  = pred - 4·y
w_j  = w_j - err · x_j          (gradient update, lr = 1)
```

and returns the updated weights to the client. Everything stays secret-shared;
only the `clamp` uses the carry-based secure comparison from
[`mpc_secure_comparison`](../mpc_secure_comparison). This extends
[`mpc_client_federated_average`](../mpc_client_federated_average) from averaging
to an actual training update.

With `w = [1, -1]`, `x = [2, 1]`, `y = 1`: `z = 1`, `pred = 3`, `err = -1`, so
`w` updates to `[3, 0]`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_federated_sgd --client-input 0=2 --client-input 0=1 --client-input 0=1 --expected-output-clients 1
```
