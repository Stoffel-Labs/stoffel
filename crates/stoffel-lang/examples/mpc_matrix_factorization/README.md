# MPC Matrix-Factorization Recommendation

Private recommendation via matrix factorization. A recommender factorizes the
ratings matrix into latent user and item factor vectors; the predicted rating is
the dot product of the two. Here client 0 holds a user's latent factors (plus an
observed rating) and client 1 holds an item's latent factors — neither client
sees the other's factors.

```
pred = <u, v>                  (predicted rating)
err  = pred - observed
u_j  = u_j - err · v_j          (one matrix-factorization SGD update, lr = 1)
```

The predicted rating is returned to both clients. With `u = [3, 2]`,
`v = [1, 2]`, `observed = 5`: `pred = 7`, `err = 2`, and the user factors update
to `[1, -2]`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_matrix_factorization --client-input 0=3 --client-input 0=2 --client-input 0=5 --client-input 1=1 --client-input 1=2 --expected-output-clients 2
```
