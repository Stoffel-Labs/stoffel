# MPC Matrix-Factorization Recommendation

Private recommendation via matrix factorization with a realistic latent
dimension (`k = 16`). A recommender factorizes the ratings matrix into latent
user and item factor vectors; the predicted rating is their dot product. Client
0 holds a user's `k`-dimensional factors (plus an observed rating) and client 1
holds an item's factors — neither client sees the other's factors.

```
pred = <u, v>                  (predicted rating)
err  = pred - observed
u_j  = u_j - err · v_j          (one matrix-factorization SGD update, lr = 1)
```

Both the dot product and the gradient run as literal-bound loops of secret
multiplications, so the compiler provisions exactly `k` beaver triples for each.
The predicted rating is returned to both clients.

The example uses two all-ones length-16 factor vectors (`pred = 16`) and an
observed rating of `20`, so the user factors update to `1 - (16-20)·1 = 5`.

Run it from the repository root (16 user factors + observed rating for client 0,
16 item factors for client 1):

```sh
stoffel run crates/stoffel-lang/examples/mpc_matrix_factorization \
  --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 \
  --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 \
  --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 \
  --client-input 0=1 --client-input 0=1 --client-input 0=1 --client-input 0=1 \
  --client-input 0=20 \
  --client-input 1=1 --client-input 1=1 --client-input 1=1 --client-input 1=1 \
  --client-input 1=1 --client-input 1=1 --client-input 1=1 --client-input 1=1 \
  --client-input 1=1 --client-input 1=1 --client-input 1=1 --client-input 1=1 \
  --client-input 1=1 --client-input 1=1 --client-input 1=1 --client-input 1=1 \
  --expected-output-clients 2
```
