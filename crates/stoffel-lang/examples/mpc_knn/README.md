# MPC k-NN (nearest neighbour)

1-nearest-neighbour classification: squared-L2 distances from a secret query to a
set of labelled points, then argmin to pick the closest, returning its label as a
secret share. (k-NN with majority vote extends this with `mpc_sorting_network` +
`mpc_mode`.)

The example classifies query `(1,1)` against points `(0,0)/(10,10)/(5,5)` → label
of the nearest `(0,0)` = 0. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_knn --client-input 0=1 --client-input 0=1 --expected-output-clients 1
```
