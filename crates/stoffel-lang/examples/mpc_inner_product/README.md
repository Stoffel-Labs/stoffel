# MPC Inner Product

Secure dot product of two secret vectors and a small linear (matrix-vector)
layer — the cheap, multiply-only core of private linear models.

`dot(a, b) = Σ aᵢbᵢ` uses a single **batched** secure multiply
(`Share.batch_mul`) followed by a local summation. A linear layer just applies
`dot` to each row of the weight matrix. No comparisons, so it is fast: one
multiply batch per dot product.

The example checks `dot([1,2,3],[4,5,6]) = 32` and a 2×3 layer `W·x = [19, 25]`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_inner_product --client-input 0=1 --client-input 0=2 --client-input 0=3 --client-input 1=4 --client-input 1=5 --client-input 1=6 --expected-output-clients 2
```
