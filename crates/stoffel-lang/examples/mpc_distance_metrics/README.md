# MPC Distance Metrics

L1 and squared-L2 distances between two secret vectors. Squared-L2
`Σ(xᵢ−yᵢ)²` needs no comparison (squaring removes the sign); L1 `Σ|xᵢ−yᵢ|` uses
`abs_diff` (one comparison per coordinate). Foundations for nearest-neighbour and
clustering.

The example computes `L1([1,5,3],[4,1,3]) = 7` and `L2² = 25`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_distance_metrics
```
