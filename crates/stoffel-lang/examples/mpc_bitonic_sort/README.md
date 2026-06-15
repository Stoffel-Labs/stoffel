# MPC Bitonic Sort

Batcher's bitonic sorting network for a power-of-two list of secret values. The
comparator schedule is generated from index logic (`partner = i ⊕ j`, direction
from `i ∧ k`) and applied with a directional compare-exchange — fully
data-oblivious, and scales better than the naive O(n²) network.

The example sorts 8 values and asserts the result is ascending. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_bitonic_sort
```
