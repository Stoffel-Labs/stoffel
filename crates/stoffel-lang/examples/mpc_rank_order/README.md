# MPC Rank / Order Statistics

The rank of each secret element = the number of strictly smaller elements
(`Σⱼ [arr[j] < arr[i]]`). The rank vector is a permutation that places each
element into sorted position (the basis for sorting and order statistics).

The example computes ranks of `[30,10,20]` → `[2,0,1]`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_rank_order
```
