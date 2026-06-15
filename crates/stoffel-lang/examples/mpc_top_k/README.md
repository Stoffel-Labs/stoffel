# MPC Top-k / Order Statistic

The `k`-th smallest of a secret list (order statistic): sort with a fixed network
and read index `k−1`. Top-k is the symmetric tail. Data-oblivious.

The example takes the 2nd smallest of `[50,20,40,10,30]` (→ 20). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_top_k
```
