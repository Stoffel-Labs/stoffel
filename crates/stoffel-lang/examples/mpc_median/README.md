# MPC Median

Median (and, generally, percentiles) of a secret list: sort with a fixed
compare-and-swap network (see `mpc_sorting_network`) and read the middle element.
Data-oblivious.

The example takes the median of `[50,20,40,10,30]` (→ 30). `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_median
```
