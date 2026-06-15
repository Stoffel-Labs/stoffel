# MPC Sorting Network

Sort a small list of secret values with a fixed **compare-and-swap network**,
then read off the median — a data-oblivious building block for order statistics.

`cas(x, y)` orders a pair: `lt = [x < y]`, `min = select(lt, x, y)`,
`max = select(lt, y, x)` — one secure comparison + two oblivious selects. A
9-comparator network sorts 5 elements; because the comparator sequence is fixed
(independent of the values), the access pattern reveals nothing. The median is
the middle element after sorting.

The example sorts `[50,20,40,10,30]`, asserts the result is ascending, and checks
the median is `30`. `κ` is small for speed; production uses `κ ≈ 40`.

```sh
stoffel run crates/stoffel-lang/examples/mpc_sorting_network
```
