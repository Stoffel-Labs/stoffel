# MPC Argmax / Argmin

Find the index of the largest (or smallest) value in a list of secret values,
returning the winning index **as a secret share** — the position is never
revealed in the clear. This is the typical output stage of private
classification/scoring.

A tournament tracks the running best value and its index; each step compares the
next value with the current best (`less_than`) and obliviously updates both with
`select`. The candidate index `i` is public (the loop counter), but which one
wins stays hidden.

The example finds argmax (index 3, value 90) and argmin (index 2, value 10) of
`[30, 70, 10, 90, 50]` and asserts both. `κ` is small for speed; production uses
`κ ≈ 40`.

Run it from the repository root:

```sh
stoffel run crates/stoffel-lang/examples/mpc_argmax
```
