# MPC Histogram

Count the elements of a secret list falling into each **public** half-open bucket
`[lo, hi)`. Each membership is a range check (`x ≥ lo ∧ x < hi`); per-bucket
counts are the sums. Only the counts are revealed.

The example buckets `[5,12,18,25,8]` into `[0,10),[10,20),[20,30)` → `[2,2,1]`.
`κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_histogram --client-input 0=5 --client-input 1=12 --client-input 2=18 --client-input 3=25 --client-input 4=8 --expected-output-clients 5
```
