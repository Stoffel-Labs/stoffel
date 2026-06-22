# MPC Set Cardinalities

Intersection and union sizes of two secret sets: `|A ∩ B|` is the sum of
membership flags; `|A ∪ B| = |A| + |B| − |A ∩ B|`. Reveals only the counts.

The example computes `|{3,5,8} ∩ {5,8,9}| = 2` and `|∪| = 4`. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_set_cardinality --client-input 0=3 --client-input 0=5 --client-input 0=8 --client-input 1=5 --client-input 1=8 --client-input 1=9 --expected-output-clients 2
```
