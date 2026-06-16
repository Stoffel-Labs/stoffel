# MPC Set Intersection

Intersection cardinality of two **secret** sets: for each `a ∈ A`, test membership
in `B` (OR of equalities) and sum the flags. Reveals only `|A ∩ B|`.

The example intersects `{3,5,8}` and `{5,8,9}` → 2. `κ` is small for speed.

```sh
stoffel run crates/stoffel-lang/examples/mpc_set_intersection --client-input 0=3 --client-input 0=5 --client-input 0=8 --client-input 1=5 --client-input 1=8 --client-input 1=9 --expected-output-clients 2
```
